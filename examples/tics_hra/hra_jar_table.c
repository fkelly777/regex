/**
 * @file    rxp_jar_table.c
 * @author  Titan IC Systems <support@titanicsystems.com>
 *
 * @section DESCRIPTION
 *
 *   The JAR (Job Awaiting Response) table is used to keep track of jobs until responses are received. When a job
 *   is sent to the RXP, the job is added to the JAR table. A JAR table job ID is assigned which contains information
 *   about the thread sending the job, a sequence number and the index in a buffer pool. When a response is received
 *   the job ID is parsed to find the appropriate entry in the JAR table. The sequence number, thread ID and buffer
 *   pool index are all used to ensure that the entry in the JAR table is valid. The JAR table contains a pointer to
 *   the job data and expected matches, so that the matches in the response may be validated.
 *
 * @section LICENSE
 *
 *   BSD LICENSE
 *
 *   Copyright (C) 2014-2019 Titan IC Systems Ltd. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Titan IC Systems Ltd. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/queue.h>

#include "hra_errors.h"
#include "hra_jar_table.h"
#include "hra_platform.h"

#define HRA_JAR_TABLE_TIMEOUT_MS     30000

#define HRA_ERR(a...) fprintf(stderr, a);

/**
 * Function removes entry from active list and adds it to the free list.
 *
 * @param jar_table    JAR table to remove entry from
 * @param entry        Entry to remove
 */
static void
rxp_jar_table_remove_entry(struct rxp_jar_table *jar_table,
                           struct rxp_jar_buffer *entry);

/*********************************************************************************************************************/
/*                          PUBLIC FUNCTIONS                                                                         */
/*********************************************************************************************************************/

/*
 * Function initializes the specified JAR table.
 */
rxp_jar_table_t*
rxp_jar_table_init(uint8_t thread_index)
{
    int i;
    uint64_t secs;
    rxp_jar_table_t *jar_table;

    if (NULL == (jar_table = calloc(1, sizeof(rxp_jar_table_t))))
    {
        HRA_ERR("Error: Failed to allocate memory for JAR table\n");
        return (NULL);
    }

    jar_table->initialised = JAR_TABLE_INITIALISED;

    TAILQ_INIT(&(jar_table->free_list));
    TAILQ_INIT(&(jar_table->active_list));

    /*
     * Initialize the timeout period.
     */
    secs = HRA_JAR_TABLE_TIMEOUT_MS / 1000;
    jar_table->timeout_ticks = hra_ticks_per_sec() * secs;

    for (i = 0; i < HRA_NUM_JAR_ENTRIES; i++)
    {
        jar_table->buffer_pool[i].table_index       = i;                /* Allows direct access via the buffer pool */
        jar_table->buffer_pool[i].sequence_number   = 0;                /* Incremented each time buffer is used */
        jar_table->buffer_pool[i].thread_index      = thread_index;     /* Each thread uses a different jar table */
        jar_table->buffer_pool[i].active            = 0;                /* Set to 1 when buffer is used */
        jar_table->buffer_pool[i].job               = NULL;             /* Pointer to application specific job data */
        jar_table->buffer_pool[i].timeouts          = 0;                /* Job timeouts */
        jar_table->buffer_pool[i].tag               = 0;                /* Application specific tag */

        TAILQ_INSERT_HEAD(&(jar_table->free_list), &jar_table->buffer_pool[i], jar_entry);
    }
    return (jar_table);
}

/*
 * Function adds a job to the specified job table. It creates a job ID and returns this via a parameter.
 */
int
rxp_jar_table_add_job(rxp_jar_table_t *jar_table,
                      void *job,
                      int tag,
                      uint32_t *job_id)
{
    struct rxp_jar_buffer *entry;

    if ((jar_table == NULL) || (job_id == NULL))
    {
        HRA_ERR("Error: NULL pointer passed to function %s\n", __FUNCTION__);
        return (HRA_STATUS_NULL_POINTER);
    }

    if (jar_table->initialised != JAR_TABLE_INITIALISED)
    {
        HRA_ERR("Error: Jar table not initialised: %s\n", __FUNCTION__);
        return (HRA_STATUS_NOT_INITIALIZED);
    }

    *job_id = 0;

    /*
     * Check if there are any entries in the free list. If so, remove the entry from the free list and add it to
     * the active list.
     */
    entry = TAILQ_LAST(&(jar_table->free_list), rxp_jar_list);
    if (entry != NULL)
    {
        TAILQ_REMOVE(&(jar_table->free_list), entry, jar_entry);
        TAILQ_INSERT_HEAD(&(jar_table->active_list), entry, jar_entry);

        /*
         * Increment the entry sequence number. If it has wrapped and is now 0, then increment it. The sequence
         * number is used in the JAR table job ID, and this ensures that the job ID is never 0 which is considered
         * to be an invalid value.
         */
        entry->sequence_number++;
        if (entry->sequence_number == 0)
        {
            entry->sequence_number++;
        }

        /*
         * Mark the entry as active, populate a pointer to the specifed job and register the time at which the job
         * was added to the JAR table.
         */
        entry->active    = 1;
        entry->job       = job;
        entry->start_ticks = hra_ticks_read();
        entry->tag       = tag;
        entry->timeouts  = 0;

        /*
         * Construct the JAR table job ID. This is sent to the RXP in the Job Descriptor and returned in the response
         * descriptor. It is used to look up and validate the JAR table entry.
         */
        *job_id = (((uint32_t)entry->table_index) << 16) +
            (((uint32_t)entry->sequence_number) << 8) +
            (uint32_t)(entry->thread_index);
    }

    return (HRA_STATUS_OK);
}

/*
 * Function looks up an entry in the JAR table by parsing the passed in received job ID and extracting
 * the table entry.
 */
int
rxp_jar_table_check_response(rxp_jar_table_t *jar_table,
                             uint32_t job_id,
                             void **job,
                             int *tag)
{
    uint16_t table_index;
    uint8_t sequence_number;
    uint8_t thread_index;
    struct rxp_jar_buffer *entry;

    if ((jar_table == NULL) || (job == NULL) || (tag == NULL))
    {
        HRA_ERR("Error: NULL pointer passed to function %s\n", __FUNCTION__);
        return (HRA_STATUS_NULL_POINTER);
    }

    if (jar_table->initialised != JAR_TABLE_INITIALISED)
    {
        HRA_ERR("Error: Jar table not initialised: %s\n", __FUNCTION__);
        return (HRA_STATUS_NOT_INITIALIZED);
    }

    *job = NULL;

    /*
     * Extract the table index, sequence number and thread index from the received job ID.
     */
    table_index     = (uint16_t)(job_id >> 16);
    sequence_number = (uint8_t)(job_id >> 8);
    thread_index    = (uint8_t)(job_id);

    /*
     * This could happen if the job ID in the response is corrupted.
     */
    if (table_index >= HRA_NUM_JAR_ENTRIES)
    {
        HRA_ERR("Error: JAR table index out of bounds\n");
        return (HRA_STATUS_INVALID_JAR_INDEX);
    }

    /*
     * The table index part of the job ID is used to lookup the entry in the buffer pool.
     */
    entry = &(jar_table->buffer_pool[table_index]);

    /*
     * The sequence numbers may not match if a response was delayed, the JAR table entry timed out, the entry was
     * reused and then the original response was received.
     * The thread index may not match if the packet steering is not working properly.
     * The active parameter in the entry may be 0 if the entry timed out before a response was received.
     */
    if ((sequence_number == entry->sequence_number) &&
        (thread_index == entry->thread_index) &&
        (entry->active == 1))
    {
        *job = entry->job;
        *tag = entry->tag;
        rxp_jar_table_remove_entry(jar_table, entry);
    }


    return (HRA_STATUS_OK);
}

/*
 * Function looks up an entry in the JAR table by parsing the passed in received job ID and extracting
 * the table entry.
 */
int
rxp_jar_table_check_response2(rxp_jar_table_t *jar_table,
                              uint32_t job_id,
                              void **job,
                              int *tag,
                              uint64_t *latency_ticks)
{
    uint16_t table_index;
    uint8_t sequence_number;
    uint8_t thread_index;
    struct rxp_jar_buffer *entry;

    if ((jar_table == NULL) || (job == NULL) || (tag == NULL))
    {
        HRA_ERR("Error: NULL pointer passed to function %s\n", __FUNCTION__);
        return (HRA_STATUS_NULL_POINTER);
    }

    if (jar_table->initialised != JAR_TABLE_INITIALISED)
    {
        HRA_ERR("Error: Jar table not initialised: %s\n", __FUNCTION__);
        return (HRA_STATUS_NOT_INITIALIZED);
    }

    *job = NULL;

    /*
     * Extract the table index, sequence number and thread index from the received job ID.
     */
    table_index     = (uint16_t)(job_id >> 16);
    sequence_number = (uint8_t)(job_id >> 8);
    thread_index    = (uint8_t)(job_id);

    /*
     * This could happen if the job ID in the response is corrupted.
     */
    if (table_index >= HRA_NUM_JAR_ENTRIES)
    {
        HRA_ERR("Error: JAR table index out of bounds\n");
        return (HRA_STATUS_INVALID_JAR_INDEX);
    }

    /*
     * The table index part of the job ID is used to lookup the entry in the buffer pool.
     */
    entry = &(jar_table->buffer_pool[table_index]);

    /*
     * The sequence numbers may not match if a response was delayed, the JAR table entry timed out, the entry was
     * reused and then the original response was received.
     * The thread index may not match if the packet steering is not working properly.
     * The active parameter in the entry may be 0 if the entry timed out before a response was received.
     */
    if ((sequence_number == entry->sequence_number) &&
        (thread_index == entry->thread_index) &&
        (entry->active == 1))
    {
        *job = entry->job;
        *tag = entry->tag;
        *latency_ticks = hra_ticks_read() - entry->start_ticks;
        rxp_jar_table_remove_entry(jar_table, entry);
    }


    return (HRA_STATUS_OK);
}

/*
 * Check the tail of the active list in the JAR table. If the entry has been in the active list for longer
 * than a timeout period then check the maximum permitted timeouts. If the entry has timed out less than the
 * maximum number of permitted timeouts then re-enqueue the entry, and update the job ID. Else remove the
 * entry from the active list.
 */
int
rxp_jar_table_check_timeout(rxp_jar_table_t *jar_table,
                            void **job,
                            unsigned int max_timeouts,
                            uint32_t *job_id,
                            enum rxp_jar_table_timeout_status *status)
{
    uint64_t diff_ticks;
    uint64_t current_ticks;
    struct rxp_jar_buffer *entry;

    if ((jar_table == NULL) || (job == NULL) || (status == NULL) || (job_id == NULL))
    {
        HRA_ERR("Error: NULL pointer passed to function %s\n", __FUNCTION__);
        return (HRA_STATUS_NULL_POINTER);
    }

    if (jar_table->initialised != JAR_TABLE_INITIALISED)
    {
        HRA_ERR("Error: Jar table not initialised: %s\n", __FUNCTION__);
        return (HRA_STATUS_NOT_INITIALIZED);
    }

    *job = NULL;
    *status = HRA_JAR_TABLE_NO_TIMEOUT;

    entry = TAILQ_LAST(&(jar_table->active_list), rxp_jar_list);
    if (entry != NULL)
    {
        current_ticks = hra_ticks_read();
        diff_ticks    = current_ticks - entry->start_ticks;
        if (diff_ticks > jar_table->timeout_ticks)
        {
            *job = entry->job;
            entry->timeouts++;

            /*
             * If the entry has timed out less than the maximum permitted amount then calculate a new job ID,
             * reset the start time and move the entry to the head of the active list. The job should be sent to
             * the RXP again. Else remove the entry from the active list. The job is considered timed out and
             * is not retransmitted.
             */
            if (entry->timeouts < max_timeouts)
            {
                entry->start_ticks = hra_ticks_read();

                entry->sequence_number++;
                if (entry->sequence_number == 0)
                {
                    entry->sequence_number++;
                }

                /*
                 * Construct the JAR table job ID. This is sent to the RXP in the Job Descriptor and returned in the
                 * response descriptor. It is used to look up and validate the JAR table entry.
                 */
                *job_id = (((uint32_t)entry->table_index) << 16) +
                    (((uint32_t)entry->sequence_number) << 8) +
                    (uint32_t)(entry->thread_index);

                TAILQ_REMOVE(&(jar_table->active_list), entry, jar_entry);
                TAILQ_INSERT_HEAD(&(jar_table->active_list), entry, jar_entry);

                *status = HRA_JAR_TABLE_TIMEOUT_AND_REENQUEUED;
            }
            else
            {
                rxp_jar_table_remove_entry(jar_table, entry);
                *status = HRA_JAR_TABLE_FINAL_TIMEOUT;
            }
        }
    }

    return (HRA_STATUS_OK);
}

/*
 * Function returns non-0 if jar table is full.
 */
int
rxp_jar_table_full(rxp_jar_table_t *jar_table,
                   unsigned *full)
{
    if ((jar_table == NULL) || (full == NULL))
    {
        HRA_ERR("Error: NULL pointer passed to function %s\n", __FUNCTION__);
        return (HRA_STATUS_NULL_POINTER);
    }

    if (jar_table->initialised != JAR_TABLE_INITIALISED)
    {
        HRA_ERR("Error: Jar table not initialised: %s\n", __FUNCTION__);
        return (HRA_STATUS_NOT_INITIALIZED);
    }

    *full = (NULL == TAILQ_LAST(&(jar_table->free_list), rxp_jar_list));

    return (HRA_STATUS_OK);
}

/**********************************************************************************************************************/
/*                                   LOCAL FUNCTIONS                                                                  */
/**********************************************************************************************************************/

/*
 * Function removes entry from active list and adds it to the free list.
 */
static void
rxp_jar_table_remove_entry(struct rxp_jar_table *jar_table,
                           struct rxp_jar_buffer *entry)
{
    entry->active = 0;
    entry->job    = NULL;
    TAILQ_REMOVE(&(jar_table->active_list), entry, jar_entry);
    TAILQ_INSERT_HEAD(&(jar_table->free_list), entry, jar_entry);
}
