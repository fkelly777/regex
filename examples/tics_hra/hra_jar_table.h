/**
 * @file    rxp_jar_table.h
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

#ifndef _HRA_JAR_TABLE_H_
#define _HRA_JAR_TABLE_H_

#include <time.h>
#include <sys/queue.h>

#define JAR_TABLE_INITIALISED 0x12345432
#define HRA_NUM_JAR_ENTRIES   (1024)

struct rxp_jar_buffer {
    int              active;
    int              tag;
    uint16_t         table_index;
    uint8_t          sequence_number;
    uint8_t          thread_index;
    uint64_t         start_ticks;
    void            *job;
    unsigned         timeouts;
    /*
     * This holds the pointers to the next and previous entries in
     * the tail queue.
     */
    TAILQ_ENTRY(rxp_jar_buffer) jar_entry;
};

TAILQ_HEAD(rxp_jar_list, rxp_jar_buffer);
struct rxp_jar_table
{
    uint32_t                initialised;
    uint64_t                timeout_ticks;
    struct rxp_jar_buffer   buffer_pool[HRA_NUM_JAR_ENTRIES];
    struct rxp_jar_list     free_list;
    struct rxp_jar_list     active_list;
};

typedef struct rxp_jar_table rxp_jar_table_t;

enum rxp_jar_table_timeout_status {
    HRA_JAR_TABLE_NO_TIMEOUT,
    HRA_JAR_TABLE_TIMEOUT_AND_REENQUEUED,
    HRA_JAR_TABLE_FINAL_TIMEOUT
};

/**
 * Function initializes the specified JAR table. The free list and active list are initialized. Every entry in
 * the buffer pool is initialized. Then every entry in the buffer pool is added to the free list.
 *
 * @param thread_index   Parameter which is used to uniquely identify the JAR table
 * @return               Pointer to JAR table if ok, else NULL
 */
rxp_jar_table_t*
rxp_jar_table_init(uint8_t thread_index);

/**
 * Function adds a job to the specified JAR table. It returns a JAR table job ID which is used in the job descriptor
 * send to the RXP. When a response is received the job ID is used to lookup an entry in the JAR table. If no entries
 * are available in the JAR table, then a job ID of 0 is returned. This is considered to be an invalid value.
 *
 * @param jar_table         JAR table to add job to
 * @param job               Job to add to JAR table
 * @param tag               Application specific tag associated with job
 * @param job_id            JAR table job ID is returned if entry available in JAR table, else 0
 * @return                  HRA_STATUS_OK if ok, else error code- note that no available entries in the JAR table is
 *                          not considered an error.
 */
int
rxp_jar_table_add_job(rxp_jar_table_t *jar_table,
                      void *job,
                      int tag,
                      uint32_t *job_id);

/**
 * Function looks up an entry in the JAR table by parsing the passed in received job ID and extracting
 * the table entry. The entry is validated to ensure that if refers to the job described in the job ID.
 * It is possible that the entry may refer to a different job- this may happen if the JAR table entry
 * timed out.
 *
 * @param jar_table         JAR table to check for entry
 * @param job_id            Received job ID to use for JAR table lookup
 * @param job               Pointer to job if entry found, else NULL
 * @param tag               Application specific tag associated with job
 * @return                  HRA_STATUS_OK if ok, else error code
 */
int
rxp_jar_table_check_response(rxp_jar_table_t *jar_table,
                             uint32_t job_id,
                             void **job,
                             int *tag);

int
rxp_jar_table_check_response2(rxp_jar_table_t *jar_table,
                             uint32_t job_id,
                             void **job,
                             int *tag,
                             uint64_t *latency_ticks);

/**
 * Check the tail of the active list in the JAR table. If the entry has been in the active list for longer
 * than a timeout period then check the maximum permitted timeouts. If the entry has timed out less than the
 * maximum number of permitted timeouts then re-enqueue the entry, and update the job ID. Else remove the
 * entry from the active list.
 *
 * @param jar_table    JAR table to check for timeout
 * @param job          Pointer to job pointer- populated if an entry has timed out
 * @param max_timeouts Re-enqueue entry if the number of timeouts is less than this value
 * @param job_id       New job ID- populated if the entry is re-enqueued
 * @param status       Returned timeout status of the job in the JAR table.
 *                     HRA_JAR_TABLE_NO_TIMEOUT if the tail entry has not timed out
 *                     HRA_JAR_TABLE_TIMEOUT_AND_REENQUEUED if the tail entry has timed out but has been re-enqueued
 *                     HRA_JAR_TABLE_FINAL_TIMEOUT if the tail entry has timed out the maximum permitted times
 * @return             HRA_STATUS_OK if ok, else error code
 */
int
rxp_jar_table_check_timeout(rxp_jar_table_t *jar_table,
                            void **job,
                            unsigned int max_timeouts,
                            uint32_t *job_id,
                            enum rxp_jar_table_timeout_status *status);

/**
 * Function returns non-0 in full paramater if jar table is full.
 *
 * @param jar_table    JAR table to check
 * @param full         Set to non-zero if JAR table is full
 * @return             HRA_STATUS_OK if ok, else error code
 */
int
rxp_jar_table_full(rxp_jar_table_t *jar_table,
                   unsigned *full);

#endif /* _HRA_JAR_TABLE_H_ */
