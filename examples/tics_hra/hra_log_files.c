/**
 * @file    hra_log_files.c
 * @author  Titan IC Systems <support@titanicsystems.com>
 *
 * @section DESCRIPTION
 *
 *   Supports functionality for debug logging of match discrepancies,
 *   all matches and all responses.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <stdbool.h>
#include "hra_jobset.h"
#include "hra_log_files.h"
#include "hra_errors.h"

#define HRA_LOG_FILE_MAX_ENTRIES            4096
#define HRA_MATCH_DISCREPANCIES_STRING_LEN  200

int log_file_count = 0;

struct hra_match_discrepancies_log {
    int num_entries;
    bool truncated;
    bool do_not_truncate;
    bool file_created;
    char entry[HRA_LOG_FILE_MAX_ENTRIES][160];
};

struct hra_match_discrepancies_log *match_discrepancies_logs;

struct hra_debug_match {
    uint32_t rxp_job_id;
    uint32_t user_job_id;
    uint32_t rule_id;
    uint64_t start_ptr;
    uint32_t length;
    int jobset_iteration;
    int thread_index;
};

struct hra_debug_match_log {
    int num_entries;
    bool truncated;
    bool do_not_truncate;
    bool file_created;
    struct hra_debug_match matches[HRA_LOG_FILE_MAX_ENTRIES];
};

struct hra_debug_match_log *debug_match_logs;

struct hra_debug_match_log *debug_unique_match_logs;

struct hra_debug_response {
    uint32_t rxp_job_id;
    uint32_t user_job_id;
    uint16_t  status;
    uint8_t  match_count;
    uint8_t  detected_match_count;
    uint16_t primary_thread_count;
    uint16_t instruction_count;
    uint16_t latency_count;
    uint16_t pmi_min_byte_ptr;
    int jobset_iteration;
    int thread_index;
};

struct hra_debug_response_log {
    int num_entries;
    bool truncated;
    bool do_not_truncate;
    bool file_created;
    struct hra_debug_response responses[HRA_LOG_FILE_MAX_ENTRIES];
};

struct hra_debug_response_log *debug_response_logs;

static int hra_log_match_discrepancies_dump_id (int log_file_id, bool final_dump);
static int hra_log_debug_matches_dump_id       (int log_file_id, bool final_dump);
static int hra_log_debug_unique_matches_dump_id(int log_file_id, bool final_dump);
static int hra_log_debug_responses_dump_id     (int log_file_id, bool final_dump);

/*
 * Function allocates memory for the buffers to store log file entries until the end of the
 * application.
 */
static int
hra_log_files_init_internal(int num_log_files, bool do_not_truncate)
{
    int ret = HRA_STATUS_OK;

    if (NULL == (match_discrepancies_logs = (struct hra_match_discrepancies_log *)
       calloc(num_log_files, sizeof(struct hra_match_discrepancies_log))))
    {
       ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
    }
    else if (NULL == (debug_match_logs = (struct hra_debug_match_log *)
       calloc(num_log_files, sizeof(struct hra_debug_match_log))))
    {
       ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
    }
    else if (NULL == (debug_unique_match_logs = (struct hra_debug_match_log *)
        calloc(num_log_files, sizeof(struct hra_debug_match_log))))
    {
       ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
    }
    else if (NULL == (debug_response_logs = (struct hra_debug_response_log *)
       calloc(num_log_files, sizeof(struct hra_debug_response_log))))
    {
       ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
    }

    log_file_count = num_log_files;

    if (ret == HRA_STATUS_OK)
    {
        int i;

        for (i = 0; i < num_log_files; i++)
        {
            match_discrepancies_logs[i].do_not_truncate = do_not_truncate;
            debug_match_logs[i].do_not_truncate         = do_not_truncate;
            debug_unique_match_logs[i].do_not_truncate  = do_not_truncate;
            debug_response_logs[i].do_not_truncate      = do_not_truncate;
        }
    }

    return (ret);
}

int
hra_log_files_init(int num_log_files)
{
    return hra_log_files_init_internal(num_log_files, false);
}

int
hra_log_files_init_do_not_truncate(int num_log_files)
{
    return hra_log_files_init_internal(num_log_files, true);
}

/*
 * Function frees all the memory which has been allocated for the log files.
 */
void
hra_log_files_free(void)
{
    if (match_discrepancies_logs)
    {
       free(match_discrepancies_logs);
    }
    if (debug_match_logs)
    {
       free(debug_match_logs);
    }
    if (debug_unique_match_logs)
    {
       free(debug_unique_match_logs);
    }
    if (debug_response_logs)
    {
       free(debug_response_logs);
    }
}

/*
 * Dump all the logs to file i.e. the match discrepancies log, debug original matches log,
 * debug unique match log and debug responses log.
 */
int
hra_log_files_dump(void)
{
    int ret = HRA_STATUS_OK;
    int err;

    if (HRA_STATUS_OK != (err = hra_log_match_discrepancies_dump()))
    {
        printf("Warning: rxp_log_match_discrepancies_dump() failed\n");
        ret = err;
    }

    if (HRA_STATUS_OK != (err = hra_log_debug_matches_dump()))
    {
        printf("Warning: rxp_log_debug_matches_dump() failed\n");
        ret = err;
    }

    if (HRA_STATUS_OK != (err = hra_log_debug_unique_matches_dump()))
    {
        printf("Warning: rxp_log_debug_unique_matches_dump() failed\n");
        ret = err;
    }

    if (HRA_STATUS_OK != (err = hra_log_debug_responses_dump()))
    {
        printf("Warning: rxp_log_debug_responses_dump() failed\n");
        ret = err;
    }

    return (ret);
}

/*
 * Function prints a string to the specified match discrepancies file. The entry can either be for
 * an expected match and actual match pair, an expected match only or an actual match only.
 */
void
hra_log_match_discrepancies_add(int log_file_id,
                                enum hra_match_discrepancy_type match_discrepancy_type,
                                uint32_t rxp_job_id,
                                uint32_t exp_user_job_id,
                                uint32_t exp_rxp_rule_id,
                                uint64_t exp_start_ptr,
                                uint32_t exp_length,
                                uint32_t act_user_job_id,
                                uint32_t act_rxp_rule_id,
                                uint64_t act_start_ptr,
                                uint32_t act_length,
                                int score,
                                int thread_index,
                                int jobset_iteration,
                                int exp_cross_boundary_flag,
                                int exp_undetectable_flag,
                                int act_cross_boundary_flag,
                                uint16_t rxp_status)

{
    char *log_string;

    if (match_discrepancies_logs[log_file_id].num_entries >= HRA_LOG_FILE_MAX_ENTRIES)
    {
        if (match_discrepancies_logs[log_file_id].do_not_truncate)
        {
            /* Flush the log. */
            hra_log_match_discrepancies_dump_id(log_file_id, false);
            match_discrepancies_logs[log_file_id].num_entries = 0;
        }
        else
        {
            match_discrepancies_logs[log_file_id].truncated = 1;
            return;
        }
    }

    log_string = match_discrepancies_logs[log_file_id].entry[match_discrepancies_logs[log_file_id].num_entries];

    switch (match_discrepancy_type)
    {
        case HRA_MATCH_EXPECTED_AND_ACTUAL:
            snprintf(log_string, HRA_MATCH_DISCREPANCIES_STRING_LEN,
                "0x%08"PRIx32 ", %d, %d, %"PRIu32 ", %"PRIu32 ", %"PRIu64 ", %"PRIu32
                ", %d, %"PRIu32 ", %"PRIu32 ", %"PRIu64 ", %"PRIu32
                ", %d, %d, %d, 0x%x\n",
                rxp_job_id,
                exp_cross_boundary_flag,
                exp_undetectable_flag,
                exp_user_job_id,
                exp_rxp_rule_id,
                exp_start_ptr,
                exp_length,
                act_cross_boundary_flag,
                act_user_job_id,
                act_rxp_rule_id,
                act_start_ptr,
                act_length,
                score,
                jobset_iteration,
                thread_index,
                rxp_status);
            break;

        case HRA_MATCH_EXPECTED_ONLY:
            snprintf(log_string, HRA_MATCH_DISCREPANCIES_STRING_LEN,
                "0x%08"PRIx32 ", %d, %d, %"PRIu32 ", %"PRIu32 ", %"PRIu64 ", %"PRIu32
                ", -, -, -, -, -"
                ", %d, %d, %d, 0x%x\n",
                rxp_job_id,
                exp_cross_boundary_flag,
                exp_undetectable_flag,
                exp_user_job_id,
                exp_rxp_rule_id,
                exp_start_ptr,
                exp_length,
                score,
                jobset_iteration,
                thread_index,
                rxp_status);
            break;

        case HRA_MATCH_ACTUAL_ONLY:
            snprintf(log_string, HRA_MATCH_DISCREPANCIES_STRING_LEN,
                "0x%08"PRIx32 ", -, -, -, -, -, -"
                ", %d, %"PRIu32 ", %"PRIu32 ", %"PRIu64 ", %"PRIu32
                ", %d, %d, %d, 0x%x\n",
                rxp_job_id,
                act_cross_boundary_flag,
                act_user_job_id,
                act_rxp_rule_id,
                act_start_ptr,
                act_length,
                score,
                jobset_iteration,
                thread_index,
                rxp_status);
            break;

    }

    match_discrepancies_logs[log_file_id].num_entries++;
}

/*
 * Function dumps the stored match discrepancies for the given log_file_id.
 */
static int
hra_log_match_discrepancies_dump_id(int log_file_id, bool final_dump)
{
    int j;
    char file_name[50];
    FILE *fp;
    int ret = HRA_STATUS_OK;
    struct tm *log_local_time;
    time_t log_time;

    sprintf(file_name, "match_discrepancies_queue_%02d.csv", log_file_id);

    /* Print comfort message? */
    if (!match_discrepancies_logs[log_file_id].file_created || final_dump)
    {
        printf("Info: Preparing to dump log file %s...done\n", file_name);
    }

    if (!match_discrepancies_logs[log_file_id].file_created)
    {
        /* First dump.  Create new file. */
        fp = fopen(file_name, "w");
        if (fp)
        {
            match_discrepancies_logs[log_file_id].file_created = true;
            log_time = time(0);
            log_local_time = localtime(&log_time);
            fprintf(fp, "#File created by hra on %s\n", asctime(log_local_time));
            fprintf(fp, "#rxp_job_id, e_cross_boundary, e_undetectable, e_job_id, e_rid, e_sp,"
                " e_l, a_cross_boundary, a_job_id, a_rid, a_sp, a_l, score, iteration, thread_index, rxp_status\n");
        }
    }
    else
    {
        /* Subsequent dump.  Append. */
        fp = fopen(file_name, "a");
    }

    if (fp == NULL)
    {
        printf("Warning: Open file %s for writing...failed\n", file_name);
        ret = HRA_STATUS_CANNOT_CREATE_LOG_FILE;
    }
    else
    {
        for (j = 0; j < match_discrepancies_logs[log_file_id].num_entries; j++)
        {
            fprintf(fp, "%s", match_discrepancies_logs[log_file_id].entry[j]);
        }

        if (match_discrepancies_logs[log_file_id].truncated)
        {
            fprintf(fp, "# File truncated due to excessive entries\n");
        }
        fclose(fp);
    }

    return ret;
}

/*
 * Function dumps the stored match discrepancies to log files, one per log.
 */
int
hra_log_match_discrepancies_dump(void)
{
    int i;
    int ret = HRA_STATUS_OK;

    for (i = 0; i < log_file_count; i++)
    {
        ret = hra_log_match_discrepancies_dump_id(i, true);
        if (ret != HRA_STATUS_OK)
        {
            break;
        }
    }


    return (ret);
}

/*
 * Function adds a match to the debug matches log. This log can later be dumped to file
 */
void
hra_log_debug_matches_add(int log_file_id,
                          uint32_t rxp_job_id,
                          uint32_t user_job_id,
                          uint32_t rule_id,
                          uint64_t start_ptr,
                          uint32_t length,
                          int thread_index,
                          int jobset_iteration)
{
    struct hra_debug_match *debug_match;
    int match_index;

    if (debug_match_logs[log_file_id].num_entries < HRA_LOG_FILE_MAX_ENTRIES)
    {
        match_index = debug_match_logs[log_file_id].num_entries;
        debug_match = &(debug_match_logs[log_file_id].matches[match_index]);

        debug_match->rxp_job_id       = rxp_job_id;
        debug_match->user_job_id      = user_job_id;
        debug_match->rule_id          = rule_id;
        debug_match->start_ptr        = start_ptr;
        debug_match->length           = length;
        debug_match->jobset_iteration = jobset_iteration;
        debug_match->thread_index     = thread_index;

        debug_match_logs[log_file_id].num_entries++;

        if (debug_match_logs[log_file_id].num_entries >= HRA_LOG_FILE_MAX_ENTRIES)
        {
            if (debug_match_logs[log_file_id].do_not_truncate)
            {
                /* Flush the log. */
                hra_log_debug_matches_dump_id(log_file_id, false);
                debug_match_logs[log_file_id].num_entries = 0;
            }
        }
    }
    else
    {
        debug_match_logs[log_file_id].truncated = 1;
    }
}

/*
 * Function adds a unique match to the debug unique matches log. This log can later be dumped to file
 */
void
hra_log_debug_unique_matches_add(int log_file_id,
                                 uint32_t rxp_job_id,
                                 uint32_t user_job_id,
                                 uint32_t rule_id,
                                 uint64_t start_ptr,
                                 uint32_t length,
                                 int thread_index,
                                 int jobset_iteration)
{
    struct hra_debug_match *debug_match;
    int match_index;

    if (debug_unique_match_logs[log_file_id].num_entries < HRA_LOG_FILE_MAX_ENTRIES)
    {
        match_index = debug_unique_match_logs[log_file_id].num_entries;
        debug_match = &(debug_unique_match_logs[log_file_id].matches[match_index]);

        debug_match->rxp_job_id       = rxp_job_id;
        debug_match->user_job_id      = user_job_id;
        debug_match->rule_id          = rule_id;
        debug_match->start_ptr        = start_ptr;
        debug_match->length           = length;
        debug_match->jobset_iteration = jobset_iteration;
        debug_match->thread_index     = thread_index;

        debug_unique_match_logs[log_file_id].num_entries++;

        if (debug_unique_match_logs[log_file_id].num_entries >= HRA_LOG_FILE_MAX_ENTRIES)
        {
            if (debug_unique_match_logs[log_file_id].do_not_truncate)
            {
                /* Flush the log. */
                hra_log_debug_unique_matches_dump_id(log_file_id, false);
                debug_unique_match_logs[log_file_id].num_entries = 0;
            }
        }
    }
    else
    {
        debug_unique_match_logs[log_file_id].truncated = 1;
    }
}

/*
 * Function dumps the debug matches for the given log_file_id.
 */
static int
hra_log_debug_matches_dump_id(int log_file_id, bool final_dump)
{
    int j;
    FILE *fp;
    int ret = HRA_STATUS_OK;
    char file_name[50];
    struct tm *log_local_time;
    time_t log_time;

    sprintf(file_name, "debug_matches_queue_%02d.csv", log_file_id);

    /* Print comfort message? */
    if (!debug_match_logs[log_file_id].file_created || final_dump)
    {
        printf("Info: Preparing to dump log file %s...done\n", file_name);
    }

    if (!debug_match_logs[log_file_id].file_created)
    {
        /* First dump.  Create new file. */
        fp = fopen(file_name, "w");
        if (fp)
        {
            debug_match_logs[log_file_id].file_created = true;
            log_time = time(0);
            log_local_time = localtime(&log_time);
            fprintf(fp, "#File created by hra on %s\n", asctime(log_local_time));
            fprintf(fp, "#rxp_job_id, job_id, rule_id, start_pointer, length, iteration, thread_index\n");
        }
    }
    else
    {
        /* Subsequent dump.  Append. */
        fp = fopen(file_name, "a");
    }
    if (fp == NULL)
    {
        printf("Warning: Open file %s for writing...failed\n", file_name);
        ret = HRA_STATUS_CANNOT_CREATE_LOG_FILE;
    }
    else
    {
        for (j = 0; j <debug_match_logs[log_file_id].num_entries; j++)
        {
            fprintf(fp, "0x%08"PRIx32 ", %"PRIu32 ", %"PRIu32 ", %"PRIu64 ", %"PRIu32 ", %d, %d\n",
                debug_match_logs[log_file_id].matches[j].rxp_job_id,
                debug_match_logs[log_file_id].matches[j].user_job_id,
                debug_match_logs[log_file_id].matches[j].rule_id,
                debug_match_logs[log_file_id].matches[j].start_ptr,
                debug_match_logs[log_file_id].matches[j].length,
                debug_match_logs[log_file_id].matches[j].jobset_iteration,
                debug_match_logs[log_file_id].matches[j].thread_index);

        }

        if (debug_match_logs[log_file_id].truncated)
        {
            fprintf(fp, "# File truncated due to excessive entries\n");
        }
        fclose(fp);
    }

    return (ret);
}

/*
 * Function dumps the debug matches logs to log files, one per log.
 */
int
hra_log_debug_matches_dump(void)
{
    int i;
    int ret = HRA_STATUS_OK;

    for (i = 0; i < log_file_count; i++)
    {
        ret = hra_log_debug_matches_dump_id(i, true);
        if (ret != HRA_STATUS_OK)
        {
            break;
        }
    }

    return ret;
}

/*
 * Function dumps the debug unique matches for the given log_file_id.
 */
static int
hra_log_debug_unique_matches_dump_id(int log_file_id, bool final_dump)
{
    int j;
    FILE *fp;
    int ret = HRA_STATUS_OK;
    char file_name[50];
    struct tm *log_local_time;
    time_t log_time;

    sprintf(file_name, "debug_unique_matches_queue_%02d.csv", log_file_id);

    /* Print comfort message? */
    if (!debug_unique_match_logs[log_file_id].file_created || final_dump)
    {
        printf("Info: Preparing to dump log file %s...done\n", file_name);
    }

    if (!debug_unique_match_logs[log_file_id].file_created)
    {
        /* First dump.  Create new file. */
        fp = fopen(file_name, "w");
        if (fp)
        {
            debug_unique_match_logs[log_file_id].file_created = true;
            log_time = time(0);
            log_local_time = localtime(&log_time);
            fprintf(fp, "#File created by hra on %s\n", asctime(log_local_time));
            fprintf(fp, "#rxp_job_id, job_id, rule_id, start_pointer, length, iteration, thread_index\n");
        }
    }
    else
    {
        /* Subsequent dump.  Append. */
        fp = fopen(file_name, "a");
    }
    if (fp == NULL)
    {
        printf("Warning: Open file %s for writing...failed\n", file_name);
        ret = HRA_STATUS_CANNOT_CREATE_LOG_FILE;
    }
    else
    {
        for (j = 0; j <debug_unique_match_logs[log_file_id].num_entries; j++)
        {
            fprintf(fp, "0x%08"PRIx32 ", %"PRIu32 ", %"PRIu32 ", %"PRIu64 ", %"PRIu32 ", %d, %d\n",
                debug_unique_match_logs[log_file_id].matches[j].rxp_job_id,
                debug_unique_match_logs[log_file_id].matches[j].user_job_id,
                debug_unique_match_logs[log_file_id].matches[j].rule_id,
                debug_unique_match_logs[log_file_id].matches[j].start_ptr,
                debug_unique_match_logs[log_file_id].matches[j].length,
                debug_unique_match_logs[log_file_id].matches[j].jobset_iteration,
                debug_unique_match_logs[log_file_id].matches[j].thread_index);

        }

        if (debug_unique_match_logs[log_file_id].truncated)
        {
            fprintf(fp, "# File truncated due to excessive entries\n");
        }
        fclose(fp);
    }

    return (ret);
}

/*
 * Function dumps the debug unique matches logs to files, one per log.
 */
int
hra_log_debug_unique_matches_dump(void)
{
    int i;
    int ret = HRA_STATUS_OK;

    for (i = 0; i < log_file_count; i++)
    {
        ret = hra_log_debug_unique_matches_dump_id(i, true);
        if (ret != HRA_STATUS_OK)
        {
            break;
        }
    }

    return (ret);
}

/*
 * Function adds a response to the debug response log. This log can later be dumped to file
 */
void
hra_log_debug_responses_add(int log_file_id,
                            uint32_t rxp_job_id,
                            uint32_t user_job_id,
                            uint16_t  status,
                            uint8_t  match_count,
                            uint8_t  detected_match_count,
                            uint16_t primary_thread_count,
                            uint16_t instruction_count,
                            uint16_t latency_count,
                            uint16_t pmi_min_byte_ptr,
                            int thread_index,
                            int jobset_iteration)
{
    struct hra_debug_response *debug_response;
    int response_index;

    if (debug_response_logs[log_file_id].num_entries < HRA_LOG_FILE_MAX_ENTRIES)
    {
        response_index = debug_response_logs[log_file_id].num_entries;
        debug_response = &(debug_response_logs[log_file_id].responses[response_index]);

        debug_response->rxp_job_id           = rxp_job_id;
        debug_response->user_job_id          = user_job_id;
        debug_response->status               = status;
        debug_response->match_count          = match_count;
        debug_response->detected_match_count = detected_match_count;
        debug_response->primary_thread_count = primary_thread_count;
        debug_response->instruction_count    = instruction_count;
        debug_response->latency_count        = latency_count;
        debug_response->pmi_min_byte_ptr     = pmi_min_byte_ptr;
        debug_response->jobset_iteration     = jobset_iteration;
        debug_response->thread_index         = thread_index;

        debug_response_logs[log_file_id].num_entries++;

        if (debug_response_logs[log_file_id].num_entries >= HRA_LOG_FILE_MAX_ENTRIES)
        {
            if (debug_response_logs[log_file_id].do_not_truncate)
            {
                hra_log_debug_responses_dump_id(log_file_id, false);
                debug_response_logs[log_file_id].num_entries = 0;
            }
        }
    }
    else
    {
        debug_response_logs[log_file_id].truncated = 1;
    }
}

/**
 * Function dumps the debug responses log for the give log_file_id.
 */
static int
hra_log_debug_responses_dump_id(int log_file_id, bool final_dump)
{
    int j;
    char file_name[50];
    FILE *fp;
    int ret = HRA_STATUS_OK;
    struct tm *log_local_time;
    time_t log_time;

    sprintf(file_name, "debug_responses_queue_%02d.csv", log_file_id);

    /* Print comfort message? */
    if (!debug_response_logs[log_file_id].file_created || final_dump)
    {
        printf("Info: Preparing to dump log file %s...done\n", file_name);
    }

    if (!debug_response_logs[log_file_id].file_created)
    {
        /* First dump.  Create new file. */
        fp = fopen(file_name, "w");
        if (fp)
        {
            debug_response_logs[log_file_id].file_created = true;
            log_time = time(0);
            log_local_time = localtime(&log_time);
            fprintf(fp, "#File created by hra on %s\n", asctime(log_local_time));
            fprintf(fp, "#rxp_job_id, job_id, status, match_count, detected_match_count, primary_thread_count, "
                "instruction_count, latency_count, pmi_min_byte_ptr, iteration, thread_index\n");
        }
    }
    else
    {
        /* Subsequent dump.  Append. */
        fp = fopen(file_name, "a");
    }
    if (fp == NULL)
    {
        printf("Warning: Open file %s for writing...failed\n", file_name);
        ret = HRA_STATUS_CANNOT_CREATE_LOG_FILE;
    }
    else
    {
        for (j = 0; j <debug_response_logs[log_file_id].num_entries; j++)
        {
            fprintf(fp, "0x%08"PRIx32 ", %"PRIu32 ", 0x%"PRIx16 ", %"PRIu8 ", %"PRIu8 ", %"PRIu16 ", %"PRIu16
                ", %"PRIu16 ", %"PRIu16 ", %d, %d\n",
                debug_response_logs[log_file_id].responses[j].rxp_job_id,
                debug_response_logs[log_file_id].responses[j].user_job_id,
                debug_response_logs[log_file_id].responses[j].status,
                debug_response_logs[log_file_id].responses[j].match_count,
                debug_response_logs[log_file_id].responses[j].detected_match_count,
                debug_response_logs[log_file_id].responses[j].primary_thread_count,
                debug_response_logs[log_file_id].responses[j].instruction_count,
                debug_response_logs[log_file_id].responses[j].latency_count,
                debug_response_logs[log_file_id].responses[j].pmi_min_byte_ptr,
                debug_response_logs[log_file_id].responses[j].jobset_iteration,
                debug_response_logs[log_file_id].responses[j].thread_index);
        }

        if (debug_response_logs[log_file_id].truncated)
        {
            fprintf(fp, "# File truncated due to excessive entries");
        }
        fclose(fp);
    }

    return (ret);
}

/**
 * Function dumps the debug responses logs to files, one per log.
 */
int
hra_log_debug_responses_dump(void)
{
    int i;
    int ret = HRA_STATUS_OK;

    for (i = 0; i < log_file_count; i++)
    {
        ret = hra_log_debug_responses_dump_id(i, true);
        if (ret != HRA_STATUS_OK)
        {
            break;
        }
    }

    return (ret);
}
