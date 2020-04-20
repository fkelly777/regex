/**
 * @file    hra_jobset.h
 * @author  Titan IC Systems <support@titanicsystems.com>
 *
 * @section DESCRIPTION
 *
 *   This file provides functionality to scan a directory looking for
 *   .des, .pkt and .exp files. The data is extracted from these files
 *   and stored in a job entry table.
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

#ifndef _HRA_JOBSET_H_
#define _HRA_JOBSET_H_

struct hra_expected_match {
    uint32_t job_id;
    uint32_t rxp_rule_id;
    uint16_t start_ptr;
    uint16_t length;
};

struct hra_job {
    uint32_t user_job_id;
    uint16_t ctrl;
    uint16_t job_length;
    uint16_t subset_ids[4];
    uint8_t *job_data;
    uint16_t num_exp_matches;
    struct hra_expected_match *exp_matches;
};

struct hra_job_table {
    int num_entries;
    struct hra_job *jobs;
};

/**
 * Function reads .des, .pkt and .exp files from the specified directory. These file contain job descriptors, job
 * packet data and expected matches. Memory is allocated for the jobset information. The files are parsed and the values
 * are stored in memory.
 *
 * @param job_table         Pointer to structure where the number of job entries and job entry data is to be stored.
 * @param jobset_dir        Directory where .des, .pkt and .exp files are stored.
 * @return                  HRA_STATUS_OK if ok, else an error code
 */
int
hra_jobset_read(struct hra_job_table *job_table,
                const char *jobset_dir);

/**
 * Function prints all the job entry information in the specified job_table.
 *
 * @param job_table  Jobset table containing information to be printed.
 */
void
hra_jobset_print(struct hra_job_table *job_table);

/**
 * Function frees all the memory which has been allocated for the job entry table.
 *
 * @param job_table    Job entry table to be freed
 */
void
hra_jobset_free_table(struct hra_job_table *job_table);

#endif /* _HRA_JOBSET_H_ */
