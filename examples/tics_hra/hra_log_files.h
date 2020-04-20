/**
 * @file    hra_log_files.h
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

#ifndef _HRA_LOG_FILES_H_
#define _HRA_LOG_FILES_H_

#define DEBUG_MODE_NORMAL               0
#define DEBUG_MODE_BASIC                1
#define DEBUG_MODE_ENHANCED             2
#define DEBUG_MODE_ENHANCED_NO_TRUNCATE 3

enum hra_match_discrepancy_type {
    HRA_MATCH_EXPECTED_AND_ACTUAL,
    HRA_MATCH_EXPECTED_ONLY,
    HRA_MATCH_ACTUAL_ONLY
};

/**
 * Function allocates memory for the buffers to store log file entries until the end of the
 * application.
 *
 * @param num_log_file  Number of log files of each type to create
 * @return              HRA_STATUS ok if successful or HRA_STATUS_MEMORY_ALLOCATION_FAILED
 */
int
hra_log_files_init(int num_log_files);

/**
 * Function allocates memory for the buffers to store log file entries.
 * During the test run, if all the log entries are filled, they will
 * immediately be flushed to file.
 * In other words, the log data will not be truncated.
 *
 * @param num_log_file  Number of log files of each type to create
 * @return              HRA_STATUS ok if successful or HRA_STATUS_MEMORY_ALLOCATION_FAILED
 */
int
hra_log_files_init_do_not_truncate(int num_log_files);


/**
 * Dump all the logs to file i.e. the match discrepancies log, debug matches log and responses log.
 *
 * @return  HRA_STATUS_OK if ok, else error code
 */
int
hra_log_files_dump(void);

/*
 * Free all the log files allocated
 */
void
hra_log_files_free(void);

/**
 * Function prints a string to the specified match discrepancies file. The entry can either be for
 * an expected match and actual match pair, an expected match only or an actual match only.
 *
 * @param log_file_id            ID of match discrepancy log file
 * @param match_discrepancy_type Expected/actual pair, just expected match or just actual match
 * @param rxp_job_id             Job ID sent to RXP- allocated by JAR table if enabled
 * @param exp_user_job_id        User job ID for expected match
 * @param exp_rxp_rule_id        RXP rule ID for expected match
 * @param exp_start_ptr          Start pointer of expected match
 * @param exp_length             Length of expected match
 * @param act_user_job_id        User job ID of actual match
 * @param act_rxp_rule_id        RXP rule ID of actual match
 * @param act_start_ptr          Start pointer of actual match
 * @param act_length             Length of actual match
 * @param score                  Score allocated to match
 * @param thread_index           Used to identify thread on which match was detected
 * @param jobset_iteration       Iteration of jobset which job was part of
 * @param cross_boundary_flag    Indication whether this expected match crosses the job boundary
 * @param undetectable_flag      Indication whether this expected match can be found using the job_length and
 *                               job_overlap length
 * @param rxp_status             Status value returned in rxp response structure.
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
                                uint16_t rxp_status);


/**
 * Function dumps the stored match discrepancies to log files- one per log.
 *
 * @return HRA_STATUS_OK if ok, else HRA_STATUS_CANNOT_CREATE_LOG_FILE
 */
int
hra_log_match_discrepancies_dump(void);

/**
 * Function adds a match to the debug matches log. This log can later be dumped to file
 *
 * @param log_file_id       ID of debug match log file
 * @param rxp_job_id        Job ID sent to RXP- allocated by JAR table if enabled
 * @param user_job_id       User job ID of match
 * @param rule_id           Rule ID of match
 * @param start_ptr         Start pointer of match
 * @param length            Length of match
 * @param thread_index      Used to identify thread on which match was detected
 * @param jobset_iteration  Iteration of jobset which job was part of
 */
void
hra_log_debug_matches_add(int log_file_id,
                          uint32_t rxp_job_id,
                          uint32_t user_job_id,
                          uint32_t rule_id,
                          uint64_t start_ptr,
                          uint32_t length,
                          int thread_index,
                          int jobset_iteration);

/**
 * Function adds a match to the debug matches log. This log can later be dumped to file
 *
 * @param log_file_id       ID of debug match log file
 * @param rxp_job_id        Job ID sent to RXP- allocated by JAR table if enabled
 * @param user_job_id       User job ID of match
 * @param rule_id           Rule ID of match
 * @param start_ptr         Start pointer of match
 * @param length            Length of match
 * @param thread_index      Used to identify thread on which match was detected
 * @param jobset_iteration  Iteration of jobset which job was part of
 */
void
hra_log_debug_unique_matches_add(int log_file_id,
                                 uint32_t rxp_job_id,
                                 uint32_t user_job_id,
                                 uint32_t rule_id,
                                 uint64_t start_ptr,
                                 uint32_t length,
                                 int thread_index,
                                 int jobset_iteration);

/**
 * Function dumps the debug matches logs to a single file.
 *
 * @return HRA_STATUS_OK if ok, else HRA_STATUS_CANNOT_CREATE_LOG_FILE
 */
int
hra_log_debug_matches_dump(void);

/**
 * Function dumps the debug matches logs to a single file.
 *
 * @return HRA_STATUS_OK if ok, else HRA_STATUS_CANNOT_CREATE_LOG_FILE
 */
int
hra_log_debug_unique_matches_dump(void);

/**
 * Function adds a match to the debug responses log. This log can later be dumped to file
 *
 * @param log_file_id          ID of debug response log file
 * @param rxp_job_id           Job ID sent to RXP- allocated by JAR table if enabled
 * @param user_job_id          User job ID of response
 * @param status               Status field of response
 * @param match_count          Number of matches returned
 * @param detected_match_count Number of matches detected by RXP
 * @param primary_thread_count Count of primary threads triggered by the job
 * @param instruction_count    Number of instructions executed for job
 * @param latency_count        Approx job scan count (RXP core clock cycles div 256)
 * @param rof_revision         Lower bits of REVISION field in ROF
 * @param thread_index         Used to identify thread on which response was received
 * @param jobset_iteration     Iteration of jobset which job was part of
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
                            uint16_t rof_revision,
                            int thread_index,
                            int jobset_iteration);

/**
 * Function dumps the debug responses logs to a single file.
 *
 * @return HRA_STATUS_OK if ok, else HRA_STATUS_CANNOT_CREATE_LOG_FILE
 */
int
hra_log_debug_responses_dump(void);

#endif /* _HRA_LOG_FILES_H_ */
