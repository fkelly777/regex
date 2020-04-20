/**
 * @file    hra_errors.h
 * @author  Titan IC Systems <support@titanicsystems.com>
 *
 * @section DESCRIPTION
 *
 *   Errors used in hra_file_scan
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

#ifndef _HRA_ERRORS_H_
#define _HRA_ERRORS_H_

#define HRA_STATUS_OK                                   0
#define HRA_STATUS_FAIL                                 -1
#define HRA_STATUS_MAIN_LOOP_STALLED                    -2
#define HRA_STATUS_MAIN_LOOP_EXITED_BY_SIGNAL           -3
#define HRA_STATUS_MEMORY_ALLOCATION_FAILED             -4
#define HRA_STATUS_CANNOT_CREATE_LOG_FILE               -5
#define HRA_STATUS_NULL_POINTER                         -6
#define HRA_STATUS_SCAN_JOBSET_DIR_FAILED               -14
#define HRA_STATUS_NO_JOBSET_DES_FILES_FOUND            -15
#define HRA_STATUS_INVALID_JOBSET_DES_FILE_NAME         -16
#define HRA_STATUS_JOBSET_DES_FILE_PROCESS_ERROR        -17
#define HRA_STATUS_JOBSET_EXP_FILE_PROCESS_ERROR        -18
#define HRA_STATUS_JOBSET_PKT_FILE_PROCESS_ERROR        -19
#define HRA_STATUS_JOBSET_FILE_NOT_FOUND                -20
#define HRA_STATUS_JOBSET_INVALID_FILE                  -21
#define HRA_STATUS_JOBSET_DES_FILE_INVALID_PARAMS       -22
#define HRA_STATUS_JOBSET_EXP_FILE_INVALID_PARAMS       -23
#define HRA_STATUS_WRONG_JOB_DATA_LENGTH                -24
#define HRA_STATUS_INVALID_JOB_DATA_CHARACTER           -25
#define HRA_STATUS_STRING_TO_ULONG_FAILED               -26
#define HRA_STATUS_NOT_INITIALIZED                      -27
#define HRA_STATUS_INVALID_JAR_INDEX                    -28

#endif /* _HRA_ERRORS_H_ */

