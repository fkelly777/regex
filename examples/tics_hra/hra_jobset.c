/**
 * @file    hra_jobset.c
 * @author  Titan IC Systems <support@titanicsystems.com>
 *
 * @section DESCRIPTION
 *
 *   This file provides functionality to scan a directory looking for
 *    .des, .pkt and .exp files. The data is extracted from these files
 *   and stored in a job entry table.
 *
 * @section LICENSE
 *
 *   BSD LICENSE
 *
 *   Copyright (C) 2014-2020 Titan IC Systems Ltd. All rights reserved.
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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <malloc.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "hra_jobset.h"
#include "hra_errors.h"
#include <rxp.h>

enum rxp_file_type {
    RXP_DESCRIPTOR_FILE,
    RXP_EXPECTED_MATCHES_FILE,
    RXP_JOB_DATA_FILE
};

/* Following code assumes that all these extensions are of the same length */
#define RXP_DESCRIPTOR_EXTENSION       (const char*)".des"
#define RXP_EXPECTED_MATCHES_EXTENSION (const char*)".exp"
#define RXP_JOB_DATA_EXTENSION         (const char*)".pkt"

#define RXP_DESCRIPTOR_PREFIX          (const char*)"job_0x"
#define RXP_DESCRIPTOR_JOB_ID_LENGTH   8
//#define RXP_MAX_JOB_LENGTH             2048
#define RXP_JOBSET_MAX_FILE_NAME_LEN   1024

/*
 * Each .des file has lines of the format:
 *      job_id,flow_id,ctrl,job_length,subset_id_0,subset_id_1,subset_id_2,subset_id_3
 * The following #defines are used to identify the parameter position in a .des file.
 */
#define RXP_DES_FILE_JOB_ID_FIELD       0
#define RXP_DES_FILE_FLOW_ID_FIELD      1
#define RXP_DES_FILE_CTRL_FIELD         2
#define RXP_DES_FILE_JOB_LENGTH_FIELD   3
#define RXP_DES_FILE_SUBSET_ID_0        4
#define RXP_DES_FILE_SUBSET_ID_1        5
#define RXP_DES_FILE_SUBSET_ID_2        6
#define RXP_DES_FILE_SUBSET_ID_3        7
#define RXP_DES_FILE_NUM_FIELDS         8

/*
 * Each .pkt file has lines of the format:
 *  job_id, rxp_rule_id, start_ptr, length, rule
 * The following #defines are used to identify the parameter position in a .pkt file.
 */
#define RXP_EXP_FILE_JOB_ID_FIELD        0
#define RXP_EXP_FILE_RXP_RULE_ID_FIELD   1
#define RXP_EXP_FILE_START_PTR_FIELD     2
#define RXP_EXP_FILE_LENGTH_FIELD        3
#define RXP_EXP_FILE_NUM_FIELDS          4

int job_index = 0;

/**
 * Function processes a data line from a job descriptor file. The data should consist of 8 comma separated entries
 * in the format:
 *      job_id,flow_id,ctrl,job_length,subset_id_0,subset_id_1,subset_id_2,subset_id_3
 * Whitespace at the beginning and end of entries is ignored.
 *
 * @param line       Line to process
 * @param job        Structure to populate with job data
 * @return           HRA_STATUS_OK if ok
 */
static int
hra_jobset_process_des_file_line(char *line,
                                 struct hra_job *job);

/**
 * Function processes a data line from an expected matches file. The data should consist of comma separated entries
 * in the format:
 *      job_id, rxp_rule_id, start_ptr, length, rule
 * Whitespace at the beginning and end of entries is ignored.
 *
 * @param line       Line to process
 * @param job        Structure to populate with job data
 * @return           HRA_STATUS_OK if ok
 */
static int
hra_jobset_process_exp_file_line(char *line,
                                 struct hra_expected_match *exp_match);

/**
 * Function processes a data line from a job data file. The job data should be stored on a single data line and will
 * consist of hexadecimal pairs of digits without spaces.
 * Whitespace at the beginning and end of entries is ignored.
 *
 * @param line       Line to process
 * @param job        Structure to populate with job data
 * @return           HRA_STATUS_OK if ok
 */
static int
hra_jobset_process_pkt_file_line(char *line,
                                 struct hra_job *job);

/**
 * Function is called by scandir for every file in a directory. The function checks whether each file has a
 * specific extension, as specified by the RXP_DESCRIPTOR_EXTENSION value. If it does a non-zero value is returned.
 * Else a zero value is returned.
 *
 * @param entry  Directory entry structure containing file name
 * @return       HRA_STATUS_OK if file extension does not match, else non-zero
 */
static int
hra_jobset_find_des_files(const struct dirent *entry);

/**
 * Function validates that the file name which is passed in is of the correct format for a job descriptor file. Each
 * filename must be of the form:
 *      job_0xXXXXXXXX.des
 * The X characters should be validate hex characters [0-9][a-f][A-F]
 *
 * @param file_name to validate
 * @return HRA_STATUS_OK if name is valid
 */
static int
hra_jobset_validate_des_file_name(char* file_name);

/**
 * Function reads the number of data lines in a file i.e. lines which are not comments or all blank space.
 * If the file is a .des or .pkt file it validates that there is a single data line.
 * If the file is a .exp file it allocates memory for all the expected matches.
 *
 * @param fp                File pointer
 * @param filename          Name of file being processed
 * @param file_type         Type of file (.des, .pkt or .exp)
 * @param job_table         Table containing job entries
 * @return                  If >= 0 number of lines, else an error
 */
static int
hra_jobset_get_num_data_lines(FILE *fp,
                              char *filename,
                              enum rxp_file_type file_type,
                              struct hra_job_table *job_table);

/**
 * This function processes a .des, .exp or .pkt file. The number of lines in the file is determined and validated. Each
 * line is read and file type specific functions are called to process the lines.
 *
 * @param filename          Name of file to process
 * @param path              Path to file
 * @param file_type         Type of file to process
 * @param job_table         Table storing job entries
 * @return                  HRA_STATUS_OK if ok, else error
 */
static int
hra_jobset_process_file(char *filename,
                        const char *path,
                        enum rxp_file_type file_type,
                        struct hra_job_table *job_table);

/**
 * Function strips whitespace from the start of a string. Note that this function modifies the starting pointer
 * of the string.
 *
 * @param ptr   Pointer to string- the pointer is moified by the function
 */
static void
hra_left_strip(char **ptr);

/**
 * Function strips whitespace from the end of a string. The starting pointer is not modified, unlike
 * hra_left_strip. Any whitespace at the end of the string is replaced with \0 characters.
 *
 * @param ptr   String which whitespace is stripped from end of
 */
static void
hra_right_strip(char *ptr);

/**
 * Function converts a string to an unsigned long. It checks for error conditions. The string which is passed in
 * should have no trailing whitespace.
 *
 * @param string   String to convert to unsigned long
 * @param value    Used to return converted value
 * @return         HRA_STATUS_OK if ok, else error code
 */
static int
hra_string_to_ulong(char *string, unsigned long *value);

/**
 * Function for reading packed binary version of jobset directory.
 *
 * @param job_table  Table storing job entries
 * @param filename   Name of binary file
 * @return           HRA_STATUS_OK if ok, else error
 */
static int
hra_jobset_read_packed(struct hra_job_table *job_table, const char *filename);

/*********************************************************************************************************************/
/*                          PUBLIC FUNCTIONS                                                                         */
/*********************************************************************************************************************/

/*
 * Function reads job descriptors, job packet data and expected matches
 * from the specified location.
 * If the location is a directory, it contains .des, .exp, .emb and .pkt files
 * If the location is a standard file, the same data is present in a
 * single packed binary file.
 * Regardless of the location type, memory is allocated for the jobset information.
 * The file(s) are parsed and the values are stored in memory.
 */
int
hra_jobset_read(struct hra_job_table *job_table,
                const char *jobset_location)
{
    struct dirent **namelist = NULL;
    int num_files;
    int i;
    char *filename;
    int name_length;
    int ext_length;
    char *current_file_ext;
    int ret = HRA_STATUS_OK;
    struct stat sb;

    if ((job_table == NULL) || (jobset_location == NULL))
    {
        printf("Warning: NULL parameter passed to %s\n", __FUNCTION__);
        return (HRA_STATUS_NULL_POINTER);
    }

    /*
     * If the jobset_location is a standard file, assume it's a binary packed
     * version of the jobset.
     * Otherwise, we'll assume it's a directory jobset.
     */
    if (stat(jobset_location, &sb) == 0)
    {
        if (S_ISREG(sb.st_mode))
        {
            return hra_jobset_read_packed(job_table, jobset_location);
        }
    }

    /*
     * Reset job_index in case this is not the first jobset to have been processed.
     */
    job_index = 0;

    /*
     * Scan directory for Job Descriptor files. The find_des_files selects only files with the correct extension, whilst
     * the alphasort parameter produces a list of files which are sorted in alphabetical order.
     */
    num_files = scandir(jobset_location, &namelist, hra_jobset_find_des_files, alphasort);

    if (num_files < 0)
    {
        printf("Warning: scandir failed with error: [%s]\n", strerror(errno));
        ret = HRA_STATUS_SCAN_JOBSET_DIR_FAILED;
    }
    else if (num_files == 0)
    {
        printf("Warning: No files found with extension [%s]\n", RXP_DESCRIPTOR_EXTENSION);
        ret = HRA_STATUS_NO_JOBSET_DES_FILES_FOUND;
    }
    else if (NULL == (job_table->jobs = (struct hra_job *)calloc(num_files, sizeof(struct hra_job))))
    {
        printf("Warning: Failed to allocate memory for RXP job entries table (%d job entries found)\n",
            num_files);
        ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
    }
    else
    {
        job_table->num_entries = num_files;

        /*
         * For each job descriptor file found, process the file, then process an associated expected matches file
         * and job packet data file. The original filename is modified to created filenames with different
         * extensions.
         */
        for (i = 0; i < num_files; i++)
        {
            /*
             * Print messages to inform the user of progress processing the jobset. Be sure to print a message
             * when the last entry is being processed.
             */
            if ((((i+1) % 100) == 0) || ((i+1) == num_files))
            {
                printf("\rInfo: Loading jobset %s...%d of %d", jobset_location, i + 1, num_files);
            }

            if (HRA_STATUS_OK != hra_jobset_validate_des_file_name(namelist[i]->d_name))
            {
                printf("\nWarning: Invalid filename [%s]\n", namelist[i]->d_name);
                ret = HRA_STATUS_INVALID_JOBSET_DES_FILE_NAME;
                break;
            }
            /* Make copy of filename so that it can be modified */
            else if (NULL == (filename = strdup(namelist[i]->d_name)))
            {
                printf("\nWarning: Failed to allocate memory\n");
                ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
                break;
            }
            /* Process job descriptor file */
            else if (hra_jobset_process_file(filename, jobset_location, RXP_DESCRIPTOR_FILE, job_table))
            {
                printf("\nWarning: Failed to process file [%s]\n", filename);
                free(filename);
                ret = HRA_STATUS_JOBSET_DES_FILE_PROCESS_ERROR;
                break;
            }
            else
            {
                name_length      = strlen(filename);
                ext_length       = strlen(RXP_DESCRIPTOR_EXTENSION);
                current_file_ext = &filename[name_length - ext_length];

                /*
                 * Replace the file name extension with the expected matches extension and process expected matches
                 * file
                 */
                sprintf(current_file_ext, RXP_EXPECTED_MATCHES_EXTENSION);
                if (hra_jobset_process_file(filename, jobset_location, RXP_EXPECTED_MATCHES_FILE, job_table))
                {
                    printf("\nWarning: Failed to process file [%s]\n", filename);
                    free(filename);
                    ret = HRA_STATUS_JOBSET_EXP_FILE_PROCESS_ERROR;
                    break;
                }

                /* Replace the file name extension with the job data extension and process job data file */
                sprintf(current_file_ext, RXP_JOB_DATA_EXTENSION);
                if (hra_jobset_process_file(filename, jobset_location, RXP_JOB_DATA_FILE, job_table))
                {
                    printf("\nWarning: Failed to process file [%s]\n", filename);
                    free(filename);
                    ret = HRA_STATUS_JOBSET_PKT_FILE_PROCESS_ERROR;
                    break;
                }

                job_index++;
                free(filename);
            }
        }
    }

    /* Free memory after the main loop to ensure that it is all freed regardless of any errors encountered */
    if (namelist)
    {
        for (i = 0; i < num_files; i++)
        {
            free(namelist[i]);
        }
        free(namelist);
    }

    if (ret == HRA_STATUS_OK)
    {
        printf("\nInfo: All job entry files processed successfully.\n");
    }

    return (ret);
}

/*
 * Function prints all the job entry information in the specified job_table.
 */
void
hra_jobset_print(struct hra_job_table *job_table)
{
    int i, j;

    if (job_table == NULL)
    {
        printf("Job entry table is NULL\n");
        return;
    }

    for (i = 0; i < job_table->num_entries; i++) {
        printf("======Job %d=====\n", i);
        printf("user_job_id = %d\n", job_table->jobs[i].user_job_id);
        printf("ctrl = %d\n", job_table->jobs[i].ctrl);
        printf("job_length = %d\n", job_table->jobs[i].job_length);
        printf("subset_id_0 = %d\n", job_table->jobs[i].subset_ids[0]);
        printf("subset_id_1 = %d\n", job_table->jobs[i].subset_ids[1]);
        printf("subset_id_2 = %d\n", job_table->jobs[i].subset_ids[2]);
        printf("subset_id_3 = %d\n", job_table->jobs[i].subset_ids[3]);

        for (j = 0; j < job_table->jobs[i].job_length; j++) {
            printf("0x%02x ", job_table->jobs[i].job_data[j]);
        }
        printf("\n");

        for (j = 0; j < job_table->jobs[i].num_exp_matches; j++) {
            printf(" Match %d\n", j);
            printf("  job_id = %d\n", job_table->jobs[i].exp_matches[j].job_id);
            printf("  rxp_rule_id = %d\n", job_table->jobs[i].exp_matches[j].rxp_rule_id);
            printf("  start_ptr = %d\n", job_table->jobs[i].exp_matches[j].start_ptr);
            printf("  length = %d\n", job_table->jobs[i].exp_matches[j].length);
        }
        printf("\n\n");
    }
}

/*
 * Function frees all the memory which has been allocated for the job entry table.
 */
void
hra_jobset_free_table(struct hra_job_table *job_table)
{
    int i;

    if (job_table->jobs)
    {
        for (i = 0; i < job_table->num_entries; i++)
        {
            if (job_table->jobs[i].job_data)
            {
                free(job_table->jobs[i].job_data);
            }
            job_table->jobs[i].job_data = NULL;

            if (job_table->jobs[i].exp_matches)
            {
                free(job_table->jobs[i].exp_matches);
            }
            job_table->jobs[i].exp_matches = NULL;
        }
        free(job_table->jobs);
        job_table->jobs = NULL;
    }

    job_table->num_entries = 0;
}

/**********************************************************************************************************************/
/*                                   LOCAL FUNCTIONS                                                                  */
/**********************************************************************************************************************/

/*
 * Function is called by scandir for every file in a directory. The function checks whether each file has a
 * specific extension, as specified by the RXP_DESCRIPTOR_EXTENSION value. If it does a non-zero value is returned.
 * Else a zero value is returned.
 */
static int
hra_jobset_find_des_files(const struct dirent *entry)
{
    size_t name_length;
    size_t ext_length;
    int matching_file = 0;
    const char *current_file_ext;

    name_length = strlen(entry->d_name);
    ext_length  = strlen(RXP_DESCRIPTOR_EXTENSION);

    /*
     * Check that the file length is greater than or equal to the extension length. If so compare the end of the name
     * with the extension string. strncmp returns 0 if the strings match, so invert this value.
     */
    if (name_length >= ext_length) {
        current_file_ext = &entry->d_name[name_length - ext_length];
        matching_file = !strncmp(RXP_DESCRIPTOR_EXTENSION, current_file_ext, ext_length);
    }

    return (matching_file);
}

/**
 * Function validates that the file name which is passed in is of the correct format for a job descriptor file. Each
 * filename must be of the form:
 *      job_0xXXXXXXXX.des
 * The X characters should be validate hex characters [0-9][a-f][A-F]
 */
static int
hra_jobset_validate_des_file_name(char* file_name)
{
    size_t prefix_length;
    size_t ext_length;
    size_t exp_file_name_length;
    size_t file_name_length;
    size_t ext_offset;
    int ret = HRA_STATUS_OK;
    int i;

    prefix_length        = strlen(RXP_DESCRIPTOR_PREFIX);
    ext_length           = strlen(RXP_DESCRIPTOR_EXTENSION);
    ext_offset           = prefix_length + RXP_DESCRIPTOR_JOB_ID_LENGTH;
    exp_file_name_length = prefix_length + ext_length + RXP_DESCRIPTOR_JOB_ID_LENGTH;

    file_name_length     = strlen(file_name);

    /* Check that the file name has the expected length */
    if (exp_file_name_length != file_name_length)
    {
        printf("\nWarning: File name [%s] is not of expected length [%ld]\n", file_name, exp_file_name_length);
        ret = HRA_STATUS_INVALID_JOBSET_DES_FILE_NAME;
    }
    /* Check that the file name prefix is as expected */
    else if (strncmp(RXP_DESCRIPTOR_PREFIX, file_name, prefix_length))
    {
        printf("\nWarning: File name [%s] does not have expected prefix [%s]\n", file_name,
            RXP_DESCRIPTOR_PREFIX);
        ret = HRA_STATUS_INVALID_JOBSET_DES_FILE_NAME;
    }
    /* Check that the file name extension is as expected */
    else if (strncmp(RXP_DESCRIPTOR_EXTENSION, &file_name[ext_offset], ext_length))
    {
        printf("\nWarning: File name [%s] does not have expected extension [%s]\n", file_name,
            RXP_DESCRIPTOR_EXTENSION);
        ret = HRA_STATUS_INVALID_JOBSET_DES_FILE_NAME;
    }
    else
    {
        /* Check that the digits forming the job ID part of the filename are hex digits */
        for (i = 0; i < RXP_DESCRIPTOR_JOB_ID_LENGTH; i++)
        {
            if (0 == isxdigit(file_name[prefix_length]))
            {
                printf("\nWarning: File name [%s] contains an invalid character [%c]\n", file_name,
                    file_name[prefix_length]);
                ret = HRA_STATUS_INVALID_JOBSET_DES_FILE_NAME;
                break;
            }
        }
    }

    return (ret);
}

/*
 * This function processes a .des, .exp or .pkt file. The number of lines in the file is determined and validated. Each
 * line is read and file type specific functions are called to process the lines.
 */
static int
hra_jobset_process_file(char *filename,
                        const char *path,
                        enum rxp_file_type file_type,
                        struct hra_job_table *job_table)
{
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char *line_ptr;
    int num_data_lines = 0;
    int exp_match_index = 0;
    int ret = HRA_STATUS_OK;
    char full_filename[RXP_JOBSET_MAX_FILE_NAME_LEN];
    int line_count = 0;

    snprintf(full_filename, RXP_JOBSET_MAX_FILE_NAME_LEN, "%s//%s", path, filename);
    fp = fopen(full_filename, "r");

    /*
     * Each job must have a .des and .pkt file. However, it is not necessary to have a .exp file.
     */
    if (fp == NULL)
    {
        if (file_type == RXP_EXPECTED_MATCHES_FILE)
        {
            //printf("\nInfo: File [%s] does not exist\n", full_filename);
            job_table->jobs[job_index].num_exp_matches = 0;
        }
        else
        {
            printf("\nWarning: Failed to open file [%s]\n", full_filename);
            ret = HRA_STATUS_JOBSET_FILE_NOT_FOUND;
        }
    }
    /*
     * Do a first pass over the file to count the number of lines containing data to be processed. Validate that
     * the number of lines is consistent with that required of the file type and allocate resources where required.
     * num_data_lines contains the number of lines with data if it is greater than or equal to 0.
     * A value less than 0 indicates an error.
     */
    else if ((num_data_lines = hra_jobset_get_num_data_lines(fp, filename, file_type, job_table)) < 0)
    {
        printf("\nWarning: problem processing file [%s]\n", filename);
        ret = HRA_STATUS_JOBSET_INVALID_FILE;
    }
    else if (num_data_lines > 0)
    {
        /* Process each line and call the appropriate file type specific processing function. */
        while ((read = getline(&line, &len, fp)) != -1)
        {
            line_count++;

            /* Skip comment lines or lines which are all whitespace.  */
            line_ptr = line;
            hra_left_strip(&line_ptr);
            if ((line_ptr[0] == '#') || (line_ptr[0] == '\0'))
            {
                continue;
            }

            /*
             * Call a file specific function to process the individual lines and store the parsed values in the job
             * entry table.
             */
            switch (file_type)
            {
                case RXP_DESCRIPTOR_FILE:
                    if (0 != hra_jobset_process_des_file_line(line_ptr, &job_table->jobs[job_index]))
                    {
                        printf("\nWarning: Failed to process line %d of file [%s]\n", line_count, filename);
                        ret = HRA_STATUS_JOBSET_INVALID_FILE;
                        goto done;
                    }
                    break;

                case RXP_EXPECTED_MATCHES_FILE:
                    if (0 != hra_jobset_process_exp_file_line(line_ptr,
                        &(job_table->jobs[job_index].exp_matches[exp_match_index])))
                    {
                        printf("\nWarning: Failed to process line %d of file [%s]\n", line_count, filename);
                        ret = HRA_STATUS_JOBSET_INVALID_FILE;
                        goto done;
                    }
                    exp_match_index++;
                    break;

                case RXP_JOB_DATA_FILE:
                    if (0 != hra_jobset_process_pkt_file_line(line_ptr, &job_table->jobs[job_index]))
                    {
                        printf("\nWarning: Failed to process line %d of file [%s]\n", line_count, filename);
                        ret = HRA_STATUS_JOBSET_INVALID_FILE;
                        goto done;
                    }
                    break;
            }
        }

done:
        free(line);
    }

    if (fp)
    {
        fclose(fp);
    }

    return (ret);
}

/*
 * Function reads the number of data lines in a file i.e. lines which are not comments or all blank space.
 * If the file is a .des or .pkt file it validates that there is a single data line.
 * If the file is a .exp file it allocates memory for all the expected matches.
 */
static int
hra_jobset_get_num_data_lines(FILE *fp,
                                char *filename,
                                enum rxp_file_type file_type,
                                struct hra_job_table *job_table)
{
    int num_data_lines = 0;
    char *line = NULL;
    char *line_ptr;
    size_t len = 0;
    ssize_t read;

    /*
     * Scan the entire file and check for lines with data on them.
     * Comment lines are not included in the count. These are lines in which the first non-whitespace character is a
     * '#'. Spaces and tabs are both included in the non-whitespace character set. Lines which contain all whitespace
     * or which are completely blank are also not included in the count.
     */
    while ((read = getline(&line, &len, fp)) != -1)
    {
        line_ptr = line;
        hra_left_strip(&line_ptr);
        if ((line_ptr[0] == '#') || (line_ptr[0] == '\0'))
        {
            continue;
        }
        num_data_lines++;
    }

    switch (file_type)
    {
        /* Job descriptor files must have exactly one line of data. */
        case RXP_DESCRIPTOR_FILE:
            if (num_data_lines != 1)
            {
                printf("\nWarning: %s has %d data lines, expected one line\n", filename, num_data_lines);
                num_data_lines = HRA_STATUS_JOBSET_INVALID_FILE;
            }
            break;

        /*
         * Expected match files will have zero or more lines of data. When there are no lines there are no expected
         * matches for the job. When there are matches, memory should be allocated to store the expected matches.
         */
        case RXP_EXPECTED_MATCHES_FILE:
            job_table->jobs[job_index].num_exp_matches = num_data_lines;

            if (num_data_lines != 0)
            {
                if (NULL == (job_table->jobs[job_index].exp_matches = (struct hra_expected_match *)
                    calloc(num_data_lines, sizeof(struct hra_expected_match))))
                {
                    printf("\nWarning: Failed to allocated memory for expected matches\n");
                    num_data_lines =  HRA_STATUS_MEMORY_ALLOCATION_FAILED;
                }
            }
            break;

        /* Job data files should have exactly one line of data */
        case RXP_JOB_DATA_FILE:
            if (num_data_lines != 1)
            {
                printf("\nWarning: %s has %d data lines, expected one line\n", filename, num_data_lines);
                num_data_lines = HRA_STATUS_JOBSET_INVALID_FILE;
            }
            break;

        default:
            break;
    }

    /* Move back to start of file */
    rewind(fp);

    if (line)
    {
        free(line);
    }

    return (num_data_lines);
}

/*
 * Function processes a data line from a job descriptor file. The data should consist of 8 comma separated entries
 * in the format:
 *      job_id,flow_id,ctrl,job_length,subset_id_0,subset_id_1,subset_id_2,subset_id_3
 */
static int
hra_jobset_process_des_file_line(char *line,
                                 struct hra_job *job)
{
    char *parameter;
    char *saveptr = NULL;
    int  i;
    unsigned long value;
    int ret = HRA_STATUS_OK;

    /* Remove leading white space */
    hra_left_strip(&line);

    /*
     * Parse the line. Functions expects to find exactly RXP_DES_FILE_NUM_FIELDS comma separated entries on the line.
     * Each parameter is bounds checked.
     */
    for (i = 0; i < RXP_DES_FILE_NUM_FIELDS; i++, line = NULL)
    {
        /* Break out of loop if an error has been detected */
        if (ret != 0)
        {
            break;
        }

        /* Extract a comma separated parameter and strip leading and trailing white space. */
        parameter = strtok_r(line, ",", &saveptr);
        if (parameter == NULL)
        {
            printf("\nWarning: failed to extract expected parameter\n");
            ret =  HRA_STATUS_JOBSET_DES_FILE_INVALID_PARAMS;
            break;
        }
        hra_left_strip(&parameter);
        hra_right_strip(parameter);

        /* Convert parameter to unsigned long */
        if (HRA_STATUS_OK != (ret = hra_string_to_ulong(parameter, &value)))
        {
            printf("\nWarning: failed to convert [%s] to number\n", parameter);
            break;
        }

        /* Boundary check the specific parameter and store in the appropriate location. */
        switch (i)
        {
            case RXP_DES_FILE_JOB_ID_FIELD:
                if ((value == 0) || (value > UINT32_MAX))
                {
                    printf("\nWarning: job_id is invalid [%ld]\n", value);
                    ret =  HRA_STATUS_JOBSET_DES_FILE_INVALID_PARAMS;
                }
                job->user_job_id = (uint32_t)value;
                break;

            case RXP_DES_FILE_FLOW_ID_FIELD:
                /* Parameter not used */
                break;

            case RXP_DES_FILE_CTRL_FIELD:
                if (value > UINT16_MAX)
                {
                    printf("\nWarning: ctrl is invalid [%ld]\n", value);
                    ret =  HRA_STATUS_JOBSET_DES_FILE_INVALID_PARAMS;
                }
                job->ctrl = (uint16_t)value;
                break;

            case RXP_DES_FILE_JOB_LENGTH_FIELD:
                if ((value == 0) || (value > RXP_MAX_JOB_LENGTH))
                {
                    printf("\nWarning: job_length is invalid [%ld]\n", value);
                    ret =  HRA_STATUS_JOBSET_DES_FILE_INVALID_PARAMS;
                }
                job->job_length = (uint16_t)value;
                break;

            case RXP_DES_FILE_SUBSET_ID_0:
            case RXP_DES_FILE_SUBSET_ID_1:
            case RXP_DES_FILE_SUBSET_ID_2:
            case RXP_DES_FILE_SUBSET_ID_3:
                if (value > UINT16_MAX)
                {
                    printf("\nWarning: subset id is invalid [%ld]\n", value);
                    ret =  HRA_STATUS_JOBSET_DES_FILE_INVALID_PARAMS;
                }
                job->subset_ids[i - RXP_DES_FILE_SUBSET_ID_0] = (uint16_t)value;
                break;

            default:
                break;
        }

    }

    /* Validate that there are no further fields */
    parameter = strtok_r(NULL, ",", &saveptr);
    if (parameter != NULL)
    {
        printf("\nWarning: Unexpected parameters found\n");
        ret =  HRA_STATUS_JOBSET_DES_FILE_INVALID_PARAMS;
    }

    return(ret);
}

/*
 * Function processes a data line from an expected matches file. The data should consist of comma separated entries
 * in the format:
 *      job_id, rxp_rule_id, start_ptr, length, rule
 */
static int
hra_jobset_process_exp_file_line(char *line,
                                 struct hra_expected_match *exp_match)
{
    char *parameter;
    char *saveptr = NULL;
    int i;
    unsigned long value;
    int ret = HRA_STATUS_OK;

    hra_left_strip(&line);

    for (i = 0; i < RXP_EXP_FILE_NUM_FIELDS; i++, line=NULL)
    {
        /* Break out of loop if an error has been detected */
        if (ret != 0)
        {
            break;
        }

        /* Extract a comma separated parameter and strip leading and trailing white space. */
        parameter = strtok_r(line, ",", &saveptr);
        if (parameter == NULL)
        {
            printf("\nWarning: failed to extract expected parameter\n");
            ret =  HRA_STATUS_JOBSET_EXP_FILE_INVALID_PARAMS;
            break;
        }
        hra_left_strip(&parameter);
        hra_right_strip(parameter);

        /* Convert parameter to unsigned long */
        if (HRA_STATUS_OK != (ret = hra_string_to_ulong(parameter, &value)))
        {
            printf("\nWarning: failed to convert [%s] to number\n", parameter);
            break;
        }

        /* Boundary check the specific parameter and store in the appropriate location. */
        switch (i)
        {
            case RXP_EXP_FILE_JOB_ID_FIELD:
                if ((value == 0) || (value > UINT32_MAX))
                {
                    printf("\nWarning: job_id is invalid [%ld]\n", value);
                    ret =  HRA_STATUS_JOBSET_EXP_FILE_INVALID_PARAMS;
                }
                exp_match->job_id = (uint32_t)value;
                break;

            case RXP_EXP_FILE_RXP_RULE_ID_FIELD:
                if ((value == 0) || (value > UINT32_MAX))
                {
                    printf("\nWarning: rxp_rule_id is invalid [%ld]\n", value);
                    ret =  HRA_STATUS_JOBSET_EXP_FILE_INVALID_PARAMS;
                }
                exp_match->rxp_rule_id = (uint32_t)value;
                break;

            case RXP_EXP_FILE_START_PTR_FIELD:
                if (value > UINT16_MAX)
                {
                    printf("\nWarning: start_ptr is invalid [%ld]\n", value);
                    ret =  HRA_STATUS_JOBSET_EXP_FILE_INVALID_PARAMS;
                }
                exp_match->start_ptr = (uint16_t)value;
                break;

            case RXP_EXP_FILE_LENGTH_FIELD:
                if ((value == 0) || (value > UINT16_MAX))
                {
                    printf("\nWarning: length is invalid [%ld]\n", value);
                    ret =  HRA_STATUS_JOBSET_EXP_FILE_INVALID_PARAMS;
                }
                exp_match->length = (uint16_t)value;
                break;

            default:
                break;
        }
    }

    parameter = strtok_r(NULL, ",", &saveptr);
    if (parameter == NULL)
    {
        printf("\nWarning: Rule parameter not found\n");
        ret =  HRA_STATUS_JOBSET_EXP_FILE_INVALID_PARAMS;
    }

    return(ret);
}

/*
 * Function processes a data line from a job data file. The job data should be stored on a single data line and will
 * consist of hexadecimal pairs of digits without spaces.
 */
static int
hra_jobset_process_pkt_file_line(char *line,
                                 struct hra_job *job)
{
    int i;
    int line_length;
    char temp[] = "00";
    int ret = 0;

    /* Strip leading and trailing whitespace. */
    hra_left_strip(&line);
    hra_right_strip(line);

    line_length = strlen(line);

    if (line_length != (job->job_length * 2))
    {
        printf("\nWarning: job data length is not as expected\n");
        ret = HRA_STATUS_WRONG_JOB_DATA_LENGTH;
    }
    else if (NULL == (job->job_data = (uint8_t *)calloc(line_length/2, sizeof(uint8_t))))
    {
        printf("\nWarning: Memory allocate failure\n");
        ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
    }
    else
    {
        /*
         * Iterate through all the pairs of characters in the line. Validate that the characters are valid hexadecimal
         * digits and convert to a number.
         */
        for (i = 0; i < line_length; i+=2)
        {
            if (0 == isxdigit(line[i]))
            {
                printf("\nWarning: [%c] is invalid hex digit\n", line[i]);
                ret = HRA_STATUS_INVALID_JOB_DATA_CHARACTER;
                break;
            }
            else if (0 == isxdigit(line[i+1]))
            {
                printf("\nWarning: [%c] is invalid hex digit\n", line[i+1]);
                ret = HRA_STATUS_INVALID_JOB_DATA_CHARACTER;
                break;
            }
            temp[0] = line[i];
            temp[1] = line[i+1];
            job->job_data[i/2] = (uint8_t)strtol(temp, 0, 16);
        }
    }

    return(ret);
}

/*
 * Function strips whitespace from the start of a string. Note that this function modifies the starting pointer
 * of the string.
 */
static void
hra_left_strip(char **ptr)
{
    if (ptr != NULL)
    {
        while ((isspace(**ptr)) || (**ptr == '\0'))
        {
            if (**ptr == '\0')
            {
                break;
            }
            (*ptr)++;
        }
    }
}

/*
 * Function strips whitespace from the end of a string. The starting pointer is not modified, unlike
 * hra_left_strip. Any whitespace at the end of the string is replaced with \0 characters.
 */
static void
hra_right_strip(char *ptr)
{
    char *first = ptr;

    if (ptr != NULL)
    {
        for(ptr += (strlen(ptr) - 1); ptr >= first; ptr--)
        {
            if (isspace(*ptr))
            {
                *ptr = '\0';
            }
            else
            {
                break;
            }
        }
    }
}

/**
 * Function converts a string to an unsigned long. It checks for error conditions. The string which is passed in
 * should have no trailing whitespace.
 */
static int
hra_string_to_ulong(char *string, unsigned long *value)
{
    char *endptr;
    int ret = HRA_STATUS_OK;

    if ((string == NULL) || (value == NULL))
    {
        printf("Error: Null pointer passed to function\n");
        ret = HRA_STATUS_NULL_POINTER;
    }
    else
    {
        /* To distinguish success/failure after call */
        errno = 0;
        *value = strtoul(string, &endptr, 0);

        /* Check for various possible errors */
        if (((errno == ERANGE) && (*value == ULONG_MAX)) ||
            ((errno != 0) && (*value == 0)) ||
            (endptr == string) ||
            (*endptr != '\0'))
        {
            printf("Error: Failed to convert [%s] to unsigned long\n", string);
            ret = HRA_STATUS_STRING_TO_ULONG_FAILED;
        }
    }

    return (ret);
}

/* ************************************/
/* PACKED BINARY JOBSET PARSING TOOLS */
/* ************************************/

/*
 * The jobs are encoded in a nested TLV format as follows.
 * (Conceptually, this is somewhat like arrays of structures inside arrays
 * to several levels of depth.
 * The difference is that the structure elements are of variable length.
 * Hence the type and length approach instead of simple fixed size
 * structure definitions.
 *
 * ├─ Top level TLV.  See tlv_type_job_pack
 * └─── Jobs TLV's. See tlv_type_job.
 *      ├─ descriptor TLV.  See tlv_type_desc.
 *      ├─ expected TLV. See tlv_type_exp.
 *      │    └── expected match tlvs.  See tlv_type_exp_match
 *      ├─ embedded TLV. See tlv_type_emb.
 *      │    └── embedded match tlvs.  See tlv_type_emb_match
 *      └─ job data TLV.  See tlv_type_job_data.
 */

#define TLV_TYPE_JOB_PACK   10
#define TLV_TYPE_JOB        20
#define TLV_TYPE_DESC       30
#define TLV_TYPE_EXP        40
#define TLV_TYPE_EXP_MATCH  50
#define TLV_TYPE_EMB        60
#define TLV_TYPE_EMB_MATCH  70
#define TLV_TYPE_JOB_DATA   80

struct tlv_type_job_pack
{
    uint32_t t;
    uint64_t l;     /* note: this top level tlv has a 64bit length field. */
    struct
    {
        uint32_t num_jobs;
        uint8_t payload[0];
    } v;
} __attribute__ ((__packed__));

struct tlv_type_job
{
    uint32_t t;
    uint32_t l;
    struct
    {
        char job_name[32];
        uint8_t payload[0];
    } v;
} __attribute__ ((__packed__));

struct tlv_type_desc
{
    uint32_t t;
    uint32_t l;
    struct
    {
        uint32_t job_id;
        uint32_t rsvd;
        uint32_t ctrl;
        uint32_t job_length;
        uint32_t subset_ids[4];
    } v;
} __attribute__ ((__packed__));

struct tlv_type_exp
{
    uint32_t t;
    uint32_t l;
    struct
    {
        uint32_t num_matches;
        uint8_t payload[0];
    } v;
} __attribute__ ((__packed__));

struct tlv_type_exp_match
{
    uint32_t t;
    uint32_t l;
    struct
    {
        uint32_t job_id;
        uint32_t rule_id;
        uint32_t start_ptr;
        uint32_t length;
        char     rule[0];
    } v;
} __attribute__ ((__packed__));

struct tlv_type_emb
{
    uint32_t t;
    uint32_t l;
    struct
    {
        uint32_t num_matches;
        uint8_t payload[0];
    } v;
} __attribute__ ((__packed__));

struct tlv_type_emb_match
{
    uint32_t t;
    uint32_t l;
    struct
    {
        uint32_t job_id;
        uint32_t rule_id;
        uint32_t start_ptr;
        uint32_t length;
        char     rule[0];
    } v;
} __attribute__ ((__packed__));

struct tlv_type_job_data
{
    uint32_t t;
    uint32_t l;
    struct
    {
        uint8_t data[0];
    } v;
} __attribute__ ((__packed__));

int proc_tlv_type_desc(struct tlv_type_desc *desc, struct hra_job *job);
int proc_tlv_type_exp_match(struct tlv_type_exp_match *tlv, struct hra_expected_match *exp_match);
int proc_tlv_type_exp(struct tlv_type_exp *tlv, struct hra_job *job);
int proc_tlv_type_job_data(struct tlv_type_job_data *tlv, struct hra_job *job);
int proc_job_tlv(struct tlv_type_job *tlv, struct hra_job *job);

/*
 * Apart from the top level tlv_job_pack_tlv, all of the TLV's have uint32_t
 * for type and length.  When calculating offsets, use the following #define.
 */
#define SIZEOF_TYPE_AND_LENGTH (8)

int proc_tlv_type_desc(struct tlv_type_desc *desc, struct hra_job *job)
{
    int ret = HRA_STATUS_OK;

    if (desc->t == TLV_TYPE_DESC)
    {
        job->user_job_id   = desc->v.job_id;
        job->ctrl          = desc->v.ctrl;
        job->job_length    = desc->v.job_length;
        job->subset_ids[0] = desc->v.subset_ids[0];
        job->subset_ids[1] = desc->v.subset_ids[1];
        job->subset_ids[2] = desc->v.subset_ids[2];
        job->subset_ids[3] = desc->v.subset_ids[3];
    }
    else
    {
        printf("\nWarning: Malformed descriptor\n");
        ret = HRA_STATUS_FAIL;
    }

    return ret;
}

int proc_tlv_type_exp_match(struct tlv_type_exp_match *tlv, struct hra_expected_match *exp_match)
{
    int ret = HRA_STATUS_OK;

    if (tlv->t == TLV_TYPE_EXP_MATCH)
    {
        exp_match->job_id      = tlv->v.job_id;
        exp_match->rxp_rule_id = tlv->v.rule_id;
        exp_match->start_ptr   = tlv->v.start_ptr;
        exp_match->length      = tlv->v.length;
    }
    else
    {
        printf("\nWarning: Malformed expected match\n");
        ret = HRA_STATUS_FAIL;
    }

    return ret;
}

int proc_tlv_type_exp(struct tlv_type_exp *tlv, struct hra_job *job)
{
    int ret = HRA_STATUS_OK;

    if (tlv->t == TLV_TYPE_EXP)
    {
        uint32_t num_matches = tlv->v.num_matches;

        if ((job->exp_matches = (struct hra_expected_match *)
            calloc(num_matches, sizeof(struct hra_expected_match))))
        {
            uintptr_t base = (uintptr_t)tlv->v.payload;
            uint32_t offset = 0;
            uint32_t i;

            for (i = 0; i < tlv->v.num_matches; i++)
            {
                struct tlv_type_exp_match *exp_match = (struct tlv_type_exp_match *)(base + offset);
                ret = proc_tlv_type_exp_match(exp_match, &job->exp_matches[i]);
                if (ret < 0)
                    break;
                offset += SIZEOF_TYPE_AND_LENGTH + exp_match->l;
                /* Defensive check to ensure we don't go beyond the end of the top level tlv. */
                if (offset > tlv->l)
                {
                    printf("\nWarning: Malformed expected batch\n");
                    ret = HRA_STATUS_FAIL;
                    break;
                }
            }
            job->num_exp_matches = i;
        }
        else
        {
            printf("\nWarning: Failed to allocated memory for expected matches\n");
            ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
        }
    }
    else
    {
        printf("\nWarning: Malformed expected batch\n");
        ret = HRA_STATUS_FAIL;
    }

    return ret;
}

int proc_tlv_type_job_data(struct tlv_type_job_data *tlv, struct hra_job *job)
{
    int ret = HRA_STATUS_OK;

    if (tlv->t != TLV_TYPE_JOB_DATA)
    {
        printf("\nWarning: Malformed job data\n");
        ret = HRA_STATUS_FAIL;
    }
    else if (tlv->l != job->job_length)
    {
        printf("\nWarning: job data length is not as expected\n");
        ret = HRA_STATUS_WRONG_JOB_DATA_LENGTH;
    }
    else if (NULL == (job->job_data = (uint8_t *)calloc(tlv->l, sizeof(uint8_t))))
    {
        printf("\nWarning: Memory allocate failure\n");
        ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
    }
    else
    {
        memcpy(job->job_data, tlv->v.data, tlv->l);
    }

    return ret;
}

int proc_job_tlv(struct tlv_type_job *tlv, struct hra_job *job)
{
    int ret = HRA_STATUS_OK;

    uint32_t offset = 0;
    uintptr_t base = (uintptr_t)tlv->v.payload;

    struct tlv_type_desc *desc = (struct tlv_type_desc *)(base);
    ret = proc_tlv_type_desc(desc, job);
    if (ret < 0)
        goto out;

    offset += SIZEOF_TYPE_AND_LENGTH + desc->l;
    /* Defensive check to ensure we don't go beyond the end of the top level tlv. */
    if (offset > tlv->l)
    {
        printf("\nWarning: Malformed job\n");
        ret = HRA_STATUS_FAIL;
        goto out;
    }
    struct tlv_type_exp *exp = (struct tlv_type_exp *)(base + offset);
    ret = proc_tlv_type_exp(exp, job);
    if (ret < 0)
        goto out;

    offset += SIZEOF_TYPE_AND_LENGTH + exp->l;
    /* Defensive check to ensure we don't go beyond the end of the top level tlv. */
    if (offset > tlv->l)
    {
        printf("\nWarning: Malformed job\n");
        ret = HRA_STATUS_FAIL;
        goto out;
    }
    struct tlv_type_emb *emb = (struct tlv_type_emb *)(base + offset);
    /* We don't use the embedded data. */

    offset += SIZEOF_TYPE_AND_LENGTH + emb->l;
    /* Defensive check to ensure we don't go beyond the end of the top level tlv. */
    if (offset > tlv->l)
    {
        printf("\nWarning: Malformed job\n");
        ret = HRA_STATUS_FAIL;
        goto out;
    }
    struct tlv_type_job_data *job_data = (struct tlv_type_job_data *)(base + offset);
    ret = proc_tlv_type_job_data(job_data, job);
    if (ret < 0)
        goto out;

out:
    return ret;
}

static int
hra_jobset_read_packed(struct hra_job_table *job_table, const char *filename)
{
    int ret = HRA_STATUS_OK;
    int num_jobs;
    struct stat sb;

    int fd = open(filename, O_RDONLY);
    if (fd)
    {
        uintptr_t base;
        fstat(fd, &sb);
        base = (uintptr_t)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (base)
        {
            struct tlv_type_job_pack *top = (struct tlv_type_job_pack *)base;
            int offset = 0;

            offset += sizeof(*top);

            num_jobs = top->v.num_jobs;

            if (NULL == (job_table->jobs = (struct hra_job *)calloc(num_jobs, sizeof(struct hra_job))))
            {
                printf("Warning: Failed to allocate memory for RXP job entries table (%d job entries found)\n",
                    num_jobs);
                ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
            }
            else
            {
                job_table->num_entries = num_jobs;
                job_index = 0;

                for (job_index = 0; job_index < num_jobs; job_index++)
                {
                    struct tlv_type_job *job_tlv = (struct tlv_type_job *)(base + offset);
                    struct hra_job *job = &job_table->jobs[job_index];

                    /*
                     * Print messages to inform the user of progress processing the jobset.
                     * Be sure to print a message when the last entry is being processed.
                     */
                    if ((((job_index + 1) % 100) == 0) || ((job_index + 1) == num_jobs))
                    {
                        printf("\rInfo: Loading jobset %d of %d", job_index + 1, num_jobs);
                    }

                    ret = proc_job_tlv(job_tlv, job);
                    if (ret < 0)
                    {
                        printf("\nWarning: Failed loading job %d, err %d\n", job_index + 1, ret);
                        break;
                    }
                    offset += SIZEOF_TYPE_AND_LENGTH + job_tlv->l;
                    /* Defensive check to ensure we don't go beyond the end of the file. */
                    if (offset > sb.st_size)
                    {
                        printf("\nWarning: Malformed job file\n");
                        ret = HRA_STATUS_FAIL;
                        break;
                    }
                }
                printf("\nInfo: Loaded %d jobs\n", job_index);
                munmap((void*)base, sb.st_size);
            }
        }
        else
        {
            printf("%s %d, mmap failed\n", __FUNCTION__, __LINE__);
            ret = HRA_STATUS_MEMORY_ALLOCATION_FAILED;
        }
        close(fd);
    }
    else
    {
        printf("%s %d, failed to open file %s\n", __FUNCTION__, __LINE__, filename);
        return (HRA_STATUS_JOBSET_FILE_NOT_FOUND);
    }

    return (ret);
}
