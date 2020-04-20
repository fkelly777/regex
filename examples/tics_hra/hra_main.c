/**
 * @file    hra_main.c
 * @author  Titan IC Systems <support@titanicsystems.com>
 *
 * @section DESCRIPTION
 *
 *   Host Reference Application (HRA)- this file implements the main()
 *   function and packet processing routines of the HRA. One Rx/Tx queue pair is
 *   created for each configured thread. A rules file and jobset (job
 *   descriptors, expected matches and job data) are read in from files and
 *   stored in memory. The RXP is initialized and the rules memories are
 *   programmed. A packet processing loop is run on all active threads. Each
 *   thread reads job data from the jobset, creates job packets and sends these
 *   to the RXP. Responses are processed in the same loop. A Jobs Awaiting
 *   Responses (JAR) table is used to track outstanding jobs. When a response is
 *   received the matches contained within the response are compared against
 *   expected matches and a score table is created.
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

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include <rxp-api.h>

#include "hra_jar_table.h"
#include "hra_jobset.h"
#include "hra_errors.h"
#include "hra_log_files.h"
#include "hra_platform.h"
#include "hra_build_revision.h"

#ifdef DPDK
#include <rte_lcore.h>
#endif

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#define INVALID_STRTOL_CONVERSION(value, string, endptr) \
                (errno == ERANGE) || \
                ((errno != 0) && (value == 0)) || \
                (endptr == string) || \
                (*endptr != '\0') || \
                ((int)value < 0)

/* Macro used to identify that a response has no expected matches */
#define HRA_NO_MATCHES              (-1)
#define BURST_TX_DRAIN_NS           100000 /* TX drain every ~100us */
#define MAX_TIMER_PERIOD            86400 /* 1 day max */

/* Jobs will be dispatched either when the dispatch list is full, or the number of enqueued bytes exceeds this limit */
#define HRA_BYTE_OUT_THRESHOLD      16384

#define RXP_CONFIGURE_RXP_ATTEMPTS  1
#define RXP_SMALL_JOB_COUNT_WARNING 1000000

/* A value of 0 indicates that there will be no retransmission of lost jobs */
#define HRA_MAX_TIMEOUTS            0

#define NS_PER_SEC                  1E9

/*
 * Structure for 'match' statistics, i.e. score table and false positive count.
 */
struct match_stats {
    uint64_t score[8];
    uint64_t false_positives;
};

/*
 * Statistics structure to record application level statistics.
 */
struct queue_statistics {
    uint64_t jobs_scanned;
    uint64_t bytes_scanned;
    uint64_t matches;
    uint64_t rx_pkts;
    uint64_t valid_responses;
    uint64_t invalid_responses;
    uint64_t job_timeouts;
    uint64_t job_retransmits;
    uint64_t jobs_aborted;
    uint64_t tx_busy;
    uint64_t primary_thread_count;
    uint64_t instruction_count;
    uint64_t max_pt_set;
    uint64_t max_st_set;
    uint64_t max_latency_set;
    uint64_t max_match_set;
    uint64_t max_prefix_set;
    uint64_t hpm_set;
    uint64_t anymatch_set;
    uint64_t latency_total;
    uint64_t latency_min;
    uint64_t latency_max;
    uint64_t matched_bytes;

    struct match_stats ms_normal;
    struct match_stats ms_aborted;
};

/*
 * Structure to hold the context for each queue.
 */
struct queue_ctx {
    int id;
    int core;
    int handle;
    int status;
    bool active;
    int first_job_id,
        last_job_id,
        num_jobs;
    pthread_t tid;
    struct queue_statistics statistics;
    size_t resp_buf_size;
    uint8_t *resp_buf;
    sem_t start_sem;
};

static uint64_t job_timeouts_detected = 0;

/* Variable used to indicate that packet processing loop should process packets */
static int process_packets = 1;

/* Variables for programming 'max/threshold' settings. */
static uint32_t max_prefixes    = 0,
                max_matches     = 0,
                max_latency     = 0,
                max_pri_threads = 0;

/* Job batch size and bytes threshold. */
static size_t job_batch_size = RXP_TX_BURST_DEFAULT;
static size_t job_batch_bytes_threshold = 0;  /* zero for no threshold. */

/* Period between statistics updates in seconds*/
static uint64_t stats_timer_secs = 1;

/* Struct contains jobset info, such as job descriptors, packet data and expected matches */
struct hra_job_table hra_job_table;

/* Pointer for per queue context */
struct queue_ctx *queues;

/* Number of queues in use */
static unsigned num_queues = 1;

/*
 * For processing a range of jobs in the job directory.
 * These values run from 1 to number of jobs.
 */
static int first_job_id = -1;
static int last_job_id = -1;

/*
 * Size of response buffer to allocate.  It needs to be at least big enough to
 * contain a worst case response, ie. one with MAX_MATCHES responses.
 */
#define RXP_RESP_BUF_SIZE_DEFAULT (RXP_RESP_BUF_SIZE_MIN * 16)
static size_t resp_buf_size = RXP_RESP_BUF_SIZE_DEFAULT;

/******************************************************************************/
/* GLOBALS WHICH CAN BE MODIFIED FROM COMMAND LINE                            */
/******************************************************************************/

/* Max number of iterations of the jobset to scan. A value of 0 implies continuous transmission */
int64_t max_jobset_iterations = 0;

static int iteration_timer_secs = 0;

/* Port ID to use for communicating with the RXP */
long rxp_port_id = 0;

/*  Name of ROF file */
static char *rof_file_name = NULL;

/*  Name of incremental update ROFI file */
static char **incremental_update_file_name = NULL;
static unsigned incremental_update_file_cnt = 0;

/* Directory to search for jobset files */
static char *jobset_dir = NULL;

static long mode = 0;
static int jar_table_enabled = 1;
static int score_table_enabled = 1;

long hra_debug_level = 0;

/*  Time in seconds to delay before applying incremental rules update
 *  in case multiple update-rule-files specified, the update_delay between
 *  them still keeps the same */
static int incremental_update_delay = 0;

static int extended_stats_enabled = 0;

static int rxp_read_cluster_values = 0;
static int rxp_periodic_cluster = 0;

/*
 * When an incremental rules update is required, this flag is set to
 * signal the active job threads to quiesce their processing.
 */
static bool quiesce_queues = false;

/******************************************************************************/
/* STATIC FUNCTION PROTOTYPES                                                 */
/******************************************************************************/

/**
 * Parse the argument given in the command line of the application
 *
 * @param argc   Command line argument count
 * @param argv   Command line argument values
 * @return       HRA_STATUS_OK if ok, else error code
 */
static int
hra_parse_args(int argc,
               char **argv);

/**
 * This is the main processing loop. The code runs in a continuous loop
 * performing these steps.
 *  - Attempts to add a job to the transmit table- this can only be done if there are sufficient free entries in the
 *    JAR table. If the number of jobs in the transmit table has reached a threshold then the buffer is flushed.
 *  - Once every drain ticks, any packets in the transmit table are sent. This ensures that packets do not spend
 *    an excessive period in the
 *  - Once every stats_timer_period the queue statistics are sent- this is only performed by the main thread.
 *  - Packets are read from the receive queue. The matches are validated against the expected matches, and the
 *    job buffers are freed.
 *  - The tail of the JAR table is checked. The tail contains the oldest entry. If the entry has been in the JAR table
 *    for longer that a certain period, then the job/response is considered lost. The job may be retransmitted up to
 *    a maximum number of attempts. After the maximum number of attempts the job is considered lost and no further
 *    attempts are made.
 *
 * Note: This function is primarily responsible for implementing the HRA functionality using the provided functions.
 * Users should use this function as a starting point for developing new applications.
 *
 * @param thread_data RXP port information
 * return             HRA_STATUS_OK if packet processing completes successfully, else an error code
 */
static void *
hra_main_loop(void *thread_data);

/**
 * Function prints statistics which have been gathered by the application. Per queue and aggregate statistics
 * are both printed.
 */
static void
hra_display_application_stats(void);

/**
 * CTRL-C handler function. Sets process_packets to 0 to end packet processing
 *
 * @param signal_number   unused
 */
static void
hra_signal_handler(int signal_number);

/**
 * Function reads registers on from the RXP and displays statistics. Bit rate is also calculated and displayed.
 *
 * @param port_id        ID of port
 * @param test_duration  Duration of packet processing loop
 * @return               HRA_STATUS_OK if ok, else an error code
 */
static int
hra_display_rxp_stats(unsigned port_id,
                      double test_duration);

int
hra_display_cluster_stats(int report);

/**
 * Function registers handler for CTRL-C
 *
 * @return   Return code from sigaction
 */
static int
hra_init_signal_handler(void);

/**
 * This function compares the matches in a response against the expected matches for the job. Each expected match is
 * compared against the received matches. The rule ID, start pointer and match length in the expected match is compared
 * against each received match. A score is calculated:
 *  - If the rule IDs match 4 points (0x1 << 2) are awarded.
 *  - If the rule IDs don't match then a score of 0 is awarded.
 *  - If the start pointers also match 2 (0x1 << 1) points are awarded.
 *  - If the lengths also match 1 (0x1 << 0) point is awarded.
 * Thus the score is a value of 0 or between 4 and 7. The highest score for each expected match is identified. This is
 * taken as the score for that expected match. The corresponding received match is then tagged, and is not compared
 * against any further expected matches. The highest score for each expected match is determined, and the score for the
 * entire job is taken as the lowest of the expected match scores. For instance consider the case where there are 3
 * expected matches and 3 received matches. If the score for two of the expected matches is 7, but the score for the
 * third is 4, then the job is awarded a score of 4.
 * If there are no expected matches, a score of HRA_NO_MATCHES (-1) is returned.
 *
 * @param resp_desc         Response descriptor to be examined
 * @param job               Job which contains expected matches
 * @param jar_table_job_id  Job ID used by the JAR table and actually used to scan jobs
 * @param jobset_iteration  Iteration of jobset which response belongs to- used for logging
 * @return                  Score if there are expected matches, else HRA_NO_MATCHES (-1)
 */
static int
hra_check_response(struct queue_ctx *queue,
                   struct rxp_response *resp_data,
                   struct hra_job *job,
                   uint32_t jar_table_job_id,
                   int jobset_iteration);

/**
 * Print a banner which includes information about the version of the program.
 */
static void
hra_print_banner(void);

/**
 * Display application usage.
 *
 * @param prgname   Program name
 */
static void
hra_usage(const char *prgname);

/**
 * Function attempts to enqueue a job for transmission. A job entry is read from the job entry table and
 * an attempt is made to add an entry to the jar table. If there is sufficient room in the jar table then
 * rxp_prepare_job() is called to create a packet. rxp_enqueue_job() and adds the job to to a dispatch list.
 * The list will be flushed if it contains RXP_MAX_PKT_BURST entries using rxp_dispatch_jobs().
 *
 * @param job_count         Identifies the entry in the job entry table to be used
 * @param job_iterations    The number of iterations of jobset which have been completed
 * @param jar_table         JAR table used by this core
 * @param iteration_timeout If set indicates that hra has run for the desired time
 */
static void
hra_transmit(struct queue_ctx *queue,
             struct rxp_job_batch *ctx,
             int *job_count,
             int64_t *jobset_iterations,
             rxp_jar_table_t *jar_table,
             uint64_t iteration_timeout);

/**
 * Function receives responses from a queue. The JAR table is examined for the corresponding entry. The matches
 * matches are validated against the expected matches registered in the jobset.
 *
 * @param queue_id                  RXP queue ID
 * @param jar_table                 JAR table used by this thread
 * @param responses_and_timeouts    Number of valid responses or timed out entries
 * @return                          Number of received packets
 */
static unsigned int
hra_receive(struct queue_ctx *queue,
            rxp_jar_table_t *jar_table,
            uint64_t *responses_and_timeouts);

/**
 * Function waits for incremental_update_delay seconds and then programs the rules memories using
 * the file specified with incremental_update_file_name.
 * Statistics are periodically displayed.
 *
 * @param thread_data RXP port information
 * return             HRA_STATUS_OK if packet processing completes successfully, else an error code
 */
static int
hra_incremental_rtru_loop(void *thread_data);

/******************************************************************************/
/* MAIN FUNCTION                                                              */
/******************************************************************************/
/**
 * Main function.
 *  -Initializes RXP port and queues
 *  -Reads jobset into memory
 *  -Initializes RXP
 *  -Programs rules memories on RXP
 *  -Starts main processing loops on all threads
 *  -Displays stats
 *
 * @param argc   Command line argument count
 * @param argv   Command line argument values
 * @return       HRA_STATUS_OK if ok, else error code
 */
int
main(int argc, char **argv)
{
    int ret;
    struct timeval loop_start;
    struct timeval loop_end;
    struct timeval loop_time_taken;
    struct timeval program_rules_start;
    struct timeval program_rules_end;
    struct timeval program_rules_time_taken;
    double test_duration;
    unsigned i;
    unsigned j;
    struct tm *begin;
    time_t begin_time;
    unsigned num_jobs;

    /*
     * Print information banner to screen.
     */
    hra_print_banner();

    /*
     * Print out the current time and date.
     */
    begin_time = time(0);
    begin = localtime(&begin_time);
    printf("Info: Processing Started: %s\n", asctime(begin));

    /* Platform specific initialisation. */
    if ((ret = rxp_platform_init(rxp_port_id, argc, argv)) < 0)
    {
        printf("Info: platform_init returned error %d, %s,\n", ret, strerror(-ret));
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }

#ifdef DPDK
    num_queues = rte_lcore_count();

    /*
     * Parse application arguments (after the EAL/DPDK ones)
     */
    argc -= ret;
    argv += ret;
#endif

    /*
     * Parse application arguments.
     */
    printf("Info: Beginning to process application command line arguments...done\n");
    ret = hra_parse_args(argc, argv);
    if (ret < 0)
    {
        printf("Error: Processing application command line arguments...failed\n");
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }
    /* If incremental update is done after a while, there must be at least 2 threads */
    if ((incremental_update_file_name != NULL) && (incremental_update_delay > 0))
    {
        if (num_queues <= 1)
        {
            printf("Error: In RTRU mode, when incremental_update_delay != 0, at least 2 threads required\n");
            ret = HRA_STATUS_FAIL;
            goto cleanup;
        }
    }

    /*
     * If logging is enabled then allocate memory to store the logs until the end of the application.
     */
    if (hra_debug_level >= DEBUG_MODE_ENHANCED)
    {
        printf("Info: Beginning to initialize debug logs...done\n");
        if (hra_debug_level == DEBUG_MODE_ENHANCED_NO_TRUNCATE)
        {
            ret = hra_log_files_init_do_not_truncate(num_queues);
        }
        else
        {
            ret = hra_log_files_init(num_queues);
        }
        if (ret != HRA_STATUS_OK)
        {
            printf("Error: Debug log initialization...failed\n");
            ret = HRA_STATUS_FAIL;
            goto cleanup;
        }
    }

    /* Initialise timer settings. */
    hra_ticks_init();

    if (rxp_read_cluster_values)
    {
        printf("Info: Beginning to read cluster stats...done\n");
        ret = hra_display_cluster_stats(0);
        if (ret != HRA_STATUS_OK)
        {
            printf("Error: Reading cluster stats...failed\n");
        }
        goto cleanup;
    }

    /*
     * Allocate queue contexts. One rx/tx queue pair is created per thread.
     */
    printf("Info: Beginning to allocate memory for queue contexts...done\n");
    queues = calloc(num_queues, sizeof(struct queue_ctx));
    if (queues == NULL)
    {
        printf("Error: Allocating memory for queue contexts...failed\n");
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }

    /*
     * Read the jobset i.e. job descriptors, job data and expected matches from .des, .pkt
     * and .exp files in the specified directory.
     */
    printf("Info: Beginning to load jobset %s...done\n", jobset_dir);
    ret = hra_jobset_read(&hra_job_table, jobset_dir);
    if (ret != HRA_STATUS_OK)
    {
        printf("Error: Loading jobset %s...failed\n", jobset_dir);
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }

    /*
     * If they were provided, take the user provided job_id range,
     * otherwise use defaults.
     */
    if (first_job_id < 0)
    {
        first_job_id = 1;
    }
    if (last_job_id < 0)
    {
        last_job_id = hra_job_table.num_entries;
    }
    /* Validate first_job_id and last_job_id against size of jobset loaded. */
    if (first_job_id < 1 ||
        first_job_id > hra_job_table.num_entries ||
        last_job_id < 1 ||
        last_job_id > hra_job_table.num_entries)
    {
        printf("Error: first_job_id and last_job_id must be in range 1 to %d\n",
                hra_job_table.num_entries);
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }
    if (last_job_id < first_job_id)
    {
        printf("Error: list_job_id (%d) must be >= first_job_id (%d)\n",
                last_job_id, first_job_id);
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }

    num_jobs = last_job_id - first_job_id + 1;
    /*
     * Truncate number of jobs to integer multiple of queues
     */
    if (num_jobs < num_queues)
    {
        printf("Error: Job count (%d) must be >= core count (%d)\n",
            num_jobs, num_queues);
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }
    if ((num_jobs % num_queues) != 0)
    {
        int truncate = num_jobs % num_queues;
        num_jobs -= truncate;
        last_job_id -= truncate;
        printf("Info: Truncating job count to integer multiple %d of core count %d\n",
            num_jobs, num_queues);
    }

    printf("Info: Processing jobs %d to %d\n", first_job_id, last_job_id);

    /*
     * Make up to RXP_CONFIGURE_RXP_ATTEMPTS attempts to configure the RXP. Configuration
     * could potentially fail due to a corrupted packet whilst initializing the RXP or
     * during rules programming.
     */
    for (i = 0; i < RXP_CONFIGURE_RXP_ATTEMPTS; i++)
    {
        printf("Info: Beginning to configure the RXP, attempt %d of %d...done\n",
            i + 1, RXP_CONFIGURE_RXP_ATTEMPTS);

        /*
         * Program the rules memories on the RXP.
         */
        printf("Info: Beginning to program the RXP rules memories...done\n");
        gettimeofday(&program_rules_start, NULL);
        ret = rxp_program_rules(rxp_port_id, rof_file_name, false);
        if (ret < 0)
        {
            perror("Error: Programming the RXP rules memories...failed");
            continue;
        }
        else
        {
            gettimeofday(&program_rules_end, NULL);
            timersub(&program_rules_end, &program_rules_start, &program_rules_time_taken);
            printf("Info: Programming the RXP rules memories...done\n");
            printf("Info: Programming the RXP rules memories took %.3f seconds\n",
                (double)program_rules_time_taken.tv_sec + (double)(program_rules_time_taken.tv_usec)/1000000);
        }

        /*
         * If an incremental update file name is specified but the delay is set to 0 then immediately perform
         * an incremental rules update. This behavior allows validation of incremental compilation with rxpc.
         */
        if ((incremental_update_file_name != NULL) && (incremental_update_delay == 0))
        {
            /*
             * Apply incremental update to rules memories if a ROFI file is specified and the incremental
             * update period is 0.
             */
            for (j = 0; j < incremental_update_file_cnt; j++)
            {
                printf("Info: Beginning to program the RXP rules with [%d]-th incremental update...done\n", j);
                gettimeofday(&program_rules_start, NULL);
                ret = rxp_program_rules(rxp_port_id, incremental_update_file_name[j], true);
                if (ret < 0)
                {
                    printf("Error: Programming the RXP rules with [%d]-th incremental update...failed", j);
                    break;
                }
                else
                {
                    gettimeofday(&program_rules_end, NULL);
                    timersub(&program_rules_end, &program_rules_start, &program_rules_time_taken);
                    printf("Info: Programming the RXP rules with [%d]-th incremental update...done\n", j);
                    printf("Info: Programming the RXP rules with [%d]-th incremental update took %.3f seconds\n", j,
                        (double)program_rules_time_taken.tv_sec + (double)(program_rules_time_taken.tv_usec)/1000000);
                }
            }

            if ((j == incremental_update_file_cnt) && (ret == 0))
            {
                /* all update are good, so exit for the outer for loop */
                break;
            }
            else
            {
                /* not all update are good, so go back to the outer for loop to finish the maximum try count */
                continue;
            }
        }
        else
        {
             break;
        }
    }

    if (ret < 0)
    {
        printf("Error: RXP configuration...failed\n");
        goto cleanup;
    }

    /* Set 'max/thresholds' if applicable. */
    if (max_matches && rxp_set_max_matches(rxp_port_id, max_matches) < 0)
    {
        perror("Set max matches");
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }
    if (max_prefixes && rxp_set_max_prefixes(rxp_port_id, max_prefixes) < 0)
    {
        perror("Set max prefixes");
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }
    if (max_latency && rxp_set_max_latency(rxp_port_id, max_latency) < 0)
    {
        perror("Set max latency");
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }
    if (max_pri_threads && rxp_set_max_pri_threads(rxp_port_id, max_pri_threads) < 0)
    {
        perror("Set max primary threads");
        ret = HRA_STATUS_FAIL;
        goto cleanup;
    }
    rxp_read_max_matches(rxp_port_id, &max_matches);
    rxp_read_max_prefixes(rxp_port_id, &max_prefixes);
    rxp_read_max_latency(rxp_port_id, &max_latency);
    rxp_read_max_pri_threads(rxp_port_id, &max_pri_threads);
    printf("Info: max_matches %d, max_prefixes %d, max_latency %d, max_pri_threads %d\n",
            max_matches, max_prefixes, max_latency, max_pri_threads);
    printf("Info: job_batch_size %zu, job_batch_bytes_threshold %zu\n",
            job_batch_size, job_batch_bytes_threshold);
    printf("Info: resp_buf_size %zu\n", resp_buf_size);

    /*
     * Initialize Ctrl-C signal handler
     */
    hra_init_signal_handler();

    printf("Info: Starting main packet processing loop...done\n");

    /*
     * Register start time of main packet processing loop
     */
    gettimeofday(&loop_start, NULL);

    /*
     * Run the hra_main_loop() function on all configured threads, and wait for each loop to return.
     * It is run on the master thread as a separate function call in order to check the return code.
     */
    printf("Info: Beginning to launch the HRA main processing loop...done\n");

    /* Get queue/core mapping, i.e. what core will each queue thread execute on. */
    unsigned *queue_core = calloc(num_queues, sizeof(queue_core[0]));
    hra_get_queue_core_map(rxp_port_id, queue_core, num_queues);

    for (i = 1; i < num_queues; i++)
    {
        queues[i].id = i;
        queues[i].core = queue_core[i];
        queues[i].active = true;
        queues[i].resp_buf_size = resp_buf_size;
        queues[i].resp_buf = malloc(queues[i].resp_buf_size);
        sem_init(&queues[i].start_sem, 0, 1);
        ret = hra_thread_create(&queues[i].tid, hra_main_loop, &queues[i], queues[i].core);
        if (ret != 0)
        {
            printf("Error: Failed to start processing thread %d, error %d (%s)\n",
                   i, ret, strerror(ret));
        }
    }

    free(queue_core);

    /*
     * If incremental_update_delay is non-zero then start a processing loop which will perform the
     * incremental update after the specified number of seconds. The Master thread and queue 0 are
     * used to perform the update. It is vital that the incremental update is performed on a queue
     * with is not being used to scan jobs.
     */
    if (incremental_update_delay)
    {
        hra_incremental_rtru_loop(&rxp_port_id);
    }
    else
    {
        queues[0].id = 0;
        queues[0].core = 0;
        queues[0].active = true;
        queues[0].resp_buf_size = resp_buf_size;
        queues[0].resp_buf = malloc(queues[0].resp_buf_size);
        sem_init(&queues[0].start_sem, 0, 1);

        hra_set_thread_affinity(queues[0].core);
        hra_main_loop(&queues[0]);
    }

    if (queues[0].status < 0)
    {
        printf("Error: Master thread returned with an error %d\n", queues[0].status);
        ret = queues[0].status;
    }
    else
    {
        ret = 0;
    }

    for (i = 1; i < num_queues; i++)
    {
        ret = hra_thread_join(&queues[i].tid, queues[i].core, NULL);
        if (ret != 0)
        {
            printf("Error: Failed to join thread %d, error %d\n", i, ret);
            ret = HRA_STATUS_FAIL;
        }
        else if (queues[i].status != 0)
        {
            printf("Error: thread %d returned with an error %d\n", i, queues[i].status);
            ret = HRA_STATUS_FAIL;
        }
    }

    /*
     * Register the time when the main loop is complete and find the time taken.
     */
    gettimeofday(&loop_end, NULL);
    timersub(&loop_end, &loop_start, &loop_time_taken);
    test_duration = (double)loop_time_taken.tv_sec + (double)(loop_time_taken.tv_usec)/1000000;

    printf("Info: Finished main processing loop - duration %.3fs\n", test_duration);

    /*
     * Print the statistics as gathered by the HRA application.
     */
    hra_display_application_stats();

    if (rxp_periodic_cluster)
    {
        hra_display_cluster_stats(1);
    }

    /*
     * Read RXP stats and display them.
     */
    hra_display_rxp_stats(rxp_port_id, test_duration);

    /*
     * If logging is enabled then dump the logs to file.
     */
    if (hra_debug_level >= DEBUG_MODE_ENHANCED)
    {
        printf("Info: Beginning to dump log files...done\n");
        if (HRA_STATUS_OK != hra_log_files_dump())
        {
            printf("Error: Dumping log files...failed\n");
        }
    }

    /*
     * Make a thread error highly visible after statistics have been printed
     */
    if (ret == HRA_STATUS_MAIN_LOOP_STALLED)
    {
        printf("Error: Packet processing exited early due to stall on responses\n");
    }
    else if (ret == HRA_STATUS_MAIN_LOOP_EXITED_BY_SIGNAL)
    {
        printf("Info: Packet processing exited due to Ctrl-C\n");
    }

    if (job_timeouts_detected)
    {
        printf("Warning: There were %" PRIu64 " timed out jobs for which a response was not received\n",
            job_timeouts_detected);
    }


cleanup:

    if (hra_debug_level >= DEBUG_MODE_ENHANCED)
    {
        /* Free the log files */
        hra_log_files_free();
    }

    /*
     * Free the jobset memory.
     */
    hra_jobset_free_table(&hra_job_table);

    /*
     * Free the queue context structures
     */
    if (queues)
    {
        for (i = 0; i < num_queues; i++)
        {
            if (queues[i].resp_buf)
            {
                free(queues[i].resp_buf);
            }
        }
        free(queues);
    }

    rxp_platform_uninit(rxp_port_id);

    return (ret);
}

/**
 * Print a banner which includes information about the version of the program.
 */
static void
hra_print_banner(void)
{
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("Host Reference Application - validates RXP behavior and performance\n");
    /*
     * If we're not building from a repo, just display the 'version'.
     * Otherwise, display additional build data that has been derived from git.
     */
    if (strlen(scm_revision) == 0)
    {
        printf("Version '%s'\n", RXP_API_VERSION);
    }
    else
    {
        printf("Version '%s' Revision '%s' Tag '%s'\n",
                RXP_API_VERSION, scm_revision, scm_tag);
        printf("Built on '%s' at '%s' from branch '%s'\n",
                build_hostname, build_time, scm_branch);
    }
    printf("Copyright (C) 2014-2019 Titan IC Systems Ltd. All rights reserved.\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("\n");
}

/*
 * Display application usage.
 */
static void
hra_usage(const char *prgname)
{
    printf("\n%s -p RXP_PORT -c CORE_COUNT -f ROF_FILENAME -j JOBSET_DIR\n"
           "     [-i ITERATIONS -m MODE -d DEBUG -s -S -u UPDATE_TIME -U UPDATE_FILENAME -e -t SCAN_TIME]\n"
           "  -p RXP_PORT       : ID of port used to communicate with RXP (default is 0)\n"
           "  -c CORE_COUNT     : Number of RXP queues to use.  Each queue is serviced by a CPU core\n"
           "  -f ROF_FILENAME   : ROF filename including path\n"
           "  -j JOBSET_DIR     : Jobset Directory Name\n"
           "  -i ITERATIONS     : Number of iterations of the jobset to scan (default is 0 which\n"
           "                      causes continuous transmission)\n"
           "  -m MODE           : 0 JAR table and score table enabled\n"
           "                      1 JAR table enabled and score table disabled\n"
           "                      2 JAR table disabled and score table enabled\n"
           "                      3 JAR table disabled and score table disabled\n"
           "  -d DEBUG          : 0 Normal level of debug\n"
           "                      1 Display queue stats\n"
           "                      2 Display queue stats and create log file\n"
           "                      3 Display queue stats and create log file but do not truncate log files.\n"
           "                        (Beware, files may be very large and throughput degraded.\n"
           "  -s                : Read RXP cluster stats and exit\n"
           "  -S                : Read RXP cluster stats periodically and display on screen\n"
           "  -u UPDATE_TIME    : Perform incremental rules update after UPDATE_TIME s (default is\n"
           "                      0 which causes an update immediately after initial rules\n"
           "                      programming\n"
           "  -U UPDATE_FILENAME: ROFI file to use for incremental rules update\n"
           "  -e                : Print extended statistics\n"
           "  -t SCAN_TIME      : Time period to scan jobs\n"
           "  -X MAX_PREFIXES   : Set max prefixes value\n"
           "  -H MAX_MATCHES    : Set max matches value\n"
           "  -Y MAX_LATENCY    : Set max latency value\n"
           "  -D MAX_PRI_THREADS: Set max primary threads value\n"
           "  -B JOB_BATCH_SIZE        : Set job batch size (%d to %d).\n"
           "  -b JOB_BATCH_BYTES_THRESH: Set job batch bytes threshold.\n"
           "  -r RESPONSE_BUFFER_SIZE  : Set response buffer size (default %zu, min %zu).\n"
           "  -F FIRST_JOB_ID   : First job to process (1 to num jobs in jobdir)\n"
           "  -L LAST_JOB_ID    : Last job to process (1 to num jobs in jobdir)\n"
           "  -h                  Display this help text and exit\n"
           "\n"
           " e.g.\n"
           "    %s -p 0 -c 4 -f synthetic.rof -j synthetic -i 100\n",
           prgname, RXP_TX_BURST_MIN, RXP_TX_BURST_MAX, RXP_RESP_BUF_SIZE_DEFAULT,
           RXP_RESP_BUF_SIZE_MIN, prgname);
}

/*
 * Parse the argument given in the command line of the application
 */
static int
hra_parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    char *prgname = argv[0];
    char *endptr;

    argvopt = argv;

    while ((opt = getopt(argc, argvopt, "c:p:i:f:j:m:d:sSu:U:et:X:H:Y:D:B:b:r:F:L:h")) != EOF)
    {
        errno = 0;

        switch (opt)
        {
            case 'c':
                num_queues = strtol(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(num_queues, optarg, endptr))
                {
                    printf("Error: Invalid thread count [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;
            /* RXP port ID */
            case 'p':
                rxp_port_id = strtol(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(rxp_port_id, optarg, endptr))
                {
                    printf("Error: Invalid port ID [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }

                if (rxp_port_id > UINT8_MAX)
                {
                    printf("Error: Port ID [%ld] must be less than %d\n", rxp_port_id, UINT16_MAX);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }

                break;

            /* Number of iterations of jobset to scan */
            case 'i':
                max_jobset_iterations = (int64_t)strtol(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(max_jobset_iterations, optarg, endptr))
                {
                    printf("Error: Invalid jobset iterations [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* ROF filename name including path to the file */
            case 'f':
                rof_file_name = optarg;
                break;

            /* Jobset directory name */
            case 'j':
                jobset_dir = optarg;
                break;

            /* Mode */
            case 'm':
                mode = strtol(optarg, &endptr, 0);
                if ((INVALID_STRTOL_CONVERSION(mode, optarg, endptr)) ||
                    (mode > 3))
                {
                    printf("Error: Invalid mode [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }

                if (mode > 3)
                {
                    printf("Error: Mode [%ld] must be 0 or 3\n", mode);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }

                if( mode == 0 || mode == 1 )
                {
                    jar_table_enabled = 1;
                }
                else
                {
                    jar_table_enabled = 0;
                }

                if( mode == 0 || mode == 2 )
                {
                    score_table_enabled = 1;
                }
                else
                {
                    score_table_enabled = 0;
                }
                break;

            /* Debug level */
            case 'd':
                hra_debug_level = strtol(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(hra_debug_level, optarg, endptr))
                {
                    printf("Error: Invalid debug level [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }

                if (hra_debug_level > DEBUG_MODE_ENHANCED_NO_TRUNCATE)
                {
                    printf("Error: Debug level [%ld] must be less than %d\n",
                        hra_debug_level, DEBUG_MODE_ENHANCED_NO_TRUNCATE);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* Read stats from RXP and exit*/
            case 's':
                rxp_read_cluster_values = 1;
                break;

            /* Read stat values periodically */
            case 'S':
                rxp_periodic_cluster = 1;
                break;

            /* Delay before applying incremental update */
            case 'u':
                incremental_update_delay = strtol(optarg, &endptr, 0);
                if ((INVALID_STRTOL_CONVERSION(incremental_update_delay, optarg, endptr)) ||
                    (mode > 1))
                {
                    printf("Error: Invalid incremental_update_delay period [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* ROF filename name including path to the file */
            case 'U':
                incremental_update_file_cnt++;
                if (incremental_update_file_cnt == 1)
                {
                    incremental_update_file_name = calloc(incremental_update_file_cnt, sizeof(char *));
                }
                else
                {
                    incremental_update_file_name = realloc(incremental_update_file_name, sizeof(char *) * incremental_update_file_cnt);
                }
                if (!incremental_update_file_name)
                {
                    printf("Error: incremental_update_file_name allocation failure\n");
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                incremental_update_file_name[incremental_update_file_cnt - 1] = optarg;
                break;

            /* Enable extended statistics- i.e. statistics gathered from responses. */
            case 'e':
                extended_stats_enabled = 1;
                break;

            /* Time to scan jobs */
            case 't':
                iteration_timer_secs = strtoul(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(iteration_timer_secs, optarg, endptr))
                {
                    printf("Error: Invalid scan time [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* Program max_prefixes. */
            case 'X':
                max_prefixes = strtoul(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(max_prefixes, optarg, endptr))
                {
                    printf("Error: Invalid max prefix [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* Program max_matches. */
            case 'H':
                max_matches = strtoul(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(max_matches, optarg, endptr))
                {
                    printf("Error: Invalid max match [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* Program max_latency. */
            case 'Y':
                max_latency = strtoul(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(max_latency, optarg, endptr))
                {
                    printf("Error: Invalid max latency [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* Program max_pri_threads. */
            case 'D':
                max_pri_threads = strtoul(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(max_pri_threads, optarg, endptr))
                {
                    printf("Error: Invalid max primary threads [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* Program job_batch_size. */
            case 'B':
                job_batch_size = strtoul(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(max_pri_threads, optarg, endptr) ||
                   job_batch_size < RXP_TX_BURST_MIN ||
                   job_batch_size > RXP_TX_BURST_MAX)
                {
                    printf("Error: Invalid job_batch_size [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* Program job_batch_bytes_threshold. */
            case 'b':
                job_batch_bytes_threshold = strtoul(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(max_pri_threads, optarg, endptr))
                {
                    printf("Error: Invalid job_batch_bytes_threshold [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* Program resp_buf_size. */
            case 'r':
                resp_buf_size = strtoul(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(resp_buf_size, optarg, endptr) ||
                    (resp_buf_size < RXP_RESP_BUF_SIZE_MIN))
                {
                    printf("Error: Invalid resp_buf_size [%s]\n", optarg);
                    printf("Must be at least %zu bytes, i.e. big enough " \
                           "for a response with all matches populated\n",
                           RXP_RESP_BUF_SIZE_MIN);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* Program first_job_id. */
            case 'F':
                first_job_id = strtoul(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(first_job_id, optarg, endptr))
                {
                    printf("Error: Invalid first job id [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;

            /* Program last_job_id. */
            case 'L':
                last_job_id = strtoul(optarg, &endptr, 0);
                if (INVALID_STRTOL_CONVERSION(last_job_id, optarg, endptr))
                {
                    printf("Error: Invalid last job id [%s]\n", optarg);
                    hra_usage(prgname);
                    return (HRA_STATUS_FAIL);
                }
                break;



            case 'h':
                hra_usage(prgname);
                exit(0);
                break;

            default:
                hra_usage(prgname);
                return (HRA_STATUS_FAIL);
        }
    }

    if (optind < argc)
    {
        while (optind < argc)
        {
            printf("Error: Invalid option: [%s]\n", argv[optind++]);
        }
        hra_usage(prgname);
        return (HRA_STATUS_FAIL);
    }

    /*
     * Check to make sure rof_file_name & jobset_dir have been passed values
     * unless we only want to read the RXP stats.
     */
    if (!rxp_read_cluster_values)
    {
        if ((rof_file_name == NULL) || (jobset_dir == NULL))
        {
            printf("Error: Please specify ROF filename and jobset directory\n");
            hra_usage(prgname);
            return (HRA_STATUS_FAIL);
        }
    }

    /*
     * If an incremental rule supdate period is specified then an incremental rules file must also be specified.
     */
    if (incremental_update_delay && (incremental_update_file_name == NULL))
    {
        printf("Error: Please specify ROFI filename for incremental update\n");
        hra_usage(prgname);
        return (HRA_STATUS_FAIL);
    }

    if (optind >= 0)
    {
        argv[optind-1] = prgname;
    }

    ret = optind-1;
    optind = 0; /* reset getopt lib */

    return (ret);
}

/**********************************************************************************************************************/
/*                       FUNCTIONS USED FOR MAIN LOOP PACKET PROCESSING                                               */
/**********************************************************************************************************************/

/*
 * This is the main processing loop. The code runs in a continuous loop
 * performing these steps.
 *  - Attempts to add a job to the transmit table- this can only be done if there are sufficient free entries in the
 *    JAR table. If the number of jobs in the transmit table has reached a threshold then the buffer is flushed.
 *  - Once every drain ticks, any packets in the transmit table are sent. This ensures that packets do not spend
 *    an excessive period in the
 *  - Once every stats_timer_period the queue statistics are sent- this is only performed by the main thread.
 *  - Packets are read from the receive queue. The matches are validated against the expected matches, and the
 *    job buffers are freed.
 *  - The tail of the JAR table is checked. The tail contains the oldest entry. If the entry has been in the JAR table
 *    for longer that a certain period, then the job/response is considered lost. The job may be retransmitted up to
 *    a maximum number of attempts. After the maximum number of attempts the job is considered lost and no further
 *    attempts are made.
 */
static void *
hra_main_loop(void *thread_data)
{
    uint64_t prev_ticks, diff_ticks, cur_ticks, timer_ticks, timeout_ticks;
    const uint64_t drain_ticks = (hra_ticks_per_sec() + NS_PER_SEC - 1) /
                                NS_PER_SEC * BURST_TX_DRAIN_NS;
    uint64_t timeout_period_ticks = hra_ticks_per_sec() * 5;
    uint64_t iteration_timer_ticks = 0;

    uint64_t stats_timer_period = stats_timer_secs * hra_ticks_per_sec() ; /* default period is 10 seconds */
    uint64_t iteration_timer_period = iteration_timer_secs * hra_ticks_per_sec(); /* default period is 0 seconds */

    int next_job_id;
    rxp_jar_table_t *jar_table;
    struct hra_job *job;
    int64_t jobset_iterations = 0;
    uint64_t responses_and_timeouts = 0;
    uint64_t max_responses_and_timeouts;
    int ret = HRA_STATUS_OK;
    uint64_t prev_rx_pkts = 0;
    uint64_t iteration_timeout = 0;
    struct rxp_job_batch *ctx;
    struct queue_ctx *queue = thread_data;
    bool tx_ready;
    bool do_restart;

    prev_ticks = hra_ticks_read();
    timer_ticks = 0;
    timeout_ticks = 0;

    /*
     * Each queue processes a 1/num_queues slice of the jobset. Do this by using our queue id as an
     * offset into the job table, then each time incrementing job_id by num_queues.
     * See also function hra_transmit().
     */
    queue->first_job_id = first_job_id + queue->id;
    queue->last_job_id  = last_job_id;
    queue->num_jobs     = (last_job_id - first_job_id + 1) / num_queues;

    next_job_id = queue->first_job_id;
    max_responses_and_timeouts = queue->num_jobs * max_jobset_iterations;

    fflush(stdout);

    /*
     * Initialize JAR table which is used to keep track of jobs until a response is received.
     */
    jar_table = rxp_jar_table_init(queue->id);

    ctx = rxp_job_batch_alloc(job_batch_size, job_batch_bytes_threshold);
    if (!ctx)
    {
        printf("Error: job_batch_alloc fail\n");
        exit(HRA_STATUS_FAIL);
    }

    printf("Info: Entering main loop on queue %u, thread_id = %lu, core %d\n",
        queue->id, queue->tid, queue->core);

restart:
    do_restart = false;

    /* Wait for permission to open the queue and start sending jobs. */
    sem_wait(&queue->start_sem);

    queue->handle = rxp_open(rxp_port_id);
    if (queue->handle < 0)
    {
        printf("Error: Failed to open RXP queue %d, error %d (%s)\n",
            queue->id, errno, strerror(errno));
        exit(HRA_STATUS_FAIL);
    }
    queue->active = true;

    printf("Info: Starting job processing on queue %u\n", queue->id);
    while (process_packets)
    {
        cur_ticks = hra_ticks_read();

        /*
         * Check if the maximum number of packets to transmit has been transmitted and responses have been
         * received for all packets, or if the scan timeout has been exceeded. If so then exit the loop.
         */
        if (((max_jobset_iterations != 0) || (iteration_timeout)) &&
            (responses_and_timeouts >= max_responses_and_timeouts))
        {
            break;
        }

        /*
         * Transmit a job if possible
         */
        hra_transmit(queue, ctx, &next_job_id, &jobset_iterations, jar_table, iteration_timeout);

        /*
         * Every drain_ticks number of ticks this loop is entered.
         * If there are any packets in the tx queue they will be transmitted.
         * This ensures that packets never spend an excessive time in the
         * queue when the transmit packet rate is low.
         */
        diff_ticks = cur_ticks - prev_ticks;
        if (diff_ticks > drain_ticks)
        {
            /*
             * If there are any packets in the transmit queue send
             * them now.
             */
            if (ctx->count > 0)
            {
                ret = rxp_dispatch_jobs(queue->handle, ctx);
                if ((ret < 0) && (ret != -EBUSY))
                {
                    printf("Error: Fatal error dispatching jobs (%d)\n", ret);
                    exit(HRA_STATUS_FAIL);
                }
                if (ret == -EBUSY || ctx->count != 0)
                {
                    /* Wasn't able to push all jobs to RXP. */
                    queue->statistics.tx_busy++;
                }
            }

            /*
             * Exit out of the loop if no packets have been received within a specified time
             */
            timeout_ticks += diff_ticks;
            if (timeout_ticks >= timeout_period_ticks)
            {
                if (prev_rx_pkts == queue->statistics.rx_pkts)
                {
                    printf("Error: No further packets received - exiting loop\n");
                    queue->active = false;
                    queue->status = HRA_STATUS_MAIN_LOOP_STALLED;
                    return NULL;
                }
                prev_rx_pkts = queue->statistics.rx_pkts;
                timeout_ticks = 0;
            }

            /*
             * If the stats timer is enabled, then check the time since the
             * last statistics were printed. If this exceeds the stats timer
             * period then print the stats.
             */
            if (stats_timer_secs > 0)
            {
                 /* advance the timer */
                timer_ticks += diff_ticks;

                /* if timer has reached its timeout */
                if (timer_ticks >= stats_timer_period)
                {
                    /* do this only on master core */
                    if (queue->id == 0)
                    {
                        hra_display_application_stats();

                        if (rxp_periodic_cluster)
                        {
                            hra_display_cluster_stats(0);
                        }

                        /* reset the timer */
                        timer_ticks = 0;
                    }
                }
            }

            if (iteration_timer_secs > 0)
            {
                /* advance the timer */
                iteration_timer_ticks += diff_ticks;

                /* if timer has reached its timeout */
                if (iteration_timer_ticks >= (uint64_t) iteration_timer_period)
                {
                    max_responses_and_timeouts = queue->statistics.jobs_scanned;
                    iteration_timeout = 1;
                    iteration_timer_ticks = 0;
                }
            }

            prev_ticks = cur_ticks;
        }

        /*
         * Receive any responses from the queue and validate the responses against the entries in the JAR table.
         */
        hra_receive(queue, jar_table, &responses_and_timeouts);

        /*
         * Check the tail entry in the JAR table. If it has timed out then retransmit the job unless the maximum
         * number of attempts has already been made to transmit the job.
         * Only check the tail of the JAR table if there is space in the tx batch to add a new entry i.e. if
         * it is possible to enqueue the packet again if needs be.
         */
        if ((jar_table_enabled) && (ctx->count < ctx->max_jobs))
        {
            if (0 > rxp_queue_status(queue->handle, NULL, &tx_ready))
            {
                printf("Error: Checking TX queue status failed\n");
                exit(HRA_STATUS_FAIL);
            }

            if (tx_ready)
            {
                enum rxp_jar_table_timeout_status timeout_status;
                uint32_t job_id;
                rxp_jar_table_check_timeout(jar_table, (void**)&job, HRA_MAX_TIMEOUTS, &job_id, &timeout_status);
                if (timeout_status == HRA_JAR_TABLE_TIMEOUT_AND_REENQUEUED)
                {
                    if (ctx->count < ctx->max_jobs)
                    {
                        ret = rxp_scan_job(queue->handle, ctx, job_id, job->job_data,
                            job->job_length,
                            job->subset_ids[0], job->subset_ids[1],
                            job->subset_ids[2], job->subset_ids[3],
                            (job->ctrl & RXP_CTRL_JOB_DESC_HPM_ENABLE),
                            (job->ctrl & RXP_CTRL_JOB_DESC_ANYMATCH_ENABLE));
                        if ((ret < 0) && (ret != -EBUSY))
                        {
                            printf("Error: Failed to scan job\n");
                            exit(HRA_STATUS_FAIL);
                        }
                        queue->statistics.job_retransmits++;
                    }
                }
                else if (timeout_status == HRA_JAR_TABLE_FINAL_TIMEOUT)
                {
                    /*
                     * If a job times out then all the expected matches should have a score of 0.
                     * The job is passed to hra_check_response() with response data containing 0 matches.
                     * The rxp_jar_table_check_timeout() function does not currently return the tag which
                     * is used to hold the iteration number. Thus a value of -1 is used.
                     */
                    struct rxp_response resp_data;
                    queue->statistics.job_timeouts++;
                    responses_and_timeouts++;
                    resp_data.header.match_count = 0;
                    if (score_table_enabled)
                    {
                        hra_check_response(queue, &resp_data, job, job_id, -1);
                    }
                }
            }
        }


        /* If there's an incremental update request, we'll break from the loop. */
        if (quiesce_queues)
        {
            printf("Info: Quiesce job processing on queue %u.\n", queue->id);
            do_restart = true;
            break;
        }
    } /* while (process_packets) */

    /* Flush any outstanding responses. */
    usleep(50000);
    printf("Info: Flushing rx queue %d\n", queue->id);
    while (hra_receive(queue, jar_table, &responses_and_timeouts))
    {
        usleep(50000);
    }

    /* Close the queue and mark it as inactive. */
    rxp_close(queue->handle);
    queue->active = false;

    if (process_packets == 0)
    {
        /* CTRL-C exit. */
        queue->status = HRA_STATUS_MAIN_LOOP_EXITED_BY_SIGNAL;
    }
    else if (do_restart)
    {
        /*
         * We exited the job processing loop to allow an incremental rules update.
         * Jump back to restart job processing.
         */
        goto restart;
    }
    else
    {
        queue->status = 0;
    }

    free(jar_table);
    rxp_job_batch_free(ctx);

    return NULL;
}

/*
 * Function enqueues a job for transmission if there are sufficient resources available, and dispatches a burst of
 * jobs if sufficient jobs have been enqueued.
 */
static void
hra_transmit(struct queue_ctx *queue,
             struct rxp_job_batch *ctx,
             int *job_id,
             int64_t *jobset_iterations,
             rxp_jar_table_t *jar_table,
             uint64_t iteration_timeout)
{
    uint32_t rxp_job_id;
    struct hra_job *job;
    int ret;
    unsigned i;
    bool tx_ready;

    if (0 > rxp_queue_status(queue->handle, NULL, &tx_ready))
    {
        printf("Error: Checking TX queue status failed\n");
        exit(HRA_STATUS_FAIL);
    }

    /*
     * Transmit multiple packets if possible. This improves performance with small packets.
     */
    for (i = 0; i < ctx->max_jobs; i++)
    {
        /*
         * If max_jobset_iterations is non-0 then the system will stop enqueuing jobs when the jobs in the jobset have
         * been enqueued max_jobset_iterations times.
         */
        if (tx_ready && ((max_jobset_iterations == 0) || (*jobset_iterations < max_jobset_iterations)) &&
            (iteration_timeout != 1))
        {
            /* Don't try to enqueue any more packets if the transmit buffer is full */
            if (ctx->count < ctx->max_jobs)
            {
                /*
                 * Fetch a job entry from the job entry table.
                 * Note that the job_id runs from 1 to max, hence the minus 1
                 * to access the jobs array.
                 */
                job = &hra_job_table.jobs[*job_id - 1];

                /*
                 * Try to add the job entry to the jar table. If there are insufficient resources on the jar table
                 * then a rxp_job_id of 0 is returned. Else a valid rxp_job_id is returned.
                 */
                if (jar_table_enabled)
                {
                    rxp_jar_table_add_job(jar_table, job, *jobset_iterations, &rxp_job_id);
                }
                else
                {
                    rxp_job_id = *job_id;
                }

                /*
                 * If the rxp_job_id is valid then call rxp_scan_job to enqueue the job for transmission. Increment
                 * the count of enqueued packets and the job_idx.
                 */
                if (rxp_job_id != 0)
                {
                    ret = rxp_scan_job(queue->handle, ctx, rxp_job_id, job->job_data, job->job_length,
                        job->subset_ids[0], job->subset_ids[1],
                        job->subset_ids[2], job->subset_ids[3],
                        (job->ctrl & RXP_CTRL_JOB_DESC_HPM_ENABLE),
                        (job->ctrl & RXP_CTRL_JOB_DESC_ANYMATCH_ENABLE));

                    if ((ret < 0) && (ret != -EBUSY))
                    {
                        printf("Error: Failed to prepare job\n");
                        exit(HRA_STATUS_FAIL);
                    }

                    (*job_id) += num_queues;
                    queue->statistics.jobs_scanned++;
                    queue->statistics.bytes_scanned += job->job_length;
                    if (*job_id > queue->last_job_id)
                    {
                        *job_id = queue->first_job_id;
                        (*jobset_iterations)++;
                    }
                }
            }
            else if (ctx->count > 0)
            {
                ret = rxp_dispatch_jobs(queue->handle, ctx);
                if ((ret < 0) && (ret != -EBUSY))
                {
                    printf("Error: Fatal error dispatching jobs (%d)\n", ret);
                    exit(HRA_STATUS_FAIL);
                }
                if (ret == -EBUSY || ctx->count != 0)
                {
                    /* Wasn't able to push all jobs to RXP. */
                    queue->statistics.tx_busy++;
                }
                break;
            }
        }
    }
}

static void
hra_proc_response(struct queue_ctx *queue,
                  struct rxp_response *resp,
                  rxp_jar_table_t *jar_table,
                  uint64_t *responses_and_timeouts)
{
    struct hra_job *job = NULL;
    int jobset_iteration = -1;
    uint32_t user_job_id;
    uint64_t latency;

    struct rxp_response_desc *header  = &resp->header;
    struct rxp_match_tuple   *matches = &resp->matches[0];

    uint32_t job_id = header->job_id;

    queue->statistics.matches += header->detected_match_count;
    if (jar_table_enabled)
    {
        rxp_jar_table_check_response2(jar_table, job_id, (void**)&job, &jobset_iteration, &latency);
        if (NULL != job)
        {
            if (score_table_enabled)
            {
                hra_check_response(queue, resp, job, job_id, jobset_iteration);
            }

            queue->statistics.valid_responses++;
            (*responses_and_timeouts)++;

            user_job_id = job->user_job_id;

            queue->statistics.latency_total += latency;
            if (latency > queue->statistics.latency_max)
            {
                queue->statistics.latency_max = latency;
            }
            if ((latency < queue->statistics.latency_min) ||
               (queue->statistics.latency_min == 0))
            {
                queue->statistics.latency_min = latency;
            }
        }
        else
        {
            queue->statistics.invalid_responses++;
            user_job_id = 0;
        }
    }
    else
    {
        if (score_table_enabled)
        {
            job = &hra_job_table.jobs[job_id - 1];
            if (NULL != job)
            {
                hra_check_response(queue, resp, job, job_id, jobset_iteration);
            }
        }

        queue->statistics.valid_responses++;
        (*responses_and_timeouts)++;
        user_job_id = job_id;
    }

    /* Calculate byte match ratio */
    unsigned int j;
    /*Store the matched bytes to calculate the Byte match ratio*/
    for (j = 0; j < header->match_count; j++)
    {
        queue->statistics.matched_bytes += matches[j].length;
    }

    /*
     * If debugging is enabled then log all matches and responses received. These will later
     * be dumped to files.
     */
    if (hra_debug_level >= DEBUG_MODE_ENHANCED)
    {
        unsigned int j;
        for (j = 0; j < header->match_count; j++)
        {
            hra_log_debug_matches_add(queue->id,
                job_id, user_job_id,
                matches[j].rule_id,
                matches[j].start_ptr,
                matches[j].length,
                queue->id,
                jobset_iteration);
        }

        hra_log_debug_responses_add(queue->id,
                    job_id, user_job_id,
                    header->status,
                    header->match_count,
                    header->detected_match_count,
                    header->primary_thread_count,
                    header->instruction_count,
                    header->latency_count,
                    header->pmi_min_byte_ptr,
                    queue->id,
                    jobset_iteration);
    }

    /*
     * Record additional statistics based on parameters in response descriptor if parameter is set.
     */
    if (extended_stats_enabled)
    {
        queue->statistics.primary_thread_count += header->primary_thread_count;
        queue->statistics.instruction_count += header->instruction_count;

        if (header->status & RXP_RESP_STATUS_MAX_PRI_THREADS)
        {
            queue->statistics.max_pt_set++;
        }
        if (header->status & RXP_RESP_STATUS_MAX_SEC_THREADS)
        {
            queue->statistics.max_st_set++;
        }
        if (header->status & RXP_RESP_STATUS_MAX_LATENCY)
        {
            queue->statistics.max_latency_set++;
        }
        if (header->status & RXP_RESP_STATUS_MAX_MATCH)
        {
            queue->statistics.max_match_set++;
        }
        if (header->status & RXP_RESP_STATUS_MAX_PREFIX)
        {
            queue->statistics.max_prefix_set++;
        }
        if (header->status & RXP_RESP_STATUS_HPM)
        {
            queue->statistics.hpm_set++;
        }
        if (header->status & RXP_RESP_STATUS_ANYMATCH)
        {
            queue->statistics.anymatch_set++;
        }
    }
}


/*
 * Function receives responses from a queue. The JAR table is examined for the corresponding entry. The matches
 * matches are validated against the expected matches registered in the jobset.
 */
static unsigned int
hra_receive(struct queue_ctx *queue,
            rxp_jar_table_t *jar_table,
            uint64_t *responses_and_timeouts)
{
    bool rx_ready;
    unsigned num_rx_pkts = 0;
    struct rxp_response *resp;
    struct rxp_response_batch resp_ctx = {0};

    resp_ctx.buf = queue->resp_buf;
    resp_ctx.buf_size = queue->resp_buf_size;

    /*
     * Get responses from the receive queue
     */
    if (0 > rxp_queue_status(queue->handle, &rx_ready, NULL))
    {
        printf("Error: Checking RX queue status failed\n");
        exit(HRA_STATUS_FAIL);
    }

    /*
     * Validate the responses against the entries in the JAR table.
     */
    while (rx_ready)
    {
        int num_resps = rxp_read_response_batch(queue->handle, &resp_ctx);
        if (num_resps < 0)
        {
            printf("Error: Receiving response failed\n");
            exit(HRA_STATUS_FAIL);
        }
        else if (num_resps == 0)
        {
            break;
        }

        while ((resp = rxp_next_response(&resp_ctx)) != NULL)
        {
            queue->statistics.rx_pkts++;
            num_rx_pkts++;

            /* Process this response. */
            hra_proc_response(queue, resp, jar_table, responses_and_timeouts);

        } /* while (resp ...) */

        /* Check if there are more responses */
        rxp_queue_status(queue->handle, &rx_ready, NULL);

    } /* while (rx_ready) */

    return (num_rx_pkts);
}

/*
 * This function compares the matches in a response against the expected matches for the job. Each expected match is
 * compared against the received matches. The rule ID, start pointer and match length in the expected match is compared
 * against each received match.
 */
static int
hra_check_response(struct queue_ctx *queue,
                   struct rxp_response *resp_data,
                   struct hra_job *job,
                   uint32_t jar_table_job_id,
                   int jobset_iteration)
{
    int i,j;
    int exp_match_score;
    int previous_exp_match_score;
    int response_score = HRA_NO_MATCHES;
    int match_count = resp_data->header.match_count;
    struct hra_expected_match *match_used[RXP_MAX_MATCHES];
    int match_score[RXP_MAX_MATCHES];
    int match_used_index;
    int log_all_matches = 0;
    bool job_aborted = (resp_data->header.status & RXP_RESP_STATUS_MAX_PRI_THREADS) ||
                       (resp_data->header.status & RXP_RESP_STATUS_MAX_SEC_THREADS) ||
                       (resp_data->header.status & RXP_RESP_STATUS_MAX_LATENCY) ||
                       (resp_data->header.status & RXP_RESP_STATUS_MAX_MATCH) ||
                       (resp_data->header.status & RXP_RESP_STATUS_MAX_PREFIX);
    bool anymatch_termination = resp_data->header.status & RXP_RESP_STATUS_ANYMATCH;
    struct match_stats *ms;

    /* Point to either 'normal' or 'aborted' match stats structure. */
    if (job_aborted)
    {
        ms = &queue->statistics.ms_aborted;
        queue->statistics.jobs_aborted++;
    }
    else
    {
        ms = &queue->statistics.ms_normal;
    }

    /*
     * It is more efficient to only zero the entries in these arrays that will be used, than
     * to initialize the entire array, when there are a small number of matches.
     */
    memset(match_used, 0, match_count * sizeof(struct hra_expected_match *));
    memset(match_score, 0, match_count * sizeof(int));

    /*
     * Iterate through all the expected matches.
     */
    for (i = 0; i < job->num_exp_matches; i++)
    {
        response_score = 7;
        exp_match_score = 0;
        match_used_index = -1;
        previous_exp_match_score = -1;
        /*
         * Iterate through all the received matches.
         */
        for (j = 0; j < match_count; j++)
        {
            /*
             * If this match has already been assigned a score 7 for another expected match then
             * continue to process the next received match.
             */
            if (match_score[j] == 7)
            {
                continue;
            }

            /*
             * Award points based on whether the rule id, start pointer and length in the expected match and
             * received match are equal.
             */
            if (job->exp_matches[i].rxp_rule_id == resp_data->matches[j].rule_id)
            {
                int current_score = 4;

                /*
                 * If this match has scored between 1 and 6 for a previous expected match it may still
                 * score higher for this expected match so we need to reconsider it. This behaviour
                 * only occurs if the list of matches was truncated due to something like exceeding the
                 * MAX_MATCH_COUNT threshold.
                 */
                if (match_score[j] > 0)
                {
                    previous_exp_match_score = match_score[j];
                }

                if (job->exp_matches[i].start_ptr == resp_data->matches[j].start_ptr)
                {
                    current_score += 2;
                    if (job->exp_matches[i].length == resp_data->matches[j].length)
                    {
                        current_score += 1;
                    }
                }

                /*
                 * The highest score is taken for each expected match.
                 */
                if (current_score > exp_match_score)
                {
                    /*
                     * The current score should be used only in the following circumstances:
                     *   1. If this match has not already been used for an expected match.
                     *   2. If it has already been used but scores higher for this expected match.
                     */
                    if((previous_exp_match_score == -1) ||
                       (previous_exp_match_score > -1 &&
                       current_score > previous_exp_match_score))
                    {
                        exp_match_score = current_score;
                        match_used_index = j;
                    }
                    /*
                     * If the previous score is not used then it needs reset for the next actual match
                     */
                    else
                    {
                        previous_exp_match_score = -1;
                    }
                }

                /*
                 * No need for further inspection if the score is 7.
                 */
                if (current_score == 7)
                {
                    break;
                }
            }
        }
        /*
         * Increment the queue_statistics. Every expected match gets a score.
         * If this match is being used and was previously used for another expected match then
         * the score table is adjusted accordingly.
         */
        if(previous_exp_match_score > -1 &&
           exp_match_score > previous_exp_match_score)
        {
            ms->score[exp_match_score]++;
            ms->score[previous_exp_match_score]--;
            ms->score[0]++;
        }
        else
        {
            ms->score[exp_match_score]++;
        }

        /*
         * Eliminate the highest scoring received match from further inspection. If all matches are score 0, then none
         * are removed.
         */
        if (match_used_index >= 0)
        {
            /*
             * Update match_used[] array,
             * i.e. which actual match is the expected match associated with.
             */

            /*
             * If the match was previously associated with a different expected match,
             * then that expected match is about to loose its association.
             * Log it to match discrepencies with a score of zero.
             */
            if (match_used[match_used_index] != NULL && hra_debug_level >= DEBUG_MODE_ENHANCED)
            {
                struct hra_expected_match *exp = match_used[match_used_index];
                hra_log_match_discrepancies_add(queue->id,
                    HRA_MATCH_EXPECTED_ONLY, jar_table_job_id, job->user_job_id,
                    exp->rxp_rule_id,
                    exp->start_ptr,
                    exp->length,
                    job->user_job_id,
                    0xffffffff,
                    0xffffffff,
                    0xffffffff,
                    0, queue->id, jobset_iteration, false, false, false,
                    resp_data->header.status);
            }

            match_used[match_used_index] = &(job->exp_matches[i]);
            match_score[match_used_index] = exp_match_score;
        }

        /*
         * The response score is the lowest score amongst all the expected match scores.
         */
        if (exp_match_score < response_score)
        {
            response_score = exp_match_score;
        }

        /*
         * If logging is enabled then log any expected matches which receive a score 0. Also enable logging of all
         * matches and expected matches for this response. If the score is less than 7 but greater than 0, then
         * enable logging of all matches and expected matches.
         */
        if (hra_debug_level >= DEBUG_MODE_ENHANCED)
        {
            if (exp_match_score == 0)
            {
                hra_log_match_discrepancies_add(queue->id,
                    HRA_MATCH_EXPECTED_ONLY, jar_table_job_id, job->user_job_id,
                    job->exp_matches[i].rxp_rule_id,
                    job->exp_matches[i].start_ptr,
                    job->exp_matches[i].length,
                    job->user_job_id,
                    0xffffffff,
                    0xffffffff,
                    0xffffffff,
                    exp_match_score, queue->id, jobset_iteration, false, false, false,
                    resp_data->header.status);

                log_all_matches = 1;
            }
            else if (exp_match_score < 7)
            {
                log_all_matches = 1;
            }
        }

        /*
         * Special case processing for an 'anymatch termination' response.
         *
         * For a response that has the 'anymatch termination' flag set,
         * it is expected that there will be a single match populated
         * in the response.
         *
         * If that single match is paired with an expected match:
         * (i) the appropriate score will be assigned to that expected match.
         * (ii) the other expected matches will not be assigned a score.
         *
         * If the match is not paired with an expected match, all the expected
         * matches will be assigned a score zero by the normal execution
         * of the exp for loop.
         */
        if (match_used_index >= 0 && anymatch_termination)
        {
            /*
             * We made a match in the current iteration of the exp for loop.
             * The score will have been calculated and assigned above.
             * Any score zeros that would have been logged
             * in previous iterations of the exp for loop are now decremented.
             */
            ms->score[0] -= i;

            /* Break out of the exp loop. */
            break;
        }

    } /* for (i = 0; i < job->num_exp_matches; i++) */

    for (i = 0; i < match_count; i++)
    {
        if (match_score[i] == 0)
        {
            ms->false_positives++;
            log_all_matches = 1;
        }
    }

    /*
     * If logging is enabled then log the responses and matches. The logs have a finite size. When the logs fill
     * no further responses or matches will be logged.
     */
    if (hra_debug_level >= DEBUG_MODE_ENHANCED)
    {
        if ((job->num_exp_matches != match_count) || log_all_matches)
        {
            for (i = 0; i < match_count; i++)
            {
                if (match_used[i])
                {
                    hra_log_match_discrepancies_add(queue->id,
                        HRA_MATCH_EXPECTED_AND_ACTUAL, jar_table_job_id, job->user_job_id,
                        (match_used[i])->rxp_rule_id,
                        (match_used[i])->start_ptr,
                        (match_used[i])->length,
                        job->user_job_id,
                        resp_data->matches[i].rule_id,
                        resp_data->matches[i].start_ptr,
                        resp_data->matches[i].length,
                        match_score[i], queue->id, jobset_iteration, false, false, false,
                        resp_data->header.status);
                }
                else
                {
                   hra_log_match_discrepancies_add(queue->id,
                        HRA_MATCH_ACTUAL_ONLY, jar_table_job_id, job->user_job_id,
                        0xffffffff,
                        0xffff,
                        0xffff,
                        job->user_job_id,
                        resp_data->matches[i].rule_id,
                        resp_data->matches[i].start_ptr,
                        resp_data->matches[i].length,
                        match_score[i], queue->id, jobset_iteration, false, false, false,
                        resp_data->header.status);
                }
            }
        }
    }

    return (response_score);
}

/*
 * Function prints statistics which have been gathered by the application. Per queue and aggregate statistics
 * are both printed.
 */
static void
hra_display_application_stats(void)
{
    uint64_t total_tx_busy = 0;
    uint64_t total_jobs_scanned = 0;
    uint64_t total_bytes_scanned = 0;
    uint64_t total_matches = 0;
    uint64_t total_rx_pkts = 0;
    uint64_t total_valid_responses = 0;
    uint64_t total_invalid_responses = 0;
    uint64_t total_job_timeouts = 0;
    uint64_t total_job_retransmits = 0;
    uint64_t total_score_normal[8] = { 0 };
    uint64_t total_false_positives_normal = 0;
    uint64_t total_score_aborted[8] = { 0 };
    uint64_t total_false_positives_aborted = 0;
    uint64_t total_jobs_aborted = 0;
    uint64_t total_primary_thread_count = 0;
    uint64_t total_instruction_count = 0;
    uint64_t total_max_pt_set = 0;
    uint64_t total_max_st_set = 0;
    uint64_t total_max_latency_set = 0;
    uint64_t total_max_match_set = 0;
    uint64_t total_max_prefix_set = 0;
    uint64_t total_hpm_set = 0;
    uint64_t total_anymatch_set = 0;
    unsigned queue_id;
    const char clr[] = { 27, '[', '2', 'J', '\0' };
    const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

    /*
     * Using this blank array along with memcmp as a succinct way to check if
     * any scores are set in an array.
     */
    const uint64_t bunch_of_zeros[8] = { 0 };

    /* Clear screen and move to top left */
    printf("%s%s", clr, topLeft);

    printf("\nInfo: HRA statistics ==================================================================");

    for (queue_id = 0; queue_id < num_queues; queue_id++)
    {
        printf("\nInfo: Statistics for queue %u ----------------------------------------------------------"
               "\nInfo: Jobs scanned      : %20"PRIu64
                      " Tx busy           : %20"PRIu64
               "\nInfo: Valid responses   : %20"PRIu64
                      " Invalid responses : %20"PRIu64
               "\nInfo: Job retransmits   : %20"PRIu64
                      " Job timeouts      : %20"PRIu64
               "\nInfo: Jobs aborted      : %20"PRIu64,
               queue_id,
               queues[queue_id].statistics.jobs_scanned,
               queues[queue_id].statistics.tx_busy,
               queues[queue_id].statistics.valid_responses,
               queues[queue_id].statistics.invalid_responses,
               queues[queue_id].statistics.job_retransmits,
               queues[queue_id].statistics.job_timeouts,
               queues[queue_id].statistics.jobs_aborted);

        printf("\nInfo: Latency min (s)   : %20.6f"
                      " Latency max (s)   : %20.6f"
               "\nInfo: Latency avg (s)   : %20.6f",
               (double)queues[queue_id].statistics.latency_min / hra_ticks_per_sec(),
               (double)queues[queue_id].statistics.latency_max / hra_ticks_per_sec(),
               ((double)queues[queue_id].statistics.latency_total /
               queues[queue_id].statistics.jobs_scanned) / hra_ticks_per_sec());

        total_valid_responses += queues[queue_id].statistics.valid_responses;
        total_invalid_responses += queues[queue_id].statistics.invalid_responses;
        total_job_timeouts += queues[queue_id].statistics.job_timeouts;
        total_job_retransmits += queues[queue_id].statistics.job_retransmits;

        total_tx_busy += queues[queue_id].statistics.tx_busy;
        total_jobs_scanned += queues[queue_id].statistics.jobs_scanned;
        total_bytes_scanned += queues[queue_id].statistics.bytes_scanned;
        total_rx_pkts += queues[queue_id].statistics.rx_pkts;
        total_matches += queues[queue_id].statistics.matches;

        if (extended_stats_enabled)
        {
            printf("\nInfo: Primary threads   : %20"PRIu64
                          " Instruction count : %20"PRIu64
                   "\nInfo: HPM set           : %20"PRIu64
                   "\nInfo: AnyMatch set      : %20"PRIu64,
                   queues[queue_id].statistics.primary_thread_count,
                   queues[queue_id].statistics.instruction_count,
                   queues[queue_id].statistics.hpm_set,
                   queues[queue_id].statistics.anymatch_set);

            printf("\nInfo: Max Pri Thread set: %20"PRIu64
                          " Max Sec Thread set: %20"PRIu64
                   "\nInfo: Max Latency set   : %20"PRIu64
                          " Max Match set     : %20"PRIu64
                   "\nInfo: Max Prefix set    : %20"PRIu64,
                   queues[queue_id].statistics.max_pt_set,
                   queues[queue_id].statistics.max_st_set,
                   queues[queue_id].statistics.max_latency_set,
                   queues[queue_id].statistics.max_match_set,
                   queues[queue_id].statistics.max_prefix_set);

            total_primary_thread_count += queues[queue_id].statistics.primary_thread_count;
            total_instruction_count    += queues[queue_id].statistics.instruction_count;
            total_max_pt_set           += queues[queue_id].statistics.max_pt_set;
            total_max_st_set           += queues[queue_id].statistics.max_st_set;
            total_max_latency_set      += queues[queue_id].statistics.max_latency_set;
            total_max_match_set        += queues[queue_id].statistics.max_match_set;
            total_max_prefix_set       += queues[queue_id].statistics.max_prefix_set;
            total_hpm_set              += queues[queue_id].statistics.hpm_set;
            total_anymatch_set         += queues[queue_id].statistics.anymatch_set;
        }

        printf("\nInfo: Score_table(7:0) = {"
               "%"PRIu64 ", %"PRIu64 ", %"PRIu64 ", %"PRIu64", %" PRIu64", %" PRIu64 ", %"PRIu64 ", %"PRIu64
               "}, false_positives = %"PRIu64,
               queues[queue_id].statistics.ms_normal.score[7],
               queues[queue_id].statistics.ms_normal.score[6],
               queues[queue_id].statistics.ms_normal.score[5],
               queues[queue_id].statistics.ms_normal.score[4],
               queues[queue_id].statistics.ms_normal.score[3],
               queues[queue_id].statistics.ms_normal.score[2],
               queues[queue_id].statistics.ms_normal.score[1],
               queues[queue_id].statistics.ms_normal.score[0],
               queues[queue_id].statistics.ms_normal.false_positives);

        total_jobs_aborted += queues[queue_id].statistics.jobs_aborted;
        total_score_normal[7] += queues[queue_id].statistics.ms_normal.score[7];
        total_score_normal[6] += queues[queue_id].statistics.ms_normal.score[6];
        total_score_normal[5] += queues[queue_id].statistics.ms_normal.score[5];
        total_score_normal[4] += queues[queue_id].statistics.ms_normal.score[4];
        total_score_normal[3] += queues[queue_id].statistics.ms_normal.score[3];
        total_score_normal[2] += queues[queue_id].statistics.ms_normal.score[2];
        total_score_normal[1] += queues[queue_id].statistics.ms_normal.score[1];
        total_score_normal[0] += queues[queue_id].statistics.ms_normal.score[0];
        total_false_positives_normal += queues[queue_id].statistics.ms_normal.false_positives;

        /* Print score for aborted jobs if there were any detected. */
        BUILD_BUG_ON(sizeof(bunch_of_zeros) != sizeof(queues[queue_id].statistics.ms_aborted.score));
        if (queues[queue_id].statistics.ms_aborted.false_positives ||
            memcmp(queues[queue_id].statistics.ms_aborted.score, bunch_of_zeros,
                   sizeof(bunch_of_zeros)))
        {
            printf("\nInfo: Score_table_max(7:0) = {"
                   "%"PRIu64 ", %"PRIu64 ", %"PRIu64 ", %"PRIu64", %" PRIu64", %" PRIu64 ", %"PRIu64 ", %"PRIu64
                   "}, false_positives = %"PRIu64,
                   queues[queue_id].statistics.ms_aborted.score[7],
                   queues[queue_id].statistics.ms_aborted.score[6],
                   queues[queue_id].statistics.ms_aborted.score[5],
                   queues[queue_id].statistics.ms_aborted.score[4],
                   queues[queue_id].statistics.ms_aborted.score[3],
                   queues[queue_id].statistics.ms_aborted.score[2],
                   queues[queue_id].statistics.ms_aborted.score[1],
                   queues[queue_id].statistics.ms_aborted.score[0],
                   queues[queue_id].statistics.ms_aborted.false_positives);
            total_score_aborted[7] += queues[queue_id].statistics.ms_aborted.score[7];
            total_score_aborted[6] += queues[queue_id].statistics.ms_aborted.score[6];
            total_score_aborted[5] += queues[queue_id].statistics.ms_aborted.score[5];
            total_score_aborted[4] += queues[queue_id].statistics.ms_aborted.score[4];
            total_score_aborted[3] += queues[queue_id].statistics.ms_aborted.score[3];
            total_score_aborted[2] += queues[queue_id].statistics.ms_aborted.score[2];
            total_score_aborted[1] += queues[queue_id].statistics.ms_aborted.score[1];
            total_score_aborted[0] += queues[queue_id].statistics.ms_aborted.score[0];
            total_false_positives_aborted += queues[queue_id].statistics.ms_aborted.false_positives;
        }
    }

    printf("\n=======================================================================================\n");
    printf("\nInfo: Aggregate HRA statistics --------------------------------------------------------"
           "\nInfo: Jobs scanned      : %20"PRIu64
                  " Tx busy           : %20"PRIu64
           "\nInfo: Valid responses   : %20"PRIu64
                  " Invalid responses : %20"PRIu64
           "\nInfo: Job retransmits   : %20"PRIu64
                  " Job timeouts      : %20"PRIu64
           "\nInfo: Jobs aborted      : %20"PRIu64,
           total_jobs_scanned,
           total_tx_busy,
           total_valid_responses,
           total_invalid_responses,
           total_job_retransmits,
           total_job_timeouts,
           total_jobs_aborted);

    if (extended_stats_enabled)
    {
        printf("\nInfo: Primary threads   : %20"PRIu64
                      " Instruction count : %20"PRIu64
               "\nInfo: HPM set           : %20"PRIu64
                      " AnyMatch set      : %20"PRIu64,
               total_primary_thread_count,
               total_instruction_count,
               total_hpm_set,
               total_anymatch_set);

        printf("\nInfo: Max Pri Thread set: %20"PRIu64
                      " Max Sec Thread set: %20"PRIu64
               "\nInfo: Max Latency set   : %20"PRIu64
                      " Max Match set     : %20"PRIu64
               "\nInfo: Max Prefix set    : %20"PRIu64,
               total_max_pt_set,
               total_max_st_set,
               total_max_latency_set,
               total_max_match_set,
               total_max_prefix_set);
    }

    printf("\nInfo: Score_table(7:0) = {"
           "%"PRIu64 ", %"PRIu64 ", %"PRIu64 ", %"PRIu64", %" PRIu64", %" PRIu64 ", %"PRIu64 ", %"PRIu64
           "}, false_positives = %"PRIu64,
           total_score_normal[7],
           total_score_normal[6],
           total_score_normal[5],
           total_score_normal[4],
           total_score_normal[3],
           total_score_normal[2],
           total_score_normal[1],
           total_score_normal[0],
           total_false_positives_normal);

    /* Print score for aborted jobs if there were any detected. */
    BUILD_BUG_ON(sizeof(bunch_of_zeros) != sizeof(total_score_aborted));
    if (total_false_positives_aborted ||
        memcmp(total_score_aborted, bunch_of_zeros, sizeof(bunch_of_zeros)))
    {
        printf("\nInfo: Score_table_max(7:0) = {"
               "%"PRIu64 ", %"PRIu64 ", %"PRIu64 ", %"PRIu64", %" PRIu64", %" PRIu64 ", %"PRIu64 ", %"PRIu64
               "}, false_positives = %"PRIu64,
               total_score_aborted[7],
               total_score_aborted[6],
               total_score_aborted[5],
               total_score_aborted[4],
               total_score_aborted[3],
               total_score_aborted[2],
               total_score_aborted[1],
               total_score_aborted[0],
               total_false_positives_aborted);
    }

    printf("\n=======================================================================================\n");

    /*
     * Set global value for reporting
     */
    job_timeouts_detected = total_job_timeouts;
}

/*
 * Function reads registers on from the RXP and displays statistics. Bit rate is also calculated and displayed.
 */
int
hra_display_rxp_stats(unsigned port_id,
                      double test_duration)
{
    int ret = 0;
    double bit_rate;

    // HACK
    unsigned i;
    long bytes_scanned;

	(void)port_id;

    bytes_scanned = 0;
    for (i = 0; i < num_queues; i++)
        bytes_scanned += queues[i].statistics.bytes_scanned;

    struct rxp_stats stats;

    if (0 != rxp_read_stats(rxp_port_id, &stats))
    {
        printf("Error: Failed to read rxp stats\n");
        ret = HRA_STATUS_FAIL;
    }
    else
    {
        /* Calculate byte match ratio */
        uint64_t matched_bytes = 0;
        unsigned queue_id;
        for (queue_id = 0; queue_id < num_queues; queue_id++)
        {
            matched_bytes += queues[queue_id].statistics.matched_bytes;
        }

        printf("\n=======================================================================================\n");
        printf("\nInfo: Statistics read from RXP\n");
        printf("Info: The number of jobs, responses, matches and errors are 32 bit values and may wrap\n");
        printf("Info: The number of job_bytes is a 64 bit value\n");
        printf("Info: Number of jobs       : %" PRIu32 "\n", stats.num_jobs);
        printf("Info: Number of responses  : %" PRIu32 "\n", stats.num_responses);
        printf("Info: Number of matches    : %" PRIu32 "\n", stats.num_matches);
        printf("Info: Number of job bytes  : %" PRIu64 "\n", stats.num_bytes);
        printf("Info: Number of job errors : %" PRIu32 "\n", stats.num_job_errors);
        printf("Info: Byte match ratio     : %.4f \n", ((double)matched_bytes) / ((double)stats.num_bytes));

        printf("Info: Elapsed time         : %.3f seconds\n", test_duration);

        if (test_duration < 0.1)
        {
            printf("Info: Throughput           : N/A Gbps (Scan jobs for > 0.1s for meaningful value)\n");
        }
        else
        {
            bit_rate = ((double)stats.num_bytes * 8) / ((double)1000000000 * test_duration);
            printf("Info: Throughput           : %.3f Gbps\n", bit_rate);
        }
        printf("\n=======================================================================================\n\n");
    }

    return (ret);
}

int
hra_display_cluster_stats(int report)
{
    int ret = 0;
    struct rxp_perf_stats stats;
    int i;
    static unsigned long long total_cache_hit_duty_cycle;
    static unsigned long long total_cache_miss_duty_cycle;
    static unsigned long long total_pe_nd_duty_cycle;
    static unsigned long long total_pe_primary_thread_valid_duty_cycle;
    static unsigned long long total_cluster_hit_duty_cycle[16];
    static unsigned long long total_cluster_instruction_duty_cycle[16];
    static unsigned long long average_cluster_hit_duty_cycle;
    static unsigned long long average_cluster_instruction_duty_cycle;
    static int count = 0;

    memset(&stats, 0, sizeof(stats));

    if (report && count)
    {
        printf("\n=======================================================================================\n");
        printf("\nInfo: Cluster stat averages on port %u\n", 0);
        printf("\nInfo:             hit_dc  inst_dc\n");
        printf("Info: Cluster av: %3llu%%    %3llu%%\n", average_cluster_hit_duty_cycle / (count*16),
            average_cluster_instruction_duty_cycle / (count*16));
        printf("\nInfo:             hit_dc  miss_dc\n");
        printf("Info: L2 cache  : %3llu%%    %3llu%%\n", total_cache_hit_duty_cycle / count,
            total_cache_miss_duty_cycle / count);
        printf("\nInfo:             nd_dc   ptv_dc\n");
        printf("Info: PE        : %3llu%%    %3llu%%\n",
            total_pe_nd_duty_cycle / count, total_pe_primary_thread_valid_duty_cycle / count);
        printf("\n=======================================================================================\n");
    }
    else if (0 != (ret = rxp_read_perf_stats(rxp_port_id, &stats)))
    {
        printf("Error: Failed to read cluster stats values: %d\n", ret);
        ret = HRA_STATUS_FAIL;
    }
    else
    {
        count++;
        total_cache_hit_duty_cycle += stats.l2_cache.cache_hit_duty_cycle;
        total_cache_miss_duty_cycle += stats.l2_cache.cache_miss_duty_cycle;
        total_pe_nd_duty_cycle += stats.pe.nd_duty_cycle;
        total_pe_primary_thread_valid_duty_cycle += stats.pe.primary_thread_valid_duty_cycle;
        printf("\n=======================================================================================\n");
        printf("\nInfo: Cluster stats on port %u\n", 0);
        printf("\nInfo:            jce_idle_id  tce_idle_id  hit_dc  inst_dc :: hit_dc  inst_dc\n");
        for (i = 0; i < 16; i++)
        {
            total_cluster_hit_duty_cycle[i] += stats.cluster[i].hit_duty_cycle;
            total_cluster_instruction_duty_cycle[i] += stats.cluster[i].instruction_duty_cycle;
            average_cluster_hit_duty_cycle += stats.cluster[i].hit_duty_cycle;
            average_cluster_instruction_duty_cycle += stats.cluster[i].instruction_duty_cycle;
            printf("Info: Cluster %02d:   %4u         %4u       %3u%%     %3u%%  :: %3llu%%     %3llu%%\n", i, stats.cluster[i].jce_idle_id,
                stats.cluster[i].tce_idle_id, stats.cluster[i].hit_duty_cycle,
                stats.cluster[i].instruction_duty_cycle, total_cluster_hit_duty_cycle[i] / count,
                total_cluster_instruction_duty_cycle[i] / count);
        }
        printf("Info: Cluster av:                                          :: %3llu%%     %3llu%%\n", average_cluster_hit_duty_cycle / (count*16),
            average_cluster_instruction_duty_cycle / (count*16));
        printf("\nInfo:             hit_dc  miss_dc  rf  rpcf                :: hit_dc  miss_dc\n");
        printf("Info: L2 cache  :  %3u%%   %3u%%   %4u %4u                 :: %3llu%%     %3llu%%\n", stats.l2_cache.cache_hit_duty_cycle,
            stats.l2_cache.cache_miss_duty_cycle, stats.l2_cache.request_fifo_num_entries,
            stats.l2_cache.read_pending_completion_fifo_num_entries, total_cache_hit_duty_cycle / count,
            total_cache_miss_duty_cycle / count);
        printf("\nInfo:             nd_dc  ptv_dc                            :: nd_dc   ptv_dc\n");
        printf("Info: PE        : %3u%%   %3u%%                              :: %3llu%%     %3llu%%\n", stats.pe.nd_duty_cycle, stats.pe.primary_thread_valid_duty_cycle,
            total_pe_nd_duty_cycle / count, total_pe_primary_thread_valid_duty_cycle / count);

        printf("\n=======================================================================================\n");
    }

    return (ret);
}

/**
 * CTRL-C handler function
 *
 * @param signal_number   unused
 */
static void
hra_signal_handler(int signal_number)
{
    (void) signal_number;
    process_packets = 0;
}

/*
 * Function registers handler for CTRL-C
 */
static int
hra_init_signal_handler(void)
{
    struct sigaction sa;
    int rc;

    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = &hra_signal_handler;
    rc = sigaction (SIGINT, &sa, NULL);

    return (rc);
}

/* Check if range of threads are 'inactive'. */
static bool hra_all_threads_inactive(int q_start, int q_end)
{
    bool all_threads_inactive = true;
    int q;

    for (q = q_start; q < q_end; q++)
    {
        if (queues[q].active)
        {
            all_threads_inactive = false;
            break;
        }
    }

    return all_threads_inactive;
}

/* Wait for range of threads to become 'inactive'. */
static int hra_wait_for_threads_inactive(int q_start, int q_end)
{
    bool all_threads_inactive = false;

    do
    {
        all_threads_inactive = hra_all_threads_inactive(q_start, q_end);
        if (!all_threads_inactive)
        {
            sched_yield();
        }
    } while (!all_threads_inactive);

    return 0;
}

/* Check if range of threads are 'active'. */
static bool hra_all_threads_active(int q_start, int q_end)
{
    bool all_threads_active = true;
    int q;

    for (q = q_start; q < q_end; q++)
    {
        if (!queues[q].active)
        {
            all_threads_active = false;
            break;
        }
    }

    return all_threads_active;
}

/* Wait for range of threads to become 'active'. */
static int hra_wait_for_threads_active(int q_start, int q_end)
{
    bool all_threads_active = false;

    do
    {
        all_threads_active = hra_all_threads_active(q_start, q_end);
        if (!all_threads_active)
        {
            sched_yield();
        }
    } while (!all_threads_active);

    return 0;
}

/* Quiesce the job processing on a range of queues. */
static int hra_quiesce_queues(int q_start, int q_end)
{
    quiesce_queues = true;
    hra_wait_for_threads_inactive(q_start, q_end);
    quiesce_queues = false;

    return 0;
}

/* Signal restart to a range of queues. */
static int hra_restart_queues(int q_start, int q_end)
{
    int q;

    for (q = q_start; q < q_end; q++)
    {
        sem_post(&queues[q].start_sem);
    }

    hra_wait_for_threads_active(q_start, q_end);

    return 0;
}

/*
 * Function waits for incremental_update_delay seconds and then programs the rules memories using
 * the file specified with incremental_update_file_name[].
 * Statistics are periodically displayed.
 */
static int
hra_incremental_rtru_loop(void *thread_data)
{
    int ret = HRA_STATUS_OK;
    struct timeval program_rules_start;
    struct timeval program_rules_end;
    struct timeval program_rules_time_taken;
    struct timespec prev_time, cur_time;
    uint64_t diffns;
    uint64_t timer_ns = 0;
    uint64_t update_timer_ns = 0;
    unsigned incremental_update_done = 0;
    unsigned incremental_update_done_cnt = 0;

	(void)thread_data;

    printf("Info: hra_incremental_rtru_loop\n");
    clock_gettime(CLOCK_MONOTONIC, &prev_time);

    hra_wait_for_threads_active(1, num_queues);

    while (process_packets)
    {
        clock_gettime(CLOCK_MONOTONIC, &cur_time);
        diffns = (cur_time.tv_sec - prev_time.tv_sec) * NS_PER_SEC +
                (cur_time.tv_nsec - prev_time.tv_nsec);

        if (diffns > 100000000L) /* Every 100ms */
        {
            /*
             * If the stats timer is enabled, then check the time since the
             * last statistics were printed. If this exceeds the stats timer
             * period then print the stats.
             */
            if (stats_timer_secs > 0)
            {
                 /* advance the timer */
                timer_ns += diffns;

                /* if timer has reached its timeout */
                if (timer_ns >= (stats_timer_secs * NS_PER_SEC))
                {
                    hra_display_application_stats();

                    /* reset the timer */
                    timer_ns = 0;
                }
            }

            /* advance the timer */
            update_timer_ns += diffns;

            if ((incremental_update_done == 0) && (update_timer_ns > (incremental_update_delay * NS_PER_SEC)))
            {

                printf("Info: Beginning to program the RXP rules with [%d]-th incremental update...done\n",
                        incremental_update_done_cnt);
                gettimeofday(&program_rules_start, NULL);

                /* Need to stop jobs on other threads. */
                hra_quiesce_queues(1, num_queues);

                ret = rxp_program_rules(rxp_port_id, incremental_update_file_name[incremental_update_done_cnt], true);
                if (ret < 0)
                {
                    printf("Error: Programming the RXP rules with [%d]-th incremental update...failed\n",
                           incremental_update_done_cnt);
                    process_packets = 0;
                    break;
                }
                else
                {
                    gettimeofday(&program_rules_end, NULL);
                    timersub(&program_rules_end, &program_rules_start, &program_rules_time_taken);
                    printf("Info: Programming the RXP rules with [%d]-th incremental update...done\n",
                            incremental_update_done_cnt);
                    printf("Info: Programming the RXP rules with [%d]-th incremental update took %.3f seconds\n",
                        incremental_update_done_cnt,
                        (double)program_rules_time_taken.tv_sec + (double)(program_rules_time_taken.tv_usec)/1000000);
                }
                hra_restart_queues(1, num_queues);

                incremental_update_done_cnt++;
                if (incremental_update_done_cnt >= incremental_update_file_cnt)
                {
                    incremental_update_done = 1;
                }
                else
                {
                    update_timer_ns = 0;
                }
            }

            /*
             * After the incremental update has been applied, check if all other threads are finished processing.
             * If so then exit from the loop.
             */
            if (incremental_update_done && hra_all_threads_inactive(1, num_queues))
            {
                printf("Info: All threads finished processing\n");
                break;
            }

            prev_time = cur_time;
        }
    }

    printf("Info: Exiting hra_rtru_loop\n");

    return (HRA_STATUS_OK);
}
