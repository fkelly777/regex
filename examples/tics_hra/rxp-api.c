#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_eal.h>
#include <rte_regexdev.h>

//#include "/usr/include/rxp-api.h"
#include "rxp-api.h"

#define RXP_NUM_QUEUES 1

#define MAX_SCAN 64
#define MAX_RESP 64

/* Queue pair struct. */
struct rxp_qp {
	/* Handle used by hra. */
	int rxp_handle;

	/* id passed to dpdk regex apis. */
	uint16_t id;

	/* How many iov's per regex_op. */
	unsigned max_iov;

	/* Is the queue pair in use. */
	bool is_open;

	/* Array of regex ops for scanning jobs. */
	struct {
		unsigned max_ops;
		struct rte_regex_ops **ops;
		unsigned cidx,
			 pidx,
			 max_idx;
	} scan;

	/* A single regex op for submit_job. */
	struct {
		struct rte_regex_ops **ops;
	} submit;

	/* Array of pointers to regex ops for reading responses. */
	struct {
		unsigned max_ops;
		struct rte_regex_ops **ops;
	} resp;
};

/* Regex dev struct. */
struct rxp_regex_dev {

	/* ID passed to dpdk regex apis */
	uint8_t id;

	/* todo: maybe make this an array of pointers instead. */
	unsigned num_qps;
	struct rxp_qp *qps;

	struct rte_regex_dev_info info;
	struct rte_regex_dev_config cfg;
};

/* Array of devs. */
unsigned num_qps = 0;
unsigned num_rxp_devs = 0;
/* todo: maybe make this an array of pointers instead. */
struct rxp_regex_dev *rxp_devs = NULL;

/* todo: need a flat rxp_handle to qp lut. */
static inline int
rxp_handle_to_dev_and_qp(int rxp_handle,
	struct rxp_regex_dev **dev,
	struct rxp_qp **qp)
{
	unsigned d;

	for (d = 0; d < num_rxp_devs; d++) {
		struct rxp_regex_dev *this_dev = &rxp_devs[d];
		unsigned q;
		for (q = 0; q < this_dev->num_qps; q++) {
			struct rxp_qp *this_qp = &this_dev->qps[q];
			if (this_qp->rxp_handle == rxp_handle) {
				*dev = this_dev;
				*qp = this_qp;
				return 0;
			}
		}
	}

	/* not found. */
	return -EINVAL;
}

static inline int
rxp_to_dev(unsigned rxp, uint8_t *dev_id, struct rxp_regex_dev **dev)
{
	unsigned d;

	/* At this time, rxp is just a proxy for dev id. */
	for (d = 0; d < num_rxp_devs; d++) {
		struct rxp_regex_dev *this_dev = &rxp_devs[d];
		if (rxp == this_dev->id) {
			if (dev_id) {
				*dev_id = this_dev->id;
			}
			if (dev) {
				*dev = this_dev;
			}
			return 0;
		}
	}

	/* not found. */
	return -EINVAL;
}

static int
rxp_free_ops_array(struct rte_regex_ops **ops, unsigned num_ops, unsigned num_iov)
{
	unsigned i;

	for (i = 0; i < num_ops; i++) {

		struct rte_regex_ops *op = ops[i];

		if (op) {
			if (op->bufs) {
				unsigned j;
				for (j = 0; j < num_iov; j++) {
					struct rte_regex_iov *iov = (*op->bufs)[j];
					if (iov) {
						free(iov);
					}
				}
				free(op->bufs);
			}
			free(op);
		}
	}

	return 0;
}

static int
rxp_qp_uninit(struct rxp_qp *qp)
{
	if (!qp)
		return 0;

	if (qp->scan.ops) {
		rxp_free_ops_array(qp->scan.ops, qp->scan.max_ops, qp->max_iov);
		free(qp->scan.ops);
	}

	if (qp->submit.ops) {
		rxp_free_ops_array(qp->submit.ops, 1, qp->max_iov);
		free(qp->submit.ops);
	}

	if (qp->resp.ops) {
		rxp_free_ops_array(qp->resp.ops, qp->resp.max_ops, 0);
		free(qp->resp.ops);
	}

	return 0;
}

static int
rxp_qp_init(uint16_t id, struct rxp_qp *qp, struct rte_regex_dev_info *info)
{
	int ret = 0;
	unsigned i;
	unsigned num_scan_ops = MAX_SCAN + 1;
	unsigned num_resp_ops = MAX_RESP + 1;
	unsigned max_iov = info->max_scatter_gather ? info->max_scatter_gather : 1;
	unsigned max_matches = info->max_matches;

	qp->id = id;

	qp->rxp_handle = num_qps++;

	/*
	 * Allocate regex ops for scan.
	 * This is an array of regex ops, each containing an array of one rte_regex_iov.
	 */
	qp->scan.ops = calloc(num_scan_ops, sizeof(qp->scan.ops[0]));
	qp->scan.max_ops = num_scan_ops;
	qp->scan.max_idx = num_scan_ops - 1;
	for (i = 0; i < num_scan_ops; i++) {
		unsigned j;
		struct rte_regex_ops *op = calloc(1, sizeof(*op));

		struct rte_regex_iov **iovs = calloc(max_iov, sizeof(iovs[0]));
		for (j = 0; j < max_iov; j++) {
			iovs[j] = calloc(1, sizeof(*iovs[j]));
		}
		op->bufs = (void*)iovs;

		qp->scan.ops[i] = op;
	}

	/*
	 * Allocate regex ops for 'submit'.
	 * This is an array of a single regex ops.
	 */
	qp->submit.ops = calloc(1, sizeof(qp->submit.ops[0]));
	qp->submit.ops[0] = calloc(1, sizeof(*qp->submit.ops[0]));

	struct rte_regex_iov **iovs = calloc(max_iov, sizeof(iovs[0]));
	iovs[0] = calloc(1, sizeof(*iovs[0]));
	qp->submit.ops[0]->bufs = (void*)iovs;

	/*
	 * Allocate regex ops for responses.
	 * This is an array of regex ops, each containing space for the maximum
	 * number of matches.
	 */
	qp->resp.ops = calloc(num_resp_ops, sizeof(qp->scan.ops[0]));
	qp->resp.max_ops = num_resp_ops;
	for (i = 0; i < num_resp_ops; i++) {
		struct rte_regex_ops *op;
		size_t size = sizeof(*op) + (sizeof(op->matches[0]) * max_matches);
		op = calloc(1, size);
		qp->resp.ops[i] = op;
	}

	return ret;
}

static int
rxp_regex_uninit(struct rxp_regex_dev *dev)
{
	int ret = 0;

	if (dev->qps) {
		unsigned q;
		for (q = 0; q < dev->num_qps; q++) {
			rxp_qp_uninit(&dev->qps[q]);
		}
		free(dev->qps);
	}

	return ret;
}

static int
rxp_regex_init(uint8_t dev_id, struct rxp_regex_dev *dev)
{
	int ret = 0;
	unsigned q;

	dev->id = dev_id;

	ret = rte_regex_dev_info_get(dev_id, &dev->info);

	if (ret != 0) {
		return ret;
	}

	printf("Info: max_qps = %d\n", dev->info.max_queue_pairs);
	printf("Info: max_sges = %d\n", dev->info.max_scatter_gather);

	dev->cfg.nb_queue_pairs = dev->info.max_queue_pairs;

	dev->qps = calloc(dev->cfg.nb_queue_pairs, sizeof(dev->qps[0]));
	dev->num_qps = dev->cfg.nb_queue_pairs;
	for (q = 0; q < dev->num_qps; q++) {
		rxp_qp_init(q, &dev->qps[q], &dev->info);
	}

	num_rxp_devs++;

	return ret;
}

/* RXP and DPDK specific initialistion. */
/* todo: only look for dev id with rxp value? */
int rxp_platform_init(__rte_unused unsigned rxp, int argc, char *argv[])
{
	int ret, i;
	uint8_t dev_count;
	int ret_args_stripped = 0;

	/* Initialise DPDK EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
	{
		return -1;
		//rte_exit(EXIT_FAILURE, "Invalid EAL arguments!\n");
	}

	/* Parse application arguments (after the EAL options) */
	argc -= ret;
	argv += ret;
	ret_args_stripped = ret;

	dev_count = rte_regex_dev_count();
	printf("Info: REGEX Devices = %d\n", dev_count);

	if (dev_count == 0)
	{
		return -1;
	}

	rxp_devs = calloc(dev_count, sizeof(rxp_devs[0]));
	assert(rxp_devs);

	/* Get card ID and program RXP/s */
	for (i = 0; i < dev_count; i++)
	{
		rxp_regex_init(i, &rxp_devs[i]);
	}

	return ret_args_stripped;
}


/* Template for platform specific un-initialistion. */
int rxp_platform_uninit(__rte_unused unsigned rxp)
{
	if (rxp_devs) {
		unsigned i;
		for (i = 0; i < num_rxp_devs; i++) {
			rxp_regex_uninit(&rxp_devs[i]);
		}
		free(rxp_devs);
	}

	return 0;
}

int rxp_queue_status(__rte_unused int rxp_handle, bool *rx_ready, bool *tx_ready)
{
	int ret = 1;

	/* todo: need dev/qp logic here. */
	if (rx_ready) {
		*rx_ready = true;
	}

	if (tx_ready) {
		*tx_ready = true;
	}

	return ret;
}

/* Map a single job to a regex op. */
static inline int
rxp_job_to_regex_op(struct rte_regex_ops *op,
		uint32_t jobid,
	 	const uint8_t *buf,
		uint16_t len,
	 	uint16_t subset0,
	 	uint16_t subset1,
		uint16_t subset2,
	 	uint16_t subset3,
	 	bool enable_hpm,
		bool enable_anymatch)
{
	struct rte_regex_iov *iov = (*op->bufs)[0];

	iov->buf_size = len;
	iov->buf_addr = buf;

	op->num_of_bufs = 1;

	op->user_id = jobid;
	op->req_flags = 0;
	op->group_id0 = subset0;
	if (subset1)
	{
		op->group_id1 = subset1;
		op->req_flags |= RTE_REGEX_OPS_REQ_GROUP_ID1_VALID_F;
	}
	if (subset2)
	{
		op->group_id2 = subset2;
		op->req_flags |= RTE_REGEX_OPS_REQ_GROUP_ID2_VALID_F;
	}
	if (subset3)
	{
		op->group_id3 = subset3;
		op->req_flags |= RTE_REGEX_OPS_REQ_GROUP_ID3_VALID_F;
	}
	if (enable_hpm)
	{
		op->req_flags |= RTE_REGEX_OPS_REQ_MATCH_HIGH_PRIORITY_F;
	}
	if (enable_anymatch)
	{
		op->req_flags |= RTE_REGEX_OPS_REQ_STOP_ON_MATCH_F;
	}

	return 0;
}


int rxp_submit_job(int rxp_handle,
	uint32_t jobid,
	const uint8_t *buf,
	uint16_t len,
	uint16_t subset0,
	uint16_t subset1,
	uint16_t subset2,
	uint16_t subset3,
	bool enable_hpm,
	bool enable_anymatch)
{
	struct rxp_regex_dev *dev;
	struct rxp_qp *qp;

	if (rxp_handle_to_dev_and_qp(rxp_handle, &dev, &qp) != 0) {
		return -EINVAL;
	}

	if (len > RXP_MAX_JOB_LENGTH)
	{
		return -EINVAL;
	}
	if ((subset1 == 0) || (jobid == 0))
	{
		return -EINVAL;
	}

	//NOTE: Note enable_hpm && enable_anymatch are not used in BF2 as only 1bit
	if (enable_hpm || enable_anymatch)
	{
		printf("Error: HPM and Anymatch not supported in BF2\n");
		return -EINVAL;
	}

	rxp_job_to_regex_op(qp->submit.ops[0], jobid, buf, len, subset0, subset1,
			subset2, subset3, enable_hpm, enable_anymatch);
	int num_enqueued = rte_regex_enqueue_burst(dev->id, qp->id, qp->submit.ops, 1);

	if (num_enqueued < 1)
	{
		printf("Error: rxp_submit_job() failed\n");
		return -1;
	}

	return 0;
}

/*
 * Helper for read response.
 * Map a single generic regex op to an rxp response.
 */
static int
regex_op_to_rxp_resp(struct rte_regex_ops *op, struct rxp_response *resp)
{
	int ret = 0;
	unsigned i;

	/* Flags/status */
	resp->header.status = 0;
	if (op->rsp_flags & RTE_REGEX_OPS_RSP_PMI_SOJ_F) {
		resp->header.status |= RXP_RESP_STATUS_PMI_SOJ;
	}
	if (op->rsp_flags & RTE_REGEX_OPS_RSP_PMI_EOJ_F) {
		resp->header.status |= RXP_RESP_STATUS_PMI_EOJ;
	}
	if (op->rsp_flags & RTE_REGEX_OPS_RSP_MAX_SCAN_TIMEOUT_F) {
		resp->header.status |= RXP_RESP_STATUS_MAX_LATENCY;
	}
	if (op->rsp_flags & RTE_REGEX_OPS_RSP_MAX_MATCH_F) {
		resp->header.status |= RXP_RESP_STATUS_MAX_MATCH;
	}
	if (op->rsp_flags & RTE_REGEX_OPS_RSP_MAX_PREFIX_F) {
		resp->header.status |= RXP_RESP_STATUS_MAX_PREFIX;
	}

	/* Number matches and user id. */
	resp->header.match_count = op->nb_matches;
	resp->header.detected_match_count = op->nb_actual_matches;
	resp->header.job_id = op->user_id;

	/* Matches */
	for (i = 0; i < op->nb_matches; i++) {
		resp->matches[i].rule_id   = op->matches[i].rule_id;
		resp->matches[i].start_ptr = op->matches[i].offset;
		resp->matches[i].length	= op->matches[i].len;
	}

	return ret;
}

void rxp_job_batch_free(struct rxp_job_batch *ctx)
{
	if (ctx)
	{
		free(ctx);
	}
}

struct rxp_job_batch *rxp_job_batch_alloc(size_t max_jobs, size_t bytes_threshold)
{
	struct rxp_job_batch *ctx = NULL;

	ctx = calloc(1, sizeof(*ctx) + (sizeof(ctx->job[0]) * max_jobs));
	if (ctx)
	{
		ctx->max_jobs = max_jobs;
		ctx->bytes_threshold = bytes_threshold;
	}

	return ctx;
}

int rxp_dispatch_jobs(int rxp_handle, struct rxp_job_batch *ctx)
{
	int ret = 0;
	struct rxp_regex_dev *dev;
	struct rxp_qp *qp;
	uint16_t ops_sent = 0;

	if (rxp_handle_to_dev_and_qp(rxp_handle, &dev, &qp) != 0) {
		return -EINVAL;
	}

	while (qp->scan.pidx != qp->scan.cidx) {
		/*
		 * The following logic deals with wrap around of the
		 * producer/consumer indices.
		 */
		unsigned num_ops = 0;
		if (qp->scan.pidx > qp->scan.cidx) {
			num_ops = qp->scan.pidx - qp->scan.cidx;
		} else {
			num_ops = qp->scan.max_idx - qp->scan.cidx + 1;
		}
		if (num_ops) {
			ret = rte_regex_enqueue_burst(dev->id, qp->id, &qp->scan.ops[qp->scan.cidx], num_ops);
			if (ret > 0) {
				ops_sent += ret;
				qp->scan.cidx += ret;
				if (qp->scan.cidx > qp->scan.max_idx) {
					qp->scan.cidx = qp->scan.cidx - qp->scan.max_idx - 1;
				}
				ctx->count -= ret;
			} else {
				/*
				 * Unable to enqueue any more jobs.
				 * Break from loop and return.
				 */
				break;
			}
		}
	}

	return ops_sent;
}

int rxp_scan_job(int rxp_handle,
	struct rxp_job_batch *ctx,
	uint32_t jobid,
	const uint8_t *buf,
	uint16_t len,
	uint16_t subset0,
	uint16_t subset1,
	uint16_t subset2,
	uint16_t subset3,
	bool enable_hpm,
	bool enable_anymatch)
{
	int ret = 0;
	struct rxp_regex_dev *dev;
	struct rxp_qp *qp;
	struct rte_regex_ops *op;

	if (rxp_handle_to_dev_and_qp(rxp_handle, &dev, &qp) != 0) {
		return -EINVAL;
	}

	if (len > RXP_MAX_JOB_LENGTH)
	{
		return -EINVAL;
	}
	if ((subset1 == 0) || (jobid == 0))
	{
		return -EINVAL;
	}

	unsigned cur_pidx = qp->scan.pidx;
	unsigned next_pidx = cur_pidx + 1;
	if (next_pidx > qp->scan.max_idx) {
		next_pidx = 0;
	}

	if (next_pidx == qp->scan.cidx) {
		return -EBUSY;
	} else {
		if (next_pidx != qp->scan.cidx) {
			op = qp->scan.ops[cur_pidx];

			ret = rxp_job_to_regex_op(op, jobid, buf, len, subset0, subset1,
					subset2, subset3, enable_hpm, enable_anymatch);
			if (ret == 0) {
				ctx->count++;
				qp->scan.pidx = next_pidx;
				if (ctx->count >= ctx->max_jobs) {
					ret = rxp_dispatch_jobs(rxp_handle, ctx);
				}
			}

		}
	}


	return ret;
}

struct rte_regex_ops_matches {
	struct rte_regex_ops op;
	struct rte_regex_match matches[254];
};


int rxp_read_response_batch(int rxp_handle, struct rxp_response_batch *ctx)
{
	int i;
	struct rxp_regex_dev *dev;
	struct rxp_qp *qp;

	if (rxp_handle_to_dev_and_qp(rxp_handle, &dev, &qp) != 0) {
		return -EINVAL;
	}

	/* Clear the context. */
	ctx->buf_used = 0;
	ctx->next_offset = 0;

	int num_dequeued = rte_regex_dequeue_burst(dev->id, qp->id, qp->resp.ops, qp->resp.max_ops);
	if (num_dequeued > 0) {
		for (i = 0; i < num_dequeued; i++)
		{
			struct rte_regex_ops *op = qp->resp.ops[i];
			struct rxp_response *resp = (struct rxp_response*)(ctx->buf + ctx->buf_used);
			size_t resp_size;
			regex_op_to_rxp_resp(op, resp);
			resp_size = sizeof(resp->header) + (sizeof(resp->matches[0]) * resp->header.match_count);
			ctx->buf_used += resp_size;

			/* todo: need resp buffer size check. */
		}
	}

	return num_dequeued;
}

struct rxp_response *rxp_next_response(struct rxp_response_batch *ctx)
{
	struct rxp_response *resp;

	if (ctx->next_offset < ctx->buf_used)
	{
		int resp_size;
		resp = (struct rxp_response*)&ctx->buf[ctx->next_offset];
		resp_size = sizeof(resp->header) +
				   (sizeof(resp->matches[0]) * resp->header.match_count);
		ctx->next_offset += resp_size;
	}
	else
	{
		resp = NULL;
	}

	return resp;
}

/* Open a queue pair to this rxp. */
int rxp_open(unsigned rxp)
{
	int ret;
	struct rxp_regex_dev *dev;

	if ((ret = rxp_to_dev(rxp, NULL, &dev)) != 0) {
		/* didn't map rxp to dev id. */
	} else {
		/* todo: need a mutex here. */

		/* find a free queue pair. */
		unsigned q;
		ret = -EBUSY;
		for (q = 0; q < dev->num_qps; q++) {
			struct rxp_qp *qp = &dev->qps[q];
			if (!qp->is_open) {
				qp->is_open = true;
				ret = qp->rxp_handle;
				break;
			}
		}
	}

	return ret;
}

int rxp_close(int rxp_handle)
{
	int ret;
	struct rxp_regex_dev *dev;
	struct rxp_qp *qp;

	if ((ret = rxp_handle_to_dev_and_qp(rxp_handle, &dev, &qp)) != 0) {
		/* didn't map handle to dev/qp. */
	} else {
		/* todo: need a mutex here. */
		qp->is_open = false;
	}

	return ret;
}

int rxp_program_rules(unsigned rxp, const char *rulesfile, __rte_unused bool incremental)
{
	struct rte_regex_dev_config dev_cfg = {0};
	struct rte_regex_dev_info dev_info;
	int ret;

	uint8_t dev_id = rxp;

	ret = rte_regex_dev_info_get(dev_id, &dev_info);
	if (ret)
		return ret;

	printf("max_qps = %d\n", dev_info.max_queue_pairs);
	printf("max_sges = %d\n", dev_info.max_scatter_gather);

	dev_cfg.nb_queue_pairs = dev_info.max_queue_pairs;
	dev_cfg.rule_db = rulesfile;

	ret = rte_regex_dev_configure(dev_id, &dev_cfg);

	return ret;
}

int rxp_read_stats(__rte_unused unsigned rxp, __rte_unused struct rxp_stats *stats)
{
	/*
         * todo: using hard coded id's to get something going quickly.
	 *       could do something at initialisation time to figure
	 *       out which stats are actually available and which
	 *       'ids' to get them from.
	 * For now, see following enums in rxpcm_pmd.c
	 *  RXPCM_XSTAT_ID_JOB_COUNT_HARD,
	 *  RXPCM_XSTAT_ID_RESPONSE_COUNT_HARD,
	 *  RXPCM_XSTAT_ID_MATCH_COUNT_HARD,
	 *  RXPCM_XSTAT_ID_JOB_BYTE_COUNT_HARD,
	 *  RXPCM_XSTAT_ID_JOB_ERROR_COUNT_HARD,
	 */
	int ret = 0;
	uint8_t dev_id;
	uint64_t values[5];
	uint16_t ids[5] = {0, 1, 2, 3, 4};


	if ((ret = rxp_to_dev(rxp, &dev_id, NULL)) != 0) {
		/* didn't map rxp to dev id. */
	} else if ((ret = rte_regex_dev_xstats_get(0, ids, values, 5)) != 5) {
		/* didn't get all requested stats. */
		ret = -EFAULT;
	} else {
		stats->num_jobs = values[0];
		stats->num_responses = values[1];
		stats->num_matches = values[2];
		stats->num_bytes = values[3];
		stats->num_job_errors = values[4];
		ret = 0;
	}

	return ret;
}

int rxp_read_perf_stats(__rte_unused unsigned rxp, __rte_unused struct rxp_perf_stats *stats)
{
	int ret = 0;

	return ret;
}

static int
rxp_attr_get(unsigned rxp, enum rte_regex_dev_attr_id attr, uint32_t *val)
{
	int ret;
	uint8_t dev_id;

	if ((ret = rxp_to_dev(rxp, &dev_id, NULL)) != 0) {
		/* didn't map rxp to dev id. */
		return ret;
	} else if ((ret = rte_regex_dev_attr_get(dev_id, attr, val)) != 0) {
		/* failed to get attribute. */
	}

	return ret;
}

static int
rxp_attr_set(unsigned rxp, enum rte_regex_dev_attr_id attr, uint32_t val)
{
	int ret;
	uint8_t dev_id;

	if ((ret = rxp_to_dev(rxp, &dev_id, NULL)) != 0) {
		/* didn't map rxp to dev id. */
		return ret;
	} else if ((ret = rte_regex_dev_attr_set(dev_id, attr, &val)) != 0) {
		/* failed to get attribute. */
	}

	return ret;
}



int rxp_read_max_matches(unsigned rxp, uint32_t *max_matches)
{
	return rxp_attr_get(rxp, RTE_REGEX_DEV_ATTR_MAX_MATCHES, max_matches);
}

int rxp_set_max_matches(unsigned rxp, uint32_t max_matches)
{
	return rxp_attr_set(rxp, RTE_REGEX_DEV_ATTR_MAX_MATCHES, max_matches);
}

int rxp_read_max_prefixes(unsigned rxp, uint32_t *max_prefixes)
{
	return rxp_attr_get(rxp, RTE_REGEX_DEV_ATTR_MAX_PREFIX, max_prefixes);
}

int rxp_set_max_prefixes(unsigned rxp, uint32_t max_prefixes)
{
	return rxp_attr_set(rxp, RTE_REGEX_DEV_ATTR_MAX_PREFIX, max_prefixes);
}

int rxp_read_max_latency(unsigned rxp, uint32_t *max_latency)
{
	/* todo: need to map from hra/rxp notion of latency to regex ns notion. */
	return rxp_attr_get(rxp, RTE_REGEX_DEV_ATTR_MAX_SCAN_TIMEOUT, max_latency);
}

int rxp_set_max_latency(unsigned rxp, uint32_t max_latency)
{
	/* todo: need to map from hra/rxp notion of latency to regex ns notion. */
	return rxp_attr_set(rxp, RTE_REGEX_DEV_ATTR_MAX_SCAN_TIMEOUT, max_latency);
}

int rxp_read_max_pri_threads(__rte_unused unsigned rxp, __rte_unused uint32_t *max_pri_threads)
{
	/* Not supported via regex. */
	return -ENOTSUP;
}

int rxp_set_max_pri_threads(__rte_unused unsigned rxp, __rte_unused uint32_t max_pri_threads)
{
	/* Not supported via regex. */
	return -ENOTSUP;
}
