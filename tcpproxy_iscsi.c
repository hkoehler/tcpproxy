/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: tcpproxy_iscsi.c 487 2011-09-30 01:52:56Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/jiffies.h>
#include <linux/crc32c.h>
#include <net/tcp.h>

#include "tcpproxy.h"
#include "tcpproxy_iscsi.h"
#include "iscsi_logger.h"
#include "scsi_subr.h"

#if 0
#define dprintk(format...) printk(format)
#define inline
#else
#define dprintk(format...)
#endif

#define PDU_POOLSIZE 64
#define SERVER_DIR 0
#define CLIENT_DIR 1
#define CANCEL 2
#define CMD_WIN_SIZE 128

struct tcpproxy_scheduler tcpproxy_iscsi_scheduler;

/* memory pool for SCSI tasks */
static struct kmem_cache *task_slab __read_mostly = NULL;
static mempool_t *task_mempool __read_mostly = NULL ;

/* memory pool for iSCSI PDUs */
static struct kmem_cache *pdu_slab __read_mostly = NULL;
static mempool_t *pdu_mempool __read_mostly = NULL;

/* fwd decl of linux/net/ipv4/tcp.c */
int tcp_send_skb_queue(struct sock *sk, struct sk_buff_head *queue);
int tcp_recv_skb_queue(struct sock *sk, struct sk_buff_head *queue);

static int iscsi_send_pdu(struct tcpproxy_session *ses,
		struct iscsi_pdu *pdu, bool direction);
static void iscsi_free_pdu(struct iscsi_pdu *pdu);
static int iscsi_tgt_port_input(struct iscsi_pdu *pdu);
static int iscsi_tgt_port_output(struct iscsi_pdu *pdu);
static int iscsi_ini_port_input(struct iscsi_pdu *pdu);
static int iscsi_ini_port_output(struct iscsi_pdu *pdu);
static int iscsi_output(struct iscsi_pdu *pdu,
		bool direction);
static int iscsi_iosched_output(struct iosched_operation *op, bool lock);

static inline struct iscsi_hdr *
pdu_hdr(struct iscsi_pdu *pdu)
{
	BUG_ON(!pdu);
	BUG_ON(!pdu->hdr_skb);
	return (struct iscsi_hdr *)pdu->hdr_skb->data;
}

static inline unsigned char *
pdu_cdb(struct iscsi_pdu *pdu)
{
	return (unsigned char *)pdu_hdr(pdu)->basehdr + 32;
}

static inline uint8_t bhs_get_opcode(struct iscsi_pdu *pdu)
{
	return pdu_hdr(pdu)->basehdr[0] & 0x3f;
}

static inline uint8_t bhs_get_tmf(struct iscsi_pdu *pdu)
{
	return pdu_hdr(pdu)->basehdr[1] & 0x7f;
}

static inline uint8_t bhs_get_pduflags(struct iscsi_pdu *pdu)
{
	return pdu_hdr(pdu)->basehdr[1];
}

static inline uint8_t bhs_get_rsp(struct iscsi_pdu *pdu)
{
	return pdu_hdr(pdu)->basehdr[2];
}

static inline uint8_t bhs_get_stat(struct iscsi_pdu *pdu)
{
	return pdu_hdr(pdu)->basehdr[3];
}

static inline uint8_t bhs_get_total_ahs_len(struct iscsi_pdu *pdu)
{
	return pdu_hdr(pdu)->basehdr[4];
}

static inline uint32_t bhs_get_data_len(struct iscsi_pdu *pdu)
{
	size_t len = (ntohl(*(uint32_t *)&pdu_hdr(pdu)->basehdr[4]) & 0x00ffffff);
	return ALIGN(len, 4);
}

static inline uint32_t bhs_get_lun(struct iscsi_pdu *pdu)
{
	return *(uint32_t *)&pdu_hdr(pdu)->basehdr[9];
}

static inline uint32_t bhs_get_itt(struct iscsi_pdu *pdu)
{
	return (ntohl(*(uint32_t *)&pdu_hdr(pdu)->basehdr[16]));
}

static inline uint32_t bhs_get_refitt(struct iscsi_pdu *pdu)
{
	return (ntohl(*(uint32_t *)&pdu_hdr(pdu)->basehdr[20]));
}

static inline uint32_t bhs_get_cmdsn(struct iscsi_pdu *pdu)
{
	return (ntohl(*(uint32_t *)&pdu_hdr(pdu)->basehdr[24]));
}

static inline uint32_t bhs_get_statsn(struct iscsi_pdu *pdu)
{
	return (ntohl(*(uint32_t *)&pdu_hdr(pdu)->basehdr[24]));
}

static inline uint32_t bhs_get_expcmdsn(struct iscsi_pdu *pdu)
{
	return (ntohl(*(uint32_t *)&pdu_hdr(pdu)->basehdr[28]));
}

static inline uint32_t bhs_get_maxcmdsn(struct iscsi_pdu *pdu)
{
	return (ntohl(*(uint32_t *)&pdu_hdr(pdu)->basehdr[32]));
}

static inline void bhs_get_isid(struct iscsi_pdu *pdu, char isid[6])
{
	int i;
	for(i = 0; i < 6; i++)
		isid[i] = pdu_hdr(pdu)->basehdr[8+i];
}

static inline void bhs_set_data_len(struct iscsi_pdu *pdu, uint32_t len)
{
	size_t ahs_len = bhs_get_total_ahs_len(pdu);
	size_t total_len = (ahs_len << 24)  | len;
	*(uint32_t *)&pdu_hdr(pdu)->basehdr[4] = htonl(total_len);
}

static inline void bhs_set_cmdsn(struct iscsi_pdu *pdu, uint32_t sn)
{
	*(uint32_t *)&pdu_hdr(pdu)->basehdr[24] = htonl(sn);
}

static inline void bhs_set_expstatsn(struct iscsi_pdu *pdu, uint32_t sn)
{
	*(uint32_t *)&pdu_hdr(pdu)->basehdr[28] = htonl(sn);
}

static inline void bhs_set_statsn(struct iscsi_pdu *pdu, uint32_t sn)
{
	*(uint32_t *)&pdu_hdr(pdu)->basehdr[24] = htonl(sn);
}

static inline void bhs_set_expcmdsn(struct iscsi_pdu *pdu, uint32_t sn)
{
	*(uint32_t *)&pdu_hdr(pdu)->basehdr[28] = htonl(sn);
}

static inline void bhs_set_maxcmdsn(struct iscsi_pdu *pdu, uint32_t sn)
{
	*(uint32_t *)&pdu_hdr(pdu)->basehdr[32] = htonl(sn);
}

static inline void bhs_set_refcmdsn(struct iscsi_pdu *pdu, uint32_t sn)
{
	*(uint32_t *)&pdu_hdr(pdu)->basehdr[32] = htonl(sn);
}

static inline void bhs_print_isid(const char *p, char isid[6])
{
	int i;
	printk(KERN_INFO "%s: ISID = ", p);
	for(i = 0; i < 6; i++)
		printk(KERN_CONT "%02x" , isid[i]);
	printk(KERN_CONT "\n");
}

static inline uint16_t bhs_get_cid(struct iscsi_pdu *pdu)
{
	return ntohs(*(uint16_t *)&pdu_hdr(pdu)->basehdr[20]);
}

/* Serial Number Arithmetic RFC1982 */
static inline int iscsi_sna_lt(uint32_t n1, uint32_t n2)
{
	const uint32_t SERIAL_BITS = 2147483648UL;
	return n1 != n2 && ((n1 < n2 && (n2 - n1 < SERIAL_BITS)) ||
			(n1 > n2 && (n2 - n1 < SERIAL_BITS)));
}

/*
 * add pad bytes to socket buffer
 */
static inline void iscsi_pad(struct sk_buff *skb)
{
	size_t pad = ALIGN(skb->len, 4) - skb->len;
	if (pad) {
		int i;
		char *p = skb_put(skb, pad);
		for(i = 0; i < pad; i++)
			p[i] = 0;
	}
}

/*
 * get I-T-L nexus with LUN attached
 */
inline static struct iscsi_itl *
iscsi_get_itl(struct iscsi_connection *data, uint32_t lun)
{
	struct iscsi_itl *itl = NULL;

	if (data->it) {
		itl = iscsi_it_lookup_itl(data->it, lun);
		if (!itl)
			printk(KERN_ERR "I-T-L (%s, %s, %d) not found\n",
					data->initiator_name, data->target_name, lun);
	}
	else
		printk(KERN_ERR "I-T (%s, %s) not found\n",
				data->initiator_name, data->target_name);

	return itl;
}

/* get IO scheduler operation from SCSI CDB */
inline static enum iosched_opcode
iscsi_get_iosched_opcode(uint8_t opcode)
{
	if (scsi_cdb_is_read(opcode))
		return IOSCHED_READ;
	if (scsi_cdb_is_write(opcode))
		return IOSCHED_WRITE;
	return IOSCHED_NONE;
}

/* get a reference to a flow */
void iosched_acquire_flow(struct iosched_flow *flow)
{
	struct iscsi_it *it = container_of(flow, struct iscsi_itl, flow)->it;
	iscsi_tgt_acquire_it(it);
}

/* release a reference to a flow */
void iosched_release_flow(struct iosched_flow *flow)
{
	struct iscsi_it *it = container_of(flow, struct iscsi_itl, flow)->it;
	iscsi_tgt_release_it(it);
}

/*
 * create new task by initiator task tag (ITT)
 * return already existing task due to retransmits or linked commands
 */
static struct scsi_task *
iscsi_create_task(struct iscsi_connection *conn, struct iscsi_pdu *pdu)
{
	struct hlist_head *hh;
	struct hlist_node *hn;
	struct scsi_task *task;
	uint32_t lun, itt, cmdsn;

	itt = bhs_get_itt(pdu);
	cmdsn = bhs_get_cmdsn(pdu);
	lun = bhs_get_lun(pdu);
	hh = &conn->task_htbl[hash_32(itt, TASK_HASH_ORDER)];
	hlist_for_each_entry(task, hn, hh, hlist)
		if (task->itt == itt) {
			if (task->pini_cmdsn == cmdsn)
				printk(KERN_INFO "%s: retransmitted command ITT=%x CmdSN=%x\n",
						__func__, itt, cmdsn);
			else
				printk(KERN_INFO "%s: linked command ITT=%d\n", __func__, itt);
			break;
		}

	if (hn == NULL) {
		task = (struct scsi_task *)mempool_alloc(task_mempool, GFP_KERNEL);
		if (!task)
			return NULL;
		hh = &conn->task_htbl[hash_32(itt, TASK_HASH_ORDER)];
		hlist_add_head(&task->hlist, hh);
		conn->num_tasks++;
	}

	pdu->task = task;
	task->itt = itt;
	task->lun = lun;
	task->pini_cmdsn = cmdsn;
	task->priv = NULL;
	task->iosize = 0;
	task->random = 0;
	task->read = 0;
	if (bhs_get_opcode(pdu) == ISCSI_SCSI_CMD) {
		task->opcode = pdu_cdb(pdu)[0];
		task->tmf = 0;
		/*printk(KERN_INFO "%s: itt %d\n",
				__func__, task->itt);*/
	}
	else if (bhs_get_opcode(pdu) == ISCSI_TASK_CMD) {
		task->opcode = 0;
		task->tmf = bhs_get_tmf(pdu);
		task->refitt = bhs_get_refitt(pdu);
		/*printk(KERN_INFO "%s: ref itt %d, itt %d\n",
				__func__, task->refitt, task->itt);*/
	}
	else
		BUG();

	return task;
}

/*
 * look up task by ITT
 * return NULL if not found
 */
static struct scsi_task *
iscsi_lookup_task(struct iscsi_connection *conn, uint32_t itt)
{
	struct hlist_head *hh;
	struct hlist_node *hn, *htmp;
	struct scsi_task *task;

	hh = &conn->task_htbl[hash_32(itt, TASK_HASH_ORDER)];
	hlist_for_each_entry_safe(task, hn, htmp, hh, hlist)
		if (task->itt == itt)
			return task;

	return NULL;
}

/*
 * destroy task
 */
static void iscsi_destroy_task(struct iscsi_connection *conn, struct scsi_task *task)
{
	conn->num_tasks--;
	if (task->priv)
		iscsi_free_pdu((struct iscsi_pdu *)task->priv);
	hlist_del(&task->hlist);
	mempool_free(task, task_mempool);

	if (conn->num_tasks > CMD_WIN_SIZE)
		printk(KERN_WARNING "more than %d tasks pending between %s and %s\n",
				CMD_WIN_SIZE, conn->initiator_name, conn->target_name);
}

/*
 * abort single task
 */
static void iscsi_abort_task(struct iscsi_connection *conn, struct scsi_task *task)
{
	struct iscsi_itl *itl;
	struct iosched_operation op;
	enum iosched_opcode opcode;

	itl = iscsi_get_itl(conn, task->lun);
	if (itl) {
		opcode = iscsi_get_iosched_opcode(task->opcode);
		/* delete queued READ/WRITE task */
		if (opcode == IOSCHED_READ || opcode == IOSCHED_WRITE) {
			op.op = IOSCHED_ABORT;
			op.client = &conn->iosched_client;
			op.flow = &itl->flow;
			op.queue = &itl->lun->queue;
			op.lun = task->lun;
			op.tag = task->itt;
			op.lba = 0;
			iosched_input(&op);
		}
		iscsi_itl_cancel(itl, task);
	}
	printk(KERN_INFO "%s: aborted task from %s to %s with ITT=%x\n",
			__func__, conn->initiator_name, conn->target_name, task->itt);
	iscsi_destroy_task(conn, task);
	/*
	 * open up command window,
	 * response will never be sent from vTgt port
	 */
	if (conn->tgt_port.pending > 0)
		conn->tgt_port.pending--;
}

/*
 * Abort task set, i.e. all tasks associated with specified LUN in session.
 * All tasks with (vIni) CmdSN less than specified CmdSN are aborted.
 * Only abort SCSI tasks. TMF tasks cannot be aborted in SCSI.
 */
static void iscsi_abort_task_set(struct iscsi_connection *conn,
		uint32_t lun, uint32_t cmdsn)
{
	int i;
	struct hlist_node *hn, *htmp;
	struct scsi_task *task;

	for (i = 0; i < TASK_HASH_SIZE; i++)
		hlist_for_each_entry_safe(task, hn, htmp, &conn->task_htbl[i], hlist)
			if (task->lun == lun && task->tmf == 0 &&
				iscsi_sna_lt(task->vini_cmdsn, cmdsn))
				iscsi_abort_task(conn, task);
	printk(KERN_INFO "aborted task set on LUN %d from %s\n",
			lun, conn->initiator_name);
}

/*
 * Abort all tasks in iSCSI connection
 * Only abort SCSI tasks not TMF tasks themselves if cleanup == false
 */
static void iscsi_abort_all_tasks(struct iscsi_connection *conn, bool cleanup)
{
	int i;
	struct hlist_node *hn, *htmp;
	struct scsi_task *task;

	for (i = 0; i < TASK_HASH_SIZE; i++)
		hlist_for_each_entry_safe(task, hn, htmp, &conn->task_htbl[i], hlist)
			if (cleanup || task->tmf == 0)
				iscsi_abort_task(conn, task);
	printk(KERN_INFO "aborted all tasks from %s\n", conn->initiator_name);
	/* sanity check on clean-up */
	if (cleanup && conn->num_tasks != 0)
		printk(KERN_WARNING "%s: number of tasks = %d, initiator: %s\n",
			__func__, conn->num_tasks, conn->initiator_name);
}

/*
 * copy data segment to continuous buffer
 * return current data offset
 */
static size_t iscsi_copy_data(struct iscsi_pdu *pdu)
{
	struct sk_buff *skb;
	struct iscsi_connection *conn = pdu->conn;
	size_t off = conn->data_off;

	skb_queue_walk(&pdu->data_skb_queue, skb) {
		if (off + skb->len > sizeof(conn->data_buf)) {
			printk(KERN_WARNING "%s: data buffer too small", __func__);
			break;
		}
		skb_copy_bits(skb, 0, &conn->data_buf[off], skb->len);
		off += skb->len;
	}
	conn->data_off = off;

	return off;
}

/*
 * Create Task from PDU and insert it into task list of iSCSI connection
 * Schedule iSCSI SCSI command PDU.
 */
static int iscsi_scsi_cmd(struct iscsi_connection *conn, struct iscsi_pdu *pdu)
{
	struct iosched_operation *op;
	struct scsi_task *task;
	struct iscsi_itl *itl;
	uint32_t itt, lun, iosize = 0;
	uint64_t lba = 0;
	enum iosched_opcode opcode;
	unsigned char *cdb = pdu_cdb(pdu);

	itt = bhs_get_itt(pdu);
	lun = bhs_get_lun(pdu);
	task = iscsi_create_task(conn, pdu);
	if (task == NULL) {
		iscsi_free_pdu(pdu);
		return -ENOMEM;
	}

	itl = iscsi_get_itl(conn, task->lun);
	if (itl == NULL)  {
		iscsi_free_pdu(pdu);
		return -ENOENT;
	}

	opcode = iscsi_get_iosched_opcode(cdb[0]);
	/* check for writes with unsolicited data */
	if (opcode == IOSCHED_WRITE)
		if (!(bhs_get_pduflags(pdu) & ISCSI_FINAL)) {
			if (unlikely(task->priv != NULL)) {
				printk(KERN_WARNING "write command with data already attached!\n");
				iscsi_free_pdu((struct iscsi_pdu *)task->priv);
			}
			task->priv = (void *)pdu;
			dprintk(KERN_INFO "unsolicited data ITT=%d cmd_pdu=%p\n", itt, pdu);
			return 0;
		}

	/* update IO specific attributes */
	if (opcode == IOSCHED_READ || opcode == IOSCHED_WRITE) {
		iosize = scsi_cdb_get_len(pdu_cdb(pdu));
		lba = scsi_cdb_get_lba(pdu_cdb(pdu));

		/*
		 * Characterize IO (sequential vs random, read vs. write)
		 */
		task->iosize = iosize;
		mutex_lock(&itl->mtx);
		if (opcode == IOSCHED_READ) {
			task->read = true;
			if (lba != itl->next_read_lba)
				task->random = true;
			itl->next_read_lba = lba + iosize;
		}
		else {
			task->read = false;
			if (lba != itl->next_write_lba)
				task->random = true;
			itl->next_write_lba = lba + iosize;
		}

		/* update fine-grained metrics */
		itl->curr_fg_metrics->ios_received++;
		mutex_unlock(&itl->mtx);
	}

	/* feed IO scheduler with R/W SCSI commands */
	if (opcode == IOSCHED_READ || opcode == IOSCHED_WRITE) {
		op = &pdu->iosched_op;
		op->op = opcode;
		op->client = &conn->iosched_client;
		op->flow = &itl->flow;
		op->queue = &itl->lun->queue;
		op->lun = lun;
		op->tag = itt;
		op->lba = lba;
		op->len = iosize;
		op->iosched_output = iscsi_iosched_output;
		/* keep connection alive while IO scheduler is working on PDU */
		tcpproxy_session_get(conn->ses);
		return iosched_input((struct iosched_operation *)pdu);
	}

	/* all other SCSI commands bypass the IO scheduler */
	return iscsi_ini_port_output(pdu);
}

/*
 * Schedule iSCSI write data PDU.
 */
static int iscsi_write_data(struct iscsi_connection *conn, struct iscsi_pdu *pdu)
{
	struct iosched_operation *op;
	struct iscsi_itl *itl;
	struct iscsi_pdu *cmd_pdu;
	struct scsi_task *task;
	uint32_t itt;
	uint32_t lun;

	itt = bhs_get_itt(pdu);
	lun = bhs_get_lun(pdu);
	itl = iscsi_get_itl(conn, lun);
	if (itl == NULL) {
		iscsi_free_pdu(pdu);
		return -ENOENT;
	}

	task = iscsi_lookup_task(conn, itt);
	if (task == NULL) {
		iscsi_free_pdu(pdu);
		return -ENOMEM;
	}

	cmd_pdu = (struct iscsi_pdu *)task->priv;
	/* no unsolicited data for write */
	if (cmd_pdu == NULL)
		return iscsi_ini_port_output(pdu);

	/* queue unsolicited data to command PDU */
	list_add_tail(&pdu->list, &cmd_pdu->data_list);
	dprintk(KERN_INFO "queue data ITT=%d\n", itt);

	/* scheduler command + unsolicited data */
	if (bhs_get_pduflags(pdu) & ISCSI_FINAL) {
		/* end unsolicited data phase */
		task->priv = NULL;
		dprintk(KERN_INFO "send data ITT=%d cmd_pdu=%p\n", itt, cmd_pdu);
		/* feed IO scheduler with write commands */
		op = &cmd_pdu->iosched_op;
		op->op = IOSCHED_WRITE;
		op->client = &conn->iosched_client;
		op->flow = &itl->flow;
		op->queue = &itl->lun->queue;
		op->lun = lun;
		op->tag = itt;
		op->lba = scsi_cdb_get_lba(pdu_cdb(cmd_pdu));
		op->len = scsi_cdb_get_len(pdu_cdb(cmd_pdu));
		op->iosched_output = iscsi_iosched_output;
		/* keep connection alive while IO scheduler is working on PDU */
		tcpproxy_session_get(conn->ses);
		return iosched_input((struct iosched_operation *)cmd_pdu);
	}

	return 0;
}

/*
 * Remove task from iSCSI connection by PDU's ITT and destroy it
 * Check if target or LUN has been reset
 */
static int iscsi_scsi_rsp(struct iscsi_connection *conn, struct iscsi_pdu *pdu)
{
	struct scsi_task *task;
	struct iscsi_itl *itl;
	struct scsi_sense_hdr sshdr;
	uint32_t lun, cmdsn;

	/*
	 * destroy task despite of what the response looks like
	 */
	task = iscsi_lookup_task(conn, bhs_get_itt(pdu));
	if (task) {
		/* update stats in I-T-L nexus */
		itl = iscsi_get_itl(conn, task->lun);
		if (itl == NULL)
			return -ENOENT;
		iscsi_itl_response(itl, task);
		lun = task->lun;
		cmdsn = task->vini_cmdsn;
		iscsi_destroy_task(conn, task);
	}
	/*
	 * in case task cannot be found on our side this can be due to a
	 * previously cleared task set
	 */
	else {
		printk(KERN_WARNING "no task with ITT %x pending from %s on %s\n",
				bhs_get_itt(pdu), conn->initiator_name, conn->target_name);
		return 0;
	}

	/*
	 * clear task state on our side on LUN/target reset
	 */
	if (bhs_get_rsp(pdu) == 0 && bhs_get_stat(pdu) == SAM_STAT_CHECK_CONDITION) {
		iscsi_copy_data(pdu);
		if (!scsi_normalize_sense((u8 *)conn->data_buf+2,
			(int)conn->data_off-2, &sshdr)) {

			printk(KERN_ERR "failed to normalize sense data from %s on %s\n",
					conn->initiator_name, conn->target_name);
			return -EINVAL;
		}
		printk(KERN_INFO "check condition from %s key=%x, asc=%x, ascq=%x\n",
				conn->target_name, sshdr.sense_key, sshdr.asc, sshdr.ascq);
		if (sshdr.sense_key == UNIT_ATTENTION)
			if (sshdr.asc == 0x29 || sshdr.asc == 0x2f)
				iscsi_abort_task_set(conn, lun, cmdsn);
		conn->data_off = 0;
	}

	return 0;
}

/*
 * forward task management function requests to back-end
 * create TMF task in iSCSI session to be looked up on TMF response
 */
static int iscsi_task_cmd(struct iscsi_connection *conn, struct iscsi_pdu *pdu)
{
	struct scsi_task *task, *rtask;

	task = iscsi_create_task(conn, pdu);
	if (task == NULL) {
		iscsi_free_pdu(pdu);
		return -ENOMEM;
	}

	switch (task->tmf) {
	case ISCSI_ABORT_TASK:
		/*
		 * according to iSCSI RFC section 10.5.5
		 * the CmdSN of the command to be aborted has to be specified
		 * we have to rewrite the CmdSN to match the on used by vIni
		 */
		rtask = iscsi_lookup_task(conn, task->refitt);
		if (!rtask)
			break;
		bhs_set_refcmdsn(pdu, rtask->vini_cmdsn);
		break;
	case ISCSI_ABORT_TASK_SET:
	case ISCSI_CLEAR_TASK_SET:
	case ISCSI_CLEAR_ACA:
	case ISCSI_LOGICAL_UNIT_RESET:
	case ISCSI_TARGET_WARM_RESET:
	case ISCSI_TARGET_COLD_RESET:
		break;
	default:
		printk(KERN_ERR "%s: invalid TMF code %d, ITT %d\n",
				__func__, task->tmf, task->refitt);
		iscsi_free_pdu(pdu);
		return -EINVAL;
	}
	//printk(KERN_INFO "%s: TMF %d\n", __func__, task->opcode);

	return iscsi_ini_port_output(pdu);
}

/*
 * abort tasks on positive TMF response
 */
static int iscsi_task_rsp(struct iscsi_connection *conn, struct iscsi_pdu *pdu)
{
	struct scsi_task *task, *rtask;
	uint8_t rsp;
	bool del_task = false;

	task = iscsi_lookup_task(conn, bhs_get_itt(pdu));
	if (!task) {
		printk(KERN_ERR "%s: TMF task with ITT %d not found\n",
				__func__, bhs_get_itt(pdu));
		return 0;
	}

	/*
	 * task state is owned by target
	 * clean up task set on our side on positive response
	 * if task not found we might have not processed the SCSI
	 * response yet and try to abort it
	 */
	rsp = bhs_get_rsp(pdu);
	if (rsp == ISCSI_FUNCTION_COMPLETE)
		del_task = true;
	if (rsp == ISCSI_TASK_NOT_FOUND)
		del_task = true;
	if (rsp == ISCSI_LUN_NOT_FOUND)
		del_task = true;

	if (del_task)
		switch (task->tmf) {
		case ISCSI_ABORT_TASK:
			rtask = iscsi_lookup_task(conn, task->refitt);
			if (!rtask)
				break;
			iscsi_abort_task(conn, rtask);
			break;
		case ISCSI_ABORT_TASK_SET:
		case ISCSI_CLEAR_TASK_SET:
		case ISCSI_LOGICAL_UNIT_RESET:
			/*
			 * abort all tasks of LUN in connection/session
			 * other virtual initiator ports might see a unit attention
			 */
			iscsi_abort_task_set(conn, task->lun, task->vini_cmdsn);
			break;
		case ISCSI_CLEAR_ACA:
			break;
		case ISCSI_TARGET_WARM_RESET:
		case ISCSI_TARGET_COLD_RESET:
			/*
			 * abort all task on connection
			 * other virtual initiator ports might see a unit attention
			 * target cold reset tears down the connection, so we race with
			 * the disconnect handler in this case
			 */
			iscsi_abort_all_tasks(conn, false);
			break;
		default:
			printk(KERN_ERR "%s: invalid TMF code %d, ITT %d\n",
					__func__, task->tmf, task->refitt);
			return -EINVAL;
		}
	iscsi_destroy_task(conn, task);

	return 0;
}

/*
 * Allocate new socket buffer for iSCSI data segment
 */
static inline struct sk_buff *
iscsi_alloc_data(struct iscsi_connection *conn, bool direction)
{
	size_t skb_size;
	struct sk_buff *skb;
	struct tcpproxy_session *ses = conn->ses;
	struct socket *sock = direction ? ses->ses_inbound_sock :
		ses->ses_outbound_sock;

	skb_size = sizeof(conn->data_buf);
	skb_size = ALIGN(skb_size, 4);
	skb = alloc_skb(skb_size + sock->sk->sk_prot->max_header, GFP_KERNEL);
	if (!skb)
		return NULL;
	/* reserver head room for TCP/IP headers */
	skb_reserve(skb, skb_tailroom(skb)-sizeof(conn->data_buf));

	return skb;
}

/*
 * attach/replace data segment of PDU
 */
static inline void
iscsi_pdu_attach_data(struct iscsi_pdu *pdu, struct sk_buff *skb)
{
	/* update data length */
	bhs_set_data_len(pdu, skb->len);
	/* add NULL bytes after data segment */
	iscsi_pad(skb);
	skb_queue_purge(&pdu->data_skb_queue);
	skb_queue_tail(&pdu->data_skb_queue, skb);
}

/*
 * parse iSCSI text command and response
 */
static int iscsi_text(struct iscsi_pdu *pdu, bool direction)
{
	struct iscsi_connection *conn = pdu->conn;
	__be32 loc_addr, addr;
	__be16 loc_port;
	size_t text_len, kv_len;
	char *dp, *p, *addr_str, *tpgt, *sep;
	struct sk_buff *skb;
	struct tcpproxy_session *ses = conn->ses;

	/* get local address and port of proxy */
	loc_addr = inet_sk(ses->ses_inbound_sock->sk)->inet_saddr;
	loc_port = inet_sk(ses->ses_inbound_sock->sk)->inet_sport;

	/* XXX need more testing */
	if (bhs_get_pduflags(pdu) & ISCSI_CONTINUE)
		printk(KERN_WARNING "%s: more data to come in login cmd."
				" This hasn't been fully tested yet!\n", __func__);

	/* allocate new socket buffer */
	skb = iscsi_alloc_data(conn, direction);
	if (skb == NULL) {
		printk(KERN_ERR "%s: out of memory\n", __func__);
		return -ENOMEM;
	}

	/* extract key/value pairs after last text segment received */
	text_len = iscsi_copy_data(pdu);
	/* key/value pairs always null-terminated */
	conn->data_buf[sizeof(conn->data_buf)-1] = 0;
	if ((bhs_get_pduflags(pdu) & ISCSI_CONTINUE) == 0) {
		dp = conn->data_buf;
		while (dp < conn->data_buf + text_len) {
			kv_len = strlen(dp) + 1;
			if (kv_len == 1)
				break;
			printk(KERN_INFO "%s: %s (%s)\n",
					__func__, dp, direction ? "out" : "in");
			/* replace server address with proxy address */
			if (strstr(dp, "TargetAddress=")) {
				addr_str = dp + strlen("TargetAddress=");
				sep = strstr(addr_str, ",");
				if (sep) {
					*sep = 0;
					tpgt = sep+1;
					addr = in_aton(addr_str);
					printk(KERN_INFO "%s: replace target address %s"
							" with local address %pI4\n",
							__func__, addr_str, &loc_addr);
					*sep = ',';
					p = skb_tail_pointer(skb);
					skb_put(skb, sprintf(p, "TargetAddress=%pI4:%d,%s",
							&loc_addr, ntohs(loc_port), tpgt)+1);
					dp += kv_len;
					continue;
				}
			}
			/* copy all other key/value pairs */
			p = skb_put(skb, kv_len);
			memcpy(p, dp, kv_len);
			dp += kv_len;
		}
		conn->data_off = 0;
	}

	/* throw replace old TEXT segment with our own */
	iscsi_pdu_attach_data(pdu, skb);

	return 0;
}

/*
 * Attach an iSCSI target to a connection during login
 */
static int iscsi_attach_target(struct iscsi_connection *data)
{
	struct tcpproxy_session *ses = data->ses;
	struct iscsi_srv *srv = (struct iscsi_srv *)ses->ses_srv->srv_priv_data;
	struct iscsi_tgt *tgt;
	struct iscsi_it *it;

	if (data->it)
		return 0;

	if (srv == NULL) {
		printk(KERN_ERR "%s: iSCSI server not initialized\n", __func__);
		return -EINVAL;
	}

	tgt = iscsi_srv_lookup_tgt(srv, data->target_name, false);
	if (IS_ERR(tgt)) {
		printk(KERN_ERR "%s: iSCSI target %s not found\n", __func__,
				data->target_name);
		return PTR_ERR(tgt);
	}

	it = iscsi_tgt_lookup_it(tgt, data->initiator_name);
	if (IS_ERR(it)) {
		printk(KERN_ERR "%s: failed to initialize iSCSI I-T nexus between initiator %s and target %s\n",
				__func__, data->initiator_name, data->target_name);
		return PTR_ERR(it);
	}

	data->it = it;
	return 0;
}

/*
 * parse iSCIS login command and response
 */
static int iscsi_login(struct iscsi_pdu *pdu, bool direction)
{
	struct iscsi_connection *conn = pdu->conn;
	struct sk_buff *skb;
	size_t text_len, kv_len;
	char *p, *d;
	int res;

	/* XXX need more testing */
	if (bhs_get_pduflags(pdu) & ISCSI_CONTINUE)
		printk(KERN_WARNING "%s: more data to come in login cmd."
				" This hasn't been fully tested yet!\n", __func__);

	bhs_get_isid(pdu, conn->isid);
	bhs_print_isid(__func__, conn->isid);
	conn->cid = bhs_get_cid(pdu);
	printk("%s: CID = %x\n", __func__, conn->cid);
	text_len = iscsi_copy_data(pdu);
	/* key/value pairs always null-terminated */
	conn->data_buf[sizeof(conn->data_buf)-1] = 0;

	/* allocate new socket buffer */
	skb = iscsi_alloc_data(conn, direction);
	if (skb == NULL) {
		printk(KERN_ERR "%s: out of memory\n", __func__);
		return -ENOMEM;
	}

	/* extract key/value pairs after last text segment received */
	if ((bhs_get_pduflags(pdu) & ISCSI_CONTINUE) == 0) {
		p = conn->data_buf;
		while (p < conn->data_buf + text_len) {
			kv_len = strlen(p) + 1;	/* padding */
			if (kv_len == 1)
				break;
			printk(KERN_INFO "%s: %s (%s)\n",
					__func__, p, direction ? "out" : "in");

			/* command */
			if (direction == SERVER_DIR) {
				if (strstr(p, "InitiatorName=")) {
					d = p + strlen("InitiatorName=");
					strncpy(conn->initiator_name, d, ISCSI_NAME_MAX);
				}
				else if (strstr(p, "TargetName=")) {
					d = p + strlen("TargetName=");
					strncpy(conn->target_name, d, ISCSI_NAME_MAX);
				}
				else if (strstr(p, "SessionType=")) {
					d = p + strlen("SessionType=");
					if (!strcmp(d, "Normal"))
						conn->session_type = ISCSI_NORMAL_SESSION;
					else if (!strcmp(d, "Discovery"))
						conn->session_type = ISCSI_DISCOVERY_SESSION;
					else
						printk(KERN_WARNING "%s: Unknown SessionType %s\n",
								__func__, d);
				}
			}
			/* response */
			else {
				if (strstr(p, "DataDigest=")) {
					d = p + strlen("DataDigest=");
					if (!strcmp(d, "None"))
						conn->data_digest = ISCSI_DIGEST_NONE;
					else if (!strcmp(d, "CRC32C"))
						conn->data_digest = ISCSI_DIGEST_CRC32C;
					else {
						printk(KERN_INFO "%s: Unknown DataDigest %s\n",
								__func__, d);
						return -EINVAL;
					}
				}
				else if (strstr(p, "HeaderDigest=")) {
					d = p + strlen("HeaderDigest=");
					if (!strcmp(d, "None"))
						conn->header_digest = ISCSI_DIGEST_NONE;
					else if (!strcmp(d, "CRC32C"))
						conn->header_digest = ISCSI_DIGEST_CRC32C;
					else {
						printk(KERN_ERR "%s: Unknown HeaderDigest %s\n",
								__func__, d);
						return -EINVAL;
					}
				}
				/* we don't support any higher error recovery level */
				else if (strstr(p, "ErrorRecoveryLevel=")) {
					d = p + strlen("ErrorRecoveryLevel=");
					skb_put(skb, sprintf(skb_tail_pointer(skb), "ErrorRecoveryLevel=0")+1);
					p += kv_len;
					continue;
				}
				/* we don't support multiple connections per session */
				else if (strstr(p, "MaxConnections=")) {
					d = p + strlen("MaxConnections=");
					skb_put(skb, sprintf(skb_tail_pointer(skb), "MaxConnections=1")+1);
					p += kv_len;
					continue;
				}
				/* we don't support input frame markers */
				else if (strstr(p, "IFMarker=")) {
					d = p + strlen("IFMarker=");
					skb_put(skb, sprintf(skb_tail_pointer(skb), "IFMarker=No")+1);
					p += kv_len;
					continue;
				}
				/* we don't support output frame markers */
				else if (strstr(p, "OFMarker=")) {
					d = p + strlen("OFMarker=");
					skb_put(skb, sprintf(skb_tail_pointer(skb), "OFMarker=No")+1);
					p += kv_len;
					continue;
				}
			}

			/* copy key/value pair to new data segment */
			memcpy(skb_put(skb, kv_len), p, kv_len);
			p += kv_len;
		}
		conn->data_off = 0;
	}

	/* response */
	if (direction == CLIENT_DIR) {
		conn->state = bhs_get_pduflags(pdu) & ISCSI_NSG_MASK;
		if (conn->state == ISCSI_FULL_FEATURE_PHASE)
			printk(KERN_INFO "%s: Entered full-feature phase\n", __func__);
	}
	/* command */
	else if (conn->session_type == ISCSI_NORMAL_SESSION) {
		res = iscsi_attach_target(conn);
		if (res < 0) {
			kfree_skb(skb);
			return res;
		}
	}

	/* throw replace old TEXT segment with our own */
	iscsi_pdu_attach_data(pdu, skb);

	return 0;
}

/*
 * check header digest
 */
static int iscsi_check_hdr(struct iscsi_connection *data, struct iscsi_pdu *pdu)
{
	uint32_t crc1, crc2;
	off_t off;

#if !defined(CONFIG_LIBCRC32C_MODULE) && !defined(CONFIG_LIBCRC32C)
#	error "CRC32C digest algorithm not available"
#endif

	if (data->header_digest == ISCSI_DIGEST_CRC32C) {
		off = pdu->hdr_skb->len-4;
		//printk(KERN_INFO "%s: CRC offset = %d\n", __func__, (int)off);
		crc1 = ~crc32c(0xffffffff, pdu->hdr_skb->data, off);
		crc2 = *(uint32_t *)(pdu->hdr_skb->data + off);
		if (crc1 != crc2) {
			printk(KERN_ERR "header digest mismatch detected got %x expected %x\n",
					crc2, crc1);
			return false;
		}
	}
	return true;
}

/*
 * re-calculate header digest and update it
 * test this routine by hard-coding an arbitrary target address in iscis_text()
 */
static void iscsi_update_hdr(struct iscsi_connection *data, struct iscsi_pdu *pdu,
		bool direction)
{
	off_t off;
	uint32_t crc;

	/* update checksum */
	off = pdu->hdr_skb->len-4;
	if (data->header_digest == ISCSI_DIGEST_CRC32C && off >= 48) {
		//printk(KERN_INFO "%s: CRC offset = %d\n", __func__, (int)off);
		crc = ~crc32c(0xffffffff, pdu->hdr_skb->data, off);
		*(uint32_t *)(pdu->hdr_skb->data + off) = crc;
	}
}

static void iscsi_tgt_port_init(struct iscsi_tgt_port *tgt_port)
{
	memset(tgt_port, 0, sizeof(*tgt_port));
	tgt_port->qlen = CMD_WIN_SIZE;
}

static void iscsi_tgt_port_exit(struct iscsi_tgt_port *tgt_port)
{
	tgt_port->pending = 0;
}

/*
 * update sequence numbers as required by iSCSI
 */
static void iscsi_tgt_seq_output(struct iscsi_pdu *pdu, int incr_statsn)
{
	struct iscsi_connection *conn = pdu->conn;
	struct iscsi_tgt_port *tgt_port = &conn->tgt_port;
	int cmd_wnd;

	bhs_set_statsn(pdu, tgt_port->StatSN);
	bhs_set_expcmdsn(pdu, tgt_port->ExpCmdSN);

	/*
	 * pending is not 100 % accurate
	 * Both immediate and non-immediate commands get treated
	 * the same way. Immediate command also fill up the window.
	 * We might "waste" one command slot, so what?!
	 * Immediate commands are not affected by a full command window anyway.
	 */
	if (tgt_port->pending > 0)
		tgt_port->pending--;

	if (conn->session_type == ISCSI_DISCOVERY_SESSION ||
			bhs_get_opcode(pdu) == ISCSI_LOGIN_RSP)
		tgt_port->MaxCmdSN = tgt_port->ExpCmdSN + 1;
	else {
		cmd_wnd = max(0, tgt_port->qlen - tgt_port->pending);
		tgt_port->MaxCmdSN = tgt_port->ExpCmdSN + cmd_wnd - 1;
	}
	bhs_set_maxcmdsn(pdu, tgt_port->MaxCmdSN);

	/*printk(KERN_INFO "%s: PDU=%p StatSN=%d ExpCmdSN=%d MaxCmdSN=%d\n",
			__func__, pdu, tgt_port->StatSN, tgt_port->ExpCmdSN,
			tgt_port->MaxCmdSN);*/

	/* update sequence numbers */
	if (incr_statsn)
		tgt_port->StatSN++;
}

/*
 * update ExpCmdSN as required by iSCSI
 * check whether command window is full and drop PDU in this case
 * return false if PDU has been dropped
 */
static int iscsi_tgt_seq_input(struct iscsi_pdu *pdu)
{
	struct iscsi_connection *conn = pdu->conn;
	struct iscsi_tgt_port *tgt_port = &conn->tgt_port;
	int opcode = bhs_get_opcode(pdu);
	int immediate = false;

	/* queue both immediate and non-immediate commands */
	tgt_port->pending++;

	/* is immediate command? */
	if (pdu_hdr(pdu)->basehdr[0] & ISCSI_IMMEDIATE)
		immediate = true;
	/*
	 * login is implicit immediate command
	 * must be first command on connection
	 * get very first CmdSN from initiator
	 */
	if (opcode == ISCSI_LOGIN_CMD) {
		immediate = true;
		tgt_port->ExpCmdSN = bhs_get_cmdsn(pdu);
	}

	/* is command window closed? */
	if (!immediate && iscsi_sna_lt(tgt_port->MaxCmdSN, bhs_get_cmdsn(pdu))) {
		printk(KERN_WARNING "drop PDU due to closed command window\n");
		iscsi_free_pdu(pdu);
		return false;
	}

#ifdef ISCSI_FAULT_INJECT
	if (!immediate) {
		printk(KERN_INFO "drop PDU due to fault-injection\n");
		iscsi_free_pdu(pdu);
		return false;
	}
#endif

	/* update ExpCmdSN */
	if (!immediate)
		tgt_port->ExpCmdSN = bhs_get_cmdsn(pdu) + 1;

	/*printk(KERN_INFO "%s: PDU=%p ExpCmdSN=%d queued=%d\n",
			__func__, pdu, tgt_port->ExpCmdSN,
			tgt_port->pending);*/
	return true;
}

/*
 * forward all iSCSI PDUs except SCSI commands and write data
 * dispatch PDU to corresponding handler
 */
static int iscsi_tgt_port_input(struct iscsi_pdu *pdu)
{
	int opcode = bhs_get_opcode(pdu);
	int err = 0;

	if (opcode != ISCSI_WRITE_DATA && opcode != ISCSI_SNACK)
		if (!iscsi_tgt_seq_input(pdu))
			return 0;

	switch (opcode) {
	case ISCSI_NOP_OUT:
		dprintk(KERN_INFO "%s: NOP Out\n", __func__);
		break;
	case ISCSI_SCSI_CMD:
		dprintk(KERN_INFO "%s: SCSI Command\n", __func__);
		return iscsi_scsi_cmd(pdu->conn, pdu);
	case ISCSI_TASK_CMD:
		dprintk(KERN_INFO "%s: Task Command\n", __func__);
		return iscsi_task_cmd(pdu->conn, pdu);
	case ISCSI_LOGIN_CMD:
		dprintk(KERN_INFO "%s: Login Command\n", __func__);
		err = iscsi_login(pdu, SERVER_DIR);
		break;
	case ISCSI_TEXT_CMD:
		dprintk(KERN_INFO "%s: Text Command\n", __func__);
		err = iscsi_text(pdu, SERVER_DIR);
		break;
	case ISCSI_LOGOUT_CMD:
		dprintk(KERN_INFO "%s: Logout Command\n", __func__);
		break;
	case ISCSI_WRITE_DATA:
		dprintk(KERN_INFO "%s: Write Data\n", __func__);
		return iscsi_write_data(pdu->conn, pdu);
	case ISCSI_SNACK:
		printk(KERN_ERR "%s: SNACK not supported, close connection\n", __func__);
		err = -EINVAL;
		break;
	default:
		/* XXX reject PDU */
		printk(KERN_INFO "%s: Invalid iSCSI opcode %x\n", __func__, opcode);
		err = -EINVAL;
		break;
	}

	if (err < 0) {
		iscsi_free_pdu(pdu);
		return err;
	}

	return iscsi_ini_port_output(pdu);
}

static int iscsi_tgt_port_output(struct iscsi_pdu *pdu)
{
	int opcode = bhs_get_opcode(pdu);
	struct iscsi_connection *conn = pdu->conn;
	int err = 0;

	switch (opcode) {
	case ISCSI_NOP_IN:
		if (bhs_get_itt(pdu) == ISCSI_RESERVED_TAG)
			iscsi_tgt_seq_output(pdu, false);
		else
			iscsi_tgt_seq_output(pdu, true);
		dprintk(KERN_INFO "%s: NOP In\n", __func__);
		break;
	case ISCSI_SCSI_RSP:
		dprintk(KERN_INFO "%s: SCSI Response\n", __func__);
		err = iscsi_scsi_rsp(pdu->conn, pdu);
		if (err >= 0)
			iscsi_tgt_seq_output(pdu, true);
		break;
	case ISCSI_TASK_RSP:
		dprintk(KERN_INFO "%s: Task Response\n", __func__);
		err = iscsi_task_rsp(pdu->conn, pdu);
		if (err >= 0)
			iscsi_tgt_seq_output(pdu, true);
		break;
	case ISCSI_LOGIN_RSP:
		dprintk(KERN_INFO "%s: Login Response\n", __func__);
		err = iscsi_login(pdu, CLIENT_DIR);
		if (err >= 0)
			iscsi_tgt_seq_output(pdu, true);
		break;
	case ISCSI_TEXT_RSP:
		dprintk(KERN_INFO "%s: Text Response\n", __func__);
		err = iscsi_text(pdu, CLIENT_DIR);
		if (err >= 0)
			iscsi_tgt_seq_output(pdu, true);
		break;
	case ISCSI_READ_DATA:
		dprintk(KERN_INFO "%s: Write Data\n", __func__);
		if (bhs_get_pduflags(pdu) & ISCSI_STATUS)  {
			err = iscsi_scsi_rsp(pdu->conn, pdu);
			if (err >= 0)
				iscsi_tgt_seq_output(pdu, true);
		}
		else
			iscsi_tgt_seq_output(pdu, false);
		break;
	case ISCSI_LOGOUT_RSP:
		dprintk(KERN_INFO "%s: Logout Response\n", __func__);
		/*
		 * only support one connection per session
		 * implicitly abort all tasks in session/connection
		 */
		if (bhs_get_rsp(pdu) == 0) {
			iscsi_abort_all_tasks(conn, true);
			conn->state = ISCSI_SEC_NEGOTIATION;
			conn->header_digest = ISCSI_DIGEST_NONE;
			conn->data_digest = ISCSI_DIGEST_NONE;
		}
		iscsi_tgt_seq_output(pdu, true);
		break;
	case ISCSI_R2T:
		dprintk(KERN_INFO "%s: R2T\n", __func__);
		iscsi_tgt_seq_output(pdu, false);
		break;
	case ISCSI_ASYNC:
		dprintk(KERN_INFO "%s: Async\n", __func__);
		iscsi_tgt_seq_output(pdu, true);
		break;
	case ISCSI_REJECT:
		dprintk(KERN_INFO "%s: Reject\n", __func__);
		iscsi_tgt_seq_output(pdu, true);
		break;
	default:
		err = -EINVAL;
		printk(KERN_INFO "%s: Unknown iSCSI opcode %x\n", __func__, opcode);
		break;
	}

	if (err < 0) {
		iscsi_free_pdu(pdu);
		return err;
	}

	return iscsi_output(pdu, CLIENT_DIR);
}

static void iscsi_ini_port_init(struct iscsi_ini_port *ini_port)
{
	memset(ini_port, 0, sizeof(*ini_port));
	/* make sure virt and phys CmdSNs don't match - for testing */
	ini_port->CmdSN = ini_port->MaxCmdSN = 42;
	INIT_LIST_HEAD(&ini_port->cmd_queue);
}

static void iscsi_ini_port_exit(struct iscsi_ini_port *ini_port)
{
	struct iscsi_pdu *pdu, *tmppdu;

	list_for_each_entry_safe(pdu, tmppdu, &ini_port->cmd_queue, list) {
		iscsi_free_pdu(pdu);
		list_del(&pdu->list);
	}
}

/*
 * sequences command as required by iSCSI, takes ownership of PDU
 */
static int iscsi_ini_port_output(struct iscsi_pdu *pdu)
{
	int err;
	struct iscsi_connection *conn = pdu->conn;
	struct iscsi_ini_port *ini_port = &conn->ini_port;
	uint8_t op;
	int immediate = false;

	/*printk(KERN_INFO "%s: PDU=%p CmdSN=%d ExpStatSN=%d\n",
			__func__, pdu, ini_port->CmdSN, ini_port->ExpStatSN);*/

	/* only sequence commands, let data pass-through always */
	op = bhs_get_opcode(pdu);
	if (op == ISCSI_WRITE_DATA) {
		bhs_set_expstatsn(pdu, ini_port->ExpStatSN);
		return iscsi_output(pdu, SERVER_DIR);
	}

	/* is immediate command? */
	if (pdu_hdr(pdu)->basehdr[0] & ISCSI_IMMEDIATE)
		immediate = true;
	else if (op == ISCSI_LOGIN_CMD)
		immediate = true;
	else if (op == ISCSI_LOGOUT_CMD)
		immediate = true;

	bhs_set_cmdsn(pdu, ini_port->CmdSN);
	bhs_set_expstatsn(pdu, ini_port->ExpStatSN);
	if (pdu->task)
		pdu->task->vini_cmdsn = ini_port->CmdSN;

	/*
	 * is command window closed?
	 * queue commands + unsolicited data to be send in iscsi_ini_port_input()
	 */
	if (iscsi_sna_lt(ini_port->MaxCmdSN, ini_port->CmdSN)) {
		/*printk(KERN_INFO "command window is closed (CmdSN=%d, MaxCmdSN=%d)\n",
				ini_port->CmdSN, ini_port->MaxCmdSN);*/
		list_add_tail(&pdu->list, &ini_port->cmd_queue);
	}
	else {
		err = iscsi_output(pdu, SERVER_DIR);
		if (err)
			return err;
	}

	/* don't advance CmdSN for immediate commands */
	if (!immediate)
		ini_port->CmdSN++;

	return 0;
}

static int iscsi_ini_port_input(struct iscsi_pdu *pdu)
{
	struct iscsi_connection *conn = pdu->conn;
	struct iscsi_ini_port *ini_port = &conn->ini_port;
	struct iscsi_pdu *tmppdu;
	int err;

	if (iscsi_sna_lt(ini_port->ExpStatSN, bhs_get_statsn(pdu) + 1))
		ini_port->ExpStatSN = bhs_get_statsn(pdu) + 1;
	if (iscsi_sna_lt(ini_port->MaxCmdSN, bhs_get_maxcmdsn(pdu)))
		ini_port->MaxCmdSN = bhs_get_maxcmdsn(pdu);
	if (iscsi_sna_lt(ini_port->ExpCmdSN, bhs_get_expcmdsn(pdu)))
		ini_port->ExpCmdSN = bhs_get_expcmdsn(pdu);
	/*printk(KERN_INFO "%s: PDU=%p ExpCmdSN=%d, MaxCmdSN=%d ExpStatSN=%d\n",
			__func__, pdu, ini_port->ExpCmdSN, ini_port->MaxCmdSN,
			ini_port->ExpStatSN);*/

	err = iscsi_tgt_port_output(pdu);
	if (err)
		return err;

	/* send pending commands till command window in closed */
	list_for_each_entry_safe(pdu, tmppdu, &ini_port->cmd_queue, list) {
		if (bhs_get_opcode(pdu) != ISCSI_WRITE_DATA)
			if (iscsi_sna_lt(ini_port->MaxCmdSN, bhs_get_cmdsn(pdu)))
				break;
		err = iscsi_output(pdu, SERVER_DIR);
		if (err) {
			printk(KERN_ERR "failed to send queued command (err=%d)\n", err);
			break;
		}
		list_del(&pdu->list);
	}

	return err;
}

static int iscsi_input(struct iscsi_connection *conn, struct iscsi_pdu *pdu,
		bool direction)
{
	if (!iscsi_check_hdr(conn, pdu)) {
		iscsi_free_pdu(pdu);
		return -EINVAL;
	}

	/* let either iSCSI initiator or target process PDU */
	if (direction == SERVER_DIR)
		return iscsi_tgt_port_input(pdu);
	else
		return iscsi_ini_port_input(pdu);
}

static int iscsi_output(struct iscsi_pdu *pdu,
		bool direction)
{
	int err;

	/* update data segment size and header checksum */
	iscsi_update_hdr(pdu->conn, pdu, direction);

	/* forward PDU */
	err = iscsi_send_pdu(pdu->conn->ses, pdu, direction);
	iscsi_free_pdu(pdu);
	if (err < 0) {
		printk(KERN_ERR "%s: send failed with %d\n", __func__, err);
		return err;
	}

	return 0;
}

/*
 * Transport-specific output function for IO scheduler
 */
static int iscsi_iosched_output(struct iosched_operation *op, bool lock)
{
	struct iscsi_pdu* pdu = (struct iscsi_pdu *)op;
	struct iscsi_connection *conn = pdu->conn;
	struct tcpproxy_session *ses = conn->ses;
	struct iscsi_itl *itl;
	struct scsi_task *task = pdu->task;
	int err;

	if (lock) tcpproxy_session_lock(ses);
	itl = iscsi_get_itl(conn, task->lun);
	if (itl == NULL)  {
		iscsi_free_pdu(pdu);
		err = -ENOENT;
		goto out;
	}
	/* update ITL stats */
	err = iscsi_itl_command(itl, task);
	if (err < 0) {
		iscsi_free_pdu(pdu);
		goto out;
	}
	err = iscsi_ini_port_output(pdu);

out:
	if (lock) tcpproxy_session_unlock(ses);
	/* release connection once IO scheduler is finished with PDU */
	tcpproxy_session_put(ses);
	return err;
}

static void iscsi_pdu_ctor(void *p)
{
	struct iscsi_pdu *pdu = (struct iscsi_pdu *)p;
	/* iSCSI data segment will be stored in sk_buff queue */
	skb_queue_head_init(&pdu->data_skb_queue);
	skb_queue_head_init(&pdu->send_skb_queue);
}

/*
 * reset parse state of PDU
 * allocate new socket buffer for iSCSI header
 */
static int iscsi_init_pdu(struct iscsi_pdu *pdu)
{
	struct sk_buff *skb;

	dprintk(KERN_INFO "%s: init PDU %p\n", __func__, pdu);
	INIT_LIST_HEAD(&pdu->list);
	INIT_LIST_HEAD(&pdu->data_list);
	pdu->state.offset = 0;
	pdu->state.remBaseHdr = ISCSI_BHS_SIZE;
	pdu->task = NULL;
	pdu->tstamp1.tv64 = 0;
	pdu->tstamp2.tv64 = 0;
	/* allocate socket buffer for iSCSI header */
	skb = alloc_skb(ISCSI_MAX_HDR_SIZE + MAX_TCP_HEADER,
			GFP_KERNEL);
	pdu->hdr_skb = skb;
	if (skb == NULL) {
		printk(KERN_ERR "%s: out of memory\n", __func__);
		return -ENOBUFS;
	}
	/* reserve head room for protocol headers */
	skb_reserve(skb, skb_tailroom(skb) - ISCSI_MAX_HDR_SIZE);

	return 0;
}

static struct iscsi_pdu *iscsi_alloc_pdu(struct iscsi_connection *conn)
{
	struct iscsi_pdu *pdu;
	int err;

	pdu = (struct iscsi_pdu *)mempool_alloc(pdu_mempool, GFP_NOFS);
	if (!pdu)
		return NULL;
	err = iscsi_init_pdu(pdu);
	if (err < 0) {
		mempool_free(pdu, pdu_mempool);
		return NULL;
	}
	pdu->conn = conn;

	return pdu;
}

static void iscsi_free_pdu(struct iscsi_pdu *pdu)
{
	struct iscsi_pdu *p, *tmp;

	if (unlikely(!pdu))
		return;
	dprintk(KERN_INFO "%s: pdu=%p\n", __func__, pdu);
	list_for_each_entry_safe(p, tmp, &pdu->data_list, list)
		iscsi_free_pdu(p);
	kfree_skb(pdu->hdr_skb);
	skb_queue_purge(&pdu->data_skb_queue);
	skb_queue_purge(&pdu->send_skb_queue);
	mempool_free(pdu, pdu_mempool);
}

static inline void
iscsi_queue_pdu(struct sk_buff_head *queue, struct iscsi_pdu *pdu)
{
	struct sk_buff *skb;

	dprintk(KERN_INFO "%s: pdu=%p\n", __func__, pdu);
	skb_queue_tail(queue, pdu->hdr_skb);
	pdu->hdr_skb = NULL;
	while ((skb = skb_dequeue(&pdu->data_skb_queue)))
		skb_queue_tail(queue, skb);
}

static int iscsi_send_pdu(struct tcpproxy_session *ses,
		struct iscsi_pdu *pdu, bool direction)
{
	int res;
	struct iscsi_pdu *data_pdu;
	struct socket *sock = direction ? ses->ses_inbound_sock :
		ses->ses_outbound_sock;

	dprintk(KERN_INFO "%s: send PDU %p, dir=%d\n", __func__, pdu, direction);
	iscsi_queue_pdu(&pdu->send_skb_queue, pdu);
	list_for_each_entry(data_pdu, &pdu->data_list, list)
		iscsi_queue_pdu(&pdu->send_skb_queue, data_pdu);

	res = tcp_send_skb_queue(sock->sk, &pdu->send_skb_queue);
	if (iscsi_stats.enabled && pdu->tstamp1.tv64 && pdu->tstamp2.tv64) {
		spin_lock(&iscsi_stats.lock);
		iscsi_stats.latency1 = ktime_add(iscsi_stats.latency1,
				ktime_sub(ktime_get_real(), pdu->tstamp1));
		iscsi_stats.latency2 = ktime_add(iscsi_stats.latency2,
				ktime_sub(ktime_get_real(), pdu->tstamp2));
		iscsi_stats.pdus++;
		spin_unlock(&iscsi_stats.lock);
	}

	return res;
}

/*
 * Queue partial socket buffer to PDU
 * pskb_copy() copied the skb header.
 * skb_split() might me more efficient depending on the size of the skb header
 */
inline static int
pdu_queue_skb(struct sk_buff_head *queue, struct sk_buff *skb, int offset, 
	int len, int *queued_skb)
{
	struct sk_buff *nskb;

	if (offset == 0 && len == skb->len) {
		*queued_skb = true;
		skb_queue_tail(queue, skb);
		return skb->len;
	}
	else {
		dprintk(KERN_INFO "%s: copy skb header, off=%d, len=%d\n",
				__func__, offset, len);
		nskb = pskb_copy(skb, GFP_KERNEL);
		if (!nskb)
			return -ENOBUFS;
		pskb_pull(nskb, offset);
		pskb_trim(nskb, len);
		skb_queue_tail(queue, nskb);
		return nskb->len;
	}
}

/*
 * Parse iSCSI BHS, all AHS and data segment
 */
static int iscsi_process_skb(struct iscsi_connection *conn,
		struct sk_buff *skb, bool direction)
{
	struct iscsi_pdu *pdu;
	unsigned char *buf;
	struct iscsi_parse_state *st;
	int offset = 0;	/* offset within skb */
	int queued_skb = false;
	int res = 0;
	int copy;

	dprintk(KERN_INFO "%s: skb=%p, skb->len=%d, dir=%d", __func__,
			skb, skb->len, direction);

	while (offset < skb->len) {
		if (direction == false)
			pdu = conn->inbound_pdu;
		else
			pdu = conn->outbound_pdu;
		/* allocate PDU if needed */
		if (pdu == NULL) {
			pdu = iscsi_alloc_pdu(conn);
			if (pdu == NULL) {
				res = -ENOMEM;
				goto out;
			}
			if (direction == false)
				conn->inbound_pdu = pdu;
			else
				conn->outbound_pdu = pdu;
			if (skb->tstamp.tv64)
				pdu->tstamp1 = skb_get_ktime(skb);
		}

		st = &pdu->state;
		buf = pdu->hdr_skb->data;
		/* parse and copy basic header segment */
		if (st->remBaseHdr) {
			dprintk(KERN_INFO "%s: parse BHS remBHS=%d, offset=%d", __func__,
					st->remBaseHdr, offset);
			if (offset + st->remBaseHdr <= skb->len)
				copy = st->remBaseHdr;
			else
				copy =  skb->len - offset;
			/* copy header to linear socket buffer */
			BUG_ON(st->offset + copy > ISCSI_BHS_SIZE);
			skb_copy_bits(skb, offset, &buf[st->offset], copy);
			st->remBaseHdr -= copy;
			st->offset += copy;
			offset += copy;

			/* finished parsing BHS */
			if (st->remBaseHdr == 0) {
				st->remExtHdr = bhs_get_total_ahs_len(pdu) * 4;
				st->remData = bhs_get_data_len(pdu);
				/* enable header and data digests in full-feature phase */
				if (conn->state == ISCSI_FULL_FEATURE_PHASE) {
					if (conn->header_digest == ISCSI_DIGEST_CRC32C)
						st->remExtHdr += 4;
					if (conn->data_digest == ISCSI_DIGEST_CRC32C)
						st->remData += 4;
				}
				if (ISCSI_BHS_SIZE + st->remExtHdr > ISCSI_MAX_HDR_SIZE) {
					printk(KERN_WARNING "%s: extended iSCSI header size %d too large\n",
							__func__, st->remExtHdr);
					res = -EINVAL;
					goto out;
				}
				skb_put(pdu->hdr_skb, ISCSI_BHS_SIZE + st->remExtHdr);
				dprintk(KERN_INFO "%s: BHS finished offset=%d data len=%d ext hdr len = %d\n",
						__func__, offset, st->remData, st->remExtHdr);
			}
		}
		/* parse header extensions like AHS and header digest */
		else if (st->remExtHdr) {
			dprintk(KERN_INFO "%s: parse AHS remAHS=%d, offset=%d", __func__,
					st->remExtHdr, offset);
			if (offset + st->remExtHdr <= skb->len)
				copy = st->remExtHdr;
			else
				copy =  skb->len - offset;
			/* copy header to linear socket buffer */
			BUG_ON(st->offset + copy > ISCSI_MAX_HDR_SIZE);
			skb_copy_bits(skb, offset, &buf[st->offset], copy);
			st->remExtHdr -= copy;
			st->offset += copy;
			offset += copy;
		}
		/* parse data segment and data digest */
		else if (st->remData) {
			dprintk(KERN_INFO "%s: parse Data remData=%d, offset=%d", __func__,
					st->remData, offset);
			if (offset + st->remData <= skb->len)
				copy = st->remData;
			else
				copy =  skb->len - offset;
			res = pdu_queue_skb(&pdu->data_skb_queue, skb, offset, copy, &queued_skb);
			if (res < 0)
				goto out;
			st->remData -= copy;
			offset += copy;
		}

		/* iSCSI PDU received completely */
		if (st->remBaseHdr + st->remExtHdr + st->remData == 0) {
			dprintk(KERN_INFO "%s: PDU finished opcode=%d\n",
					__func__, bhs_get_opcode(pdu));
			if (direction == SERVER_DIR)
				conn->inbound_pdu = NULL;
			else
				conn->outbound_pdu = NULL;
			if (skb->tstamp.tv64)
				pdu->tstamp2 = skb_get_ktime(skb);
			/* let iSCSI protocol engine process PDU */
			res = iscsi_input(conn, pdu, direction);
			if (res < 0)
				goto out;
			/* skb got forwarded, we don't own it anymore! */
			if (queued_skb)
				goto out;
		}
	}

out:
	if (!queued_skb)
		kfree_skb(skb);
	return res;
}

/*
 * Parse in and out-bound iSCSI PDUs
 * A direction of 0 indicates in-bound traffic.
 */
static int iscsi_process_recv_queue(struct iscsi_connection *data,
		struct sk_buff_head *queue, bool direction)
{
	int res = 0;
	struct sk_buff *skb;

	dprintk(KERN_INFO "%s: queue=%p, dir=%d", __func__, queue, direction);
	while ((skb = skb_dequeue(queue))) {
		res = iscsi_process_skb(data, skb, direction);
		if (res < 0)
			break;
	}

	return res;
}

/*
 * Receive and queue in-bound iSCSI PDUs.
 * Forward PDUs afterward.
 */
int iscsi_recv_pdu(struct tcpproxy_session *ses, bool direction)
{
	int res;
	struct sk_buff_head skb_queue;
	struct socket *sock;
	struct iscsi_connection *data;

	skb_queue_head_init(&skb_queue); // move to connection create
	tcpproxy_session_lock(ses);
	data = (struct iscsi_connection *)ses->ses_priv_data;

	/* forward from initiator to target */
	if (direction == SERVER_DIR)
		sock = ses->ses_inbound_sock;
	/* forward from target to initiator */
	else
		sock = ses->ses_outbound_sock;

	/* receive socket buffers */
	res = tcp_recv_skb_queue(sock->sk, &skb_queue);
	if (res == -EAGAIN) {
		res = 0;
		goto out;
	}
	if (res < 0) {
		printk(KERN_ERR "%s: receive failed with %d\n", __func__, res);
		goto out;
	}
	if (skb_queue_empty(&skb_queue))
		goto out;

	/* parse PDUs from socket buffers */
	res = iscsi_process_recv_queue(data, &skb_queue, direction);
	if (res < 0)
		goto out;

out:
	tcpproxy_session_unlock(ses);
	return res;
}

/*
 * Receive and forward in-bound iSCSI PDUs.
 */
int iscsi_inbound_flt(struct tcpproxy_session *ses)
{
	return iscsi_recv_pdu(ses, false);
}

/*
 * Receive and forward out-bound iSCSI PDUs.
 */
int iscsi_outbound_flt(struct tcpproxy_session *ses)
{
	return iscsi_recv_pdu(ses, true);
}

/*
 * Dequeue PDUs and forward them to target
 */
void iscsi_sched(struct list_head *list)
{
	static unsigned long logger_timeout = 0;
	static unsigned long stats_timeout = 0;
	static unsigned long fg_timeout = 0;
	static unsigned long ffg_timeout = 0;
	int latency1=0, latency2=0, pdus=0;
	s64 cum_latency;

	/* collect fine-fine-grained metrics */
	if (iscsi_ffg_metrics && time_after(jiffies, ffg_timeout)) {
		ffg_timeout = jiffies + HZ/100;
		iscsi_aggregate(SCSI_AGGR_FFG);
	}

	/* collect fine-grained metrics */
	if (iscsi_fg_metrics && time_after(jiffies, fg_timeout)) {
		fg_timeout = jiffies + HZ/10;
		iscsi_aggregate(SCSI_AGGR_FG);
	}

	if (iscsi_metrics && time_after(jiffies, logger_timeout)) {
		logger_timeout = jiffies + 6*HZ;
		iscsi_aggregate(SCSI_LOG);
	}

	if (iscsi_stats.enabled && time_after(jiffies, stats_timeout)) {
		spin_lock(&iscsi_stats.lock);
		pdus = iscsi_stats.pdus;
		if (pdus) {
			cum_latency = ktime_to_us(iscsi_stats.latency1);
			latency1 = div64_u64(cum_latency, pdus);
			cum_latency = ktime_to_us(iscsi_stats.latency2);
			latency2 = div64_u64(cum_latency, pdus);
		}
		iscsi_stats.latency1.tv64 = 0;
		iscsi_stats.latency2.tv64 = 0;
		iscsi_stats.pdus = 0;
		spin_unlock(&iscsi_stats.lock);

		printk(KERN_INFO "iscsi stats: #pdu=%d, latency1=%d us, latency2=%d us",
				pdus, latency1, latency2);
		stats_timeout = jiffies + 60*HZ;
	}

	if (iscsi_fg_metrics)
		tcpproxy_iscsi_scheduler.tps_interval = HZ/10;
	else if (iscsi_ffg_metrics)
		tcpproxy_iscsi_scheduler.tps_interval = HZ/100;
	else
		tcpproxy_iscsi_scheduler.tps_interval = 6*HZ;
}

void iscsi_exit_flt(void)
{
	iscsi_logger_exit();
	iscsi_target_exit();
	/* target references IO scheduler data */
	iosched_exit();
	if (task_mempool)
		mempool_destroy(task_mempool);
	if (task_slab)
		kmem_cache_destroy(task_slab);
	if (pdu_mempool)
		mempool_destroy(pdu_mempool);
	if (pdu_slab)
		kmem_cache_destroy(pdu_slab);
}

int iscsi_init_flt(void)
{
	int err;

	memset(&iscsi_stats, 0, sizeof(iscsi_stats));
	spin_lock_init(&iscsi_stats.lock);

	task_slab = kmem_cache_create("scsi_tasks",
					sizeof(struct scsi_task),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!task_slab)
		return -ENOMEM;

	task_mempool = mempool_create_slab_pool(TASK_POOLSIZE, task_slab);
	if (!task_mempool) {
		iscsi_exit_flt();
		return -ENOMEM;
	}

	pdu_slab = kmem_cache_create("iscsi_pdu",
					sizeof(struct iscsi_pdu),
					0, SLAB_HWCACHE_ALIGN,
					iscsi_pdu_ctor);
	if (!pdu_slab) {
		iscsi_exit_flt();
		return -ENOMEM;
	}

	pdu_mempool = mempool_create_slab_pool(PDU_POOLSIZE, pdu_slab);
	if (!pdu_mempool) {
		iscsi_exit_flt();
		return -ENOMEM;
	}

	err = iscsi_target_init();
	if (err > 0) {
		iscsi_exit_flt();
		return err;
	}

	err = iscsi_logger_init();
	if (err > 0) {
		iscsi_exit_flt();
		return err;
	}

	err = iosched_init();
	if (err > 0) {
		iscsi_exit_flt();
		return err;
	}

	return 0;
}

static int iscsi_print_pending(char *msg, size_t *size)
{
	struct tcpproxy_filter *flt = &tcpproxy_iscsi_filter;
	struct tcpproxy_session *ses;
	struct iscsi_connection *data;
	char *p = msg;
	__be32 addr;

	p += sprintf(p, "connection stats:\n");
	down_write(&flt->tpf_sem);
	list_for_each_entry (ses, &flt->tpf_ses_list, ses_list) {
		tcpproxy_session_lock(ses);
		data = (struct iscsi_connection *)ses->ses_priv_data;
		addr = inet_sk(ses->ses_inbound_sock->sk)->inet_daddr;
		p += sprintf(p, "%s (%pI4): tasks=%d\n", data->initiator_name,
				&addr, data->num_tasks);
		tcpproxy_session_unlock(ses);
	}
	up_write(&flt->tpf_sem);

	*p++ = 0;
	*size = p - msg;
	return 0;
}

static int iscsi_add_tgt(char *msg, size_t *size)
{
	int res;
	char addrstr[16];
	char iqn[ISCSI_NAME_MAX];
	struct sockaddr_storage addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
	int port;
	struct iscsi_srv *srv;
	struct iscsi_tgt *tgt;

	res = sscanf(msg, "flt iscsi add tgt %s %d %s", addrstr, &port, iqn);
	if (res != 3)
		return -EINVAL;
	memset(&addr, 0, sizeof(struct sockaddr_storage));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = in_aton(addrstr);
	sin->sin_port = htons(port);

	srv = iscsi_srv_lookup(&addr, false);
	if (IS_ERR(srv))
		return PTR_ERR(srv);

	tgt = iscsi_srv_lookup_tgt(srv, iqn, true);
	if (IS_ERR(tgt))
		return PTR_ERR(tgt);

	*size = sprintf(msg, "added iSCSI target %s on server %s\n",
			iqn, addrstr);
	return 0;
}

static int iscsi_add_lun(char *msg, size_t *size)
{
	int res;
	char addrstr[16];
	char iqn[ISCSI_NAME_MAX];
	struct sockaddr_storage addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
	int port;
	struct iscsi_srv *srv;
	struct iscsi_tgt *tgt;
	struct iscsi_lun *lun;
	int lunid;

	res = sscanf(msg, "flt iscsi add lun %s %d %s %d", addrstr, &port, iqn, &lunid);
	if (res != 4)
		return -EINVAL;
	memset(&addr, 0, sizeof(struct sockaddr_storage));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = in_aton(addrstr);
	sin->sin_port = htons(port);

	srv = iscsi_srv_lookup(&addr, false);
	if (IS_ERR(srv))
		return PTR_ERR(srv);

	tgt = iscsi_srv_lookup_tgt(srv, iqn, false);
	if (IS_ERR(tgt))
		return PTR_ERR(tgt);

	lun = iscsi_tgt_lookup_lun(tgt, lunid, true);
	if (IS_ERR(lun))
		return PTR_ERR(lun);

	*size = sprintf(msg, "added iSCSI LUN %d of target %s on server %s\n",
			lunid, iqn, addrstr);
	return 0;
}

int iscsi_print_tgts(char *msg, size_t *size)
{
	int res;
	char addrstr[16];
	int port;
	struct sockaddr_storage addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
	struct iscsi_srv *srv;

	res = sscanf(msg, "flt iscsi print tgt %s %d", addrstr, &port);
	if (res != 2)
		return -EINVAL;
	memset(&addr, 0, sizeof(struct sockaddr_storage));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = in_aton(addrstr);
	sin->sin_port = htons(port);

	srv = iscsi_srv_lookup(&addr, false);
	if (IS_ERR(srv))
		return PTR_ERR(srv);

	return iscsi_srv_dump_tgts(srv, msg, size);
}

int iscsi_print_luns(char *msg, size_t *size)
{
	int res;
	char addrstr[16];
	char iqn[ISCSI_NAME_MAX];
	int port;
	struct sockaddr_storage addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
	struct iscsi_srv *srv;
	struct iscsi_tgt *tgt;

	res = sscanf(msg, "flt iscsi print lun %s %d %s", addrstr, &port, iqn);
	if (res != 3)
		return -EINVAL;
	memset(&addr, 0, sizeof(struct sockaddr_storage));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = in_aton(addrstr);
	sin->sin_port = htons(port);

	srv = iscsi_srv_lookup(&addr, false);
	if (IS_ERR(srv))
		return PTR_ERR(srv);

	tgt = iscsi_srv_lookup_tgt(srv, iqn, false);
	if (IS_ERR(tgt))
		return PTR_ERR(tgt);

	return iscsi_tgt_dump_luns(tgt, msg, size);
}

int iscsi_configure_flt(char *msg, size_t *size)
{
	if (strstr(msg, "flt iscsi stats"))
		return iscsi_print_pending(msg, size);
	else if (strstr(msg, "flt iscsi add tgt"))
		return iscsi_add_tgt(msg, size);
	else if (strstr(msg, "flt iscsi add lun"))
		return iscsi_add_lun(msg, size);
	else if (strstr(msg, "flt iscsi print srv"))
		return iscsi_srv_list_dump(msg, size);
	else if (strstr(msg, "flt iscsi print tgt"))
		return iscsi_print_tgts(msg, size);
	else if (strstr(msg, "flt iscsi print lun"))
		return iscsi_print_luns(msg, size);
	else if (strstr(msg, "flt iscsi aggr"))
		return iscsi_aggregate(SCSI_LOG);
	else if (strstr(msg, "flt iscsi metrics on")) {
		printk(KERN_INFO "iSCSI metrics on\n");
		iscsi_metrics = true;
		return 0;
	}
	else if (strstr(msg, "flt iscsi metrics off")) {
		printk(KERN_INFO "iSCSI metrics off\n");
		iscsi_metrics = false;
		return 0;
	}
	else if (strstr(msg, "flt iscsi fgmetrics on")) {
		printk(KERN_INFO "iSCSI fine-grained metrics on\n");
		iscsi_fg_metrics = true;
		return 0;
	}
	else if (strstr(msg, "flt iscsi fgmetrics off")) {
		printk(KERN_INFO "iSCSI fine-grained metrics off\n");
		iscsi_fg_metrics = false;
		return 0;
	}
	else if (strstr(msg, "flt iscsi ffgmetrics on")) {
		printk(KERN_INFO "iSCSI fine-fine-grained metrics on\n");
		iscsi_ffg_metrics = true;
		return 0;
	}
	else if (strstr(msg, "flt iscsi ffgmetrics off")) {
		printk(KERN_INFO "iSCSI fine-fine-grained metrics off\n");
		iscsi_ffg_metrics = false;
		return 0;
	}
	else if (strstr(msg, "flt iscsi instr on")) {
		printk(KERN_INFO "iSCSI instrumentation on\n");
		iscsi_stats.enabled = true;
		net_enable_timestamp();
		return 0;
	}
	else if (strstr(msg, "flt iscsi instr off")) {
		printk(KERN_INFO "iSCSI instrumentation off\n");
		iscsi_stats.enabled = false;
		net_disable_timestamp();
		return 0;
	}
	return -EINVAL;
}

static char *iscsi_client_get_ident(void *p)
{
	struct iscsi_connection *conn = (struct iscsi_connection *)p;
	return conn->initiator_name;
}

/*
 * Attach private scheduler data to TCP proxy connection pair
 */
void iscsi_connect_flt(struct tcpproxy_session *ses)
{
	int i;
	struct iscsi_connection *data = (struct iscsi_connection *)kmalloc(
		sizeof(struct iscsi_connection), GFP_KERNEL);

	data->inbound_pdu = NULL;
	data->outbound_pdu = NULL;
	data->it = NULL;
	for (i = 0; i < TASK_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&data->task_htbl[i]);
	/* no digest expected before login completed */
	data->state = ISCSI_SEC_NEGOTIATION;
	data->header_digest = ISCSI_DIGEST_NONE;
	data->data_digest = ISCSI_DIGEST_NONE;
	data->data_off = 0;
	data->ses = ses;
	data->num_tasks = 0;
	iscsi_tgt_port_init(&data->tgt_port);
	iscsi_ini_port_init(&data->ini_port);
	iosched_client_init(&data->iosched_client);
	data->iosched_client.client = (void *)data;
	data->iosched_client.client_get_ident = iscsi_client_get_ident;

	ses->ses_priv_data = data;
}

/*
 * Free private scheduler data
 */
void iscsi_disconnect_flt(struct tcpproxy_session *ses)
{
	struct iscsi_connection *data;

	tcpproxy_session_lock(ses);
	data = (struct iscsi_connection *)ses->ses_priv_data;
	if (data) {
		/* call IO scheduler client destructor */
		if (data->iosched_client.dtor) {
			data->iosched_client.dtor(data->iosched_client.priv);
			data->iosched_client.dtor = NULL;
		}
		iscsi_free_pdu(data->inbound_pdu);
		iscsi_free_pdu(data->outbound_pdu);
		iscsi_tgt_port_exit(&data->tgt_port);
		iscsi_ini_port_exit(&data->ini_port);
		iscsi_abort_all_tasks(data, true);
		iscsi_tgt_release_it(data->it);
		kfree(ses->ses_priv_data);
		ses->ses_priv_data = NULL;
	}
	tcpproxy_session_unlock(ses);
}

/*
 * a new server socket is listening
 * create iSCSI server object
 */
int iscsi_listen_flt(struct tcpproxy_server *srv)
{
	struct sockaddr_storage addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
	struct inet_sock *inet;
	struct iscsi_srv *s;

	memset(&addr, 0, sizeof(addr));
	inet = inet_sk(srv->srv_sock->sk);
	sin->sin_family = AF_INET;
	sin->sin_port = inet->inet_sport;
	sin->sin_addr.s_addr = inet->inet_saddr;
	s = iscsi_srv_lookup(&addr, true);
	if (IS_ERR(s)) {
		printk(KERN_ERR "unable to create iSCSI server with address %pI4:%d (err=%d)\n",
				&sin->sin_addr.s_addr, ntohs(sin->sin_port), (int)PTR_ERR(s));
		return PTR_ERR(s);
	}
	srv->srv_priv_data = s;
	printk(KERN_INFO "created iSCSI server with address %pI4:%d\n",
			&sin->sin_addr.s_addr, ntohs(sin->sin_port));

	return 0;
}

/*
 * server socket is shutting down
 * clean up done in iSCSI shutdown
 */
int iscsi_shutdown_flt(struct tcpproxy_server *ses)
{
	return 0;
}

struct tcpproxy_scheduler tcpproxy_iscsi_scheduler = {
	.tps_interval = 10,
	.tps_sched = iscsi_sched,
};

struct tcpproxy_filter tcpproxy_iscsi_filter = {
	.tpf_name = "iscsi",
	.tpf_init_flt = iscsi_init_flt,
	.tpf_exit_flt = iscsi_exit_flt,
	.tpf_configure_flt = iscsi_configure_flt,
	.tpf_listen_flt = iscsi_listen_flt,
	.tpf_shutdown_flt = iscsi_shutdown_flt,
	.tpf_connect_flt = iscsi_connect_flt, /* new in-bound connection */
	.tpf_disconnect_flt = iscsi_disconnect_flt, /* either in- our out-bound connection shut down */
	.tpf_inbound_flt = iscsi_inbound_flt, /* data ready on in-bound connection */
	.tpf_outbound_flt = iscsi_outbound_flt, /* data ready on out-bound connection */
	.tpf_backend = true,
	.tpf_sched = &tcpproxy_iscsi_scheduler,
};
