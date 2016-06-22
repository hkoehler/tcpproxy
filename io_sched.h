/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: io_sched.h 438 2011-09-07 19:06:42Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#ifndef __IO_SCHEDULER_H__
#define __IO_SCHEDULER_H__

#include <linux/string.h>
#include <linux/list.h>

/*
 * The IO scheduler interface.
 * We try to separate transport from scheduler.
 * Transport can be any SCSI transport or NFS.
 * Scheduler supports both command and data phases.
 * It is modeled after SCSI as it's more reach than NFS.
 * Non-SCSI protocols (e.g. NFS) can be easily mapped to this interface.
 */

enum iosched_opcode {
	IOSCHED_NONE,		/* NOOP/pass-thru command */
	IOSCHED_READ,		/* read command */
	IOSCHED_WRITE,		/* write command */
	IOSCHED_ABORT,		/* abort command */
};

/*
 * IO queue per disk group
 * XXX assume every LUN is a disk group for now
 */
struct iosched_queue
{
	/* transport-specific opaque pointer */
	void *queue;
	/* private scheduler data initialized with NULL */
	void *priv;
	/* destructor called by iSCSI vTgt on shutdown */
	void (*dtor)(void *priv);
	/*
	 * transport-specific target identifier
	 * that's the target IQN/WWN in iSCSI/FC
	 * or server name in NFS
	 */
	char *(*queue_get_tgt_ident)(void *queue);
};

/*
 * entity which has issued the IO
 * That's either the SCSI initiator or NFS client.
 * This is a polymorphic object, behaving different for every transport
 */
struct iosched_client
{
	/* transport-specific opaque pointer */
	void *client;
	/* scheduler-specific opaque pointer, initialized with NULL */
	void *priv;
	/* transport-specific client identifier */
	char *(*client_get_ident)(void *client);
	/* destructor called by iSCSI vTgt on shutdown */
	void (*dtor)(void *priv);
};

/*
 * A flow between client and LUN
 * XXX: later flow will be between VM and vdisk
 */
struct iosched_flow
{
	/* private scheduler data initialized with NULL */
	void *priv;
	/* destructor called by iSCSI vTgt when flow is terminated */
	void (*dtor)(void *priv);
};

/*
 * IO operation + (immediate and unsolicited) data
 */
struct iosched_operation
{
	/* list entry for queuing */
	struct list_head list;
	/* type of IO */
	enum iosched_opcode op;
	/* client issued IO */
	struct iosched_client *client;
	/* flow IO belongs to */
	struct iosched_flow *flow;
	/* corresponding queue of IO (disk group) */
	struct iosched_queue *queue;
	/*
	 * IO tag
	 * SCSI allows only one outstanding command be task
	 * Hence we re-use the task tag here.
	 * Tag set for READ, WRITE and ABORT
	 */
	uint32_t tag;
	/* LUN ID - SCSI specific */
	uint16_t lun;
	/* logical block address */
	uint64_t lba;
	/* number of blocks to transfer */
	uint32_t len;
	/*
	 * forward operation and all its data to back-end
	 * lock must be true in case function gets called outside
	 * isched_input()
	 */
	int (*iosched_output)(struct iosched_operation *op, bool lock);
};

/*
 * initialize IO scheduler queue, not used by scheduler!
 */
static inline void iosched_queue_init(struct iosched_queue *queue) {
	memset(queue, 0, sizeof(*queue));
}

/*
 * initialize IO scheduler queue, not used by scheduler!
 */
static inline void iosched_client_init(struct iosched_client *client) {
	memset(client, 0, sizeof(*client));
}

/*
 * initialize IO scheduler flow object, not used by scheduler!
 */
static inline void iosched_flow_init(struct iosched_flow *flow) {
	memset(flow, 0, sizeof(*flow));
}

/* get a reference to a flow */
void iosched_acquire_flow(struct iosched_flow *flow);

/* release a reference to a flow */
void iosched_release_flow(struct iosched_flow *flow);

/*
 * new IO to be scheduled
 * to be implemented by the scheduler
 */
int iosched_input(struct iosched_operation *op);

/*
 * scheduler statistics to be logged in fix intervals
 * currently an interval is six seconds
 * called in iSCSI logger context
 */
void iosched_stats(void);

/*
 * initialize IO scheduler
 */
int iosched_init(void);

/*
 * exit IO scheduler
 */
void iosched_exit(void);

#endif /* __IO_SCHEDULER_H__ */
