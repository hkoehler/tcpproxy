/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: iscsi_target.h 487 2011-09-30 01:52:56Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

/*
 * The virtual iSCSI target.
 * We only keep metrics/stats in I-T-L objects for now
 */

#include <linux/mutex.h>
#include <linux/socket.h>
#include <linux/kref.h>

#include "../../include/netlink_iscsi_logger.h"
#include "../../include/io_metrics.h"
#include "io_sched.h"

#ifndef ISCSI_TARGET_H_
#define ISCSI_TARGET_H_

#define LUN_POOLSIZE 64
#define LUN_HASH_ORDER 6   /* 64 hash buckets */
#define LUN_HASH_SIZE (1 << LUN_HASH_ORDER)
#define LUN_HASH_MASK (LUN_HASH_SIZE - 1)

extern int iscsi_metrics;
extern int iscsi_fg_metrics;
extern int iscsi_ffg_metrics;

/*
 * SCSI logical unit
 */
struct iscsi_lun
{
	struct list_head list;
	/* LUN id */
	uint32_t id;
	/* IO queue */
	struct iosched_queue queue;
};

/*
 * iSCSI target configured by user
 */
struct iscsi_tgt
{
	struct mutex mtx;
	/* list of server */
	struct list_head list;
	/* target IQN */
	char name[ISCSI_NAME_MAX];
	/* list of LUNs */
	struct list_head luns;
	/* list of I-T nexuses created on first connect from initiator */
	struct list_head its;
};

/*
 * iSCSI server object
 * We might sit in front of multiple iSCSI servers
 */
struct iscsi_srv
{
	struct mutex mtx;
	/* the server list */
	struct list_head list;
	/* local address of iSCSI server */
	struct sockaddr_storage addr;
	/* iSCSI targets on server */
	struct list_head tgts;
};

/*
 * global list of iSCSI servers
 */
struct iscsi_srv_list
{
	struct mutex mtx;
	/* iSCSI targets on server */
	struct list_head srvs;
};

/*
 * global list of active iSCSI I-T-L nexuses
 */
struct iscsi_itl_list
{
	struct mutex mtx;
	struct list_head itls;
};

/*
 * I-T nexus attached to target on first login
 * Every iSCSI connection hold a reference to its corresponding I-T nexus
 */
struct iscsi_it
{
	/*
	 * All ITLs keyed by LUN ID
	 * The LUN has to be looked up quickly on most SCSI commands
	 * XXX: LUN ID specific to initiator
	 */
	struct hlist_head lun_htbl[LUN_HASH_SIZE];
	/* list entry from target */
	struct list_head list;
	/* how many connections do we have from initiator to target? */
	struct kref ref;
	/* back-pointer to target */
	struct iscsi_tgt *tgt;
	/* initiator IQN */
	char name[ISCSI_NAME_MAX];
};

/*
 * SCSI or TMF task pending on I-T nexus
 */
struct scsi_task
{
	/* task hash list of iSCSI connection */
	struct hlist_node hlist;
	/* task list of LUN */
	struct list_head list;
	/* SCSI opcode */
	uint8_t opcode;
	/* task management function */
	uint8_t tmf;
	/* initiator task tag */
	uint32_t itt;
	/* LUN ID */
	uint32_t lun;
	/*
	 * original and virtual initiator's command sequence numbers
	 * translate CmdSN in task management function requests
	 */
	uint32_t pini_cmdsn, vini_cmdsn;
	/* time stamp used to measure latency */
	ktime_t tstamp;
	/* number of blocks read/written, 0 if no IO */
	uint32_t iosize;
	/* whether command is read */
	bool read;
	/* whether we deal with random IO */
	bool random;
	/* reference ITT for abort task TMF */
	uint32_t refitt;
	/*
	 * transport specific pointer
	 * iSCSI might attach PDUs to a task till PDU sequence is complete
	 */
	void *priv;
};

/*
 * SCSI I-T-L Nexus
 * Keep metrics here
 */
struct iscsi_itl
{
	struct mutex mtx;
	/* I-T nexus hash list keyed by LUN ID */
	struct hlist_node hlist;
	/* active I-T-L list, pointers might be NULL */
	struct list_head list;
	/* flow object for IO scheduler */
	struct iosched_flow flow;
	/* LUN ID */
	uint32_t id;
	/* expected sequential read or write LBA respectively */
	uint64_t next_read_lba, next_write_lba;
	/* number of IO tasks in progress */
	uint32_t pending_ios;
	/* back-pointer to I-T nexus */
	struct iscsi_it *it;
	/* LUN */
	struct iscsi_lun *lun;

	/* we treat the I-T-L nexus as flow */
	struct iscsi_flow_metrics metrics;
	/* number of fine-grained ITL metrics logged in 6s interval */
	uint32_t num_fg_flow_metrics;
	/* all fine-grained metrics per flow for current interval */
	struct iscsi_fg_flow_metrics fg_metrics[100];
	/* current fine-grained metrics per flow */
	struct iscsi_fg_flow_metrics *curr_fg_metrics;

	/* number of fine-fine-grained ITL metrics logged in 6s interval */
	uint32_t num_ffg_flow_metrics;
	/* all finer-fine-grained metrics per flow for current interval */
	struct iscsi_ffg_flow_metrics ffg_metrics[1000];
	/* current fine-grained metrics per flow */
	struct iscsi_ffg_flow_metrics *curr_ffg_metrics;
};

/* dump server objects */
int iscsi_srv_list_dump(char *msg, size_t *size);
/* dump target objects of server */
int iscsi_srv_dump_tgts(struct iscsi_srv *srv, char *msg, size_t *size);
/* dump LUN objects of target */
int iscsi_tgt_dump_luns(struct iscsi_tgt *tgt, char *msg, size_t *size);

/* type of metrics to aggregate or log  */
enum scsi_aggr { SCSI_LOG, SCSI_AGGR_FG, SCSI_AGGR_FFG };
/*
 * aggregate metrics from all I-T-L objects
 * can be called in coarse (fg=false) or fine grained mode (fg=true)
 */
int iscsi_aggregate(enum scsi_aggr aggr);

/* initialize iSCSI server list */
void iscsi_srv_list_init(void);

/*
 * destroy iSCSI server list
 * And all objects underneath servers, like targets and LUNs
 */
void iscsi_srv_list_destroy(void);

/* create or look up iSCSI server object with specified local address */
struct iscsi_srv *iscsi_srv_lookup(struct sockaddr_storage *addr, bool create);

/*
 * look up or add new target to iSCSI server
 * fails if it already exists when create == true
 */
struct iscsi_tgt *iscsi_srv_lookup_tgt(struct iscsi_srv *srv,
		char iqn[ISCSI_NAME_MAX], bool create);

/*
 * look up or add new LUN to iSCSI target
 * fails if it already exists when create == true
 */
struct iscsi_lun *iscsi_tgt_lookup_lun(struct iscsi_tgt *tgt, uint32_t lun,
		bool create);

/*
 * look up I-T nexus of target by initiator IQN
 * create nexus if it doesn't exist yet
 * to be used by iSCSI proxy in login phase
 * caller gets reference to I-T nexus
 */
struct iscsi_it *iscsi_tgt_lookup_it(struct iscsi_tgt *tgt, char iqn[ISCSI_NAME_MAX]);

/*
 * acquire drop reference to I-T nexus
 */
void iscsi_tgt_acquire_it(struct iscsi_it *it);
void iscsi_tgt_release_it(struct iscsi_it *it);

/*
 * look up I-T-L nexus of I-T nexus by LUN ID
 */
struct iscsi_itl *iscsi_it_lookup_itl(struct iscsi_it *it, uint32_t lun);

/*
 * SCSI command handling in I-T-L nexus
 */
int iscsi_itl_command(struct iscsi_itl *itl, struct scsi_task *task);

/*
 * SCSI response handling in I-T-L nexus
 */
int iscsi_itl_response(struct iscsi_itl *itl, struct scsi_task *task);

/*
 * SCSI cancellation handling in I-T-L nexus
 */
int iscsi_itl_cancel(struct iscsi_itl *itl, struct scsi_task *task);

/*
 * initialize iSCSI target module
 */
int iscsi_target_init(void);

/*
 * exit iSCSI target module
 */
int iscsi_target_exit(void);

#endif /* ISCSI_TARGET_H_ */
