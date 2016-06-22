/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: tcpproxy_iscsi.h 339 2011-08-12 00:57:47Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#include <linux/types.h>
#include <linux/skbuff.h>

#include "iscsi_target.h"

#ifndef TCPPROXY_ISCSI_H_
#define TCPPROXY_ISCSI_H_

#define ISCSI_BHS_SIZE 48
#define ISCSI_MAX_AHS_SIZE (4*256)
#define ISCSI_DIGEST_SIZE 4
#define ISCSI_MAX_HDR_SIZE sizeof(struct iscsi_hdr)

#define ISCSI_TRANSIT (1 << 7)
#define ISCSI_STATUS (1 << 0)
#define ISCSI_CONTINUE (1 << 6)
#define ISCSI_IMMEDIATE (1 << 6)
#define ISCSI_FINAL (1 << 7)
#define ISCSI_CSG ((1 << 3) | (1 << 2))
#define ISCSI_NSG_MASK ((1 << 1) | (1 << 0))
#define ISCSI_RESERVED_TAG 0xFFFFFFFF

#define TASK_POOLSIZE 64
#define TASK_HASH_ORDER 6   /* 64 hash buckets */
#define TASK_HASH_SIZE (1 << TASK_HASH_ORDER)
#define TASK_HASH_MASK (TASK_HASH_SIZE - 1)

#define ISCSI_MAX_CMD 128

/*
 * Initiator and target opcodes
 */
enum {
	ISCSI_NOP_OUT       = 0x00,
	ISCSI_SCSI_CMD      = 0x01,
	ISCSI_TASK_CMD      = 0x02,
	ISCSI_LOGIN_CMD     = 0x03,
	ISCSI_TEXT_CMD      = 0x04,
	ISCSI_WRITE_DATA    = 0x05,
	ISCSI_LOGOUT_CMD    = 0x06,
	ISCSI_SNACK         = 0x10,
	ISCSI_NOP_IN        = 0x20,
	ISCSI_SCSI_RSP      = 0x21,
	ISCSI_TASK_RSP      = 0x22,
	ISCSI_LOGIN_RSP     = 0x23,
	ISCSI_TEXT_RSP      = 0x24,
	ISCSI_READ_DATA     = 0x25,
	ISCSI_LOGOUT_RSP    = 0x26,
	ISCSI_R2T           = 0x31,
	ISCSI_ASYNC         = 0x32,
	ISCSI_REJECT        = 0x3f
};

/*
 * Task Management Functions
 */
enum
{
	ISCSI_ABORT_TASK         = 1,
	ISCSI_ABORT_TASK_SET     = 2,
	ISCSI_CLEAR_ACA          = 3,
	ISCSI_CLEAR_TASK_SET     = 4,
	ISCSI_LOGICAL_UNIT_RESET = 5,
	ISCSI_TARGET_WARM_RESET  = 6,
	ISCSI_TARGET_COLD_RESET  = 7
};

/*
 * TMF responses
 */
enum {
	ISCSI_FUNCTION_COMPLETE               = 0,
	ISCSI_TASK_NOT_FOUND                  = 1,
	ISCSI_LUN_NOT_FOUND                   = 2,
	ISCSI_TASK_STILL_ALLEGIANT            = 3,
	ISCSI_TASK_REASSIGNMENT_NOT_SUPPORTED = 4,
	ISCSI_TMF_NOT_SUPPORTED               = 5,
	ISCSI_FUNCTION_AUTH_FAILED            = 6,
	ISCSI_FUNCTION_REJECTED               = 255
};

typedef enum
{
	ISCSI_DIGEST_NONE,
	ISCSI_DIGEST_CRC32C
} iscsi_digest_t;

typedef enum
{
	ISCSI_DISCOVERY_SESSION,
	ISCSI_NORMAL_SESSION
} iscsi_session_t;

typedef enum
{
	ISCSI_SEC_NEGOTIATION = 0x0,
	ISCSI_OP_NEGOTIATION = 0x1,
	ISCSI_FULL_FEATURE_PHASE = 0x3
} iscsi_state_t;

/*
 * iSCSI instrumentation statistics
 * those are turned off by default
 */
struct iscsi_stats
{
	spinlock_t lock;
	bool enabled;		/* whether stats are enabled - not protected by lock */
	int pdus;			/* number of PDUs forwarded */
	ktime_t latency1; 	/* cumulative latency of proxy (first packet of PDU) */
	ktime_t latency2; 	/* cumulative latency of proxy (last packet of PDU) */
} iscsi_stats;

/*
 * iSCSI header in network format
 */
struct iscsi_hdr
{
	char basehdr[ISCSI_BHS_SIZE];
	/* AHS + header digest (both optional) */
	char exthdr[ISCSI_MAX_AHS_SIZE+ISCSI_DIGEST_SIZE];
};

/*
 * iSCSI parser state
 */
struct iscsi_parse_state
{
	int offset;			/* offset in header */
	int remBaseHdr;		/* remaining bytes of base header to be parsed */
	int remExtHdr;		/* remaining bytes of extension header to be parsed */
	int remData;		/* remaining bytes of data segments to be parsed */
};

/*
 * iSCSI protocol data unit
 * holds reference to iSCSI connection/session
 */
struct iscsi_pdu
{
	/* let IO scheduler handle command PDU */
	struct iosched_operation iosched_op;
	/* PDU in either command or response queue */
	struct list_head list;
	/* unsolicited data PDUs of write command PDU */
	struct list_head data_list;
	/* command is bound to iSCSI/TCP connection (connection allegiance) */
	struct iscsi_connection *conn;
	/* PDU might be in progress of being parsed */
	struct iscsi_parse_state state;
	/* BHS + AHS + header digest */
	struct sk_buff *hdr_skb;
	/* data segment + data digest */
	struct sk_buff_head data_skb_queue;
	/* send queue for sending whole PDU */
	struct sk_buff_head send_skb_queue;
	/* reference to SCSI or TMF task if any */
	struct scsi_task *task;
	/* receive time stamp of first and last TCP segment of PDU */
	ktime_t tstamp1, tstamp2;
};

/*
 * virtual target port state (passive end of an iSCSI session)
 */
struct iscsi_tgt_port
{
	/*
	 * count of all available iSCSI commands per target port (session)
	 * command window is adjusted based on the number of free commands
	 * MaxCmdSN = ExpCmdSN + qlen - pending - 1
	 */
	int qlen, pending;
	/* iSCSI status variables as specified in RFC */
	uint32_t ExpCmdSN, StatSN, MaxCmdSN;
};

/*
 * virtual initiator port state (active end of an iSCSI session)
 */
struct iscsi_ini_port
{
	/* command queue */
	struct list_head cmd_queue;
	/* iSCSI status variables as specified in RFC */
	uint32_t CmdSN, ExpCmdSN, ExpStatSN, MaxCmdSN;
};

/*
 * Private data of iSCSI filter
 * Contains in- and out-bound receive queues.
 * Stores iSCSI specific attributes negotiated in login phase.
 * We consider a single iSCSI connection to be an entire session.
 */
struct iscsi_connection
{
	/* current in and out-bound PDU being parsed */
	struct iscsi_pdu *inbound_pdu, *outbound_pdu;
	/* TCP proxy session */
	struct tcpproxy_session *ses;
	/* iSCSI connection state */
	iscsi_state_t state;
	/* iSCSI end point of client */
	char initiator_name[ISCSI_NAME_MAX];
	/* iSCSI end point of server */
	char target_name[ISCSI_NAME_MAX];
	/* connection ID */
	uint16_t cid;
	/* initiator session ID */
	char isid[6];
	/* whether header and data digests are enabled */
	iscsi_digest_t header_digest, data_digest;
	/* session type */
	iscsi_session_t session_type;
	/* tasks in progress on target */
	struct hlist_head task_htbl[TASK_HASH_SIZE];
	/* number of tasks in progress */
	uint32_t num_tasks;
	/* the SCSI I-T nexus object associate with multiple iSCSI session */
	struct iscsi_it *it;
	/* target side port */
	struct iscsi_tgt_port tgt_port;
	/* initiator side port */
	struct iscsi_ini_port ini_port;
	/* client side piece of IO scheduler */
	struct iosched_client iosched_client;
	/*
	 * buffer for parsing text
	 * XXX: maybe allocate later outside connection
	 */
	char data_buf[64*1024];
	/* offset in text buffer */
	size_t data_off;
};

#endif /* TCPPROXY_ISCSI_H_ */
