/*********************************************************************************************
 * Copyright (c) 2010, SmApper Technologies Inc 
 * $Id: tcpproxy_rpc.h 15 2011-05-11 21:59:51Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#ifndef __TCPPROXY_RPC_H__
#define __TCPPROXY_RPC_H__

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/radix-tree.h>
#include <linux/hash.h>
#include <linux/mempool.h>
#include <net/tcp.h>

#define RPC_LAST_FRAG_MASK (1U << 31)
#define RPC_FRAG_SIZE_MASK (~RPC_LAST_FRAG_MASK)
#define RPC_MAX_FRAG_LEN  (4*1024*1024)
#define RPC_TIMEOUT 30
#define RPC_POOLSIZE 8
#define RPC_MAXBUFSIZE (32*1024)

#define RPC_HASH_ORDER 6   /* 64 hash buckets */
#define RPC_HASH_SIZE (1 << RPC_HASH_ORDER)
#define RPC_HASH_MASK (RPC_HASH_SIZE - 1)

#define RPC_RNDUP(n) (((n)+0x3) & ~0x3)

/* 
 * There are two types of RPC messages: request and response
 */
typedef enum {
	RPC_REQUEST = 0,
	RPC_RESPONSE = 1
} rpc_msg_t; 

/*
 * RPC client configuration, indexed with radix tree by IP
 */
struct rpc_clnt
{
	struct list_head list;
	__be32 addr;
	int prio;
};

/*
 * RPC authentication structure
 */
struct rpc_auth
{
	u32 flavor;
	u32 len;
	__be32 data[100];
};

/*
 * RPC message, either request or response 
 */
struct rpc_msg
{
	/* fragment header */
	__be32 hdr;
	/* transaction ID */
	__be32 xid;
	/* request or response */
	u32 msgtype;
	union
	{
		struct 
		{
			/* RPC version, must be 2 */
			u32 ver;
			/* program ID */
			u32 prog;
			/* program version */
			u32 progver;
			/* RPC procedure */
			u32 proc;
			/* credentials */
			struct rpc_auth cred;
			/* verifier */
			struct rpc_auth verf;
			/* dummy field marking end of record */
			u32 eor;
		} rqst;
		struct {
			/* reply status */
			u32 status;
			/* verifier */
			struct rpc_auth verf;
			/* accept status */
			u32 accept_status;
			/* dummy field marking end of record */
			u32 eor;
		} resp;
	};
};

/* XDR parser position */
struct xdr_skb_pos
{
	struct sk_buff_head *list;
	struct sk_buff *skb;
	int offset;
};

/*
 * An RPC call in its various states.
 * The corresponding private data of the TCP session, always holds a reference
 * to all RPC tasks in its hash table keyed by XID.
 * RPC task is created by the parser and first queued in the rpc_priv_data's request queue.
 * After the request has been forwarded to the back-end, the task is marked as pending.
 * When the response is received, the task is queued in rpc_priv_data's response queue.
 * The task is destroyed once the response has been forwarded to the client.
 */
struct rpc_task
{
	/*
	 * socket buffers of current RPC fragment
	 * that's either the request or response RPC message
	 */
	struct sk_buff_head skb_queue;
	/* beginning of pay load, i.e. body of either request or reply message */
	struct xdr_skb_pos xdr_pos;
	/* RPC request and response messages */
	struct rpc_msg rqst, resp;
	/* RPC request and response pay load buffers for parser output */
	char args_buf[RPC_MAXBUFSIZE], res_buf[RPC_MAXBUFSIZE];
	/* list entry in request/response queue */
	struct list_head list;
	/* list entry in rpc_priv_data's requests hash */
	struct hlist_node hlist;
	/* time when request hits proxy */
	ktime_t t_proxy;
	/* time when request hits server */
	ktime_t t_server;
	/* priority of RPC request */
	int prio;
	/* request already forwarded to back-end? */
	bool pending;
};

/* aggregated statistics of pending requests */
struct rpc_stats
{
	int n;			/* number of requests */
	s64 latency;	/* sum of latency in microseconds */
};

/* parse state of RPC message */
struct rpc_parse_state
{
	/*
	 * socket buffers of currently processed RPC fragment/message
	 * that's either the request or response RPC message
	 */
	struct sk_buff_head skb_queue;
	/* beginning of pay load, i.e. body of either request or reply message */
	struct xdr_skb_pos xdr_pos;
	/* remaining number of bytes of current RPC fragment to parse */
	int remaining;
	/* currently processed RPC message */
	struct rpc_msg msg;
	/* parse offset in @msg */
	size_t offset;
	/* has header been completely parsed? */
	bool hdr_complete;
};

/*
 * Private data of filter and scheduler.
 * Contains in- and outbound receive queues.
 */
struct rpc_priv_data
{
	/* in and outbound socket buffers */
	struct sk_buff_head inbound_queue, outbound_queue;
	/* RPC request and responses */
	struct list_head request_queue, response_queue;
	/* RPC parse state of requests and responses */
	struct rpc_parse_state inbound_state, outbound_state;

	/* priority list */
	struct list_head list;
	/* back pointer to session */
	struct tcpproxy_session *ses;
	/* client IPv4 address */
	__be32 addr;
	/* priority of traffic */
	int prio;
	/* tasks in progress */
	struct hlist_head rpc_hash[RPC_HASH_SIZE];
};

/* private data of sessions with same priority */
struct prio_queue
{
	/* list of sessions (private data) */
	struct list_head ses;
	/* max number of pending RPC requests */
	int max_rpcs;
	/* aggregated information of RPC requests */
	struct rpc_stats stats;
};

/*
 * dispatch RPC request or response
 */
int tcpproxy_dispatch_rpc(struct tcpproxy_session *ses,
		struct rpc_task *task, rpc_msg_t t);

/*
 * print/reset NFS call statistics
 */
void print_nfs_stats(char *buf, size_t *size);
void reset_nfs_stats(char *buf, size_t *size);


#endif

