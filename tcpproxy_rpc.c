/*********************************************************************************************
 * Copyright (c) 2010, SmApper Technologies Inc 
 * $Id: tcpproxy_rpc.c 15 2011-05-11 21:59:51Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/


#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/radix-tree.h>
#include <linux/hash.h>
#include <linux/mempool.h>
#include <net/tcp.h>

#include "tcpproxy.h"
#include "tcpproxy_rpc.h"

#if 0
#define dprintk(format...) printk(format)
#define inline
#else
#define dprintk(format...)
#endif

/* client configuration organized in radix tree keyed by IP */
static RADIX_TREE(rpc_clnts, GFP_KERNEL);
static LIST_HEAD(rpc_clnt_list);

/* only three priorities are defined so far 1, 2 and 3, 0 not used */
static struct prio_queue queue[4];
static DEFINE_MUTEX(queue_mtx);
/* memory pool for RPC requests */
static struct kmem_cache *rqst_slab __read_mostly;
static mempool_t *rqst_mempool __read_mostly;

/* fwd decl of linux/net/ipv4/tcp.c */
int tcp_send_skb_queue(struct sock *sk, struct sk_buff_head *queue);
int tcp_recv_skb_queue(struct sock *sk, struct sk_buff_head *queue);

/* fwd decl */
static inline struct rpc_task *
rpc_lookup_task(struct rpc_priv_data *data, __be32 xid);
static inline void rpc_init_msg(struct rpc_msg *msg);

static void rpc_insert_clnt(__be32 addr, int prio)
{
	struct rpc_clnt *clnt;

	clnt = (struct rpc_clnt *)kzalloc(
		sizeof(struct rpc_clnt), GFP_KERNEL);
	clnt->prio = prio;
	radix_tree_insert(&rpc_clnts, addr, clnt);
	list_add_tail(&clnt->list, &rpc_clnt_list);
}

static struct rpc_clnt *
rpc_lookup_clnt(__be32 addr)
{
	return radix_tree_lookup(&rpc_clnts, addr);
}

static void rpc_destroy_clnts(void)
{
	struct rpc_clnt *clnt, *tmp;

	list_for_each_entry_safe(clnt, tmp, &rpc_clnt_list, list) {
		radix_tree_delete(&rpc_clnts, clnt->addr);
		kfree(clnt);
	}
}

/* reset RPC parse state */
static void init_parse_state(struct rpc_parse_state *state)
{
	state->remaining = 0;
	state->offset = offsetof(struct rpc_msg, hdr);
	state->hdr_complete = false;
	rpc_init_msg(&state->msg);
	skb_queue_head_init(&state->skb_queue);
}

static struct rpc_priv_data *
rpc_create_priv_data(struct tcpproxy_session *ses, __be32 addr, int prio)
{
	int i;
	struct rpc_priv_data *data;
	
	data = (struct rpc_priv_data *)kzalloc(
		sizeof(struct rpc_priv_data), GFP_KERNEL);
	//printk(KERN_INFO "%s enter addr %x\n", __func__, addr);

	for (i = 0; i < RPC_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&data->rpc_hash[i]);

	INIT_LIST_HEAD(&data->request_queue);
	INIT_LIST_HEAD(&data->response_queue);
	skb_queue_head_init(&data->inbound_queue);
	skb_queue_head_init(&data->outbound_queue);
	init_parse_state(&data->inbound_state);
	init_parse_state(&data->outbound_state);
	data->addr = addr;
	data->prio = prio;
	data->ses = ses;
	ses->ses_priv_data = data;
	
	mutex_lock(&queue_mtx);
	list_add_tail(&data->list, &queue[prio].ses); 
	mutex_unlock(&queue_mtx);
	//printk(KERN_INFO "%s return\n", __func__);

	return data;
}

/* 1. initialize RPC message at beginning of parsing */
static inline void rpc_init_msg(struct rpc_msg *msg)
{
	memset(msg, 0, sizeof(*msg));
}

/* 2. create and initialize new RPC request after parsing completed */
static inline struct rpc_task *rpc_create_task(void)
{
	struct rpc_task *task;

	task = (struct rpc_task *)mempool_alloc(rqst_mempool, GFP_NOFS);
	skb_queue_head_init(&task->skb_queue);
	rpc_init_msg(&task->rqst);
	rpc_init_msg(&task->resp);

	return task;
}

/* 3. copying current parser RPC message to either request or response */
static inline void rpc_copy_msg(struct rpc_msg *msg1, struct rpc_msg *msg2)
{
	memcpy(msg1, msg2, sizeof(*msg1));
}

/* 4. attach socket buffers to RPC request after parsing finished */
static inline void rpc_queue_msg_skb(struct rpc_task *task, struct rpc_parse_state *st)
{
	struct sk_buff *skb;
	while ((skb = skb_dequeue(&st->skb_queue)))
		skb_queue_tail(&task->skb_queue, skb);
	task->xdr_pos.list = &task->skb_queue;
	task->xdr_pos.offset = st->xdr_pos.offset;
	task->xdr_pos.skb = st->xdr_pos.skb;
}

/* 
 * 5. insert request into hash map of pending requests
 * XID must have been set already
 */
static inline void rpc_insert_task(struct rpc_priv_data *data, struct rpc_task *task)
{
	struct hlist_head *hh;
	struct sk_buff *skb;

	/* 
	 * request has been received already
	 * we deal with a re-transmission here
	 * insert yet another request to be queued and transmitted
	 */
	if (rpc_lookup_task(data, task->rqst.xid))
		printk(KERN_INFO "RPC request %x retransmitted\n", task->rqst.xid);
	
	/* set time request hit proxy */
	skb = skb_peek(&task->skb_queue);
	BUG_ON(!skb);
	// XXX why is that????
	if (skb->tstamp.tv64 == 0) 
		__net_timestamp(skb);
	task->t_proxy = skb_get_ktime(skb);
	task->prio = data->prio;
	task->pending = false;
	/* finally insert into hash list */
	hh = &data->rpc_hash[hash_32(task->rqst.xid, RPC_HASH_ORDER)];
	hlist_add_head(&task->hlist, hh);
}

/*
 * 6. lookup pending request in RPC hash table after response has been received
 * insert new request if insert == true
 */
static inline struct rpc_task *
rpc_lookup_task(struct rpc_priv_data *data, __be32 xid)
{
	struct hlist_head *hh;
	struct hlist_node *hn;
	struct rpc_task *task;

	hh = &data->rpc_hash[hash_32(xid, RPC_HASH_ORDER)];
	hlist_for_each_entry(task, hn, hh, hlist)
		if (task->rqst.xid == xid && task->pending)
				return task;
	
	return NULL;
}

/* 
 * return the number of pending requests 
 * also delete requests pending for too long
 */
static int rpc_pending_tasks(struct rpc_priv_data *data)
{
	int i, n = 0;
	struct hlist_node *pos, *tmp;
	struct rpc_task *task;
	ktime_t kt;
	struct timespec dt;

	for (i = 0; i < RPC_HASH_SIZE; i++)
		hlist_for_each_entry_safe(task, pos, tmp, &data->rpc_hash[i], hlist) {
			/* ignore requests which haven't been forwarded yet */
			if (task->pending == false)
				continue;
			kt = ktime_sub(ktime_get_real(), task->t_server);
			dt = ktime_to_timespec(kt);
			if (dt.tv_sec > RPC_TIMEOUT) {
				printk(KERN_INFO "RPC request %x pending for over %d seconds\n", 
					task->rqst.xid, RPC_TIMEOUT);
				hlist_del(&task->hlist);
				mempool_free(task, rqst_mempool);
				continue;
			}
			n++;
		}
	return n;
}

/* destroy RPC all requests */
static void rpc_destroy_tasks(struct rpc_priv_data *data)
{
	int i;
	struct hlist_node *pos, *n;
	struct rpc_task *task;

	for (i = 0; i < RPC_HASH_SIZE; i++)
		hlist_for_each_entry_safe(task, pos, n, &data->rpc_hash[i], hlist)
			mempool_free(task, rqst_mempool);
}

static void rpc_destroy_priv_data(struct rpc_priv_data *data)
{
	printk(KERN_INFO "%s: %p\n", __func__, data);
	mutex_lock(&queue_mtx);
	list_del(&data->list);	
	mutex_unlock(&queue_mtx);
	rpc_destroy_tasks(data);
	kfree(data);
}

/* 
 * send single RPC request or response 
 */
static void rpc_send_msg(struct sock *sk, struct rpc_priv_data *data, 
	struct rpc_task *task, rpc_msg_t t)
{
	ktime_t kt;
	struct rpc_stats *stats;
	int res;

	/* send socket buffers */
	//printk(KERN_INFO "send msg %x\n", task->rqst.xid);
	res = tcp_send_skb_queue(sk, &task->skb_queue);
	if (res < 0)
		printk(KERN_ERR "unable to send %s: err=%d xid=%x\n", 
			t == RPC_REQUEST ? "request" : "response",
			res, task->rqst.xid);
	/* remove request form either request or response queue */
	list_del(&task->list);
	/* forward request */
	if (t == RPC_REQUEST) {
		//printk(KERN_INFO "forward request %x\n", rqst->rqst.xid);
		task->pending = true; 
		task->t_server = ktime_get_real();
	}
	/* complete request, delete request state on our site */
	else {
		//printk(KERN_INFO "complete request %x\n", rqst.rqst->xid);
		kt = ktime_sub(ktime_get_real(), task->t_proxy);
		stats = &queue[task->prio].stats;
		stats->latency += ktime_to_us(kt);
		stats->n++;

		hlist_del(&task->hlist);
		mempool_free(task, rqst_mempool);
	}	
}

/* 
 * Insert or look up RPC task
 */
static void rpc_recv_msg(struct rpc_priv_data *data, 
	struct rpc_parse_state *state, rpc_msg_t t)
{
	struct sk_buff *skb;
	struct rpc_task *task;

	/* copy current parser request and insert it into hash map */
	if (t == RPC_REQUEST) {
		task = rpc_create_task();
		if (task) {
			rpc_copy_msg(&task->rqst, &state->msg);
			rpc_queue_msg_skb(task, state);
			rpc_insert_task(data, task);
			list_add_tail(&task->list, &data->request_queue); 
		}
		else
			printk(KERN_ERR "out of memory!\n");
	}
	else {
		task = rpc_lookup_task(data, state->msg.xid);
		if (task) {
			rpc_copy_msg(&task->resp, &state->msg);
			rpc_queue_msg_skb(task, state);
			list_add_tail(&task->list, &data->response_queue); 
		}
		/*
		 * no pending request found on our site, delete RPC message
		 * XXX: Should we create an RPC task instead not to alter any traffic?
		 */
		else {
			printk(KERN_INFO "no request pending with XID %x\n", 
				state->msg.xid);
			while ((skb = skb_dequeue(&state->skb_queue)))
				kfree_skb(skb);
		}
	}
	if (task)
		tcpproxy_dispatch_rpc(data->ses, task, t);
	/*if (rqst)
		printk(KERN_INFO "finished parsing RPC %s %x with %d skbs\n", 
			t == RPC_REQUEST ? "request" : "response", rqst->rqst.xid, 
			skb_queue_len(&rqst->skb_queue));*/
}

#define parse_be32(f) \
		if (state->offset == offsetof(struct rpc_msg, f) && \
			copied < skb->len) \
		{ \
			skb_copy_bits(skb, copied, &msg->f, sizeof(__be32)); \
			copied += sizeof(__be32); \
			state->offset += sizeof(__be32); \
			dprintk(KERN_INFO "%s: %s = %x\n", __func__, #f, msg->f); \
		}

#define parse_u32(f) \
		if (state->offset == offsetof(struct rpc_msg, f) && \
			copied < skb->len) \
		{ \
			skb_copy_bits(skb, copied, &msg->f, sizeof(__be32)); \
			copied += sizeof(__be32); \
			state->offset += sizeof(__be32); \
			msg->f = ntohl(msg->f); \
			dprintk(KERN_INFO "%s: %s = %d\n", __func__, #f, msg->f); \
		}

#define parse_len(f) \
		if (state->offset == offsetof(struct rpc_msg, f.len) && \
			copied < skb->len) \
		{ \
			skb_copy_bits(skb, copied, &msg->f.len, sizeof(__be32)); \
			copied += sizeof(__be32); \
			state->offset += sizeof(__be32); \
			msg->f.len = RPC_RNDUP(ntohl(msg->f.len)); \
			if (msg->f.len > sizeof(msg->f.data)) { \
				printk(KERN_WARNING "RPC parse error: %s byte count value %d to large\n", \
					#f, msg->f.len); \
				msg->f.len = sizeof(msg->f.data);\
			} \
			else \
				dprintk(KERN_INFO "%s: %s.len = %d\n", __func__, #f, msg->f.len); \
		}

/* XXX error handling if byte count to large */
#define parse_opaque(f) \
	parse_len(f); \
	while (state->offset >= offsetof(struct rpc_msg, f.data) && \
		state->offset < offsetof(struct rpc_msg, f.data) + msg->f.len && \
		copied < skb->len) \
	{ \
		size_t off = state->offset - offsetof(struct rpc_msg, f.data); \
		size_t to_copy = msg->f.len - off; \
		size_t copy; \
		\
		if (copied + to_copy <= skb->len) \
			copy = to_copy; \
		else \
			copy =  skb->len - copied; \
		skb_copy_bits(skb, copied, &msg->f.data[off], copy); \
		copied += copy; \
		state->offset += copy; \
		dprintk(KERN_INFO "%s: parse %s offset=%d copy=%d\n", __func__, #f, off, copy); \
	} \
	if (state->offset == offsetof(struct rpc_msg, f.data) + msg->f.len) \
		state->offset = offsetof(struct rpc_msg, f.data) + sizeof(msg->f.data);

#define parse_auth(f) \
	parse_u32(f.flavor); \
	parse_opaque(f);

/*
 * Parse RPC fragments from sk_buff
 * call rpc_recv_msg after complete RPC message has been parsed
 */
static int rpc_parse_skb(struct rpc_priv_data *data, struct sk_buff *skb, 
	struct rpc_parse_state *state, rpc_msg_t t)
{
	int last;
	int *rem = &state->remaining;
	struct rpc_msg *msg = &state->msg;
	struct sk_buff *clone;
	int offset=0, copied=0;

	while (offset < skb->len) {
		/* parse RPC fragment header */
		if (state->offset == offsetof(struct rpc_msg, hdr)) {
			if (copied + sizeof(__be32) <= skb->len) {
				BUG_ON(*rem > 0);
				skb_copy_bits(skb, copied, &msg->hdr, sizeof(__be32));
				copied += sizeof(__be32);
				last = ntohl(msg->hdr) & RPC_LAST_FRAG_MASK;
				*rem = ntohl(msg->hdr) & RPC_FRAG_SIZE_MASK;
				state->offset += sizeof(__be32);
				dprintk(KERN_INFO "%s: rem = %d\n", __func__, *rem);
				if (*rem > RPC_MAX_FRAG_LEN) {
					printk(KERN_WARNING "%s: rpc fragment size %d invalid\n",
						__func__, *rem);
					printk(KERN_INFO "%s: offset=%d last=%x rem=%d len=%d\n",
							__func__, copied, last, *rem, skb->len);
					return -EINVAL;
				}
				if (*rem == 0) {
					printk(KERN_WARNING "%s: rpc fragment size is 0!\n",
						__func__);
					printk(KERN_INFO "%s: offset=%d last=%x rem=%d len=%d\n",
							__func__, copied, last, *rem, skb->len);
					return -EINVAL;
				}
				*rem += 4; /* size of rpc frag header = 4 */
			}
			else {
				printk(KERN_WARNING "%s: socket buffer to small to contain RPC fragment (len=%d)\n",
					__func__, skb->len);
				return -EINVAL;
			}
		}

		/*
		 * parse field by field of request or response header
		 * if not last RPC fragment
		 */
		if (state->hdr_complete == false) {
			parse_be32(xid);
			parse_u32(msgtype);
			if (msg->msgtype != t) {
				printk(KERN_WARNING "%s: wrong RPC message direction!\n", __func__);
				return -EINVAL;
			}
			if (t == RPC_REQUEST) {
				parse_u32(rqst.ver);
				parse_u32(rqst.prog);
				parse_u32(rqst.progver);
				parse_u32(rqst.proc);
				parse_auth(rqst.cred);
				parse_auth(rqst.verf);
				if (state->offset == offsetof(struct rpc_msg, rqst.eor))
					state->hdr_complete = true;
			}
			else {
				parse_u32(resp.status);
				parse_auth(resp.verf);
				parse_u32(resp.accept_status);
				if (state->offset == offsetof(struct rpc_msg, resp.eor))
					state->hdr_complete = true;
			}
		}

		/* queue skb of RPC fragment */
		clone = skb_clone(skb, GFP_KERNEL);
		if (clone == NULL)
			return -ENOMEM;
		pskb_pull(clone, offset);
		pskb_trim(clone, *rem);		/* rem might be > skb->len */
		skb_queue_tail(&state->skb_queue, clone);

		/* set position of RPC parser, processing the RPC pay load */
		if (state->hdr_complete && copied - offset) {
				/*printk(KERN_INFO "%s: clone = %p, offset = %d",
						__func__, clone, copied - offset);*/
				state->xdr_pos.list = &state->skb_queue;
				state->xdr_pos.skb = clone;
				state->xdr_pos.offset = copied - offset;
		}

		offset += clone->len;
		copied = offset;
		*rem -= clone->len;
		//printk(KERN_INFO "copy offset=%d skb len=%d clone len=%d, rem=%d\n", 
		//	offset, skb->len, clone->len, *rem);

		if (*rem == 0) {
			if (state->hdr_complete) {
				last = ntohl(msg->hdr) & RPC_LAST_FRAG_MASK;
				if (last) {
					rpc_recv_msg(data, state, t);
					init_parse_state(state);
				}
				else
					state->offset = offsetof(struct rpc_msg, hdr);
			}
			else {
				struct sk_buff *s;

				printk(KERN_WARNING "incomplete RPC message received!\n");
				printk(KERN_INFO "%s: offset=%d rem=%d skb len=%d clone len=%d\n",
					__func__, offset, *rem, skb->len, clone->len);
				while ((s = skb_dequeue(&state->skb_queue)))
					kfree_skb(s);
				return -EINVAL;
				/* start from the beginning */
				//init_parse_state(state);
			}
		}
	}

	return 0;
}

/*
 * Parse socket buffer queue
 */
static int rpc_parse_skb_queue(struct rpc_priv_data *data, struct sk_buff_head *queue, 
	struct rpc_parse_state *state, rpc_msg_t t)
{
	struct sk_buff *skb;
	int res=0;
	//int *rem = &state->remaining;

	//printk(KERN_INFO "%s: entry: rem %d\n", __func__, *rem);
	while ((skb = skb_dequeue(queue))) {
		res = rpc_parse_skb(data, skb, state, t);
		if (res < 0)
			break;
		//printk(KERN_INFO "%s: loop rem %d\n", __func__, *rem);
		kfree_skb(skb);
	}

	return res;
}

/*
 * Receive inbound messages and queue them in private scheduler data
 */
static int rpc_inbound_flt(struct tcpproxy_session *ses)
{
	int res;
	struct rpc_priv_data *data = (struct rpc_priv_data *)ses->ses_priv_data;

	//printk(KERN_INFO "%s\n", __func__);
	tcpproxy_session_lock(ses);
	res = tcp_recv_skb_queue(ses->ses_inbound_sock->sk, 
		&data->inbound_queue);
	if (res == -EAGAIN) {
		res = 0;
		goto out;
	}
	if (res < 0) {
		printk(KERN_ERR "%s: receive failed with %d\n", __func__, res);
		goto out;
	}
	/* insert new RPC requests, make sure to parse input only once */
	res = rpc_parse_skb_queue(data, &data->inbound_queue, 
		&data->inbound_state, RPC_REQUEST);
	
out:
	tcpproxy_session_unlock(ses);
	return res;
}

/*
 * Receive and forward outbound messages.
 */
static int rpc_outbound_flt(struct tcpproxy_session *ses)
{
	struct rpc_priv_data *data = (struct rpc_priv_data *)ses->ses_priv_data;
	struct rpc_task *task, *tmp;
	int res = 0;

	//printk(KERN_INFO "%s\n", __func__);
	mutex_lock(&queue_mtx);
	tcpproxy_session_lock(ses);
	res = tcp_recv_skb_queue(ses->ses_outbound_sock->sk,
		&data->outbound_queue);
	if (res == -EAGAIN)
		goto out;
	if (res < 0)
		printk(KERN_ERR "%s: receive failed with %d\n", __func__, res);
	if (skb_queue_empty(&data->outbound_queue)|| res == 0)
		goto out;
	
	/* dissect RPC response messages */
	res = rpc_parse_skb_queue(data, &data->outbound_queue, 
		&data->outbound_state, RPC_RESPONSE);
	if (res < 0)
		goto out;

	/* send RPC responses, delete pending requests */
	list_for_each_entry_safe(task, tmp, &data->response_queue, list)
		rpc_send_msg(ses->ses_inbound_sock->sk, data, 
			task, RPC_RESPONSE);

out:
	tcpproxy_session_unlock(ses);
	mutex_unlock(&queue_mtx);
	return res;
}

/*
 * Forward in-bound messages to back-end
 * Print out statistics every 10 seconds
 */
static void rpc_sched(struct list_head *list)
{
	struct tcpproxy_session *ses;
	struct rpc_priv_data *data;
	struct rpc_task *task, *tmp;
	int i, n;
	int prio[4];
	bool max_reached = false;

	memset(prio, 0, sizeof(prio));
	mutex_lock(&queue_mtx);
	
	for (i = 1; i <= 3; i++) {
		/* don't forward if too many requests are pending already */
		list_for_each_entry(data, &queue[i].ses, list) {
			ses = data->ses;
			BUG_ON(!ses);

			tcpproxy_session_lock(ses);
			prio[i] += rpc_pending_tasks(data);
			tcpproxy_session_unlock(ses);
			if (prio[i] >= queue[i].max_rpcs) {
				max_reached = true;
				break;
			}
		}
		prio[i] = 0;
		/* forward traffic to back-end according to priority */
		list_for_each_entry(data, &queue[i].ses, list){
			ses = data->ses;
			BUG_ON(!ses);
			n = 0;

			tcpproxy_session_lock(ses);
			/* forward requests, unless max number of req reached */
			if (max_reached == false) 
				list_for_each_entry_safe(task, tmp, &data->request_queue, list) {
					rpc_send_msg(ses->ses_outbound_sock->sk, data, 
						task, RPC_REQUEST);
					n++;
					if (prio[i] + n >= queue[i].max_rpcs)
						break;
				}
			/* update number of pending requests */
			prio[i] += rpc_pending_tasks(data);
			
			/* stop forwarding requests if threshold reached */
			if (prio[i] >= queue[i].max_rpcs)
				max_reached = true;
			tcpproxy_session_unlock(ses);
		}
	}
	mutex_unlock(&queue_mtx);
}

static void rpc_print_pending(char *msg, size_t *size)
{
	struct tcpproxy_session *ses;
	struct rpc_priv_data *data;
	int prio[4];
	int i;

	memset(prio, 0, sizeof(prio));
	mutex_lock(&queue_mtx);
	for (i = 1; i <= 3; i++) {
		list_for_each_entry(data, &queue[i].ses, list) {
			ses = data->ses;
			BUG_ON(!ses);

			tcpproxy_session_lock(ses);
			prio[i] += rpc_pending_tasks(data);
			tcpproxy_session_unlock(ses);
		}
	}
	mutex_unlock(&queue_mtx);

	*size = sprintf(msg, "P1: %d P2: %d P3: %d\n",
		prio[1], prio[2], prio[3]);
}

static void rpc_print_stats(char *msg, size_t *size)
{
	int i;
	s64 lat[4];
	struct rpc_stats *stats;

	mutex_lock(&queue_mtx);
	for (i = 1; i <= 3; i++) {
		stats = &queue[i].stats;
		if (stats->n == 0) {
			lat[i] = -1;
			continue;
		}
		lat[i] = div64_u64(stats->latency, stats->n);
	}
	*size = sprintf(msg, "P1: num=%d lat=%lld usec P2: num=%d"
		" lat=%lld usec P3: num=%d lat=%lld usec\n",
		queue[1].stats.n, lat[1],
		queue[2].stats.n, lat[2],
		queue[3].stats.n, lat[3]);
	mutex_unlock(&queue_mtx);
}

static void rpc_reset_stats(char *msg, size_t *size)
{
	int i;
	struct rpc_stats *stats;

	mutex_lock(&queue_mtx);
	for (i = 1; i <= 3; i++) {
		stats = &queue[i].stats;
		stats->n = stats->latency = 0;
	}
	mutex_unlock(&queue_mtx);
	strcpy(msg, "ok\n");
	*size = sizeof("ok\n")-1;
}

static int rpc_configure_flt(char *msg, size_t *size)
{
	char addrstr[16];
	__be32 addr;
	int prio;

	if (strstr(msg, "flt rpc client") == msg ) {
		sscanf(msg, "flt rpc client addr %s prio %d", addrstr, &prio);
		if (prio < 1 || prio > 3)
			return -EINVAL;
		addr = in_aton(addrstr);
		rpc_insert_clnt(addr, prio);
	}
	else if (strstr(msg, "flt rpc max") == msg) {
		int n;

		sscanf(msg, "flt rpc max %d prio %d", &n, &prio);
		if (prio < 1 || prio > 3)
			return -EINVAL;
		queue[prio].max_rpcs = n;
	}
	else if (strstr(msg, "flt rpc pending print") == msg)
		rpc_print_pending(msg, size);
	else if (strstr(msg, "flt rpc stat print") == msg)
		rpc_print_stats(msg, size);
	else if (strstr(msg, "flt rpc stat reset") == msg)
		rpc_reset_stats(msg, size);
	else if (strstr(msg, "flt rpc nfsstat print") == msg)
		print_nfs_stats(msg, size);
	else if (strstr(msg, "flt rpc nfsstat reset") == msg)
		reset_nfs_stats(msg, size);
	else
		return -EINVAL;
	printk(KERN_INFO "%s return\n", __func__);

	return 0;
}

/*
 * Attach private scheduler data to TCP proxy session
 */
static void rpc_create_flt(struct tcpproxy_session *ses)
{
	struct rpc_clnt *clnt;
	__be32 addr;
	/* give all unknown client low priority */
	int prio = 3;

	/* get client IP */
	printk(KERN_INFO "%s enter\n", __func__);
	addr = inet_sk(ses->ses_inbound_sock->sk)->inet_daddr;
	clnt = rpc_lookup_clnt(addr);
	printk(KERN_INFO "%s clnt=%p\n", __func__, clnt);
	if (clnt)
		prio = clnt->prio; 
	rpc_create_priv_data(ses, addr, prio);
	printk(KERN_INFO "%s prio=%d\n", __func__, prio);
}

/*
 * Free private scheduler data
 */
static void rpc_destroy_flt(struct tcpproxy_session *ses)
{
	if (ses->ses_priv_data)
		rpc_destroy_priv_data(ses->ses_priv_data);
}

static int rpc_init_flt(void)
{
	int i;

	memset(queue, 0, sizeof(queue));
	for (i = 1; i <= 3; i++) {
		INIT_LIST_HEAD(&queue[i].ses);
		queue[i].max_rpcs = 1000;
	}

	rqst_slab = kmem_cache_create(	"rpc_rqsts", 
					sizeof(struct rpc_task),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!rqst_slab)
		return -ENOMEM;
	rqst_mempool = mempool_create_slab_pool(RPC_POOLSIZE,
						rqst_slab);
	if (!rqst_mempool) {
		kmem_cache_destroy(rqst_slab);
		return -ENOMEM;
	}
	net_enable_timestamp();

	return 0;
}

static void rpc_exit_flt(void)
{
	rpc_destroy_clnts();
	if (rqst_mempool)
		mempool_destroy(rqst_mempool);
	if (rqst_slab)
		kmem_cache_destroy(rqst_slab);
	net_disable_timestamp();
}

struct tcpproxy_scheduler tcpproxy_rpc_scheduler = {
	.tps_interval = 1,
	.tps_sched = rpc_sched,
};

struct tcpproxy_filter tcpproxy_rpc_filter = {
	.tpf_name = "rpc",
	.tpf_init_flt = rpc_init_flt,
	.tpf_exit_flt = rpc_exit_flt,
	.tpf_configure_flt = rpc_configure_flt,
	.tpf_connect_flt = rpc_create_flt,
	.tpf_disconnect_flt = rpc_destroy_flt,
	.tpf_inbound_flt = rpc_inbound_flt,
	.tpf_outbound_flt = rpc_outbound_flt,
	.tpf_backend = true,
	.tpf_sched = &tcpproxy_rpc_scheduler,
};

