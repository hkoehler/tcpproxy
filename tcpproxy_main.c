/*********************************************************************************************
 * Copyright (c) 2010, SmApper Technologies Inc 
 * $Id: tcpproxy_main.c 15 2011-05-11 21:59:51Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/


#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include <linux/workqueue.h>
#include <linux/mempool.h>
#include <linux/net.h>
#include <linux/in.h>

#include <net/sock.h>
#include <net/tcp.h>

#include "tcpproxy.h"
#include "tcpproxy_internal.h"
#include "udpproxy_internal.h"

#define TCP_SES_POOLSIZE 64

#if 0
#define dprintk(format...) printk(format)
#else
#define dprintk(format...)
#endif

static void destroy_tcpsock(struct kref *);
static void destroy_all_tcpsock(void);
static void destroy_tcp_ses(struct kref *);
static void destroy_all_tcp_ses(void);
static void enable_tcp_ses(struct tcpproxy_ses *ts);
static bool disable_tcp_ses(struct tcpproxy_ses *ts, bool remove);
static void inbound_state_change(struct sock *sk);
static void inbound_data_ready(struct sock *sk, int unused);
static void outbound_state_change(struct sock *sk);
static void outbound_data_ready(struct sock *sk, int unused);
static void inbound_close(struct work_struct *work);
static void inbound_forward(struct work_struct *work);
static void outbound_close(struct work_struct *work);
static void outbound_forward(struct work_struct *work);

struct kobject			*tcpproxy_kobj = NULL;
struct workqueue_struct 	*tcpproxy_wq = NULL;

int tcpproxy_running = false;
static LIST_HEAD(tcpsock_list);
static DEFINE_MUTEX(tcpproxy_mtx);

/* memory pool for TCP sessions */
static struct kmem_cache *tcp_ses_slab __read_mostly;
static mempool_t *tcp_ses_mempool __read_mostly;

/* get reference to connection pair */
static void get_ts(struct tcpproxy_ses *ts)
{
	kref_get(&ts->ses_ref);
}

/* release reference to connection pair */
static void put_ts(struct tcpproxy_ses *ts)
{
	kref_put(&ts->ses_ref, destroy_tcp_ses);
}

/* get reference to server socket */
static void get_tcpsock(struct tcpproxy_sock *ts)
{
	kref_get(&ts->ts_ref);
}

/* release reference to server socket */
static void put_tcpsock(struct tcpproxy_sock *ts)
{
	kref_put(&ts->ts_ref, destroy_tcpsock);
}

void tcpproxy_session_get(struct tcpproxy_session *ses)
{
	get_ts((struct tcpproxy_ses *)ses);
}

void tcpproxy_session_put(struct tcpproxy_session *ses)
{
	put_ts((struct tcpproxy_ses *)ses);
}

void tcpproxy_session_lock(struct tcpproxy_session *ses)
{
	mutex_lock(&((struct tcpproxy_ses *)ses)->ses_mtx);
}

void tcpproxy_session_unlock(struct tcpproxy_session *ses)
{
	mutex_unlock(&((struct tcpproxy_ses *)ses)->ses_mtx);
}

int tcpproxy_start(void)
{
	int err = 0;

	printk(KERN_INFO "start tcpproxy\n");
	mutex_lock(&tcpproxy_mtx);
	if (tcpproxy_running == false) {
		if (!tcpproxy_wq) {
			tcpproxy_wq = create_workqueue("tcpproxyd");
			err = (tcpproxy_wq == NULL) ? -ENOMEM : 0;
			if (err)
				goto out;
		}
		tcpproxy_start_sched();
		udpproxy_start();
		tcpproxy_running = true;
	}
	else
		printk(KERN_INFO "tcpproxy already running\n");
out:
	mutex_unlock(&tcpproxy_mtx);
	
	return err;
}

void tcpproxy_stop(void)
{
	mutex_lock(&tcpproxy_mtx);
	if (tcpproxy_running == true) {
		printk(KERN_INFO "stopping tcpproxy\n");

		printk(KERN_INFO "destroy UDP sockets\n");
		udpproxy_stop();

		printk(KERN_INFO "stop schedulers\n");
		tcpproxy_exit_sched();

		printk(KERN_INFO "destroy TCP server sockets\n");
		destroy_all_tcpsock();

		/* make sure no new connections are being established */
		//printk(KERN_INFO "flushed work queue\n");
		//flush_workqueue(tcpproxy_wq);

		printk(KERN_INFO "destroy TCP sessions\n");
		destroy_all_tcp_ses();

		printk(KERN_INFO "destroy work queue\n");
		destroy_workqueue(tcpproxy_wq);
		tcpproxy_wq = NULL;

		printk(KERN_INFO "tcpproxy stopped\n");
		tcpproxy_running = false;
	}
	mutex_unlock(&tcpproxy_mtx);
}

/* connect to back-end server, create connection pair of in- and outbound sockets */
static struct tcpproxy_ses *create_tcp_ses(struct tcpproxy_sock *ss, struct socket *sock)
{
	int err = 0; 
	struct tcpproxy_ses *ts;
	struct sockaddr_in rsin;

	/*if (sock->sk->sk_state != TCP_ESTABLISHED)
		return ERR_PTR(-EINVAL);*/

	ts = (struct tcpproxy_ses *)mempool_alloc(tcp_ses_mempool, GFP_KERNEL);
	memset(ts, 0, sizeof(*ts));
	kref_init(&ts->ses_ref);
	ts->ses_enabled = false;
	mutex_init(&ts->ses_mtx);
	INIT_LIST_HEAD(&ts->ses_list);
	ts->ses_filter = ss->ts_filter;  /* TCP sessions inherit TCP filter from server socket */
	ts->ses_inbound_sock = sock;
	ts->ses_srv = ss;
	INIT_WORK(&ts->ses_inbound_close_work, inbound_close);
	INIT_WORK(&ts->ses_inbound_rx_work, inbound_forward);
	INIT_WORK(&ts->ses_outbound_close_work, outbound_close);
	INIT_WORK(&ts->ses_outbound_rx_work, outbound_forward);
	
	if (tcpproxy_filter_backend((struct tcpproxy_session *)ts)) {
		err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &ts->ses_outbound_sock);
		if (err < 0)
			goto out;

		/* XXX does block */
		memcpy(&rsin, (struct sockaddr_in *)&ss->ts_raddr, sizeof(struct sockaddr_in));
		err = kernel_connect(ts->ses_outbound_sock, (struct sockaddr *)&rsin, sizeof(rsin), 0);
		if (err < 0)
			goto out;
		printk(KERN_INFO "%s: connected out-bound sock %p\n", __func__, ts->ses_outbound_sock->sk);
	}

	/* filter create event */
	tcpproxy_filter_connect((struct tcpproxy_session *)ts);
	
	printk(KERN_INFO "created connection pair %p (%p, %p)\n", ts,
			ts->ses_inbound_sock ? ts->ses_inbound_sock->sk : NULL,
			ts->ses_outbound_sock ? ts->ses_outbound_sock->sk : NULL);
out:
	if (err < 0) {
		put_ts(ts);
		return ERR_PTR(err);
	}
	else
		return ts;
}

/* terminate both TCP sessions */
static void kill_tcp_ses(struct tcpproxy_ses *ts)
{
	if (ts->ses_inbound_sock) {
		printk(KERN_INFO "%s: release sock %p\n", __func__,
				ts->ses_inbound_sock->sk);
		kernel_sock_shutdown(ts->ses_inbound_sock, SHUT_RDWR);
		sock_release(ts->ses_inbound_sock);
	}
	if (ts->ses_outbound_sock) {
		printk(KERN_INFO "%s: release sock %p\n", __func__,
				ts->ses_outbound_sock->sk);
		kernel_sock_shutdown(ts->ses_outbound_sock, SHUT_RDWR);
		sock_release(ts->ses_outbound_sock);
	}
}

/*
 * Attach TCP proxy session to socket, by installing own socket call-backs.
 * Save old socket call-backs.
 * Append TCP session to filter-specific session list.
 * The filter takes ownership of TCP proxy session.
 */
static void enable_tcp_ses(struct tcpproxy_ses *ts)
{
	struct sock *sk;
	struct tcpproxy_filter *filter = ts->ses_filter;

	mutex_lock(&ts->ses_mtx);
	if (ts->ses_enabled == true) {
		mutex_unlock(&ts->ses_mtx);
		printk(KERN_INFO "%s: already enabled ses %p\n", __func__, ts);
		return;
	}
	if (ts->ses_inbound_sock) {
		sk = ts->ses_inbound_sock->sk;
		write_lock_bh(&sk->sk_callback_lock);
		ts->old_inbound_tcp_data_ready = sk->sk_data_ready;
		ts->old_inbound_tcp_state_change = sk->sk_state_change;
		sk->sk_user_data = ts;
		sk->sk_data_ready = inbound_data_ready;
		sk->sk_state_change = inbound_state_change;
		write_unlock_bh(&sk->sk_callback_lock);
	}

	if (ts->ses_outbound_sock) {
		sk = ts->ses_outbound_sock->sk;
		write_lock_bh(&sk->sk_callback_lock);
		ts->old_outbound_tcp_data_ready = sk->sk_data_ready;
		ts->old_outbound_tcp_state_change = sk->sk_state_change;
		sk->sk_user_data = ts;
		sk->sk_data_ready = outbound_data_ready;
		sk->sk_state_change = outbound_state_change;
		write_unlock_bh(&sk->sk_callback_lock);
	}

	ts->ses_enabled = true;
	mutex_unlock(&ts->ses_mtx);

	/* let scheduler pick up session */
	down_write(&filter->tpf_sem);
	list_add_tail(&ts->ses_list, &filter->tpf_ses_list);
	up_write(&filter->tpf_sem);

	printk(KERN_INFO "%s: enabled ses %p\n", __func__, ts);
}

/*
 * Detach TCP proxy session from socket
 * Disable socket call-backs
 * Optionally remove TCP proxy session from filter
 * Passes reference to caller if removed.
 */
static bool disable_tcp_ses(struct tcpproxy_ses *ts, bool remove)
{
	struct sock *sk;
	struct tcpproxy_filter *filter = ts->ses_filter;
	struct tcpproxy_ses *ts_iter;
	bool removed = false;

	/*
	 * remove TCP proxy session from filter,
	 * don't let scheduler process TCP session anymore
	 */
	if (remove) {
		down_write(&filter->tpf_sem);
		list_for_each_entry(ts_iter, &filter->tpf_ses_list, ses_list)
			if (ts_iter == ts) {
				list_del(&ts->ses_list);
				removed = true;
				printk(KERN_INFO "%s: removed %p\n", __func__, ts);
				break;
			}
		up_write(&filter->tpf_sem);
	}

	mutex_lock(&ts->ses_mtx);
	if (ts->ses_enabled == false) {
		printk(KERN_INFO "%s: already disabled ses %p\n", __func__, ts);
		mutex_unlock(&ts->ses_mtx);
		return removed;
	}

	if (ts->ses_inbound_sock) {
		sk = ts->ses_inbound_sock->sk;
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_user_data = NULL;
		sk->sk_data_ready = ts->old_inbound_tcp_data_ready;
		sk->sk_state_change = ts->old_inbound_tcp_state_change;
		write_unlock_bh(&sk->sk_callback_lock);
	}
	if (ts->ses_outbound_sock) {
		sk = ts->ses_outbound_sock->sk;
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_user_data = NULL;
		sk->sk_data_ready = ts->old_outbound_tcp_data_ready;
		sk->sk_state_change = ts->old_outbound_tcp_state_change;
		write_unlock_bh(&sk->sk_callback_lock);
	}
	ts->ses_enabled = false;
	mutex_unlock(&ts->ses_mtx);

	printk(KERN_INFO "%s: disabled ses %p\n", __func__, ts);
	return removed;
}

static void destroy_tcp_ses(struct kref *ref)
{
	struct tcpproxy_ses *ts;
	
	ts = container_of(ref, struct tcpproxy_ses, ses_ref);

	printk(KERN_INFO "destroy connection pair %p (%p, %p)\n", ts,
			ts->ses_inbound_sock ? ts->ses_inbound_sock->sk : NULL,
			ts->ses_outbound_sock ? ts->ses_outbound_sock->sk : NULL);

	tcpproxy_filter_disconnect((struct tcpproxy_session *)ts);
	kill_tcp_ses(ts);
	mempool_free(ts, tcp_ses_mempool);
}

static void destroy_all_tcp_ses(void)
{
	struct tcpproxy_filter *flt;
	struct tcpproxy_ses *ts, *tmp;
	struct list_head list = LIST_HEAD_INIT(list);

	list_for_each_entry(flt, &tcpproxy_filters, tpf_list) {
		down_write(&flt->tpf_sem);
		list_for_each_entry_safe(ts, tmp, &flt->tpf_ses_list, ses_list) {
			list_del(&ts->ses_list);
			disable_tcp_ses(ts, false);
			list_add_tail(&ts->ses_list, &list);
		}
		up_write(&flt->tpf_sem);
	}

	/* delete TCP sessions w/o flt semaphor held to prevent dead locks */
	list_for_each_entry_safe(ts, tmp, &list, ses_list) {
		flush_work(&ts->ses_inbound_close_work);
		flush_work(&ts->ses_inbound_rx_work);
		flush_work(&ts->ses_outbound_close_work);
		flush_work(&ts->ses_outbound_rx_work);
		put_ts(ts);
	}
}

static void inbound_close(struct work_struct *work)
{
	struct tcpproxy_ses *ts;
	struct tcpproxy_filter *flt;

	ts = container_of(work, struct tcpproxy_ses, ses_inbound_close_work);
	printk(KERN_INFO "%s: close in-bound connection %p\n", __func__, ts);
	if (disable_tcp_ses(ts, true))
		put_ts(ts);
	/* give filter a chance to process session a last time */
	flt = ts->ses_filter;
	if (tcpproxy_filter_inbound((struct tcpproxy_session *)ts) > 0)
		tcpproxy_sched(flt);
	put_ts(ts);
}

static void outbound_close(struct work_struct *work)
{
	struct tcpproxy_ses *ts;
	struct tcpproxy_filter *flt;

	ts = container_of(work, struct tcpproxy_ses, ses_outbound_close_work);
	printk(KERN_INFO "%s: close out-bound connection %p\n", __func__, ts);
	if (disable_tcp_ses(ts, true))
		put_ts(ts);
	/* give filter a chance to process session a last time */
	flt = ts->ses_filter;
	if (tcpproxy_filter_outbound((struct tcpproxy_session *)ts) > 0)
		tcpproxy_sched(flt);
	put_ts(ts);
}

/* 
 * forwards TCP traffic to back-end 
 */
static void inbound_forward(struct work_struct *work)
{
	struct tcpproxy_ses *ts;
	int res;

	ts = container_of(work, struct tcpproxy_ses, ses_inbound_rx_work);
	//printk(KERN_DEBUG "%s: sock=%p\n", __func__, ts->cp_inbound_sock->sk);
	res = tcpproxy_filter_inbound((struct tcpproxy_session*)ts);
	if (res < 0) {
		if (disable_tcp_ses(ts, true))
			put_ts(ts);
	}
	put_ts(ts);
}

/* 
 * forwards TCP traffic to clients 
 */
static void outbound_forward(struct work_struct *work)
{
	struct tcpproxy_ses *ts;
	int res;

	ts = container_of(work, struct tcpproxy_ses, ses_outbound_rx_work);
	//printk(KERN_DEBUG "%s: sock=%p\n", __func__, ts->cp_outbound_sock->sk);
	res = tcpproxy_filter_outbound((struct tcpproxy_session*)ts);
	if (res < 0) {
		if (disable_tcp_ses(ts, true))
			put_ts(ts);
	}
	put_ts(ts);
}

/*
 * accept new in-bound connection, create new outbound connection
 * returns kernel_accept() status
 */
static int accept_tcp_ses(struct tcpproxy_sock *ss)
{
	int err;
	struct socket *newsock;
	struct sock *sk;
	struct tcpproxy_ses *ts = NULL;

	err = kernel_accept(ss->ts_sock, &newsock, SOCK_NONBLOCK);
	if (err < 0) {
		if (err != -EAGAIN)
			printk(KERN_WARNING "accept failed\n");
		return err;
	}
	printk(KERN_INFO "accepted new in-bound sock %p\n", newsock->sk);
	sk = newsock->sk;

	/* don't inherit socket call-backs from tcpproxy_sock */
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data = NULL;
	sk->sk_state_change = ss->old_tcp_state_change;
	write_unlock_bh(&sk->sk_callback_lock);
	
	/* set up new in-bound socket */
	ts = create_tcp_ses(ss, newsock);
	if (IS_ERR(ts)) {
		printk(KERN_WARNING "unable to establish new connection, err=%ld\n",
			PTR_ERR(ts));
		return 0;
	}

	/* close socket again if not established */
	if (sk->sk_state != TCP_ESTABLISHED) {
		/* forward pending data since data_ready call-back hasn't been installed yet */
		tcpproxy_filter_inbound((struct tcpproxy_session *)ts);
		printk(KERN_INFO "%s: close non-established sock %p in state %d\n",
				__func__, sk, sk->sk_state);
		put_ts(ts);
		return 0;
	}

	/* enable sockets by initializing call-backs */
	get_ts(ts);
	enable_tcp_ses(ts);

	/* forward pending data since data_ready call-back hasn't been installed till now */
	if (tcpproxy_filter_inbound((struct tcpproxy_session *)ts) < 0) {
		if (disable_tcp_ses(ts, true))
			put_ts(ts);
	}
	put_ts(ts);

	return 0;
}

/*
 * accept all pending connections on TCP server socket
 */
static void accept_pending_tcp_ses(struct work_struct *work)
{
	int err;
	struct tcpproxy_sock *ss;

	ss = container_of(work, struct tcpproxy_sock, ts_connect_work);
	do {
		err = accept_tcp_ses(ss);
	} while (err >= 0);
	put_tcpsock(ss);
}

/* 
 * socket call-back for pending TCP connection
 * queue work and accept new socket in process context
 */
static void listen_state_change(struct sock *sk)
{
	struct tcpproxy_sock *ss;

	ss = (struct tcpproxy_sock *)sk->sk_user_data;
	if (ss == NULL)
		return;
	switch (sk->sk_state) {
	/* ignore connecting sockets */
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
		break;
	case TCP_ESTABLISHED:
		sk->sk_user_data = NULL;	/* disable call-back for new socket */
		printk(KERN_INFO "%s: connection pending on sock %p\n", __func__, sk);
		get_tcpsock(ss);
		if (!queue_work(tcpproxy_wq, &ss->ts_connect_work))
			put_tcpsock(ss);
		break;
	default:
		printk(KERN_ERR "%s: sock %p not established, state %d\n",
			__func__, sk, sk->sk_state);
		break;
	}
}

/* 
 * socket call-back for changing TCP state
 * A connected socket my be about to die or is already dead
 */
static void inbound_state_change(struct sock *sk)
{
	struct tcpproxy_ses *ts;

	printk(KERN_INFO "%s: check in-bound TCP state %d on sock %p\n", __func__,
		sk->sk_state, sk);
	ts = (struct tcpproxy_ses *)sk->sk_user_data;
	if (ts == NULL)
		return;
	if (ts->ses_enabled == false) {
		printk(KERN_ERR "%s: session disabled ses=%p sock=%p\n",
				__func__, ts, sk);
		return;
	}
	switch (sk->sk_state) {
	/* ignore connecting or established sockets */
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		break;
	default:
		get_ts(ts);
		if (!queue_work(tcpproxy_wq, &ts->ses_inbound_close_work))
			put_ts(ts);
	}
}

/* 
 * socket call-back for pending data
 * queue work and read data from socket in process context
 */
static void inbound_data_ready(struct sock *sk, int len)
{
	struct tcpproxy_ses *ts;

	dprintk(KERN_DEBUG "%s: %d bytes in-bound data ready %p\n",
		__func__, len, sk);
	ts = (struct tcpproxy_ses *)sk->sk_user_data;
	if (ts == NULL)
		return;
	if (ts->ses_enabled == false) {
		printk(KERN_ERR "%s: session disabled ses=%p sock=%p\n",
				__func__, ts, sk);
		return;
	}
	get_ts(ts);
	if (!queue_work(tcpproxy_wq, &ts->ses_inbound_rx_work))
		put_ts(ts);
}

/* 
 * socket call-back for changing TCP state
 * A connected socket my be about to die or is already dead
 */
static void outbound_state_change(struct sock *sk)
{
	struct tcpproxy_ses *ts;

	dprintk(KERN_INFO "%s: check out-bound TCP state %d on sock %p\n",
		__func__, sk->sk_state, sk);
	ts = (struct tcpproxy_ses *)sk->sk_user_data;
	if (ts == NULL)
		return;
	if (ts->ses_enabled == false) {
		printk(KERN_ERR "%s: session disabled ses=%p sock=%p\n",
				__func__, ts, sk);
		return;
	}
	switch (sk->sk_state) {
	/* ignore connecting or established sockets */
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		break;
	default:
		get_ts(ts);
		if (!queue_work(tcpproxy_wq, &ts->ses_outbound_close_work))
			put_ts(ts);
	}
}

/* 
 * socket call-back for pending data
 * queue work and read data from socket in process context
 */
static void outbound_data_ready(struct sock *sk, int len)
{
	struct tcpproxy_ses *ts;

	dprintk(KERN_INFO "%s: %d bytes out-bound data ready %p\n", __func__,
		len, sk);
	ts = (struct tcpproxy_ses *)sk->sk_user_data;
	if (ts == NULL)
		return;
	if (ts->ses_enabled == false) {
		printk(KERN_ERR "%s: session disabled ses=%p sock=%p\n",
				__func__, ts, sk);
		return;
	}
	get_ts(ts);
	if (!queue_work(tcpproxy_wq, &ts->ses_outbound_rx_work))
		put_ts(ts);
}

static void enable_tcpsock(struct tcpproxy_sock *ss)
{
	struct sock *sk;

	dprintk(KERN_INFO "%s %p\n", __func__, ss->ts_sock);
	sk = ss->ts_sock->sk;
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data = ss;
	ss->old_tcp_state_change = sk->sk_state_change;
	sk->sk_state_change = listen_state_change;
	write_unlock_bh(&sk->sk_callback_lock);
	/* let filter now about new server */
	tcpproxy_filter_listen((struct tcpproxy_server *)ss);
}

static void disable_tcpsock(struct tcpproxy_sock *ss)
{
	struct sock *sk;

	printk(KERN_INFO "%s %p\n", __func__, ss->ts_sock);
	if (ss->ts_sock) {
		sk = ss->ts_sock->sk;
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_user_data = NULL;
		sk->sk_state_change = ss->old_tcp_state_change;
		write_unlock_bh(&sk->sk_callback_lock);
		/* let filter now about new server */
		tcpproxy_filter_shutdown((struct tcpproxy_server *)ss);
	}
}

/* create, bind and listen on server socket */
struct tcpproxy_sock *create_tcpsock(__be32 laddr, __be16 lport,
	__be32 raddr, __be16 rport, const char *flt_name)
{
	int err=0;
	struct sockaddr_in *lsin, *rsin;
	struct socket *sock;
	struct tcpproxy_sock *ts;

	mutex_lock(&tcpproxy_mtx);

	ts = (struct tcpproxy_sock *)kzalloc(sizeof(struct tcpproxy_sock), GFP_KERNEL);
	if (!ts) {
		err = -ENOMEM;
		goto out;
	}

	ts->ts_filter = tcpproxy_lookup_filter(flt_name);
	if (ts->ts_filter == NULL) {
		printk(KERN_ERR "no such filter: %s\n", flt_name);
		err = -EINVAL;
		goto out;
	}

	INIT_LIST_HEAD(&ts->ts_list);
	list_add_tail(&ts->ts_list, &tcpsock_list); 
	INIT_WORK(&ts->ts_connect_work, accept_pending_tcp_ses);
	kref_init(&ts->ts_ref);

	lsin = (struct sockaddr_in *)&ts->ts_laddr;
	lsin->sin_family = AF_INET;
	lsin->sin_port = lport;
	lsin->sin_addr.s_addr = laddr;

	rsin = (struct sockaddr_in *)&ts->ts_raddr;
	rsin->sin_family = AF_INET;
	rsin->sin_port = rport;
	rsin->sin_addr.s_addr = raddr;

	err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &ts->ts_sock);
	if (err < 0)
		goto out;
	sock = ts->ts_sock;
	sock->sk->sk_reuse = 1;

	err = kernel_bind(sock, (struct sockaddr*)lsin, sizeof(struct sockaddr_in));
	if (err < 0)
		goto out;

	err = kernel_listen(sock, 64);
	if (err < 0)
		goto out;

	enable_tcpsock(ts);
	printk(KERN_INFO "listening on sock %p\n", ts->ts_sock);

out:
	if (!ts)
		return ERR_PTR(err);
	if (err < 0) {
		put_tcpsock(ts);
		mutex_unlock(&tcpproxy_mtx);
		return ERR_PTR(err);
	}
	else {
		mutex_unlock(&tcpproxy_mtx);
		return ts;
	}
}

static void destroy_tcpsock(struct kref *ref)
{
	struct tcpproxy_sock *ss;

	ss = container_of(ref, struct tcpproxy_sock, ts_ref);
	if (ss->ts_sock) {
		printk(KERN_INFO "destroy server socket %p\n", ss->ts_sock);
		kernel_sock_shutdown(ss->ts_sock, SHUT_RDWR);
		sock_release(ss->ts_sock);
	}
	list_del(&ss->ts_list);
	kfree(ss);
}

static void destroy_all_tcpsock(void)
{
	struct tcpproxy_sock *ss, *tmp;

	list_for_each_entry_safe(ss, tmp, &tcpsock_list, ts_list) {
		disable_tcpsock(ss);
		flush_work(&ss->ts_connect_work);
		put_tcpsock(ss);
	}
}

static int __init tcpproxy_init(void)
{
	int err=0;

	dprintk("init tcpproxy\n");
	err = tcpproxy_ctl_init();
	if (err)
		return err;

	mutex_lock(&tcpproxy_mtx);

	tcp_ses_slab = kmem_cache_create(	"tcpproxy_ses",
					sizeof(struct tcpproxy_ses),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (tcp_ses_slab == NULL) {
		mutex_unlock(&tcpproxy_mtx);
		return -ENOMEM;
	}
	tcp_ses_mempool = mempool_create_slab_pool(TCP_SES_POOLSIZE, tcp_ses_slab);
	if (tcp_ses_mempool == NULL) {
		kmem_cache_destroy(tcp_ses_slab);
		mutex_unlock(&tcpproxy_mtx);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&tcpsock_list);
	udpproxy_init();

	err = tcpproxy_register_filter(&tcpproxy_dflt_filter);
	if (err)
		goto out;

	/*err = tcpproxy_register_filter(&tcpproxy_rpc_filter);
	if (err)
		goto out; */

	err = tcpproxy_register_filter(&tcpproxy_echo_filter);
	if (err)
		goto out;

	err = tcpproxy_register_filter(&tcpproxy_iscsi_filter);
	if (err)
		goto out;
	printk(KERN_INFO "initialized\n");

out:
	if (err)
		tcpproxy_deregister_filters();
	mutex_unlock(&tcpproxy_mtx);
	return err;
}

static void __exit tcpproxy_exit(void)
{
	tcpproxy_stop();
	mutex_lock(&tcpproxy_mtx);
	tcpproxy_deregister_filters();
	if (tcp_ses_mempool)
		mempool_destroy(tcp_ses_mempool);
	if (tcp_ses_slab)
		kmem_cache_destroy(tcp_ses_slab);
	mutex_unlock(&tcpproxy_mtx);
	tcpproxy_ctl_exit();
}

MODULE_LICENSE("GPL");

module_init(tcpproxy_init)
module_exit(tcpproxy_exit)

