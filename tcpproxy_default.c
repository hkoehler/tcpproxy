/*********************************************************************************************
 * Copyright (c) 2010, SmApper Technologies Inc
 * $Id: tcpproxy_default.c 15 2011-05-11 21:59:51Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/tcp.h>

#include "tcpproxy.h"

/*
 * Private data of filter and scheduler.
 * Contains in- and outbound receive queues.
 */
struct rpc_priv_data
{
	struct sk_buff_head inbound_queue, outbound_queue;
};

/* fwd decl of linux/net/ipv4/tcp.c */
int tcp_send_skb_queue(struct sock *sk, struct sk_buff_head *queue);
int tcp_recv_skb_queue(struct sock *sk, struct sk_buff_head *queue);

int dflt_init_flt(void)
{
	return 0;
}

void dflt_exit_flt(void)
{
}

int dflt_configure_flt(char *opt, size_t *size)
{
	return -EINVAL;
}

/*
 * Attach private scheduler data to TCP proxy session
 */
void dflt_create_flt(struct tcpproxy_session *ses)
{
	struct rpc_priv_data *data = (struct rpc_priv_data *)kmalloc(
		sizeof(struct rpc_priv_data), GFP_KERNEL);
	//printk("%s: session %p\n", __func__, ses);
	//printk("%s: sock name: %x\n", __func__, 
	//	ntohl(inet_sk(ses->ses_inbound_sock->sk)->inet_daddr));

	skb_queue_head_init(&data->inbound_queue);
	skb_queue_head_init(&data->outbound_queue);
	ses->ses_priv_data = data;
}

/*
 * Free private scheduler data
 */
void dflt_destroy_flt(struct tcpproxy_session *ses)
{
	//printk("%s: session %p\n", __func__, ses);
	kfree(ses->ses_priv_data);
}

/*
 * Receive inbound messages and queue them in private scheduler data
 */
int dflt_inbound_flt(struct tcpproxy_session *ses)
{
	int res;
	struct rpc_priv_data *data = (struct rpc_priv_data *)ses->ses_priv_data;

	tcpproxy_session_lock(ses);
	res = tcp_recv_skb_queue(ses->ses_inbound_sock->sk, 
		&data->inbound_queue);
	tcpproxy_session_unlock(ses);
	
	if (res == -EAGAIN)
		return 0;
	if (res < 0)
		printk(KERN_ERR "%s: receive failed with %d\n", __func__, res);

	return res;
}

/*
 * Receive and forward outbound messages.
 */
int dflt_outbound_flt(struct tcpproxy_session *ses)
{
	struct rpc_priv_data *data = (struct rpc_priv_data *)ses->ses_priv_data;
	int res;

	res = tcp_recv_skb_queue(ses->ses_outbound_sock->sk,
		&data->outbound_queue);
	if (res == -EAGAIN)
		return 0;
	if (res < 0)
		printk(KERN_ERR "%s: receive failed with %d\n", __func__, res);
	if (skb_queue_empty(&data->outbound_queue))
		return 0;
	
	res = tcp_send_skb_queue(ses->ses_inbound_sock->sk, &data->outbound_queue);
	if (res < 0)
		printk(KERN_ERR "%s: send failed with %d\n", __func__, res);
	
	return res;
}

/*
 * Forward inbound messages to back-end
 */
void dflt_sched(struct list_head *list)
{
	struct tcpproxy_session *ses;
	struct rpc_priv_data *data;
	int res;

	list_for_each_entry(ses, list, ses_list) {
		tcpproxy_session_lock(ses);
		data = (struct rpc_priv_data *)ses->ses_priv_data;

		if (skb_queue_empty(&data->inbound_queue)) {
			tcpproxy_session_unlock(ses);
			continue;
		}
		res = tcp_send_skb_queue(ses->ses_outbound_sock->sk, &data->inbound_queue);
		tcpproxy_session_unlock(ses);

		if (res < 0)
			printk(KERN_ERR "%s: send failed with %d\n", __func__, res);
	}
}

struct tcpproxy_scheduler tcpproxy_dflt_scheduler = {
	.tps_interval = 1000,
	.tps_sched = dflt_sched,
};

struct tcpproxy_filter tcpproxy_dflt_filter = {
	.tpf_name = "tcp",
	.tpf_init_flt = dflt_init_flt,
	.tpf_exit_flt = dflt_exit_flt,
	.tpf_configure_flt = dflt_configure_flt,
	.tpf_connect_flt = dflt_create_flt,
	.tpf_disconnect_flt = dflt_destroy_flt,
	.tpf_inbound_flt = dflt_inbound_flt,
	.tpf_outbound_flt = dflt_outbound_flt,
	.tpf_backend = true,
	.tpf_sched = &tcpproxy_dflt_scheduler,
};
