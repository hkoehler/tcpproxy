/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: tcpproxy_echo.c 15 2011-05-11 21:59:51Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

/*
 * TCP filter for endurance testing
 */

#include <linux/skbuff.h>
#include <net/tcp.h>

#include "tcpproxy.h"

#define TCPPROXY_ECHO_DEBUG
#define TCPPROXY_ECHO_NO_ZCOPY

#ifdef TCPPROXY_ECHO_DEBUG
#define dprintk(format...) printk(format)
#else
#define dprintk(format...)
#endif

/* fwd decl of linux/net/ipv4/tcp.c */
int tcp_send_skb_queue(struct sock *sk, struct sk_buff_head *queue);
int tcp_recv_skb_queue(struct sock *sk, struct sk_buff_head *queue);

#ifdef TCPPROXY_ECHO_NO_ZCOPY

/*
 * forwards TCP traffic - obsolete
 * only kept for testing purposes
 */
static int forward_msg(struct socket *in_sock, struct socket *out_sock)
{
	int sent, received;
	char buf[1024];

	struct kvec vec = {
		.iov_len = sizeof(buf),
		.iov_base = buf,
	};
	struct msghdr inbound_msg = {
		.msg_flags = MSG_DONTWAIT,
	};
	struct msghdr outbound_msg = {
		.msg_flags = 0,
	};

	for (;;) {
		received = kernel_recvmsg(in_sock, &inbound_msg, &vec, 1,
			sizeof(buf), MSG_DONTWAIT);
		if (received == -EAGAIN)
			return 0;
		if (received < 0) {
			printk(KERN_ERR "%s: recv failed with %d\n", __func__, received);
			return received;
		}
		dprintk(KERN_INFO "%s: received %d bytes\n", __func__, received);

		if (received == 0)
			return 0;

		vec.iov_len = received;
		vec.iov_base = buf;
		sent = kernel_sendmsg(out_sock, &outbound_msg, &vec, 1, received);
		if (sent < 0) {
			printk(KERN_ERR "%s: send failed with %d\n", __func__, sent);
			return sent;
		}
		dprintk(KERN_INFO "%s: sent %d bytes\n", __func__, sent);

		if (received != sent ) {
			printk(KERN_ERR "%s: sent (%d) and received (%d) counter don't match\n",
				__func__, sent, received);
			return -EAGAIN;
		}

		if (received < sizeof(buf))
			break;
	}

	return 0;
}
#endif

int echo_init_flt(void)
{
	return 0;
}

void echo_exit_flt(void)
{
}

int echo_configure_flt(char *opt, size_t *size)
{
	return -EINVAL;
}

void echo_create_flt(struct tcpproxy_session *ses)
{
}

void echo_destroy_flt(struct tcpproxy_session *ses)
{
}

int echo_inbound_flt(struct tcpproxy_session *ses)
{
	int res;

#ifdef TCPPROXY_ECHO_NO_ZCOPY
	while ((res = forward_msg(ses->ses_inbound_sock, ses->ses_inbound_sock)) > 0);
#else
	struct sk_buff_head queue;

	skb_queue_head_init(&queue);

	res = tcp_recv_skb_queue(ses->ses_inbound_sock->sk,
		&queue);
	dprintk(KERN_INFO "%s: recv %d\n", __func__, res);
	if (res == -EAGAIN)
		return 0;
	if (res < 0)
		printk(KERN_ERR "%s: receive failed with %d\n", __func__, res);
	if (skb_queue_empty(&queue)  || res == 0)
		return 0;

	res = tcp_send_skb_queue(ses->ses_inbound_sock->sk, &queue);
	dprintk(KERN_INFO "%s: send %d\n", __func__, res);
	if (res < 0)
		printk(KERN_ERR "%s: send failed with %d\n", __func__, res);
#endif

	return res;
}

/*
 * this routine should never get called for pending out-bound traffic
 * as we never forward in-bound traffic
 */
int echo_outbound_flt(struct tcpproxy_session *ses)
{
	return 0;
}

struct tcpproxy_filter tcpproxy_echo_filter = {
	.tpf_name = "echo",
	.tpf_init_flt = echo_init_flt,
	.tpf_exit_flt = echo_exit_flt,
	.tpf_configure_flt = echo_configure_flt,
	.tpf_connect_flt = echo_create_flt,
	.tpf_disconnect_flt = echo_destroy_flt,
	.tpf_inbound_flt = echo_inbound_flt,
	.tpf_outbound_flt = echo_outbound_flt,
	.tpf_backend = false,
	.tpf_sched = NULL,
};

