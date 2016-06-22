/*********************************************************************************************
 * Copyright (c) 2010, SmApper Technologies Inc 
 * $Id: tcpproxy_internal.h 15 2011-05-11 21:59:51Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#ifndef __TCPPROXY_INTERNAL_H__
#define __TCPPROXY_INTERNAL_H__

#include <linux/kernel.h>

#include <linux/net.h>
#include <linux/in.h>

#include <net/sock.h>

#include "tcpproxy.h"

/*
 * A server-side socket listening for incoming connections
 * Attached as user data to ss_sock
 */
struct tcpproxy_sock
{
	/* listening socket */
	struct socket *ts_sock;
	/* filter attached to TCP sessions spawned by this server socket  */
	struct tcpproxy_filter *ts_filter;
	/* private data of filter */
	void *ts_priv_data;
	struct list_head ts_list;
	struct kref ts_ref;
	struct work_struct ts_connect_work;
	/* local proxy and remote server addresses */
	struct sockaddr_storage ts_laddr, ts_raddr;
	void (*old_tcp_state_change)(struct sock *sk);
};

/* 
 * The corresponding in- and out-bound TCP connections
 * This structure is attached as user data to both, request and response sockets
 * The out-bound socket inherits its address from the server socket
 */
struct tcpproxy_ses
{
	/* list of all connection pairs */
	struct list_head ses_list;
	/* corresponding request and response sockets */
	struct socket *ses_inbound_sock, *ses_outbound_sock;
	/* back-pointer to server socket */
	struct tcpproxy_sock *ses_srv;
	/* private message scheduler data */
	void *ses_priv_data;
	/* TCP filter inherited from server socket */
	struct tcpproxy_filter *ses_filter;

	/* the following fields are private to the proxy */
	struct kref ses_ref;
	bool ses_enabled;
	struct work_struct ses_inbound_rx_work, ses_inbound_close_work;
	struct work_struct ses_outbound_rx_work, ses_outbound_close_work;
	struct mutex ses_mtx;

	void (*old_outbound_tcp_state_change)(struct sock *sk);
	void (*old_outbound_tcp_data_ready)(struct sock *sk, int len);
	void (*old_inbound_tcp_state_change)(struct sock *sk);
	void (*old_inbound_tcp_data_ready)(struct sock *sk, int len);
};

/* TCP proxy's work queue and thread pool */
extern struct workqueue_struct *tcpproxy_wq;

/* list of available TCP filters */
extern struct list_head tcpproxy_filters;

extern int tcpproxy_running;

/* initialize device file */
int tcpproxy_ctl_init(void);
void tcpproxy_ctl_exit(void);

int tcpproxy_start(void);
void tcpproxy_stop(void);

struct tcpproxy_sock *create_tcpsock(__be32 laddr, __be16 lport,
	__be32 raddr, __be16 rport, const char *flt_name);

#endif
