/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: udpproxy_internal.h 15 2011-05-11 21:59:51Z hkoehler $
 *********************************************************************************************/

#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/mutex.h>

#include <linux/net.h>
#include <linux/in.h>

#include <net/sock.h>
#include <net/udp.h>

#ifndef UDPPROXY_INTERNAL_H_
#define UDPPROXY_INTERNAL_H_

/*
 * Connection-less client and server UDP sockets
 * Attached as user data to server socket
 */
struct udpproxy_sock
{
	struct kref us_ref;
	struct list_head us_list;
	/* socket receiving requests and responses */
	struct socket *us_srv_sock, *us_clnt_sock;
	/* receive request/response work done asynchronously */
	struct work_struct us_clnt_rx_work, us_srv_rx_work;
	/* local proxy and remote server addresses */
	struct sockaddr_storage us_laddr, us_raddr;
	/* list of transactions in progress */
	struct list_head us_trans_list;
	/* old socket call-backs */
	void (*us_old_srv_data_ready)(struct sock *, int);
	void (*us_old_clnt_data_ready)(struct sock *, int);
};

/*
 * UDP/RPC transaction in progress
 * Map request to response by looking at UDP pay load.
 * UDP proxy assume RPC pay load, hence first 4 bytes is transaction ID.
 * Attached as user data to client and server socket.
 */
struct udpproxy_trans
{
	struct list_head ut_list;
	__be32 ut_xid;
	/* UDP client to forward response to */
	struct sockaddr_storage ut_addr;
	/* receive time stamp */
	unsigned long ut_time;
};

/* initialize UDP proxy from TCP proxy */
void udpproxy_init(void);
/*
 * start back ground tasks
 */
void udpproxy_start(void);
/*
 * exit UDP proxy from TCP proxy
 * destroy all UDP sockets
 * stop back ground tasks
 */
void udpproxy_stop(void);
/* create and bind UDP socket */
struct udpproxy_sock *create_udpsock(__be32 laddr, __be16 lport,
	__be32 raddr, __be16 rport);

#endif /* UDPPROXY_INTERNAL_H_ */
