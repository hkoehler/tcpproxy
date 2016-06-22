/*********************************************************************************************
 * Copyright (c) 2010, SmApper Technologies Inc 
 * $Id: tcpproxy.h 15 2011-05-11 21:59:51Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#ifndef __TCPPROXY_H__
#define __TCPPROXY_H__

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/net.h>

/* fwc decl */
struct tcpproxy_filter;

/*
 * Server listening for in-coming connections
 * Keep in sync with struct tcpproxy_sock
 */
struct tcpproxy_server
{
	/* listening socket */
	struct socket *srv_sock;
	/* filter attached to TCP sessions spawned by this server socket  */
	struct tcpproxy_filter *srv_filter;
	/* private data of filter */
	void *srv_priv_data;
};

/*
 * This structure represent two corresponding in and out-bound connections.
 * Message filter and scheduler attach private data to session.
 *
 * This is the head of a TCP proxy connection pair.
 * Keep in sync with struct conn_pair.
 */
struct tcpproxy_session
{
	/* list of all sessions */
	struct list_head ses_list;
	/* corresponding request and response sockets */
	struct socket *ses_inbound_sock, *ses_outbound_sock;
	/* back-pointer to server socket */
	struct tcpproxy_server *ses_srv;
	/* private message scheduler data */
	void *ses_priv_data;
	/* TCP filter inherited from server socket */
	struct tcpproxy_filter *ses_filter;
};

/*
 * The message scheduler operates on all TCP proxy sessions.
 * It's usually invoked on a regular basis by a timer.
 * It can also be triggered directly by calling tcpproxy_sched().
 * The scheduler must not alter tcpproxy_sessions.
 */
struct tcpproxy_scheduler
{
	struct delayed_work tps_work;
	/* scheduler interval, can be set dynamically */
	unsigned int tps_interval;
	void (*tps_sched)(struct list_head *tcpproxy_session_head);
	bool tps_initialized;
	struct tcpproxy_filter *tps_filter;
};

/*
 * A TCP proxy message filter handles in- and out-bound messages.
 * A return code less than 0 indicates failure to the proxy.
 */
struct tcpproxy_filter
{
	/* list of all filters */
	struct list_head tpf_list;
	/* name of TCP filter for configuration */
	const char *tpf_name;
	/* init filter */
	int (*tpf_init_flt)(void);
	/* exit filter */
	void (*tpf_exit_flt)(void);
	/* set filter option */
	int (*tpf_configure_flt)(char *opt, size_t *count);
	/* a new server socket is listening */
	int (*tpf_listen_flt)(struct tcpproxy_server *ses);
	/* server socket is shutting down */
	int (*tpf_shutdown_flt)(struct tcpproxy_server *ses);
	/* a new session has been created */
	void (*tpf_connect_flt)(struct tcpproxy_session *ses);
	/* session is about to be destroyed */
	void (*tpf_disconnect_flt)(struct tcpproxy_session *ses);
	/* message from the client to be processed */
	int (*tpf_inbound_flt)(struct tcpproxy_session *ses);
	/* message from the server to be processed */
	int (*tpf_outbound_flt)(struct tcpproxy_session *ses);
	/* whether to connect to back-end */
	const bool tpf_backend;
	/* scheduler running in the back-ground */
	struct tcpproxy_scheduler *tpf_sched;
	/*
	 * List of sessions filter has been attached to.
	 * This is the argument passed to the scheduler function.
	 */
	struct list_head tpf_ses_list;
	/* read/write lock protecting session list */
	struct rw_semaphore tpf_sem;
};

/* get reference of TCP proxy session */
void tcpproxy_session_get(struct tcpproxy_session *ses);
/* release reference of TCP proxy session */
void tcpproxy_session_put(struct tcpproxy_session *ses);

/* lock session mutex */
void tcpproxy_session_lock(struct tcpproxy_session *ses);
/* unlock session mutex */
void tcpproxy_session_unlock(struct tcpproxy_session *ses);

/* default TCP proxy filter doing forwarding */
extern struct tcpproxy_filter tcpproxy_dflt_filter;
/* echo TCP proxy filter for testing */
extern struct tcpproxy_filter tcpproxy_echo_filter;
/* remote procedure call TCP proxy filter doing forwarding */
extern struct tcpproxy_filter tcpproxy_rpc_filter;
/* Internet SCSI TCP proxy filter doing forwarding */
extern struct tcpproxy_filter tcpproxy_iscsi_filter;

/* 
 * Install and init new message filter, replace old one
 */
int tcpproxy_register_filter(struct tcpproxy_filter *flt);

/*
 * Exit installed filter
 */
void tcpproxy_deregister_filters(void);

/*
 * Look up filter by name
 */
struct tcpproxy_filter *tcpproxy_lookup_filter(const char *name);

/* 
 * Pass config message to filter.
 * Filter has to respond with message using specified buffer
 * Option has to start with "flt". Otherwise not interpreted by proxy
 */
int tcpproxy_configure_filter(struct tcpproxy_filter *flt,
	char *msg, size_t *size);

/*
 * Call message scheduler.
 */
void tcpproxy_sched(struct tcpproxy_filter *flt);

/*
 * Call message filter on inbound message
 */
int tcpproxy_filter_inbound(struct tcpproxy_session *ses);

/*
 * Call message filter on inbound message
 */
int tcpproxy_filter_outbound(struct tcpproxy_session *ses);

/*
 * Call message filter when TCP server socket is created of destroyed
 */
int tcpproxy_filter_listen(struct tcpproxy_server *srv);
int tcpproxy_filter_shutdown(struct tcpproxy_server *srv);

/*
 * Call message filter on create/destruction of session
 */
void tcpproxy_filter_connect(struct tcpproxy_session *ses);
void tcpproxy_filter_disconnect(struct tcpproxy_session *ses);

/*
 * whether TCP proxy is supposed to connect to the back-end
 * this is might return false for filters written for testing
 */
bool tcpproxy_filter_backend(struct tcpproxy_session *ses);

/*
 * Init/Exit scheduler (called by tcpproxy)
 */
void tcpproxy_start_sched(void);
void tcpproxy_exit_sched(void);

#endif

