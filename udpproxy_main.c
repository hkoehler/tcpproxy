/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: udpproxy_main.c 15 2011-05-11 21:59:51Z hkoehler $
 *********************************************************************************************/

#include "tcpproxy_internal.h"
#include "udpproxy_internal.h"

#define MAX_UDP_SIZE (64*1024)
#define UDP_TIMEOUT 60
//#define UDPPROXY_DEBUG

#ifdef UDPPROXY_DEBUG
#define dprintk(format...) printk(format)
#define inline
#else
#define dprintk(format...)
#endif

/* fwd decl */
static void destroy_udpsock_kref(struct kref *ref);

static LIST_HEAD(udpsock_list);
DEFINE_MUTEX(udpproxy_mtx);
static struct delayed_work timer_work;
static bool running = false;

inline static void get_udpsock(struct udpproxy_sock *us)
{
	kref_get(&us->us_ref);
}

inline static void put_udpsock(struct udpproxy_sock *us)
{
	kref_put(&us->us_ref, destroy_udpsock_kref);
}

/*
 * atomically insert new transaction
 */
inline static struct udpproxy_trans *
insert_trans(struct udpproxy_sock *us, __be32 xid, struct sockaddr_storage *addr)
{
	struct udpproxy_trans *ut;

	dprintk(KERN_INFO "%s: xid=%x\n", __func__, xid);
	ut = (struct udpproxy_trans *)kmalloc(sizeof(struct udpproxy_trans), GFP_KERNEL);
	if (!ut)
		return NULL;
	ut->ut_xid = xid;
	ut->ut_time = get_seconds();
	memcpy(&ut->ut_addr, addr, sizeof(struct sockaddr_storage));
	mutex_lock(&udpproxy_mtx);
	list_add_tail(&ut->ut_list, &us->us_trans_list);
	mutex_unlock(&udpproxy_mtx);

	return ut;
}

/*
 * look up transaction by XID and remove it atomically
 * return locked transaction
 */
inline static struct udpproxy_trans *
remove_trans(struct udpproxy_sock *us, __be32 xid)
{
	struct udpproxy_trans *ut, *res=NULL;

	dprintk(KERN_INFO "%s: xid=%x\n", __func__, xid);
	mutex_lock(&udpproxy_mtx);
	list_for_each_entry(ut, &us->us_trans_list, ut_list)
		if (ut->ut_xid == xid) {
			list_del(&ut->ut_list);
			res = ut;
			break;
		}
	mutex_unlock(&udpproxy_mtx);

	return res;
}

inline static void destroy_trans(struct udpproxy_trans *ut)
{
	kfree(ut);
}

/*
 * Forwards UDP datagrams
 * This routine copies the message twice.
 * Depending on message direction it creates and destroys transactions.
 */
static int forward_msg(	struct udpproxy_sock *us,
						struct socket *in_sock,
						struct socket *out_sock,
						bool insert)
{
	struct udpproxy_trans *ut;
	int sent, received, res;
	char *buf;
	__be32 xid;
	struct sockaddr_storage addr;

	struct kvec vec = {
		.iov_len = MAX_UDP_SIZE,
	};
	struct msghdr recv_msg = {
		.msg_name = &addr,
		.msg_namelen = sizeof(struct sockaddr_storage),
		.msg_flags = MSG_DONTWAIT,
	};
	struct msghdr send_msg = {
		.msg_flags = 0,
	};

	buf = (char*)kmalloc(MAX_UDP_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	vec.iov_base = buf;
	res = kernel_recvmsg(in_sock, &recv_msg, &vec, 1,
		MAX_UDP_SIZE, MSG_DONTWAIT);
	if (res == -EAGAIN)
		goto out;
	if (res < 0) {
		printk(KERN_ERR "%s: recv failed with %d\n", __func__, res);
		goto out;
	}
	received = res;
	dprintk(KERN_INFO "%s: received %d bytes\n", __func__, received);

	if (received == 0)
		goto out;

	xid = *(__be32*)buf;
	if (insert) {
		ut = insert_trans(us, xid, &addr);
		if (ut == NULL) {
			res = -ENOMEM;
			goto out;
		}
	}
	else {
		ut = remove_trans(us, xid);
		if (ut) {
			/*
			 * Specify address when forwarding back to client.
			 * Unlike client socket, the server socket is not connected and
			 * we have to specify the client's address on send().
			 */
			memcpy(&addr, &ut->ut_addr, sizeof(struct sockaddr_storage));
			send_msg.msg_name = &addr;
			send_msg.msg_namelen = sizeof(addr);
			destroy_trans(ut);
		}
		else {
			dprintk(KERN_INFO "transaction %x not found\n", xid);
			res = -EEXIST;
			goto out;
		}
	}

	vec.iov_len = received;
	vec.iov_base = buf;
	res = kernel_sendmsg(out_sock, &send_msg, &vec, 1, received);
	if (res < 0) {
		printk(KERN_ERR "%s: send failed with %d\n", __func__, res);
		if (insert) {
			ut = remove_trans(us, xid);
			if (ut)
				destroy_trans(ut);
		}
		goto out;
	}
	sent = res;
	dprintk(KERN_INFO "%s: sent %d bytes\n", __func__, sent);

	if (received != sent ) {
		printk(KERN_ERR "%s: sent (%d) and received (%d) counter don't match\n",
			__func__, sent, received);
		res = -EAGAIN;
	}

out:
	kfree(buf);
	return res;
}

/*
 * forwards UDP traffic to back-end
 */
static void clnt_recv(struct work_struct *work)
{
	struct udpproxy_sock *us;
	us = container_of(work, struct udpproxy_sock, us_clnt_rx_work);
	dprintk(KERN_INFO "%s: sock=%p\n", __func__, us->us_clnt_sock->sk);
	while (forward_msg(us, us->us_clnt_sock, us->us_srv_sock, false) > 0);
	put_udpsock(us);
}

/*
 * forwards UDP traffic to clients
 */
static void srv_recv(struct work_struct *work)
{
	struct udpproxy_sock *us;
	us = container_of(work, struct udpproxy_sock, us_srv_rx_work);
	dprintk(KERN_INFO "%s: sock=%p\n", __func__, us->us_srv_sock->sk);
	while (forward_msg(us, us->us_srv_sock, us->us_clnt_sock, true) > 0);
	put_udpsock(us);
}

/*
 * socket call-back for pending request or response data
 * queue work and read data from socket in process context
 */
static void udp_data_ready(struct sock *sk, int len)
{
	struct udpproxy_sock *us;

	dprintk(KERN_INFO "%s: sk=%p len=%d\n", __func__, sk, len);
	us = (struct udpproxy_sock *)sk->sk_user_data;
	if (us == NULL)
		return;
	get_udpsock(us);
	if (sk == us->us_clnt_sock->sk)
		if (!queue_work(tcpproxy_wq, &us->us_clnt_rx_work))
			put_udpsock(us);
	if (sk == us->us_srv_sock->sk)
		if (!queue_work(tcpproxy_wq, &us->us_srv_rx_work))
			put_udpsock(us);
}

/*
 * attach call-backs to UDP socket
 * safe old call-backs
 */
static void enable_udpsock(struct udpproxy_sock *us)
{
	struct sock *sk;

	sk = us->us_srv_sock->sk;
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data = us;
	us->us_old_srv_data_ready = sk->sk_data_ready;
	sk->sk_data_ready = udp_data_ready;
	write_unlock_bh(&sk->sk_callback_lock);

	sk = us->us_clnt_sock->sk;
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data = us;
	us->us_old_clnt_data_ready = sk->sk_data_ready;
	sk->sk_data_ready = udp_data_ready;
	write_unlock_bh(&sk->sk_callback_lock);
}

/*
 * detach call-backs from UDP socket
 * restore old call-backs
 */
static void disable_udpsock(struct udpproxy_sock *us)
{
	struct sock *sk;

	if (us->us_srv_sock) {
		sk = us->us_srv_sock->sk;
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_user_data = NULL;
		sk->sk_data_ready = us->us_old_srv_data_ready;
		write_unlock_bh(&sk->sk_callback_lock);
	}
	if (us->us_clnt_sock) {
		sk = us->us_clnt_sock->sk;
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_user_data = NULL;
		sk->sk_data_ready = us->us_old_clnt_data_ready;
		write_unlock_bh(&sk->sk_callback_lock);
	}
}

static void destroy_udpsock(struct udpproxy_sock *us)
{
	struct udpproxy_trans *ut, *tmp;

	/* UDP socket already disabled, no locking needed */
	list_for_each_entry_safe(ut, tmp, &us->us_trans_list, ut_list)
		destroy_trans(ut);
	if (us->us_srv_sock) {
		sock_release(us->us_srv_sock);
		us->us_srv_sock = NULL;
	}
	if (us->us_clnt_sock) {
		sock_release(us->us_clnt_sock);
		us->us_clnt_sock = NULL;
	}
	mutex_lock(&udpproxy_mtx);
	list_del(&us->us_list);
	mutex_unlock(&udpproxy_mtx);
	kfree(us);
}

static void destroy_udpsock_kref(struct kref *ref)
{
	struct udpproxy_sock *us = container_of(ref, struct udpproxy_sock, us_ref);
	destroy_udpsock(us);
}

static void destroy_all_udpsocks(void)
{
	struct udpproxy_sock *us, *tmp;

	list_for_each_entry_safe(us, tmp, &udpsock_list, us_list) {
		disable_udpsock(us);
		flush_work(&us->us_clnt_rx_work);
		flush_work(&us->us_srv_rx_work);
		put_udpsock(us);
	}
}

/*
 * create and bind UDP socket
 * XXX IPv4 only
 */
struct udpproxy_sock *create_udpsock(__be32 laddr, __be16 lport,
	__be32 raddr, __be16 rport)
{
	int err=0;
	struct sockaddr_in *lsin, *rsin;
	struct socket *sock;
	struct sock *sk;
	struct udpproxy_sock *us;

	us = (struct udpproxy_sock *)kzalloc(sizeof(struct udpproxy_sock), GFP_KERNEL);
	INIT_LIST_HEAD(&us->us_trans_list);
	INIT_LIST_HEAD(&us->us_list);
	INIT_WORK(&us->us_clnt_rx_work, clnt_recv);
	INIT_WORK(&us->us_srv_rx_work, srv_recv);
	kref_init(&us->us_ref);

	/* create server UDP socket */
	err = sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (err < 0)
		goto out;
	us->us_srv_sock = sock;
	sk = sock->sk;
	sk->sk_reuse = 1;

	lsin = (struct sockaddr_in *)&us->us_laddr;
	lsin->sin_family = AF_INET;
	lsin->sin_port = lport;
	lsin->sin_addr.s_addr = laddr;

	err = kernel_bind(sock, (struct sockaddr*)lsin, sizeof(struct sockaddr_in));
	if (err < 0)
		goto out;
	printk(KERN_INFO "bound UDP sock %p\n", sk);

	/* create client UDP socket */
	err = sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (err < 0)
		goto out;
	us->us_clnt_sock = sock;
	sk = sock->sk;
	sk->sk_reuse = 1;

	rsin = (struct sockaddr_in *)&us->us_raddr;
	rsin->sin_family = AF_INET;
	rsin->sin_port = rport;
	rsin->sin_addr.s_addr = raddr;

	err = kernel_connect(sock, (struct sockaddr*)rsin, sizeof(struct sockaddr_in), 0);
	if (err < 0)
		goto out;
	printk(KERN_INFO "connected UDP sock %p\n", sk);

	mutex_lock(&udpproxy_mtx);
	list_add_tail(&us->us_list, &udpsock_list);
	mutex_unlock(&udpproxy_mtx);

	enable_udpsock(us);
out:
	if (err < 0) {
		put_udpsock(us);
		return ERR_PTR(err);
	}

	return us;
}

static void udpproxy_timeout(struct work_struct *work)
{
	struct udpproxy_sock *us;
	struct udpproxy_trans *ut, *tmp;
	unsigned long now = get_seconds();

	mutex_lock(&udpproxy_mtx);
	list_for_each_entry(us, &udpsock_list, us_list)
		list_for_each_entry_safe(ut, tmp, &us->us_trans_list, ut_list)
			if (now - ut->ut_time > UDP_TIMEOUT) {
				printk(KERN_WARNING "UDP RPC request %x timed out\n", ntohl(ut->ut_xid));
				list_del(&ut->ut_list);
				destroy_trans(ut);
			}
	mutex_unlock(&udpproxy_mtx);

	queue_delayed_work(tcpproxy_wq, &timer_work, 10*HZ);
}

void udpproxy_init(void)
{
	INIT_LIST_HEAD(&udpsock_list);
}

void udpproxy_start(void)
{
	if (running)
		return;
	INIT_DELAYED_WORK(&timer_work, udpproxy_timeout);
	udpproxy_timeout(NULL);
	running = true;
}

void udpproxy_stop(void)
{
	if (!running)
		return;
	destroy_all_udpsocks();
	cancel_delayed_work_sync(&timer_work);
	running = false;
}
