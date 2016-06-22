/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: tcpproxy_ctl.c 379 2011-08-19 11:06:31Z g.thiel $
 * Author: Heiko Koehler
 *********************************************************************************************/

#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#include "tcpproxy_internal.h"
#include "udpproxy_internal.h"
#include "io_sched_ext.h"

static int tcpproxy_major;
static struct class *tcpproxy_class;

static char msg[4096];
static size_t msg_size = 0;
/* only one process/thread is allowed to use ctl interface */
static DEFINE_MUTEX(mtx);

static inline void set_msg(const char *m)
{
	strcpy(msg, m);
	msg_size = strlen(m);
}

static ssize_t tcpproxy_ctl_read(struct file *filep, char __user *buf,
		size_t len, loff_t *off)
{
	int res;

	mutex_lock(&mtx);
	res = simple_read_from_buffer(buf, len, off, msg, msg_size);
	mutex_unlock(&mtx);

	return res;
}

static ssize_t tcpproxy_ctl_write(struct file *filep, const char __user *buf,
		size_t len, loff_t *off)
{
	int err;
	struct tcpproxy_sock *ts;
	struct udpproxy_sock *us;
	struct tcpproxy_filter *flt;
	char laddrstr[16], raddrstr[16], fltname[16], schedname[16];
	int lport, rport;
	__be32 laddr, raddr;
	enum io_scheduler_type st;

	if (len > sizeof(msg)-1)
		return -EINVAL;

	mutex_lock(&mtx);
	err = copy_from_user(msg, buf, sizeof(msg));
	if (err < 0)
		goto out;
	msg[len] = 0;
	printk(KERN_INFO "control: %s", msg);

	if (strstr(msg, "start") == msg) {
		err = tcpproxy_start();
		set_msg("started\n");
	}
	else if (strstr(msg, "stop") == msg) {
		tcpproxy_stop();
		set_msg("stopped\n");
	}
	else if (strstr(msg, "status") == msg) {
			if (tcpproxy_running)
				set_msg("running\n");
			else
				set_msg("stopped\n");
	}
	else if (strstr(msg, "add ") == msg ) {
		err = sscanf(msg, "add %s %s %d %s %d",
			fltname, laddrstr, &lport, raddrstr, &rport);
		if (err != 5) {
			err = -EINVAL;
			goto out;
		}
		if (tcpproxy_running == true) {
			laddr = in_aton(laddrstr);
			raddr = in_aton(raddrstr);
			if (!strcmp(fltname, "udp")) {
				us = create_udpsock(laddr, ntohs(lport),
					raddr, ntohs(rport));
				if (IS_ERR(us))
					err = PTR_ERR(us);
			}
			else {
				ts = create_tcpsock(laddr, ntohs(lport),
					raddr, ntohs(rport), fltname);
				if (IS_ERR(ts))
					err = PTR_ERR(ts);
			}
			if (err >= 0)
				set_msg("ok\n");
		}
		else
			err = -EACCES;
	}
	else if (strstr(msg, "flt ") == msg) {
		err = sscanf(msg, "flt %s", fltname);
		if (err != 1) {
			err = -EINVAL;
			goto out;
		}
		flt = tcpproxy_lookup_filter(fltname);
		if (!flt)
			err = -EINVAL;
		else
			err = tcpproxy_configure_filter(flt, msg, &msg_size);
	}
	else if (strstr(msg, "sched ") == msg) {
		err = sscanf(msg, "sched %s", schedname);
		if (err != 1) {
			err = -EINVAL;
			goto out;
		}
		err = iosched_lookup_scheduler_type_by_name(schedname, &st);
		if (!err) {
			err =  iosched_configure_scheduler(st, msg, &msg_size);
		}
	}
	else {
		err = -EINVAL;
		goto out;
	}

out:
	if (err < 0)
		set_msg("error\n");
	mutex_unlock(&mtx);
	if (err < 0)
		return err;
	else
		return len;
}

static struct file_operations fops = {
		.read = tcpproxy_ctl_read,
		.write = tcpproxy_ctl_write,
};

int tcpproxy_ctl_init(void)
{
	int err = 0;

	tcpproxy_major = register_chrdev(0, "tcpproxy", &fops);
	if (tcpproxy_major < 0) {
		printk(KERN_ERR "registering device failed with %d\n", tcpproxy_major);
		return tcpproxy_major;
	}

	tcpproxy_class = class_create(THIS_MODULE, "tcpproxy");
	if (IS_ERR(tcpproxy_class)) {
		err = PTR_ERR(tcpproxy_class);
		goto out;
	}

	device_create(tcpproxy_class, NULL, MKDEV(tcpproxy_major, 0),
			NULL, "tcpproxy");

out:
	if (err)
		unregister_chrdev(tcpproxy_major, "tcpproxy");
	return 0;
}

void tcpproxy_ctl_exit(void)
{
	device_destroy(tcpproxy_class, MKDEV(tcpproxy_major, 0));
	class_destroy(tcpproxy_class);
	unregister_chrdev(tcpproxy_major, "tcpproxy");
}
