/*********************************************************************************************
 * Copyright (c) 2010, SmApper Technologies Inc 
 * $Id: tcpproxy_filter.c 15 2011-05-11 21:59:51Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#include <linux/module.h>

#include "tcpproxy_internal.h"
#include "tcpproxy.h"

LIST_HEAD(tcpproxy_filters);

int tcpproxy_register_filter(struct tcpproxy_filter *flt)
{
	int res;
	struct tcpproxy_scheduler *sched = flt->tpf_sched;

	INIT_LIST_HEAD(&flt->tpf_ses_list);
	init_rwsem(&flt->tpf_sem);
	if (sched)
		sched->tps_filter = flt;
	res = flt->tpf_init_flt();
	if (res < 0)
		return res;
	list_add_tail(&flt->tpf_list, &tcpproxy_filters);
	printk(KERN_INFO "registered filter %s\n", flt->tpf_name);

	return 0;
}
EXPORT_SYMBOL(tcpproxy_register_filter);

void tcpproxy_deregister_filters()
{
	struct tcpproxy_filter *f, *n;

	list_for_each_entry_safe(f, n, &tcpproxy_filters, tpf_list) {
		f->tpf_exit_flt();
		list_del(&f->tpf_list);
	}
}

struct tcpproxy_filter *tcpproxy_lookup_filter(const char *name)
{
	struct tcpproxy_filter *flt = NULL;

	/* look up filter by name and assign it to TCP sock */
	list_for_each_entry(flt, &tcpproxy_filters, tpf_list)
		if (!strcmp(flt->tpf_name, name))
			return flt;

	return NULL;
}

int tcpproxy_configure_filter(struct tcpproxy_filter *flt,
	char *opt, size_t *size)
{
	return flt->tpf_configure_flt(opt, size);
}

int tcpproxy_filter_listen(struct tcpproxy_server *srv)
{
	struct tcpproxy_filter *flt = srv->srv_filter;
	BUG_ON(!flt);
	if (flt->tpf_listen_flt)
		return flt->tpf_listen_flt(srv);
	else
		return 0;
}

int tcpproxy_filter_shutdown(struct tcpproxy_server *srv)
{
	struct tcpproxy_filter *flt = srv->srv_filter;
	BUG_ON(!flt);
	if (flt->tpf_shutdown_flt)
		return flt->tpf_shutdown_flt(srv);
	else
		return 0;
}

void tcpproxy_filter_connect(struct tcpproxy_session *ses)
{
	struct tcpproxy_filter *flt = ses->ses_filter;
	BUG_ON(!flt);
	return flt->tpf_connect_flt(ses);
}

void tcpproxy_filter_disconnect(struct tcpproxy_session *ses)
{
	struct tcpproxy_filter *flt = ses->ses_filter;
	BUG_ON(!flt);
	return flt->tpf_disconnect_flt(ses);
}

int tcpproxy_filter_inbound(struct tcpproxy_session *ses)
{
	struct tcpproxy_filter *flt = ses->ses_filter;
	int res;

	BUG_ON(!flt);
	res = flt->tpf_inbound_flt(ses);
	tcpproxy_sched(flt);
	return res;
}

int tcpproxy_filter_outbound(struct tcpproxy_session *ses)
{
	struct tcpproxy_filter *flt = ses->ses_filter;
	int res;

	BUG_ON(!flt);
	res = flt->tpf_outbound_flt(ses);
	tcpproxy_sched(flt);
	return res;
}

bool tcpproxy_filter_backend(struct tcpproxy_session *ses)
{
	struct tcpproxy_filter *flt = ses->ses_filter;
	BUG_ON(!flt);
	return flt->tpf_backend;
}

static void tcpproxy_sched_fn(struct work_struct *work)
{
	struct tcpproxy_scheduler *sched;

	//sched = container_of(work, struct tcpproxy_scheduler, tps_work);
	sched = (struct tcpproxy_scheduler *)work;
	BUG_ON(!sched);
	tcpproxy_sched(sched->tps_filter);
	queue_delayed_work(tcpproxy_wq, &sched->tps_work, sched->tps_interval);
}

void tcpproxy_sched(struct tcpproxy_filter *flt)
{
	struct tcpproxy_scheduler *sched = flt->tpf_sched;

	if (sched) {
		down_read(&flt->tpf_sem);
		sched->tps_sched(&flt->tpf_ses_list);
		up_read(&flt->tpf_sem);
	}
}
EXPORT_SYMBOL(tcpproxy_sched);

void tcpproxy_start_sched()
{
	struct tcpproxy_scheduler *sched;
	struct tcpproxy_filter *flt;

	list_for_each_entry(flt, &tcpproxy_filters, tpf_list) {
		sched = flt->tpf_sched;
		if (sched) {
			if (sched->tps_initialized == true)
				continue;
			INIT_DELAYED_WORK(&sched->tps_work, tcpproxy_sched_fn);
			queue_delayed_work(tcpproxy_wq, &sched->tps_work, sched->tps_interval);
			sched->tps_initialized = true;
		}
	}
}

void tcpproxy_exit_sched()
{
	struct tcpproxy_scheduler *sched;
	struct tcpproxy_filter *flt;

	list_for_each_entry(flt, &tcpproxy_filters, tpf_list) {
		sched = flt->tpf_sched;
		if (sched) {
			if (sched->tps_initialized == false)
				continue;
			sched->tps_initialized = false;
			printk(KERN_INFO "stop scheduler %s\n", flt->tpf_name);
			cancel_delayed_work_sync(&sched->tps_work);
		}
	}
}

