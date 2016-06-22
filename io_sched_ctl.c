/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: $
 * Author: Gunther Thiel
 *********************************************************************************************/

#include "io_sched_ext.h"

/* 
 * this static represents the currently registered and thus configurable schedulers
 *
 */
static uint32_t        io_reg_schedulers = 0;

void iosched_register_scheduler(enum io_scheduler_type st) {

	io_reg_schedulers = io_reg_schedulers | st;
	printk(KERN_INFO "%s: scheduler of type=%d registered.\n",
	       __func__, (int) st);

}

void iosched_unregister_scheduler(enum io_scheduler_type st) {

	io_reg_schedulers = io_reg_schedulers & ~st;
	printk(KERN_INFO "%s: scheduler of type=%d unregistered.\n",
	       __func__, (int) st);

}

bool iosched_is_scheduler_registered(enum io_scheduler_type st) {

	return (io_reg_schedulers & st);

}

int  iosched_lookup_scheduler_type_by_name(const char *name, enum io_scheduler_type *stp) {

	if (!strcmp(name, "tb"))
		*stp = IO_SCHED_TB;
	else if (!strcmp(name, "edf"))
		*stp = IO_SCHED_EDF;
	else
		return -ENOENT;
	return 0;
}

int  iosched_configure_scheduler(enum io_scheduler_type st, char *opts, size_t *sizep) {

	int ret = -ENOENT;
	
	if (!iosched_is_scheduler_registered(st))
		goto out;

	switch (st) {

	case IO_SCHED_TB:
		ret = tb_configure_scheduler(opts, sizep);
	case IO_SCHED_EDF:
		goto out;
	default:
		goto out;

	}

 out:
	return ret;
}





