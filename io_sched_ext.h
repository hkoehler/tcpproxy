/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: $
 * Author: Gunther Thiel
 *********************************************************************************************/

#ifndef __IO_SCHEDULER_EXT_H__
#define __IO_SCHEDULER_EXT_H__

#include <linux/module.h>

enum io_scheduler_type {
	IO_SCHED_DEF = 1,
	IO_SCHED_TB  = 2,
	IO_SCHED_EDF = 4,
};

/* io_sched_ctl.c */
void iosched_register_scheduler(enum io_scheduler_type st);
void iosched_unregister_scheduler(enum io_scheduler_type st);
bool iosched_is_scheduler_registered(enum io_scheduler_type st);
int  iosched_lookup_scheduler_type_by_name(const char *name, enum io_scheduler_type *stp);
int  iosched_configure_scheduler(enum io_scheduler_type st, char *opts, size_t *sizep);

/* io_tb_sched.c */
int tb_configure_scheduler(char *opts, size_t *sizep);
int tb_add_rule(const char *rule_name, const char *clnt_name, const char * tgt_name, uint16_t lun, 
		uint32_t capacity, uint32_t rate, uint32_t tao, uint32_t sla, bool on);
int tb_update_rule(const char *rule_name, uint32_t capacity, uint32_t rate, uint32_t tao, uint32_t sla, bool on);
int tb_remove_rule(const char *rule_name);

#endif
