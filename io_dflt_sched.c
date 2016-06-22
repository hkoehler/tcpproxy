/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: io_sched.c 107 2011-06-07 02:08:31Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#include "io_sched.h"

/*
 * Default IO scheduler is passing through all IOs
 */
int iosched_input(struct iosched_operation *op)
{
	if (op->op == IOSCHED_ABORT)
		return 0;
	return op->iosched_output(op, false);
}

/*
 * initialize IO scheduler
 */
int iosched_init(void)
{
	return 0;
}

/*
 * exit IO scheduler
 */
void iosched_exit(void)
{
}

