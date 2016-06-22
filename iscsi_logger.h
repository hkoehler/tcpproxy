/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: iscsi_logger.h 339 2011-08-12 00:57:47Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#ifndef __ISCSI_LOGGER_H__
#define __ISCSI_LOGGER_H__

/*
 * iSCSI logger writes variable sized messages into files.
 * All log files reside in a specified directory and have a name of the form "unixtime.num",
 * where unixtime is the time in seconds since 1970 and num is a generation ID/counter.
 * Ideally, the files are created in a pseudo file system like shmfs w/o an actual disk as backing store.
 * Log files have a maximum size, which lets the logger roll over to a new file once a log file is "full".
 *
 * Log messages don't cross page boundaries. Several messages might be stored in the same page.
 * If a log message doesn't fit inside a page, it'll be put in the next one.
 * Internally, page-based address space fs operations are used to minimize copying.
 */

#include <linux/mm.h>

/*
 * bring up netlink socket
 */
int iscsi_logger_init(void);

/*
 * shutdown netlink socket
 */
void iscsi_logger_exit(void);

/*
 * allocate log message from in-memory log file with
 * given total size, including message header
 * use ISCSI_LOG_MSG_SIZE()
 */
struct iscsi_log_msg *
iscsi_logger_alloc(size_t size, uint8_t type);

/*
 * commit log message
 */
void iscsi_logger_commit(void);

/*
 * roll-over to next log file
 */
void iscsi_logger_roll(void);

/*
 * start logging
 */
void iscsi_logger_start(void);

/*
 * stop logging
 */
void iscsi_logger_stop(void);

#endif
