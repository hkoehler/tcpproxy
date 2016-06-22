/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: scsi_subr.h 150 2011-06-28 17:48:12Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#ifndef SCSI_SUBR_H_
#define SCSI_SUBR_H_

#include <scsi/scsi.h>
#include <scsi/scsi_eh.h>
#include <linux/byteorder/generic.h>
#include <asm/unaligned.h>

/*
 * get logical block address
 */
static inline uint64_t scsi_cdb_get_lba(unsigned char *cdb)
{
	switch (cdb[0]) {
	case READ_6:
	case WRITE_6:
		return be16_to_cpu(get_unaligned((__be16 *)&cdb[2]));
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
	case READ_12:
	case WRITE_12:
	case WRITE_VERIFY_12:
		return be32_to_cpu(get_unaligned((__be32 *)&cdb[2]));
	case READ_16:
	case WRITE_16:
		return be64_to_cpu(get_unaligned((__be64 *)&cdb[2]));
	}

	BUG();
	return 0;
}

/*
 * get number of blocks to transfer
 */
static inline uint32_t scsi_cdb_get_len(unsigned char *cdb)
{
	switch (cdb[0]) {
	case READ_6:
	case WRITE_6:
		return cdb[4];
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
		return be16_to_cpu(get_unaligned((__be16 *)&cdb[7]));
	case READ_12:
	case WRITE_12:
	case WRITE_VERIFY_12:
		return be32_to_cpu(get_unaligned((__be32 *)&cdb[6]));
	case READ_16:
	case WRITE_16:
		return be32_to_cpu(get_unaligned((__be32 *)&cdb[10]));
	}

	BUG();
	return 0;
}

static inline int scsi_cdb_is_read(uint8_t opcode)
{
	switch (opcode) {
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		return true;
	}
	return false;
}

static inline int scsi_cdb_is_write(uint8_t opcode)
{
	switch (opcode) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_VERIFY:
	case WRITE_12:
	case WRITE_VERIFY_12:
	case WRITE_16:
		return true;
	}
	return false;
}

#endif /* SCSI_SUBR_H_ */
