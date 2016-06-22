/*********************************************************************************************
 * Copyright (c) 2010, SmApper Technologies Inc
 * $Id: tcpproxy_nfs.h 15 2011-05-11 21:59:51Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#include "tcpproxy_rpc.h"

/*
 * This header files define all NFSv3 request and response types.
 * The NFS parser store the parse output in the corresponding buffer of the rpc_rqst object.
 */

#ifndef __TCPPROXY_NFS_H__
#define __TCPPROXY_NFS_H__

#define NFS_PROGRAM 100003

#define ACCESS3_READ 0x1
#define ACCESS3_LOOKUP 0x2
#define ACCESS3_MODIFY 0x4
#define ACCESS3_EXTEND 0x8
#define ACCESS3_DELETE 0x10
#define ACCESS3_EXECUTE 0x20

/* per NFS call statistics */
struct nfs_call_stat
{
	const char *op_name;
	atomic_t op_count;
};
extern struct nfs_call_stat nfs_stats[];

/*
 * Generic XDR opaque type
 */
struct xdr_opaque
{
	/* byte count of data */
	u32 len;
	__be32 data[1];
};

/*
 * specific opaque type for NFSv3 file handle
 */
struct nfs3_fh
{
	u32 len;
	__be32 data[16];
};

/*
 * specific opaque type for NFSv3 string
 */
struct nfs3_string
{
	u32 len;
	char data[512];		/* XXX: max filename length is 512 */
};

struct nfs3_post_op_fh
{
	u32 fh_follows;
	struct nfs3_fh fh;
};

enum nfs3_ftype
{
	NFS3REG = 1,
	NFS3DIR = 2,
	NFS3BLK = 3,
	NFS3CHR = 4,
	NFS3LNK = 5,
	NFS3SOCK = 6,
	NFS3FIFO = 7
};

enum nfs3_create_mode
{
	UNCHECKED = 0,
	GUARDED = 1,
	EXCLUSIVE = 2
};

enum nfs3_set_time
{
	DONT_CHANGE = 0,
	SET_TO_SERVER_TIME = 1,
	SET_TO_CLIENT_TIME = 2
};

/*
 * NFSv3 time stamp
 */
struct nfs3_time
{
	u32 secs, nsecs;
};

/*
 * NFSv3 file attributes
 */
struct nfs3_fattr
{
	u32 ftype;
	u32 mode;
	u32 nlink;
	u32 uid, gid;
	u64 size, used;
	u32 rdev[2];
	u64 fsid, fileid;
	struct nfs3_time atime, mtime, ctime;
};

struct nfs3_pre_op_attr
{
	u32 attrs_follow;
	u64 size;
	struct nfs3_time mtime, ctime;
};

struct nfs3_post_op_attr
{
	u32 attr_follows;
	struct nfs3_fattr fattr;
};

struct nfs3_wcc_data
{
	struct nfs3_pre_op_attr before;
	struct nfs3_post_op_attr after;
};

struct nfs3_sattr
{
	u32 mode_follows;
	u32 mode;
	u32 uid_follows;
	u32 uid;
	u32 gid_follows;
	u32 gid;
	u32 size_follows;
	u64 size;
	u32 atime_set;
	struct nfs3_time atime;
	u32 mtime_set;
	struct nfs3_time mtime;
};

/*
 * generic NFSv3 arguments
 * all NFSv3 call arguments start with a NFS file handle
 */
struct nfs3_args
{
	struct nfs3_fh obj;
};

/*
 * generic NFSv3 results
 * all NFSv3 call results start with an error code
 */
struct nfs3_res
{
	u32 status;
};

struct nfs3_getattr_args
{
	struct nfs3_fh obj;
};

struct nfs3_getattr_res
{
	u32 status;
	struct nfs3_fattr obj_attr;
};

struct nfs3_setattr_args
{
	struct nfs3_fh obj;
	struct nfs3_sattr attr;
	u32 ctime_follows;
	struct nfs3_time ctime;
};

struct nfs3_setattr_res
{
	u32 status;
	struct nfs3_wcc_data obj_wcc;
};

struct nfs3_lookup_args
{
	struct nfs3_fh dir;
	struct nfs3_string name;
};

struct nfs3_lookup_res
{
	u32 status;
	struct nfs3_fh obj_fh;
	struct nfs3_post_op_attr obj_attr, dir_attr;
};

struct nfs3_access_args
{
	struct nfs3_fh obj;
	u32 accessbits;
};

struct nfs3_access_res
{
	u32 status;
	struct nfs3_post_op_attr obj_attr;
	u32 accessbits;
};

struct nfs3_readlink_res
{
	u32 status;
	struct nfs3_post_op_attr sym_attr;
	struct nfs3_string data;
};

struct nfs3_read_args
{
	struct nfs3_fh file;
	u64 offset;
	u32 count;
};

struct nfs3_read_res
{
	u32 status;
	struct nfs3_post_op_attr file_attr;
	u32 count;
	u32 eof;
	struct xdr_skb_pos data;
};

struct nfs3_write_args
{
	struct nfs3_fh file;
	u64 offset;
	u32 count;
	u32 stable_how;
	struct xdr_skb_pos data;
};

struct nfs3_write_res
{
	u32 status;
	struct nfs3_wcc_data file_wcc;
	u32 count;
	u32 committed;
	__be32 verf[2];
};

struct nfs3_create_args
{
	struct nfs3_fh dir;
	struct nfs3_string name;
	u32 mode;
	struct nfs3_sattr obj_attr;
	__be32 verf[2];
};

struct nfs3_create_res
{
	u32 status;
	struct nfs3_post_op_fh obj_fh;
	struct nfs3_post_op_attr obj_attr;
	struct nfs3_wcc_data dir_wcc;
};

struct nfs3_mkdir_args
{
	struct nfs3_fh dir;
	struct nfs3_string name;
	struct nfs3_sattr attr;
};

struct nfs3_mkdir_res
{
	u32 status;
	struct nfs3_post_op_fh obj_fh;
	struct nfs3_post_op_attr obj_attr;
	struct nfs3_wcc_data dir_wcc;
};

struct nfs3_symlink_args
{
	struct nfs3_fh dir;
	struct nfs3_string name;
	struct nfs3_sattr sym_attr;
	struct nfs3_string sym_data;
};

struct nfs3_symlink_res
{
	u32 status;
	struct nfs3_post_op_fh obj_fh;
	struct nfs3_post_op_attr obj_attr;
	struct nfs3_wcc_data dir_wcc;
};

struct nfs3_mknod_args
{
	struct nfs3_fh dir;
	struct nfs3_string name;
	u32 ftype;
	struct nfs3_sattr attr;
	u32 spec[2];
};

struct nfs3_mknod_res
{
	u32 status;
	struct nfs3_post_op_fh obj_fh;
	struct nfs3_post_op_attr obj_attr;
	struct nfs3_wcc_data dir_wcc;
};

struct nfs3_remove_args
{
	struct nfs3_fh dir;
	struct nfs3_string name;
};

struct nfs3_remove_res
{
	u32 status;
	struct nfs3_wcc_data dir_wcc;
};

struct nfs3_rmdir_args
{
	struct nfs3_fh dir;
	struct nfs3_string name;
};

struct nfs3_rmdir_res
{
	u32 status;
	struct nfs3_wcc_data dir_wcc;
};

struct nfs3_rename_args
{
	struct nfs3_fh fromdir;
	struct nfs3_string fromname;
	struct nfs3_fh todir;
	struct nfs3_string toname;
};

struct nfs3_rename_res
{
	u32 status;
	struct nfs3_wcc_data fromdir_wcc;
	struct nfs3_wcc_data todir_wcc;
};

struct nfs3_link_args
{
	struct nfs3_fh object;
	struct nfs3_fh parent;
	struct nfs3_string name;
};

struct nfs3_link_res
{
	u32 status;
	struct nfs3_post_op_attr fromdir_attr;
	struct nfs3_wcc_data linkdir_wcc;
};

struct nfs3_dirent
{
	u32 value_follows;
	u64 fileid;
	struct nfs3_string filename;
	u64 cookie;
};
int nfs3_parse_dirent(struct rpc_task *rqst, struct nfs3_dirent *dirent);

struct nfs3_readdir_args
{
	struct nfs3_fh dir;
	u64 cookie;
	__be32 cookieverf[2];
	u32 count;
};

struct nfs3_readdir_res
{
	u32 status;
	struct nfs3_post_op_attr dir_attr;
	__be32 cookieverf[2];
	/*
	 * directory entries are not fully parsed by default
	 * directory entries have to be fetched by calling
	 * nfs3_parse_dirent() on list
	 */
	struct xdr_skb_pos list;
	u32 eof;
	/* used internally */
	struct nfs3_dirent curr_dirent;
};

struct nfs3_direntplus
{
	/* end of list? */
	u32 value_follows;
	u64 fileid;
	struct nfs3_string filename;
	u64 cookie;
	struct nfs3_post_op_attr attr;
	struct nfs3_post_op_fh fh;
};
int nfs3_parse_direntplus(struct rpc_task *rqst, struct nfs3_direntplus *dirent);

struct nfs3_readdirplus_args
{
	struct nfs3_fh dir;
	u64 cookie;
	__be32 cookieverf[2];
	u32 dircount;
	u32 maxcount;
};

struct nfs3_readdirplus_res
{
	u32 status;
	struct nfs3_post_op_attr dir_attr;
	__be32 cookieverf[2];
	/*
	 * directory entries are not fully parsed by default
	 * directory entries have to be fetched by calling
	 * nfs3_parse_direntplus() on list
	 */
	struct xdr_skb_pos list;
	u32 eof;
	/* used internally */
	struct nfs3_direntplus curr_dirent;
};

struct nfs3_fsstat_res
{
	u32 status;
	struct nfs3_post_op_attr obj_attr;
	u64 tbytes;
	u64 fbytes;
	u64 abytes;
	u64 tfiles;
	u64 ffiles;
	u64 afiles;
	u32 invarsec;
};

struct nfs3_fsinfo_res
{
	u32 status;
	struct nfs3_post_op_attr obj_attr;
	u32 rtmax;
	u32 rtpref;
	u32 rtmult;
	u32 wtmax;
	u32 wtpref;
	u32 wtmult;
	u32 dtpref;
	u64 maxfilesize;
	struct nfs3_time time_delta;
	u32 properties;
};

struct nfs3_pathconf_res
{
	u32 status;
	struct nfs3_post_op_attr obj_attr;
	u32 link_max;
	u32 name_max;
	u32 no_trunc;
	u32 chown_restricted;
	u32 case_insensitive;
	u32 case_preserving;
};

struct nfs3_commit_args
{
	struct nfs3_fh file;
	u64 offset;
	u32 count;
};

struct nfs3_commit_res
{
	u32 status;
	struct nfs3_wcc_data file_wcc;
	__be32 verf[2];
};

#endif
