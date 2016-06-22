/*********************************************************************************************
 * Copyright (c) 2010, SmApper Technologies Inc
 * $Id: tcpproxy_nfs.c 15 2011-05-11 21:59:51Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

/*********************************************************************************************
 * The NFS parser, unlike the RPC parser only works on complete RPC messages,
 * as it gets called by the RPC parser after a complete RPC message has been received.
 * Hence, the parser only has to walk the socket buffer queue.
 * If the end is reached before the NFS arguments have been fully parsed,
 * the NFS pay load is incomplete.
**********************************************************************************************/

#include "tcpproxy_nfs.h"

#ifdef RPC_TCPPROXY_DEBUG
#define dprintk(format...) printk(format)
#define inline
#else
#define dprintk(format...)
#endif

typedef int (*parser_t)(struct rpc_task *task);

struct nfs_call_stat nfs_stats[] = {
		{"null", {0}},
		{"getattr", {0}},
		{"setattr", {0}},
		{"lookup", {0}},
		{"access", {0}},
		{"readlink", {0}},
		{"read", {0}},
		{"write", {0}},
		{"create", {0}},
		{"mkdir", {0}},
		{"symlink", {0}},
		{"mknod", {0}},
		{"remove", {0}},
		{"rmdir", {0}},
		{"rename", {0}},
		{"link", {0}},
		{"readdir", {0}},
		{"readdirplus", {0}},
		{"fsstat", {0}},
		{"fsinfo", {0}},
		{"pathconf", {0}},
		{"commit", {0}},
};

static inline int xdr_next(struct xdr_skb_pos *p)
{
	if (p->offset >= p->skb->len) {
		if (skb_queue_is_last(p->list, p->skb))
			return false;
		p->skb = p->skb->next;
		p->offset = 0;
	}
	return true;
}

static inline int xdr_u32(struct xdr_skb_pos *p, u32 *n)
{
	if (!xdr_next(p))
		return false;
	skb_copy_bits(p->skb, p->offset, n, sizeof(u32));
	*n = ntohl(*n);
	p->offset += sizeof(u32);
	dprintk(KERN_INFO "%s: %d\n", __func__, *n);

	return true;
}

static inline int xdr_pull(struct xdr_skb_pos *p, __be32 *d, size_t s)
{
	int rem, to_copy, left, copied=0;

	rem = RPC_RNDUP(s);
	while (rem > 0) {
		if (!xdr_next(p))
			return false;
		left = p->skb->len - p->offset;
		to_copy = (rem < left) ? rem : left;
		skb_copy_bits(p->skb, p->offset, &d[copied], to_copy);
		p->offset += to_copy;
		copied += to_copy;
		rem -= to_copy;
	}

	return true;
}

static inline void xdr_ntoh(__be32 *d, size_t s)
{
	int i;
	for (i = 0; i < s; i++)
		d[i] = ntohl(d[i]);
}

static inline int xdr_u64(struct xdr_skb_pos *p, u64 *d)
{
	if (!xdr_pull(p, (__be32 *)d, sizeof(*d)))
		return false;
	xdr_ntoh((__be32 *)d, sizeof(*d));
	dprintk(KERN_INFO "%s: %lld\n", __func__, *d);
	return true;
}

static inline int xdr_opaque(struct xdr_skb_pos *p, struct xdr_opaque *d,
		size_t s)
{
	if (!xdr_u32(p, &d->len))
		return false;
	if (d->len > s - sizeof(u32))
		return false;
	if (!xdr_pull(p, &d->data[0], d->len))
		return false;

	return true;
}

static void print_nfs3_fh(const struct nfs3_fh *fh)
{
	int i;
	char buf[2*fh->len+1];
	char *data = (char *)fh->data;

	for (i = 0; i < fh->len; i++) {
		buf[i*2] = "0123456789abcdef"[(data[i] & 0xf0) >> 4];
		buf[i*2+1] = "0123456789abcdef"[data[i] & 0x0f];
	}
	buf[2*fh->len] = 0;
	dprintk(KERN_INFO "fh len = %d data=%s\n", fh->len, buf);
}

static void print_nfs3_string(const struct nfs3_string *str)
{
	int i;
	dprintk(KERN_INFO "string=\"");
	for (i = 0; i < str->len; i++)
		dprintk(KERN_CONT "%c",  str->data[i]);
	dprintk(KERN_CONT "\"\n");
}

static inline int xdr_nfs3_fh(struct xdr_skb_pos *p, struct nfs3_fh *fh)
{
	if (!xdr_opaque(p, (struct xdr_opaque *)fh, sizeof(*fh)))
		return false;
	print_nfs3_fh(fh);
	return true;
}

static inline int xdr_nfs3_string(struct xdr_skb_pos *p, struct nfs3_string *str)
{
	if (!xdr_opaque(p, (struct xdr_opaque *)str, sizeof(*str)))
		return false;
	print_nfs3_string(str);
	return true;
}

static inline int xdr_nfs3_fattr(struct xdr_skb_pos *p, struct nfs3_fattr *d)
{
	if (!xdr_pull(p, (__be32 *)d, sizeof(*d)))
		return false;
	xdr_ntoh((__be32 *)d, sizeof(*d));
	dprintk(KERN_INFO "fattr ftype=%d nlink=%d mtime=%d\n",
			d->ftype, d->nlink, d->mtime.secs);
	return true;
}

static inline int xdr_nfs3_time(struct xdr_skb_pos *p, struct nfs3_time *d)
{
	if (!xdr_u32(p, &d->secs))
		return false;
	if (!xdr_u32(p, &d->nsecs))
		return false;
	return true;
}

static inline int xdr_nfs3_sattr(struct xdr_skb_pos *p, struct nfs3_sattr *d)
{
	if (!xdr_u32(p, &d->mode_follows))
		return false;
	if (d->mode_follows && !xdr_u32(p, &d->mode))
		return false;
	if (!xdr_u32(p, &d->uid_follows))
		return false;
	if (d->uid_follows && !xdr_u32(p, &d->uid))
		return false;
	if (!xdr_u32(p, &d->gid_follows))
		return false;
	if (d->gid_follows && !xdr_u32(p, &d->gid))
		return false;
	if (!xdr_u32(p, &d->size_follows))
		return false;
	if (d->size_follows && !xdr_u64(p, &d->size))
		return false;
	if (!xdr_u32(p, &d->atime_set))
		return false;
	if (d->atime_set == SET_TO_CLIENT_TIME && !xdr_nfs3_time(p, &d->atime))
		return false;
	if (!xdr_u32(p, &d->mtime_set))
		return false;
	if (d->mtime_set == SET_TO_CLIENT_TIME && !xdr_nfs3_time(p, &d->mtime))
		return false;
	dprintk(KERN_INFO "sattr atime_set=%d mtime_set=%d\n",
			d->atime_set, d->mtime_set);
	return true;
}

static inline int xdr_nfs3_pre_op_attr(struct xdr_skb_pos *p, struct nfs3_pre_op_attr *d)
{
	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_u32(p, &d->attrs_follow))
		return false;
	if (d->attrs_follow == false)
		return true;
	if (!xdr_u64(p, &d->size))
		return false;
	if (!xdr_nfs3_time(p, &d->mtime))
		return false;
	if (!xdr_nfs3_time(p, &d->ctime))
		return false;
	return true;
}

static inline int xdr_nfs3_post_op_attr(struct xdr_skb_pos *p, struct nfs3_post_op_attr *d)
{
	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_u32(p, &d->attr_follows))
		return false;
	if (d->attr_follows == false)
		return true;
	if (!xdr_nfs3_fattr(p, &d->fattr))
		return false;
	return true;
}

static inline int xdr_nfs3_wcc_data(struct xdr_skb_pos *p, struct nfs3_wcc_data *d)
{
	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_pre_op_attr(p, &d->before))
		return false;
	if (!xdr_nfs3_post_op_attr(p, &d->after))
		return false;
	return true;
}

static inline int xdr_nfs3_post_op_fh(struct xdr_skb_pos *p, struct nfs3_post_op_fh *d)
{
	if (!xdr_u32(p, &d->fh_follows))
		return false;
	if (d->fh_follows == false)
		return true;
	if (!xdr_nfs3_fh(p, &d->fh))
		return false;
	return true;
}

static inline int nfs3_parse_getattr_res(struct rpc_task *task)
{
	struct nfs3_getattr_res *res = (struct nfs3_getattr_res *)task->res_buf;
	dprintk(KERN_INFO "%s\n", __func__);
	if (res->status == 0)
		return xdr_nfs3_fattr(&task->xdr_pos, &res->obj_attr);
	else
		return true;
}

static inline int nfs3_parse_setattr_args(struct rpc_task *task)
{
	struct nfs3_setattr_args *args = (struct nfs3_setattr_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_sattr(&task->xdr_pos, &args->attr))
		return false;
	if (!xdr_u32(&task->xdr_pos, &args->ctime_follows))
		return false;
	if (!args->ctime_follows)
		return true;
	if (!xdr_nfs3_time(&task->xdr_pos, &args->ctime))
		return false;

	return true;
}

static inline int nfs3_parse_setattr_res(struct rpc_task *task)
{
	struct nfs3_setattr_res *res = (struct nfs3_setattr_res *)task->res_buf;
	dprintk(KERN_INFO "%s\n", __func__);
	return xdr_nfs3_wcc_data(&task->xdr_pos, &res->obj_wcc);
}

static inline int nfs3_parse_lookup_args(struct rpc_task *task)
{
	struct nfs3_lookup_args *args = (struct nfs3_lookup_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_string(&task->xdr_pos, &args->name))
		return false;
	return true;
}

static inline int nfs3_parse_lookup_res(struct rpc_task *task)
{
	struct nfs3_lookup_res *res = (struct nfs3_lookup_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (res->status == 0) {
		if (!xdr_nfs3_fh(&task->xdr_pos, &res->obj_fh))
			return false;
		if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->obj_attr))
			return false;
	}
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->dir_attr))
		return false;
	return true;
}

static inline int nfs3_parse_access_args(struct rpc_task *task)
{
	struct nfs3_access_args *args = (struct nfs3_access_args *)task->args_buf;
	dprintk(KERN_INFO "%s\n", __func__);
	return xdr_u32(&task->xdr_pos, &args->accessbits);
}

static inline int nfs3_parse_access_res(struct rpc_task *task)
{
	struct nfs3_access_res *res = (struct nfs3_access_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->obj_attr))
		return false;
	if (res->status == 0 && !xdr_u32(&task->xdr_pos, &res->accessbits))
		return false;
	return true;
}

static inline int nfs3_parse_readlink_res(struct rpc_task *task)
{
	struct nfs3_readlink_res *res = (struct nfs3_readlink_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->sym_attr))
		return false;
	if (res->status == 0 && !xdr_nfs3_string(&task->xdr_pos, &res->data))
		return false;
	return true;
}

static inline int nfs3_parse_read_args(struct rpc_task *task)
{
	struct nfs3_read_args *args = (struct nfs3_read_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_u64(&task->xdr_pos, &args->offset))
		return false;
	if (!xdr_u32(&task->xdr_pos, &args->count))
		return false;
	return true;
}

static inline int nfs3_parse_read_res(struct rpc_task *task)
{
	struct nfs3_read_res *res = (struct nfs3_read_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->file_attr))
		return false;
	if (res->status == 0) {
		if (!xdr_u32(&task->xdr_pos, &res->count))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->eof))
			return false;
		memcpy(&res->data, &task->xdr_pos, sizeof(struct xdr_skb_pos));
	}
	return true;
}

static inline int nfs3_parse_write_args(struct rpc_task *task)
{
	struct nfs3_write_args *args = (struct nfs3_write_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_u64(&task->xdr_pos, &args->offset))
		return false;
	if (!xdr_u32(&task->xdr_pos, &args->count))
		return false;
	if (!xdr_u32(&task->xdr_pos, &args->stable_how))
		return false;
	memcpy(&args->data, &task->xdr_pos, sizeof(struct xdr_skb_pos));
	return true;
}

static inline int nfs3_parse_write_res(struct rpc_task *task)
{
	struct nfs3_write_res *res = (struct nfs3_write_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->file_wcc))
		return false;
	if (res->status == 0) {
		if (!xdr_u32(&task->xdr_pos, &res->count))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->committed))
			return false;
		if (!xdr_pull(&task->xdr_pos, res->verf, sizeof(res->verf)))
			return false;
	}
	return true;
}

static inline int nfs3_parse_create_args(struct rpc_task *task)
{
	struct nfs3_create_args *args = (struct nfs3_create_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_string(&task->xdr_pos, &args->name))
		return false;
	if (!xdr_u32(&task->xdr_pos, &args->mode))
		return false;
	switch (args->mode) {
	case UNCHECKED:
	case GUARDED:
		if (!xdr_nfs3_sattr(&task->xdr_pos, &args->obj_attr))
			return false;
	default:
		if (!xdr_pull(&task->xdr_pos, args->verf, sizeof(args->verf)))
			return false;
	}
	return true;
}

static inline int nfs3_parse_create_res(struct rpc_task *task)
{
	struct nfs3_create_res *res = (struct nfs3_create_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (res->status == 0) {
		if (!xdr_nfs3_post_op_fh(&task->xdr_pos, &res->obj_fh))
			return false;
		if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->obj_attr))
			return false;
	}
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->dir_wcc))
		return false;
	return true;
}

static inline int nfs3_parse_mkdir_args(struct rpc_task *task)
{
	struct nfs3_mkdir_args *args = (struct nfs3_mkdir_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (xdr_nfs3_string(&task->xdr_pos, &args->name))
		return false;
	if (xdr_nfs3_sattr(&task->xdr_pos, &args->attr))
		return false;
	return true;
}

static inline int nfs3_parse_mkdir_res(struct rpc_task *task)
{
	struct nfs3_mkdir_res *res = (struct nfs3_mkdir_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (res->status == 0) {
		if (!xdr_nfs3_post_op_fh(&task->xdr_pos, &res->obj_fh))
			return false;
		if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->obj_attr))
			return false;
	}
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->dir_wcc))
		return false;
	return true;
}

static inline int nfs3_parse_symlink_args(struct rpc_task *task)
{
	struct nfs3_symlink_args *args = (struct nfs3_symlink_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_string(&task->xdr_pos, &args->name))
		return false;
	if (!xdr_nfs3_sattr(&task->xdr_pos, &args->sym_attr))
		return false;
	if (!xdr_nfs3_string(&task->xdr_pos, &args->sym_data))
		return false;
	return true;
}

static inline int nfs3_parse_symlink_res(struct rpc_task *task)
{
	struct nfs3_symlink_res *res = (struct nfs3_symlink_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (res->status == 0) {
		if (!xdr_nfs3_post_op_fh(&task->xdr_pos, &res->obj_fh))
			return false;
		if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->obj_attr))
			return false;
	}
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->dir_wcc))
		return false;
	return true;
}

static inline int nfs3_parse_mknod_args(struct rpc_task *task)
{
	struct nfs3_mknod_args *args = (struct nfs3_mknod_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_string(&task->xdr_pos, &args->name))
		return false;
	if (!xdr_u32(&task->xdr_pos, &args->ftype))
		return false;
	switch (args->ftype) {
	case NFS3CHR:
	case NFS3BLK:
		if (!xdr_nfs3_sattr(&task->xdr_pos, &args->attr))
			return false;
		if (!xdr_u32(&task->xdr_pos, &args->spec[0]))
			return false;
		if (!xdr_u32(&task->xdr_pos, &args->spec[1]))
			return false;
		break;
	case NFS3SOCK:
	case NFS3FIFO:
		if (!xdr_nfs3_sattr(&task->xdr_pos, &args->attr))
			return false;
		break;
	default:
		break;
	}
	return true;
}

static inline int nfs3_parse_mknod_res(struct rpc_task *task)
{
	struct nfs3_mknod_res *res = (struct nfs3_mknod_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (res->status == 0) {
		if (!xdr_nfs3_post_op_fh(&task->xdr_pos, &res->obj_fh))
			return false;
		if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->obj_attr))
			return false;
	}
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->dir_wcc))
		return false;
	return true;
}

static inline int nfs3_parse_remove_args(struct rpc_task *task)
{
	struct nfs3_remove_args *args = (struct nfs3_remove_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_string(&task->xdr_pos, &args->name))
		return false;
	return true;
}

static inline int nfs3_parse_remove_res(struct rpc_task *task)
{
	struct nfs3_remove_res *res = (struct nfs3_remove_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->dir_wcc))
		return false;
	return true;
}

static inline int nfs3_parse_rmdir_args(struct rpc_task *task)
{
	struct nfs3_remove_args *args = (struct nfs3_remove_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_string(&task->xdr_pos, &args->name))
		return false;
	return true;
}

static inline int nfs3_parse_rmdir_res(struct rpc_task *task)
{
	struct nfs3_rmdir_res *res = (struct nfs3_rmdir_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->dir_wcc))
		return false;
	return true;
}

static inline int nfs3_parse_rename_args(struct rpc_task *task)
{
	struct nfs3_rename_args *args = (struct nfs3_rename_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_string(&task->xdr_pos, &args->fromname))
		return false;
	if (!xdr_nfs3_fh(&task->xdr_pos, &args->todir))
		return false;
	if (!xdr_nfs3_string(&task->xdr_pos, &args->toname))
		return false;
	return true;
}

static inline int nfs3_parse_rename_res(struct rpc_task *task)
{
	struct nfs3_rename_res *res = (struct nfs3_rename_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->fromdir_wcc))
		return false;
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->todir_wcc))
		return false;
	return true;
}

static inline int nfs3_parse_link_args(struct rpc_task *task)
{
	struct nfs3_link_args *args = (struct nfs3_link_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_fh(&task->xdr_pos, &args->parent))
		return false;
	if (!xdr_nfs3_string(&task->xdr_pos, &args->name))
		return false;
	return true;
}

static inline int nfs3_parse_link_res(struct rpc_task *task)
{
	struct nfs3_link_res *res = (struct nfs3_link_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->fromdir_attr))
		return false;
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->linkdir_wcc))
		return false;
	return true;
}

static inline int nfs3_parse_readdir_args(struct rpc_task *task)
{
	struct nfs3_readdir_args *args = (struct nfs3_readdir_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_u64(&task->xdr_pos, &args->cookie))
		return false;
	if (!xdr_pull(&task->xdr_pos, args->cookieverf, sizeof(args->cookieverf)))
		return false;
	if (!xdr_u32(&task->xdr_pos, &args->count))
		return false;
	return true;
}

int nfs3_parse_dirent(struct rpc_task *task, struct nfs3_dirent *dirent)
{
	if (!xdr_u32(&task->xdr_pos, &dirent->value_follows))
		return false;
	if (!dirent->value_follows)
		return true;
	if (!xdr_u64(&task->xdr_pos, &dirent->fileid))
		return false;
	if (!xdr_nfs3_string(&task->xdr_pos, &dirent->filename))
		return false;
	if (!xdr_u64(&task->xdr_pos, &dirent->cookie))
		return false;
	return true;
}

static inline int nfs3_parse_readdir_res(struct rpc_task *task)
{
	struct nfs3_readdir_res *res = (struct nfs3_readdir_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->dir_attr))
		return false;
	if (res->status == 0) {
		if (!xdr_pull(&task->xdr_pos, res->cookieverf, sizeof(res->cookieverf)))
			return false;
		memcpy(&res->list, &task->xdr_pos, sizeof(struct xdr_skb_pos));
		do {
			if (!nfs3_parse_dirent(task, &res->curr_dirent))
				return false;
		} while (res->curr_dirent.value_follows);
		if (!xdr_u32(&task->xdr_pos, &res->eof))
			return false;
	}

	return true;
}

static inline int nfs3_parse_readdirplus_args(struct rpc_task *task)
{
	struct nfs3_readdirplus_args *args = (struct nfs3_readdirplus_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_u64(&task->xdr_pos, &args->cookie))
		return false;
	if (!xdr_pull(&task->xdr_pos, args->cookieverf, sizeof(args->cookieverf)))
		return false;
	if (!xdr_u32(&task->xdr_pos, &args->dircount))
		return false;
	if (!xdr_u32(&task->xdr_pos, &args->maxcount))
		return false;
	return true;
}

int nfs3_parse_direntplus(struct rpc_task *task, struct nfs3_direntplus *dirent)
{
	if (!xdr_u32(&task->xdr_pos, &dirent->value_follows))
		return false;
	if (!dirent->value_follows)
		return true;
	if (!xdr_u64(&task->xdr_pos, &dirent->fileid))
		return false;
	if (!xdr_nfs3_string(&task->xdr_pos, &dirent->filename))
		return false;
	if (!xdr_u64(&task->xdr_pos, &dirent->cookie))
		return false;
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &dirent->attr))
		return false;
	if (!xdr_nfs3_post_op_fh(&task->xdr_pos, &dirent->fh))
		return false;
	return true;
}

static inline int nfs3_parse_readdirplus_res(struct rpc_task *task)
{
	struct nfs3_readdirplus_res *res = (struct nfs3_readdirplus_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->dir_attr))
		return false;
	if (res->status == 0) {
		if (!xdr_pull(&task->xdr_pos, res->cookieverf, sizeof(res->cookieverf)))
			return false;
		memcpy(&res->list, &task->xdr_pos, sizeof(struct xdr_skb_pos));
		do {
			if (!nfs3_parse_direntplus(task, &res->curr_dirent))
				return false;
		} while (res->curr_dirent.value_follows);
		if (!xdr_u32(&task->xdr_pos, &res->eof))
			return false;
	}

	return true;
}

static inline int nfs3_parse_fsstat_res(struct rpc_task *task)
{
	struct nfs3_fsstat_res *res = (struct nfs3_fsstat_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->obj_attr))
		return false;
	if (res->status == 0) {
		if (!xdr_u64(&task->xdr_pos, &res->tbytes))
			return false;
		if (!xdr_u64(&task->xdr_pos, &res->fbytes))
			return false;
		if (!xdr_u64(&task->xdr_pos, &res->abytes))
			return false;
		if (!xdr_u64(&task->xdr_pos, &res->tfiles))
			return false;
		if (!xdr_u64(&task->xdr_pos, &res->ffiles))
			return false;
		if (!xdr_u64(&task->xdr_pos, &res->afiles))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->invarsec))
			return false;
	}

	return true;
}

static inline int nfs3_parse_fsinfo_res(struct rpc_task *task)
{
	struct nfs3_fsinfo_res *res = (struct nfs3_fsinfo_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->obj_attr))
		return false;
	if (res->status == 0) {
		if (!xdr_u32(&task->xdr_pos, &res->rtmax))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->rtpref))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->rtmult))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->wtmax))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->wtpref))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->wtmult))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->dtpref))
			return false;
		if (!xdr_u64(&task->xdr_pos, &res->maxfilesize))
			return false;
		if (!xdr_nfs3_time(&task->xdr_pos, &res->time_delta))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->properties))
			return false;
	}

	return true;
}

static inline int nfs3_parse_pathconf_res(struct rpc_task *task)
{
	struct nfs3_pathconf_res *res = (struct nfs3_pathconf_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_post_op_attr(&task->xdr_pos, &res->obj_attr))
		return false;
	if (res->status == 0) {
		if (!xdr_u32(&task->xdr_pos, &res->link_max))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->name_max))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->no_trunc))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->chown_restricted))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->case_insensitive))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->case_preserving))
			return false;
	}

	return true;
}

static inline int nfs3_parse_commit_args(struct rpc_task *task)
{
	struct nfs3_commit_args *args = (struct nfs3_commit_args *)task->args_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_u64(&task->xdr_pos, &args->offset))
		return false;
	if (!xdr_u32(&task->xdr_pos, &args->count))
		return false;

	return true;
}

static inline int nfs3_parse_commit_res(struct rpc_task *task)
{
	struct nfs3_commit_res *res = (struct nfs3_commit_res *)task->res_buf;

	dprintk(KERN_INFO "%s\n", __func__);
	if (!xdr_nfs3_wcc_data(&task->xdr_pos, &res->file_wcc))
		return false;
	if (res->status == 0) {
		if (!xdr_u32(&task->xdr_pos, &res->verf[0]))
			return false;
		if (!xdr_u32(&task->xdr_pos, &res->verf[1]))
			return false;
	}

	return true;
}

static parser_t nfs3_args_parser[] = {
	NULL,	/* null */
	NULL,	/* getattr, only fh required */
	nfs3_parse_setattr_args,	/* setattr */
	nfs3_parse_lookup_args,	/* lookup */
	nfs3_parse_access_args,   /* access */
	NULL,	/* readlink */
	nfs3_parse_read_args,	/* read */
	nfs3_parse_write_args,	/* write */
	nfs3_parse_create_args,	/* create */
	nfs3_parse_mkdir_args,	/* mkdir */
	nfs3_parse_symlink_args,	/* symlink */
	nfs3_parse_mknod_args,	/* mknod */
	nfs3_parse_remove_args,	/* remove */
	nfs3_parse_rmdir_args,	/* rmdir */
	nfs3_parse_rename_args,	/* rename */
	nfs3_parse_link_args,	/* link */
	nfs3_parse_readdir_args,	/* readdir */
	nfs3_parse_readdirplus_args,	/* readdirplus */
	NULL,	/* fsstat */
	NULL,	/* fsinfo */
	NULL,	/* pathconf */
	nfs3_parse_commit_args,	/* commit */
	NULL	/* noop */
};

static parser_t nfs3_res_parser[] = {
	NULL,	/* null */
	nfs3_parse_getattr_res,	/* getattr */
	nfs3_parse_setattr_res,	/* setattr */
	nfs3_parse_lookup_res,	/* lookup */
	nfs3_parse_access_res,   /* access */
	nfs3_parse_readlink_res,	/* readlink */
	nfs3_parse_read_res,	/* read */
	nfs3_parse_write_res,	/* write */
	nfs3_parse_create_res,	/* create */
	nfs3_parse_mkdir_res,	/* mkdir */
	nfs3_parse_symlink_res,	/* symlink */
	nfs3_parse_mknod_res,	/* mknod */
	nfs3_parse_remove_res,	/* remove */
	nfs3_parse_rmdir_res,	/* rmdir */
	nfs3_parse_rename_res,	/* rename */
	nfs3_parse_link_res,	/* link */
	nfs3_parse_readdir_res,	/* readdir */
	nfs3_parse_readdirplus_res,	/* readdirplus */
	nfs3_parse_fsstat_res,	/* fsstat */
	nfs3_parse_fsinfo_res,	/* fsinfo */
	nfs3_parse_pathconf_res,	/* pathconf */
	nfs3_parse_commit_res,	/* commit */
	NULL	/* noop */
};

static inline int parse_nfs3_args(struct rpc_task *task)
{
	struct nfs3_args *args = (struct nfs3_args *)task->args_buf;
	parser_t parser;
	int proc = task->rqst.rqst.proc;

	dprintk(KERN_INFO "%s proc=%d\n", __func__, proc);
	if (proc) {
		if (!xdr_nfs3_fh(&task->xdr_pos, &args->obj))
			return -EINVAL;
		if (proc > 21)
			return -EINVAL;
		if ((parser = nfs3_args_parser[proc]))
			parser(task);
	}
	atomic_add(1, &nfs_stats[proc].op_count);

	return 0;
}

static inline int parse_nfs3_res(struct rpc_task *task)
{
	struct nfs3_res *res = (struct nfs3_res *)task->res_buf;
	parser_t parser;
	int proc = task->rqst.rqst.proc;

	dprintk(KERN_INFO "%s proc=%d\n", __func__, proc);
	if (proc) {
		if (!xdr_u32(&task->xdr_pos, &res->status))
			return -EINVAL;
		if (proc > 21)
			return -EINVAL;
		if ((parser = nfs3_res_parser[proc]))
			parser(task);
	}

	return 0;
}

int tcpproxy_dispatch_rpc(struct tcpproxy_session *ses,
		struct rpc_task *task, rpc_msg_t t)
{
	int err;

	if (task->rqst.rqst.prog != NFS_PROGRAM)
		return 0;
	if (task->rqst.rqst.progver != 3)
		return 0;

	if (t == RPC_REQUEST) {
		if ((err = parse_nfs3_args(task)))
			printk(KERN_ERR "failed to parse NFS arguments\n");
	}
	else {
		if ((err = parse_nfs3_res(task)))
			printk(KERN_ERR "failed to parse NFS result\n");
	}

	return err;
}

/*
 * Print out NFS stats
 */
void print_nfs_stats(char *msg, size_t *size)
{
	int i, max;
	char *p = msg;

	max = sizeof(nfs_stats)/sizeof(struct nfs_call_stat);
	for (i = 0; i < max; i++) {
		p += sprintf(p, "%s: %d\n", nfs_stats[i].op_name,
				nfs_stats[i].op_count.counter);
	}
	*size = p - msg;
}

void reset_nfs_stats(char *msg, size_t *size)
{
	int i, max;

	max = sizeof(nfs_stats)/sizeof(struct nfs_call_stat);
	for (i = 0; i < max; i++)
		nfs_stats[i].op_count.counter = 0;
	strcpy(msg, "ok\n");
	*size = sizeof("ok\n")-1;
}
