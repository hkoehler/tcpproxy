/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: iscsi_target.c 487 2011-09-30 01:52:56Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/hash.h>
#include <linux/hrtimer.h>
#include <linux/in.h>

#include "iscsi_target.h"
#include "iscsi_logger.h"

#define TGT_POOLSIZE 4
#define LUN_POOLSIZE 64
#define IT_POOLSIZE 64
#define ITL_POOLSIZE 64

#if 1
#define dprintk(format...) printk(format)
#else
#define dprintk(format...)
#endif

int iscsi_metrics = true;
int iscsi_fg_metrics = false;
int iscsi_ffg_metrics = false;
static struct iscsi_srv_list iscsi_srv_list;

/* memory pool for iSCSI target */
static struct kmem_cache *tgt_slab __read_mostly = NULL;
static mempool_t *tgt_mempool __read_mostly = NULL ;

/* memory pool for SCSI LUNs */
static struct kmem_cache *lun_slab __read_mostly = NULL;
static mempool_t *lun_mempool __read_mostly = NULL ;

/* memory pool for SCSI I-T nexuses */
static struct kmem_cache *it_slab __read_mostly = NULL;
static mempool_t *it_mempool __read_mostly = NULL ;

/* memory pool for SCSI I-T-L nexuses */
static struct kmem_cache *itl_slab __read_mostly = NULL;
static mempool_t *itl_mempool __read_mostly = NULL ;

/* dump server objects */
int iscsi_srv_list_dump(char *msg, size_t *size)
{
	struct sockaddr_in *sin;
	struct iscsi_srv *srv;
	char *p = msg;

	p += sprintf(p, "Servers: \n");
	mutex_lock(&iscsi_srv_list.mtx);
	list_for_each_entry(srv, &iscsi_srv_list.srvs, list) {
		sin = (struct sockaddr_in *)&srv->addr;
		p += sprintf(p, "  %pI4:%d\n", &sin->sin_addr.s_addr, ntohs(sin->sin_port));
	}
	mutex_unlock(&iscsi_srv_list.mtx);

	*p++ = 0;
	*size = p - msg;
	return 0;
}

/* dump target objects of server */
int iscsi_srv_dump_tgts(struct iscsi_srv *srv, char *msg, size_t *size)
{
	char *p = msg;
	struct iscsi_tgt *tgt;

	p += sprintf(p, "Targets: \n");
	mutex_lock(&srv->mtx);
	list_for_each_entry(tgt, &srv->tgts, list)
		p += sprintf(p, "  %s\n", tgt->name);
	mutex_unlock(&srv->mtx);

	*p++ = 0;
	*size = p - msg;
	return 0;
}

/* dump LUN objects of target */
int iscsi_tgt_dump_luns(struct iscsi_tgt *tgt, char *msg, size_t *size)
{
	char *p = msg;
	struct iscsi_lun *lun;

	p += sprintf(p, "LUNs: \n");
	mutex_lock(&tgt->mtx);
	list_for_each_entry(lun, &tgt->luns, list)
		p += sprintf(p, "  %d\n", lun->id);
	mutex_unlock(&tgt->mtx);

	*p++ = 0;
	*size = p - msg;
	return 0;
}

static void iscsi_init_flow_metrics(struct iscsi_flow_metrics *m)
{
	memset(m, 0, sizeof(*m));
	m->t1 = ktime_to_us(ktime_get());
	m->min_size = (uint32_t)-1;
}

static void iscsi_init_fg_flow_metrics(struct iscsi_itl *itl, s64 tstamp, bool reset)
{
	struct iscsi_fg_flow_metrics *m;

	if (reset)
		itl->num_fg_flow_metrics = 0;
	else
		itl->num_fg_flow_metrics++;
	if (itl->num_fg_flow_metrics >= 100) {
		printk(KERN_ERR "%s: out of fine grained metrics!\n", __func__);
		return;
	}
	m = &itl->fg_metrics[itl->num_fg_flow_metrics];
	itl->curr_fg_metrics = m;
	m->tstamp = tstamp;
	m->ios_received = 0;
	m->ios_submitted = 0;
	m->rand_read_ios_completed = 0;
	m->rand_write_ios_completed = 0;
	m->seq_read_ios_completed = 0;
	m->seq_write_ios_completed = 0;
	m->rand_read_iotime = 0;
	m->seq_read_iotime = 0;
	m->rand_write_iotime = 0;
	m->seq_write_iotime = 0;
}

static void iscsi_init_ffg_flow_metrics(struct iscsi_itl *itl, s64 tstamp, bool reset)
{
	struct iscsi_ffg_flow_metrics *m;

	if (reset)
		itl->num_ffg_flow_metrics = 0;
	else
		itl->num_ffg_flow_metrics++;
	if (itl->num_ffg_flow_metrics >= 1000) {
		printk(KERN_ERR "%s: out of fine-fine-grained metrics!\n", __func__);
		return;
	}
	m = &itl->ffg_metrics[itl->num_ffg_flow_metrics];
	itl->curr_ffg_metrics = m;
	m->tstamp = tstamp;
	m->iotime = 0;
	m->ios_submitted = 0;
	m->ios_completed = 0;
	m->max_qdepth = itl->pending_ios;
}

/* print ITL, itl must be locked by the caller */
static void iscsi_log_itl(struct iscsi_itl *itl)
{
	struct iscsi_it *it = itl->it;
	struct iscsi_tgt *tgt = it->tgt;
	struct iscsi_log_msg *msg;
	struct iscsi_flow_metrics *m = &itl->metrics;

	if (m->ios_submitted || m->errors || m->blocks_read || m->blocks_written) {
		m->t2 = ktime_to_us(ktime_get());

		/* log I-T-L metrics */
		msg = iscsi_logger_alloc(ISCSI_LOG_MSG_SIZE(sizeof(struct iscsi_itl_msg)),
				ISCSI_ITL_MSG);
		if (!msg)
			return;
		memcpy(&msg->itl.metrics, m, sizeof(*m));
		msg->itl.lun = itl->id;
		strncpy(msg->itl.inr, it->name, ISCSI_NAME_MAX);
		strncpy(msg->itl.tgt, tgt->name, ISCSI_NAME_MAX);
		iscsi_logger_commit();
		iscsi_init_flow_metrics(m);
		m->max_qdepth = itl->pending_ios;
	}
}

/* log fine-grained ITL stats, I-T-L must be locked by the caller */
static void iscsi_log_fg_itl(struct iscsi_itl *itl)
{
	struct iscsi_it *it = itl->it;
	struct iscsi_tgt *tgt = it->tgt;
	struct iscsi_log_msg *msg;
	struct iscsi_fg_flow_metrics *m;
	int i;

	for (i = 0; i < itl->num_fg_flow_metrics; i++) {
		m = &itl->fg_metrics[i];
		if (m->rand_read_ios_completed || m->rand_write_ios_completed
				|| m->seq_read_ios_completed || m->seq_write_ios_completed
				|| m->ios_received || m->ios_submitted)
			break;
	}

	if (i == itl->num_fg_flow_metrics)
		return;

	//printk(KERN_INFO "%s\n", __func__);
	/* log I-T-L metrics */
	msg = iscsi_logger_alloc(ISCSI_LOG_MSG_SIZE(sizeof(struct iscsi_fg_itl_msg)),
			ISCSI_FG_ITL_MSG);
	if (!msg)
		return;
	msg->fgitl.num = itl->num_fg_flow_metrics;
	memcpy(msg->fgitl.metrics, itl->fg_metrics, sizeof(itl->fg_metrics));
	msg->fgitl.lun = itl->id;
	strncpy(msg->fgitl.inr, it->name, ISCSI_NAME_MAX);
	strncpy(msg->fgitl.tgt, tgt->name, ISCSI_NAME_MAX);
	iscsi_logger_commit();
}

/* log fine-fine-grained ITL stats, I-T-L must be locked by the caller */
static void iscsi_log_ffg_itl(struct iscsi_itl *itl)
{
	struct iscsi_it *it = itl->it;
	struct iscsi_tgt *tgt = it->tgt;
	struct iscsi_log_msg *msg;
	struct iscsi_ffg_flow_metrics *m;
	int i, n, copied = 0;

	/* split of ffg metrics into multiple messages */
	for (;;) {
		/* how many messages to copy */
		n = itl->num_ffg_flow_metrics - copied > 100 ?
				100 : itl->num_ffg_flow_metrics - copied;

		/* check weather there's any data present */
		for (i = 0; i < n; i++) {
			m = &itl->ffg_metrics[copied+n];
			if (m->ios_completed || m->ios_submitted)
				break;
		}

		/* copy data present */
		if (i < n) {
			msg = iscsi_logger_alloc(ISCSI_LOG_MSG_SIZE(sizeof(struct iscsi_ffg_itl_msg)),
					ISCSI_FFG_ITL_MSG);
			if (!msg)
				return;
			msg->ffgitl.num = n;
			memcpy(msg->ffgitl.metrics, &itl->ffg_metrics[copied], n*sizeof(*m));
			msg->ffgitl.lun = itl->id;
			strncpy(msg->ffgitl.inr, it->name, ISCSI_NAME_MAX);
			strncpy(msg->ffgitl.tgt, tgt->name, ISCSI_NAME_MAX);
			iscsi_logger_commit();
		}

		copied += n;
		if (copied == itl->num_ffg_flow_metrics)
			break;
	}
}

/* aggregate metrics from all I-T-L objects */
int iscsi_aggregate(enum scsi_aggr aggr)
{
	int i;
	struct iscsi_srv *srv;
	struct iscsi_tgt *tgt;
	struct iscsi_it *it;
	struct iscsi_itl *itl;
	struct hlist_node *hn;
	s64 tstamp;

	tstamp = ktime_to_us(ktime_get());
	//printk("I-T-L stats:\n");
	if (aggr == SCSI_LOG)
		iscsi_logger_start();
	mutex_lock(&iscsi_srv_list.mtx);
	list_for_each_entry(srv, &iscsi_srv_list.srvs, list) {
		mutex_lock(&srv->mtx);
		list_for_each_entry(tgt, &srv->tgts, list) {
			mutex_lock(&tgt->mtx);
			list_for_each_entry(it, &tgt->its, list) {
				for (i = 0; i < LUN_HASH_SIZE; i++)
					hlist_for_each_entry(itl, hn, &it->lun_htbl[i], hlist) {
						mutex_lock(&itl->mtx);
						if (aggr == SCSI_LOG) {
							iscsi_log_itl(itl);
							if (iscsi_fg_metrics)
								iscsi_log_fg_itl(itl);
							if (iscsi_ffg_metrics)
								iscsi_log_ffg_itl(itl);
							iscsi_init_fg_flow_metrics(itl, tstamp, true);
							iscsi_init_ffg_flow_metrics(itl, tstamp, true);
						}
						else if (aggr == SCSI_AGGR_FG)
							iscsi_init_fg_flow_metrics(itl, tstamp, false);
						else if (aggr == SCSI_AGGR_FFG)
							iscsi_init_ffg_flow_metrics(itl, tstamp, false);
						mutex_unlock(&itl->mtx);
					}
			}
			mutex_unlock(&tgt->mtx);
		}
		mutex_unlock(&srv->mtx);
	}
	mutex_unlock(&iscsi_srv_list.mtx);
	if (aggr == SCSI_LOG) {
		iosched_stats();
		iscsi_logger_roll();
		iscsi_logger_stop();
	}

	return 0;
}

/* initialize iSCSI server list */
void iscsi_srv_list_init(void)
{
	mutex_init(&iscsi_srv_list.mtx);
	INIT_LIST_HEAD(&iscsi_srv_list.srvs);
}

/* destroy iSCSI server list */
void iscsi_srv_list_destroy(void)
{
	struct iscsi_srv *srv, *tmpsrv;
	struct iscsi_tgt *tgt, *tmptgt;
	struct iscsi_lun *lun, *tmplun;

	list_for_each_entry_safe(srv, tmpsrv, &iscsi_srv_list.srvs, list) {
		dprintk(KERN_INFO "%s: destroy server object %pI4\n", __func__, &srv->addr);
		list_for_each_entry_safe(tgt, tmptgt, &srv->tgts, list) {
			dprintk(KERN_INFO "%s: destroy target object %s\n", __func__, tgt->name);
			list_for_each_entry_safe(lun, tmplun, &tgt->luns, list) {
				if (lun->queue.dtor) {
					lun->queue.dtor(lun->queue.priv);
					lun->queue.dtor = NULL;
				}
				mempool_free(lun, lun_mempool);
			}
			mempool_free(tgt, tgt_mempool);
		}
		kfree(srv);
	}
}

/* look up or create iSCSI server object with specified local address */
struct iscsi_srv *iscsi_srv_lookup(struct sockaddr_storage *addr, bool create)
{
	struct iscsi_srv *srv = NULL;

	mutex_lock(&iscsi_srv_list.mtx);
	list_for_each_entry(srv, &iscsi_srv_list.srvs, list)
		if (memcmp(&srv->addr, addr, sizeof(*addr)) == 0) {
			dprintk(KERN_INFO "%s: server %p\n", __func__, srv);
			goto out;
		}

	if (!create) {
		srv = ERR_PTR(-ENOENT);
		goto out;
	}

	srv = kmalloc(sizeof(struct iscsi_srv), GFP_KERNEL);
	if (!srv) {
		srv = ERR_PTR(-ENOMEM);
		goto out;
	}
	mutex_init(&srv->mtx);
	memcpy(&srv->addr, addr, sizeof(struct sockaddr_storage));
	INIT_LIST_HEAD(&srv->tgts);
	list_add_tail(&srv->list, &iscsi_srv_list.srvs);

out:
	mutex_unlock(&iscsi_srv_list.mtx);
	return srv;
}

/*
 * look up or add new target to iSCSI server
 * fails if it already exists when create == true
 */
struct iscsi_tgt *iscsi_srv_lookup_tgt(struct iscsi_srv *srv,
		char iqn[ISCSI_NAME_MAX], bool create)
{
	struct iscsi_tgt *tgt = NULL;

	iqn[ISCSI_NAME_MAX-1] = 0; /* just to be on the safe side */
	mutex_lock(&srv->mtx);

	/* try to look up target */
	list_for_each_entry(tgt, &srv->tgts, list)
		if (!strncmp(tgt->name, iqn, ISCSI_NAME_MAX)) {
			dprintk(KERN_INFO "%s: target %p\n", __func__, tgt);
			goto out;
		}
	if (!create) {
		tgt = ERR_PTR(-ENOENT);
		goto out;
	}

	/* create new target */
	tgt = (struct iscsi_tgt *)mempool_alloc(tgt_mempool, GFP_KERNEL);
	if (!tgt) {
		tgt = ERR_PTR(-ENOMEM);
		goto out;
	}
	mutex_init(&tgt->mtx);
	strncpy(tgt->name, iqn, ISCSI_NAME_MAX);
	INIT_LIST_HEAD(&tgt->luns);
	INIT_LIST_HEAD(&tgt->its);
	list_add_tail(&tgt->list, &srv->tgts);

out:
	mutex_unlock(&srv->mtx);
	return tgt;
}

static char *queue_get_tgt_ident(void *p)
{
	struct iscsi_tgt *tgt = (struct iscsi_tgt *)p;
	return tgt->name;
}

/*
 * look up or add new LUN to iSCSI target
 * fails if it already exists when create == true
 */
struct iscsi_lun *iscsi_tgt_lookup_lun(struct iscsi_tgt *tgt, uint32_t lid,
		bool create)
{
	struct iscsi_lun *lun = NULL;

	mutex_lock(&tgt->mtx);
	/* try to look up LUN */
	list_for_each_entry(lun, &tgt->luns, list)
		if (lun->id == lid) {
			dprintk(KERN_INFO "%s: LUN %p\n", __func__, lun);
			goto out;
		}
	if (!create) {
		lun = ERR_PTR(-ENOENT);
		goto out;
	}

	/* create new LUN */
	lun = (struct iscsi_lun *)mempool_alloc(lun_mempool, GFP_KERNEL);
	if (!lun) {
		lun = ERR_PTR(-ENOMEM);
		goto out;
	}
	lun->id = lid;
	iosched_queue_init(&lun->queue);
	lun->queue.queue = (void *)tgt;
	lun->queue.queue_get_tgt_ident = queue_get_tgt_ident;
	list_add_tail(&lun->list, &tgt->luns);

out:
	mutex_unlock(&tgt->mtx);
	return lun;
}

static void iscsi_destroy_it(struct iscsi_it *it)
{
	struct iscsi_itl *itl;
	struct hlist_node *hn, *htmp;
	int i;

	dprintk(KERN_INFO "%s: destroy I-T nexus %p\n", __func__, it);
	for (i = 0; i < LUN_HASH_SIZE; i++)
		hlist_for_each_entry_safe(itl, hn, htmp, &it->lun_htbl[i], hlist) {
			if (itl->flow.dtor) {
				itl->flow.dtor(itl->flow.priv);
				itl->flow.dtor = NULL;
			}
			mempool_free(itl, itl_mempool);
		}
	list_del(&it->list);
	mempool_free(it, it_mempool);
}

/*
 * look up I-T nexus of target by initiator IQN
 * create nexus if it doesn't exist yet
 * to be used by iSCSI proxy in login phase
 * caller gets reference to I-T nexus
 */
struct iscsi_it *iscsi_tgt_lookup_it(struct iscsi_tgt *tgt, char iqn[ISCSI_NAME_MAX])
{
	struct iscsi_it *it = NULL;
	struct iscsi_itl *itl = NULL;
	struct iscsi_lun *lun = NULL;
	struct hlist_head *hh;
	int i;

	mutex_lock(&tgt->mtx);
	/* try to look up I-T nexus by name */
	list_for_each_entry(it, &tgt->its, list)
		if (!strncmp(it->name, iqn, ISCSI_NAME_MAX)) {
			dprintk(KERN_INFO "%s: get reference to I-T nexus %p\n", __func__, it);
			kref_get(&it->ref);
			goto out;
		}

	/* create I-T nexus */
	it = (struct iscsi_it *)mempool_alloc(it_mempool, GFP_KERNEL);
	if (!it) {
		it = ERR_PTR(-ENOMEM);
		goto out;
	}
	dprintk(KERN_INFO "%s: create I-T nexus %p\n", __func__, it);
	for (i = 0; i < LUN_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&it->lun_htbl[i]);
	list_add_tail(&it->list, &tgt->its);
	kref_init(&it->ref);
	it->tgt = tgt;
	strncpy(it->name, iqn, ISCSI_NAME_MAX);

	/* initialize all I-T-L nexuses from LUNs */
	list_for_each_entry(lun, &tgt->luns, list) {
		/* create I-T-L nexus */
		itl = (struct iscsi_itl *)mempool_alloc(itl_mempool, GFP_KERNEL);
		if (!itl) {
			iscsi_destroy_it(it);
			it = ERR_PTR(-ENOMEM);
			goto out;
		}
		/* init nexus */
		memset(itl, 0,sizeof(*itl));
		mutex_init(&itl->mtx);
		INIT_LIST_HEAD(&itl->list);
		iscsi_init_flow_metrics(&itl->metrics);
		iscsi_init_fg_flow_metrics(itl, ktime_to_us(ktime_get()), true);
		iscsi_init_ffg_flow_metrics(itl, ktime_to_us(ktime_get()), true);
		iosched_flow_init(&itl->flow);
		itl->id = lun->id;
		itl->it = it;
		itl->lun = lun;
		/* add nexus to I-T nexues */
		hh = &it->lun_htbl[hash_32(lun->id, LUN_HASH_ORDER)];
		hlist_add_head(&itl->hlist, hh);
	}

out:
	mutex_unlock(&tgt->mtx);
	return it;
}

static void release_it(struct kref *kref)
{
	struct iscsi_it *it = container_of(kref, struct iscsi_it, ref);
	struct iscsi_tgt *tgt = it->tgt;

	mutex_lock(&tgt->mtx);
	iscsi_destroy_it(it);
	mutex_unlock(&tgt->mtx);
}

/*
 * acquire/drop reference to I-T nexus
 */
void iscsi_tgt_acquire_it(struct iscsi_it *it)
{
	BUG_ON(!it);
	//dprintk(KERN_INFO "%s: acquire I-T nexus %p\n", __func__, it);
	kref_get(&it->ref);
}

void iscsi_tgt_release_it(struct iscsi_it *it)
{
	if (unlikely(!it))
		return;
	//dprintk(KERN_INFO "%s: release I-T nexus %p\n", __func__, it);
	kref_put(&it->ref, release_it);
}

/*
 * look up I-T-L nexus of I-T nexus by LUN ID
 */
inline struct iscsi_itl *iscsi_it_lookup_itl(struct iscsi_it *it, uint32_t lun)
{
	struct hlist_head *hh;
	struct hlist_node *hn;
	struct iscsi_itl *itl;

	hh = &it->lun_htbl[hash_32(lun, LUN_HASH_ORDER)];
	hlist_for_each_entry(itl, hn, hh, hlist)
		if (itl->id == lun)
			return itl;

	return NULL;
}

/*
 * SCSI command handling in I-T-L nexus
 */
int iscsi_itl_command(struct iscsi_itl *itl, struct scsi_task *task)
{
	task->tstamp = ktime_get();
	if (iscsi_metrics == false)
		return 0;

	if (task->iosize) {
		mutex_lock(&itl->mtx);
		itl->metrics.ios_submitted++;
		itl->pending_ios++;
		if (itl->metrics.max_qdepth < itl->pending_ios)
			itl->metrics.max_qdepth = itl->pending_ios;
		itl->curr_fg_metrics->ios_submitted++;

		if (itl->curr_ffg_metrics->max_qdepth < itl->pending_ios)
			itl->curr_ffg_metrics->max_qdepth = itl->pending_ios;
		itl->curr_ffg_metrics->ios_submitted++;
		mutex_unlock(&itl->mtx);
	}

	return 0;
}

/*
 * SCSI response handling in I-T-L nexus
 */
int iscsi_itl_response(struct iscsi_itl *itl, struct scsi_task *task)
{
	struct iscsi_flow_metrics *m = &itl->metrics;
	uint64_t iotime;

	if (iscsi_metrics == false)
		return 0;

	/* only update IO metrics if command involves IO */
	if (task->iosize) {
		mutex_lock(&itl->mtx);
		itl->pending_ios--;
		iotime = ktime_to_us(ktime_sub(ktime_get(), task->tstamp));
		iscsi_metrics_update(m, task->iosize, iotime,
				task->random, task->read);
		if (task->iosize > m->max_size)
			m->max_size = task->iosize;
		if (task->iosize < m->min_size)
			m->min_size = task->iosize;
		if (task->read)
			m->blocks_read += task->iosize;
		else
			m->blocks_written += task->iosize;
		/* XXX max cache hit threshold hard-coded */
		if (iotime < 1000)
			m->cache_hits++;
		if (task->read) {
			if (task->random) {
				itl->curr_fg_metrics->rand_read_ios_completed++;
				itl->curr_fg_metrics->rand_read_iotime += iotime;
			}
			else {
				itl->curr_fg_metrics->seq_read_ios_completed++;
				itl->curr_fg_metrics->seq_read_iotime += iotime;
			}
		}
		else {
			if (task->random) {
				itl->curr_fg_metrics->rand_write_ios_completed++;
				itl->curr_fg_metrics->rand_write_iotime += iotime;
			}
			else {
				itl->curr_fg_metrics->seq_write_ios_completed++;
				itl->curr_fg_metrics->seq_write_iotime += iotime;
			}
		}

		itl->curr_ffg_metrics->ios_completed++;
		itl->curr_ffg_metrics->iotime += iotime;
		mutex_unlock(&itl->mtx);
	}

	return 0;
}

/*
 * SCSI cancellation handling in I-T-L nexus
 */
int iscsi_itl_cancel(struct iscsi_itl *itl, struct scsi_task *task)
{
	if (iscsi_metrics == false)
		return 0;

	if (task->iosize) {
		mutex_lock(&itl->mtx);
		itl->pending_ios--;
		mutex_unlock(&itl->mtx);
	}

	return 0;
}

/*
 * exit iSCSI target module
 */
int iscsi_target_exit(void)
{
	iscsi_srv_list_destroy();
	if (lun_mempool)
		mempool_destroy(lun_mempool);
	if (lun_slab)
		kmem_cache_destroy(lun_slab);
	if (tgt_mempool)
		mempool_destroy(tgt_mempool);
	if (tgt_slab)
		kmem_cache_destroy(tgt_slab);
	if (it_mempool)
		mempool_destroy(it_mempool);
	if (it_slab)
		kmem_cache_destroy(it_slab);
	if (itl_mempool)
		mempool_destroy(itl_mempool);
	if (itl_slab)
		kmem_cache_destroy(itl_slab);
	return 0;
}

/*
 * initialize iSCSI target module
 */
int iscsi_target_init(void)
{
	int res = 0;

	iscsi_srv_list_init();
	lun_slab = kmem_cache_create("iscsi_luns",
					sizeof(struct iscsi_lun),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!lun_slab) {
		res = -ENOMEM;
		goto err;
	}
	lun_mempool = mempool_create_slab_pool(LUN_POOLSIZE, lun_slab);
	if (!lun_mempool) {
		res = -ENOMEM;
		goto err;
	}

	tgt_slab = kmem_cache_create("iscsi_tgts",
					sizeof(struct iscsi_tgt),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!tgt_slab) {
		res = -ENOMEM;
		goto err;
	}
	tgt_mempool = mempool_create_slab_pool(TGT_POOLSIZE, tgt_slab);
	if (!tgt_mempool) {
		res = -ENOMEM;
		goto err;
	}

	it_slab = kmem_cache_create("iscsi_its",
					sizeof(struct iscsi_it),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!it_slab) {
		res = -ENOMEM;
		goto err;
	}
	it_mempool = mempool_create_slab_pool(IT_POOLSIZE, it_slab);
	if (!it_mempool) {
		res = -ENOMEM;
		goto err;
	}

	itl_slab = kmem_cache_create("iscsi_itls",
					sizeof(struct iscsi_itl),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!itl_slab) {
		res = -ENOMEM;
		goto err;
	}
	itl_mempool = mempool_create_slab_pool(ITL_POOLSIZE, itl_slab);
	if (!itl_mempool) {
		res = -ENOMEM;
		goto err;
	}

	return 0;
err:
	iscsi_target_exit();
	return res;
}
