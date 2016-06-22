/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: io_sample_sched.c 226 2011-07-13 13:01:47Z hkoehler $
 * Author: Heiko Koehler
 *********************************************************************************************/

#include <linux/slab.h>
#include <linux/mempool.h>
#include <asm/atomic.h>

#include "io_sched.h"

#define IOQUEUE_POOLSIZE 64
#define IOCLIENT_POOLSIZE 64

#if 1
#	define dprintk(format...) printk(format)
#else
#	define dprintk(format...)
#endif

struct workqueue_struct *iosched_wq = 0;
struct delayed_work iosched_work;

/* memory pool for IO scheduler client data */
static struct kmem_cache *ioclient_slab __read_mostly = NULL;
static mempool_t *ioclient_mempool __read_mostly = NULL ;

/* memory pool for IO scheduler queues */
static struct kmem_cache *ioqueue_slab __read_mostly = NULL;
static mempool_t *ioqueue_mempool __read_mostly = NULL ;

/* memory pool for IO scheduler flows */
static struct kmem_cache *ioflow_slab __read_mostly = NULL;
static mempool_t *ioflow_mempool __read_mostly = NULL ;

/* list of PDUs to be sent by worker thread */
static struct list_head iosched_list = LIST_HEAD_INIT(iosched_list);
/* protect above list */
static DEFINE_SPINLOCK(iosched_list_lock);

/*
 * scheduler specific IO queue implementation
 */
struct ioqueue
{
	atomic_t counter;
};

/*
 * scheduler specific IO client implementation
 */
struct ioclient
{
	atomic_t counter;
};

/*
 * scheduler specific IO flow implementation
 */
struct ioflow
{
	/* list entry for queuing */
	struct list_head list;
	/* back pointer to iosched_flow */
	struct iosched_flow *flow;
	atomic_t counter;
};

void iosched_queue_dtor(void *p)
{
	if (p)
		mempool_free(p, ioqueue_mempool);
}

void iosched_client_dtor(void *p)
{
	if (p)
		mempool_free(p, ioclient_mempool);
}

void iosched_flow_dtor(void *p)
{
	if (p)
		mempool_free(p, ioflow_mempool);
}

/*
 * Default IO scheduler is passing through all IOs
 */
int iosched_input(struct iosched_operation *op)
{
	struct ioqueue *q = (struct ioqueue *)op->queue->priv;
	struct ioflow *f = (struct ioflow *)op->flow->priv;
	struct ioclient *c = (struct ioclient *)op->client->priv;

	/* initialize queue when used for the first time */
	if (!q) {
		q = (struct ioqueue *)mempool_alloc(ioqueue_mempool, GFP_KERNEL);
		if (!q)
			return -ENOMEM;
		op->queue->priv = q;
		op->queue->dtor = iosched_queue_dtor;
		atomic_set(&q->counter, 0);
	}

	/* initialize flow when used for the first time */
	if (!f) {
		f = (struct ioflow *)mempool_alloc(ioflow_mempool, GFP_KERNEL);
		if (!f)
			return -ENOMEM;
		op->flow->priv = f;
		op->flow->dtor = iosched_flow_dtor;
		atomic_set(&f->counter, 0);
	}

	/* initialize client when used for the first time */
	if (!c) {
		c = (struct ioclient *)mempool_alloc(ioclient_mempool, GFP_KERNEL);
		if (!c)
			return -ENOMEM;
		op->client->priv = c;
		op->client->dtor = iosched_client_dtor;
		atomic_set(&c->counter, 0);
	}

	/*
	 * Only queue read and writes
	 * aborts MUST NOT be queued as they're allocated from the stack
	 */
	if (op->op == IOSCHED_READ || op->op == IOSCHED_WRITE) {
		spin_lock(&iosched_list_lock);
		list_add(&op->list, &iosched_list);
		spin_unlock(&iosched_list_lock);
	}

	return 0;
}

static void iosched_func(struct work_struct *work)
{
	struct ioqueue *q;
	struct ioflow *f;
	struct ioclient *c;
	struct list_head oplist;
	struct iosched_operation *op;
	int err = 0, i = 0;

	INIT_LIST_HEAD(&oplist);
	spin_lock(&iosched_list_lock);
	list_splice_init(&iosched_list, &oplist);
	spin_unlock(&iosched_list_lock);

	list_for_each_entry(op, &oplist, list) {
		q = (struct ioqueue *)op->queue->priv;
		f = (struct ioflow *)op->flow->priv;
		c = (struct ioclient *)op->client->priv;

		atomic_add(1, &q->counter);
		atomic_add(1, &f->counter);
		atomic_add(1, &c->counter);
		/*dprintk(KERN_INFO "%s LBA=%llu, len=%d, queue counter=%d, flow counter=%d,"
				" client counter=%d, client=%s, target=%s",
				__func__, op->lba, op->len, q->counter.counter, f->counter.counter,
				c->counter.counter, op->client->client_get_ident(op->client->client),
				op->queue->queue_get_tgt_ident(op->queue->queue));*/
		err = op->iosched_output(op, true);
		if (err)
			printk(KERN_ERR "failed to forward IO to %s with err %d\n",
					op->queue->queue_get_tgt_ident(op->queue->queue), err);
		i++;
	}

	/*if (i)
		printk(KERN_INFO "forwarded %d ops\n", i);*/

	queue_delayed_work(iosched_wq, &iosched_work, 10);
}

/*
 * initialize IO scheduler
 */
int __iosched_init(void)
{
	INIT_DELAYED_WORK(&iosched_work, iosched_func);

	ioqueue_slab = kmem_cache_create("ioqueue",
					sizeof(struct ioqueue),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!ioqueue_slab)
		return -ENOMEM;

	ioqueue_mempool = mempool_create_slab_pool(IOQUEUE_POOLSIZE, ioqueue_slab);
	if (!ioqueue_mempool)
		return -ENOMEM;

	ioflow_slab = kmem_cache_create("ioflow",
					sizeof(struct ioflow),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!ioflow_slab)
		return -ENOMEM;

	ioflow_mempool = mempool_create_slab_pool(IOCLIENT_POOLSIZE, ioflow_slab);
	if (!ioflow_mempool)
		return -ENOMEM;

	ioclient_slab = kmem_cache_create("ioclient",
					sizeof(struct ioclient),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!ioclient_slab)
		return -ENOMEM;

	ioclient_mempool = mempool_create_slab_pool(IOCLIENT_POOLSIZE, ioclient_slab);
	if (!ioclient_mempool)
		return -ENOMEM;

	iosched_wq = create_workqueue("io_sample_sched");
	if (iosched_wq == NULL)
		return -ENOMEM;

	queue_delayed_work(iosched_wq, &iosched_work, 1000);

	return 0;
}

int iosched_init(void)
{
	int res = __iosched_init();
	if (res < 0)
		iosched_exit();
	return res;
}

/*
 * exit IO scheduler
 */
void iosched_exit(void)
{
	if (iosched_wq) {
		cancel_delayed_work_sync(&iosched_work);
		destroy_workqueue(iosched_wq);
		iosched_wq = NULL;
	}
	if (ioqueue_mempool) {
		mempool_destroy(ioqueue_mempool);
		ioqueue_mempool = NULL;
	}
	if (ioqueue_slab) {
		kmem_cache_destroy(ioqueue_slab);
		ioqueue_slab = NULL;
	}
	if (ioflow_mempool) {
		mempool_destroy(ioflow_mempool);
		ioflow_mempool = NULL;
	}
	if (ioflow_slab) {
		kmem_cache_destroy(ioflow_slab);
		ioflow_slab = NULL;
	}
	if (ioclient_mempool) {
		mempool_destroy(ioclient_mempool);
		ioclient_mempool = NULL;
	}
	if (ioclient_slab) {
		kmem_cache_destroy(ioclient_slab);
		ioclient_slab = NULL;
	}
}
