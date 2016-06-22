/*********************************************************************************************
 * Copyright (c) 2011, SmApper Technologies Inc
 * $Id: $
 * Author: Gunther Thiel
 *********************************************************************************************/

#include <linux/slab.h>
#include <linux/mempool.h>
#include <asm/atomic.h>
#include <linux/hrtimer.h>

#include "io_sched.h"
#include "io_sched_ext.h"

/*********************************************************************************************
 *
 * Structs, statics, defines etc.
 *
 *********************************************************************************************/
#if 1
#	define dprintk(format...) printk(format)
#else
#	define dprintk(format...)
#endif

struct tb_control;
struct tb_sched_rule; 

static struct tb_sched_rule * tb_find_rule(const char *clnt_name,
					   const char *tgt_name,
					   uint16_t    lun);
void tb_release_rule(struct kref *ref);
static void release_from_queue(struct tb_sched_rule *rulep, 
			       struct tb_control *tbc, 
			       int force,
			       struct list_head *outq);
static void send_ops(struct list_head *queue, int lock);

static uint32_t get_tb_rate(uint32_t rate, uint32_t tao);

/*
 * this turns on/off the actual queueing code;
 * when turned off, one can watch the tokens being consumed without doing
 * the actual queuing.
 */
static bool tb_scheduler_on;

/* 
 * max name length of IQN as per spec
 */
#define ISCSI_NAME_MAX 224

/* 
 * interval for timer triggered checking whether queued IOs need to be sent;
 * defined in ms
 */
#define CHECK_QUEUES_INTERVAL     10

/* 
 * interval for timer triggered stats output;
 * defined in ms
 */
#define STATS_INTERVAL            10000


/* 
 * initial interval for timer triggered stats output;
 * will be changed by minimum_tao (see comments at function tb_success_stats)
 * defined in ms
 */
#define SUCCESS_STATS_INTERVAL    6000

/*
 * Stuff needed for timer based work;
 *
 * One timer based work is needed to check my buffer queues in case of
 * no IO being trigger by the CTLs owning the buffer queues;
 * all other work is done event-driven (i. e. IO driven only);
 *
 * The secnd timer is needed to display stats info every n secs;
 *
 */
static struct workqueue_struct *iosched_wq = 0;
static struct delayed_work iosched_queue_work;
static struct delayed_work iosched_stats_work;
static struct delayed_work iosched_success_stats_work;

/* 
 * memory pool for IO scheduler flows;
 * this is for the struct we attach to the priv ptr of the iosched_flow struct
 */
#define IOFLOW_POOLSIZE 64
static struct kmem_cache *ioflow_slab __read_mostly = NULL;
static mempool_t *ioflow_mempool __read_mostly = NULL ;

/* 
 * memory pool for IO flow objects which have got non empty queues in their tbc's;
 * The reason why we need to keep a list of these flows is that the async worker thread
 * does not know which flows exist and which ones have got non-empty queues;
 * so, the structs which are allocated out of this pool are mainly needed by the funcs
 * tb_queue_check and flush_queues;
 */
#define QUEUED_FLOW_POOLSIZE 64
static struct kmem_cache *queued_flow_slab = NULL;
static mempool_t *queued_flow_mempool = NULL ;


/* 
 * memory pool for IO scheduler config
 */
#define CONFIG_POOLSIZE 64
static struct kmem_cache *config_slab = NULL;
static mempool_t *config_mempool = NULL ;


/* 
 * tb_sched_rule_stats (totals)
 */
struct tb_sched_rule_stats {

	/* num of IOs seen by the scheduler in total */
	atomic_t       total_ios;
	/* the next two vars should in sum equal to the one above */
	atomic_t       total_ios_queued;
	atomic_t       total_ios_unqueued;
	/* how many IOs are currently in the queue */
	atomic_t       current_qdepth;
	/* how many IOs have been released from the queue */
	atomic_t       num_released_from_queue;

};

/*
 * stats per tao; shared with userland and db
 *
 */
struct tb_sched_rule_success_stats {

	/* num of IOs seen by the scheduler in interval (tao) */
	atomic_t       total_ios;
	/* the next two vars should in sum equal to the one above */
	atomic_t       total_ios_queued;
	atomic_t       total_ios_unqueued;

	/* 
	 * to find out when we a) need to dump to userspace
	 * and b) when to reset to 0.
	 */
	s64            when_init;
};


/*
 * configuration: rules per C-T-L
 */
struct tb_sched_rule {
	
	/* needed to allow for proper deletion */
	struct kref ref_count;

	/* name of the rule; should ideally be unique */
	char             name[ISCSI_NAME_MAX];

	/* the flow, for which the rule is going to be active */
	char             tgt_name[ISCSI_NAME_MAX];
	char             clnt_name[ISCSI_NAME_MAX];
	uint16_t         lun;

	/* tb parms */
	uint32_t         tb_capacity;
	uint32_t         tb_rate;
	uint32_t         tb_tao;         /* in ms */
	
	/* when was the rule last edited; 
	 * This is needed to decide whether we need to update flow-tbc info.
	 */
	s64              last_edit;
	
	/* interval for which the rule is active */
	/* NOTE: if both values are equal, the rule is inactive (off) */
	s64              start_time;
	s64              stop_time;    

	/* stats */
	struct tb_sched_rule_stats 
	                 total_stats;

	struct tb_sched_rule_success_stats 
	                 interval_stats;

	/* to attach it to tb_sched_rules */
	struct list_head list;
};
#define tb_sched_rule_on(rule) \
	(rule->start_time == rule->stop_time) ? false : true
#define set_tb_sched_rule_off(rule) \
	rule->start_time = rule->stop_time = 0
#define set_tb_sched_rule_always_on(rule)  ({ \
	rule->start_time = 0; \
        rule->stop_time = (s64) ktime_to_ms(ktime_get())+86400LL*365LL*1000000LL; });

static struct list_head tb_sched_rules;
static struct mutex     tb_sched_rules_mtx;

/* 
 * token bucket definition 
 */
struct tb {
	uint32_t       capacity;           /* burst size scaled by 100 */
	uint32_t       rate;               /* token bucket refill rate per tao scaled by 100 */
	uint32_t       tokens;             /* number of tokens available as of now scaled by 100 */
	uint32_t       tao;                /* time interval of the bucket in ms*/
	s64            last_refresh;       /* when was the last refresh/refill done on the actual tokens value */
};

/*
 * This is the main structure which the TB scheduler uses;
 * it holds the TB parms, the queue, stats and lock structs
 */
struct tb_control {

	/* core lock */
	struct mutex     mtx;
	/* this holds all IOs, which have to be buffered because of lack of tokens */
	struct list_head io_queue;
	/* definition of the token bucket per C-T-L */
	struct tb        token_bucket;
	/* when was this info last updated; needed to allow updating rules */
	s64            last_edit;          
};

static struct list_head flows_queued;
static struct mutex     flows_queued_mtx;

/* 
 * this is the dtor for the tb_control attached per flow 
 */
void iosched_flow_dtor(void *p) {
	
	struct iosched_queue *queue;
	struct iosched_client *client;
	struct iosched_flow *flow;
	struct tb_sched_rule *rulep;
	struct iosched_operation *op;
	struct list_head outq = LIST_HEAD_INIT(outq);
	struct tb_control *tbc = (struct tb_control *) p;	

	if (p) {
		mutex_lock(&tbc->mtx);
		if(!list_empty(&tbc->io_queue)) {
			op = list_first_entry(&tbc->io_queue, struct iosched_operation, list);
			queue=op->queue;
			client=op->client;
			flow=op->flow;
			rulep=tb_find_rule(client->client_get_ident(client->client),
					   queue->queue_get_tgt_ident(queue->queue),
					   op->lun);
			release_from_queue(rulep, tbc, true, &outq);
			if (rulep)
				kref_put(&rulep->ref_count, tb_release_rule);
		}		
		mutex_unlock(&tbc->mtx);
		mutex_destroy(&tbc->mtx);
		send_ops(&outq, false);
		mempool_free(p, ioflow_mempool);
	}

}


/*********************************************************************************************
 *
 * Implementation
 *
 *********************************************************************************************/

/* 
 *    RULES SECTION
 */

/*
 * empty and delete all config rules
 * NOTE: tb_sched_rules_mtx must not be held!
 */
static void tb_empty_rules(void) {

	struct tb_sched_rule *r, *n;

	mutex_lock(&tb_sched_rules_mtx);
	list_for_each_entry_safe(r, n, &tb_sched_rules, list)
		kref_put(&r->ref_count, tb_release_rule);
	list_empty(&tb_sched_rules);
	mutex_unlock(&tb_sched_rules_mtx);
}

/* 
 * find a rule for a given flow 
 * NOTE: tb_sched_rules_mtx must be held!
 * NOTE: bumps up the ref_count, 
 *       the caller needs to ensure that it gets decreased once the rule is no longer needed.
 */
static struct tb_sched_rule * tb_find_rule(const char *clnt_name,
					   const char *tgt_name,
					   uint16_t    lun) {

	struct tb_sched_rule *r;
	
        list_for_each_entry(r, &tb_sched_rules, list) {
		if (strcmp(clnt_name, r->clnt_name))
			continue;
		if (strcmp(tgt_name, r->tgt_name))
			continue;
		if (lun != r->lun)
			continue;

		kref_get(&r->ref_count);
		return r;
        }	

	return NULL;
}

/* 
 * find a rule for a given rule_name 
 * NOTE: tb_sched_rules_mtx must be held!
 * NOTE: bumps up the ref_count, 
 *       the caller needs to ensure that it gets decreased once the rule is no longer needed.
 */

static struct tb_sched_rule * tb_find_rule_by_name(const char *rule_name) {

	struct tb_sched_rule *r;
	
        list_for_each_entry(r, &tb_sched_rules, list) {
		if (strcmp(rule_name, r->name))
			continue;

		kref_get(&r->ref_count);
		return r;
        }	

	return NULL;
}


/* 
 * remove a rule based on its name 
 * NOTE: tb_sched_rules_mtx must be held!
 */
int tb_remove_rule(const char *rule_name) {
	
	struct tb_sched_rule *r;
	int ret=-ENOENT;

        list_for_each_entry(r, &tb_sched_rules, list) {
		if (strcmp(rule_name, r->name))
			continue;

                list_del(&r->list);
		kref_put(&r->ref_count, tb_release_rule);
		return 0;
        }	

	return ret;
}

void tb_release_rule(struct kref *ref_count) {

	struct tb_sched_rule *rulep = container_of(ref_count, struct tb_sched_rule, ref_count);
	mempool_free(rulep, config_mempool);			
}

/* 
 * This routine allows to add (but not update) a rule.
 * Per clnt/tgt/lun only a single rule can exist so far.
 * If one already exists, the code below returns an error;
 * NOTE: tb_sched_rules_mtx must NOT be held!
 * TBD: add start and stop time to allow for using a rules-schedule; this would also require to change the code for "tb_find_rule",
 * to allow multiple rules for the same ITL, to check that always only one is active etc.
 */
int tb_add_rule(const char *rule_name, const char *clnt_name, const char * tgt_name, uint16_t lun, 
		uint32_t capacity, uint32_t rate, uint32_t tao, bool on) {

	struct tb_sched_rule *rulep;

	mutex_lock(&tb_sched_rules_mtx);

	/* lets see whether a rule is already active for the given flow; if so, error out. */
	rulep = tb_find_rule(clnt_name, tgt_name, lun);
	if (rulep) {
		kref_put(&rulep->ref_count, tb_release_rule);
		mutex_unlock(&tb_sched_rules_mtx);
		return -EEXIST;
	}
	/* lets see whether the rules-name is unique; if not, error out. */
	rulep = tb_find_rule_by_name(rule_name);
	if (rulep) {
		kref_put(&rulep->ref_count, tb_release_rule);
		mutex_unlock(&tb_sched_rules_mtx);
		return -EEXIST;
	}

	/* Ok, all bananas, add the new rule */

	rulep = (struct tb_sched_rule *)mempool_alloc(config_mempool, GFP_KERNEL);
	if (!rulep) {
		mutex_unlock(&tb_sched_rules_mtx);
		return -ENOMEM;
	}
	
	strcpy(rulep->clnt_name, clnt_name);
	strcpy(rulep->tgt_name, tgt_name);
	strcpy(rulep->name, rule_name);
	rulep->lun = lun;
	/*
	 * we scale the token count by 100 to deal with a higher precision
	 * when filling up the token bucket
	 */
	rulep->tb_capacity = capacity * 100;
	rulep->tb_tao = tao;
	rulep->tb_rate = get_tb_rate(rate, rulep->tb_tao);
	rulep->last_edit = ktime_to_ms(ktime_get());
	kref_init(&rulep->ref_count);
	atomic_set(&rulep->total_stats.total_ios, 0);
	atomic_set(&rulep->total_stats.total_ios_queued, 0);
	atomic_set(&rulep->total_stats.total_ios_unqueued, 0);
	atomic_set(&rulep->total_stats.current_qdepth, 0);
	atomic_set(&rulep->total_stats.num_released_from_queue, 0);
	atomic_set(&rulep->interval_stats.total_ios, 0);
	atomic_set(&rulep->interval_stats.total_ios_queued, 0);
	atomic_set(&rulep->interval_stats.total_ios_unqueued, 0);
	rulep->interval_stats.when_init = ktime_to_ms(ktime_get());
	if (on) {
		set_tb_sched_rule_always_on(rulep);
	}
	else {
		set_tb_sched_rule_off(rulep);
	}
	list_add(&rulep->list, &tb_sched_rules);
	
	mutex_unlock(&tb_sched_rules_mtx);

	return 0;
}

/* 
 * This routine allows to update ane existing rule.
 * If none exists, the code below returns an error;
 * NOTE: Updating does not allow to change the clt, tgt, lun or the rules name.
 * If any of these parms need to be modified, remove/add the rule.
 * NOTE: tb_sched_rules_mtx must NOT be held!
 * NOTE: The stats will NOT be reset because of the update.
 */
int tb_update_rule(const char *rule_name, uint32_t capacity, uint32_t rate, uint32_t tao, bool on) {

	struct tb_sched_rule *rulep;

	mutex_lock(&tb_sched_rules_mtx);
	/* lets see whether the rules-name is unique; if not, error out. */
	rulep = tb_find_rule_by_name(rule_name);
	if (!rulep) {
		mutex_unlock(&tb_sched_rules_mtx);
		return -ENOENT;
	}

	/* Ok, all bananas, update the new rule */

	rulep->tb_capacity = capacity;
	rulep->tb_tao = tao;
	rulep->tb_rate = get_tb_rate(rate, rulep->tb_tao);
	rulep->last_edit = ktime_to_ms(ktime_get());
	/* reset the interval stats as it might be crap from now on*/
	/* maybe we want to dump to pvd what we have had so far?!
	   TBD!!
	*/
	atomic_set(&rulep->interval_stats.total_ios, 0);
	atomic_set(&rulep->interval_stats.total_ios_queued, 0);
	atomic_set(&rulep->interval_stats.total_ios_unqueued, 0);
	rulep->interval_stats.when_init = ktime_to_ms(ktime_get());
	if (on) {
		set_tb_sched_rule_always_on(rulep);
	}
	else {
		set_tb_sched_rule_off(rulep);
	}
	
	kref_put(&rulep->ref_count, tb_release_rule);
	mutex_unlock(&tb_sched_rules_mtx);

	return 0;
}

/* 
 *    TB SECTION
 */

/*
 * we multiply the actual rate by 100 to get a two digit float resolution on the division;
 * we will fix this in the get_tb_tokens routine;
 *
 */
static uint32_t get_tb_rate(uint32_t rate, uint32_t tao) {

	return (uint32_t) div64_u64(rate*100,tao);
}

/* 
 * core TB logic: 
 * get_tb_tokens does the math to refill according to time and rate;
 * consume_token consumes one token if possible and returns true if possible and false if not;
 * All routines expect tbc to be locked!
 *
 */
static void get_tb_tokens(struct tb_control *tbc) {

	s64 _now;
	uint32_t diff;

	if (tbc->token_bucket.tokens < tbc->token_bucket.capacity) {
		_now = ktime_to_ms(ktime_get());
		diff = (uint32_t) tbc->token_bucket.rate*(_now - tbc->token_bucket.last_refresh);
		if (diff) {
			tbc->token_bucket.tokens=tbc->token_bucket.capacity > (tbc->token_bucket.tokens + diff) ? 
				(tbc->token_bucket.tokens + diff) :
				tbc->token_bucket.capacity;
			tbc->token_bucket.last_refresh = _now;
		}
	}

}

static inline int consume_token(struct tb_control *tbc) {

	if (tbc->token_bucket.tokens >= 100) {
		tbc->token_bucket.tokens -= 100;
		return true;
	}
	else
		return false;

}

/* 
 *    ACTION SECTION 
 * 
 * Triggered actions (by datapath)
 * Timer based (async) actions
 *
 */

/*
 * This routine releases IO from the according queue as long as tokens are available.
 * It also removes the flow from the async task list in case its queue is empty.
 * It is called by the io_sched_input as well as by the timer based queue-checker.
 * NOTE: tbc->mtx must be locked!
 */
static void release_from_queue(struct tb_sched_rule *rulep, struct tb_control *tbc, int force, struct list_head *outq) {
	
	struct iosched_operation *op, *n;
	
	/* refresh our current tokens */
	get_tb_tokens(tbc);
        list_for_each_entry_safe(op, n, &tbc->io_queue, list) {
		if (consume_token(tbc) || force) {
			list_del(&op->list);
			list_add_tail(&op->list, outq); /* queue to be flushed w/o holding tbc->mtx */
			if (rulep) {
				atomic_sub(1, &rulep->total_stats.current_qdepth);
				atomic_add(1, &rulep->total_stats.num_released_from_queue);
			}
		}
		else
			break;
		get_tb_tokens(tbc);		
        }	
	
}

/*
 * Sends all PDUs in the queue
 * This routine doesn't affect the token bucket implementation.
 * NOTE: tbc->mtx must NOT be locket!
 */
static void send_ops(struct list_head *queue, int lock)
{
	struct iosched_operation *op;
	list_for_each_entry(op, queue, list)
		op->iosched_output(op, lock);
	list_empty(queue);
}

/*
 * This routine is triggered by an incoming IO.
 * The TB scheduler attaches both the TB parms as well as
 * the queue to the flow object. The flow is a representation of the C-T-L, which is what
 * we will use to do the shaping and SLA enforcement.
 * As the C-T-L can be shared amongst multiple I-T-Ls(e. g. active/active multipathing), we will protect the
 * scheduler relevant structs (underneath the priv pointer) from within the scheduler;
 */
int iosched_input(struct iosched_operation *op) {

	struct tb_sched_rule *rulep;
	struct tb_control *tbc;
	s64 _now;
	struct iosched_queue *queue=op->queue;
	struct iosched_client *client=op->client;
	struct iosched_flow *flow=op->flow;
	struct list_head outq = LIST_HEAD_INIT(outq);

	/* TB scheduler doesn't support aborts yet */
	if (op->op == IOSCHED_ABORT)
		return 0;

	fq = NULL;

	rulep=tb_find_rule(client->client_get_ident(client->client),
			queue->queue_get_tgt_ident(queue->queue),
			op->lun);
	if (!rulep)
		goto out_io;
	if (!tb_sched_rule_on(rulep)) {
		kref_put(&rulep->ref_count, tb_release_rule);
		goto out_io;
	}
	_now=ktime_to_ms(ktime_get());
	if (rulep->start_time > _now || rulep->stop_time <= _now) {
		kref_put(&rulep->ref_count, tb_release_rule);
		goto out_io;
	}

	tbc = (struct tb_control *) flow->priv;
	if (!tbc) {
		tbc = (struct tb_control *)mempool_alloc(ioflow_mempool, GFP_KERNEL);
		if (!tbc)
			goto out_nomem;
		mutex_init(&tbc->mtx);
		INIT_LIST_HEAD(&tbc->io_queue);
		tbc->token_bucket.capacity = rulep->tb_capacity;
		tbc->token_bucket.rate = rulep->tb_rate;
		tbc->token_bucket.tao = rulep->tb_tao;
		tbc->token_bucket.tokens = tbc->token_bucket.capacity; /* shall we really or shall we let it grow from 0? */
		tbc->token_bucket.last_refresh = ktime_to_ms(ktime_get());
		tbc->last_edit = rulep->last_edit;
		flow->priv = tbc;
		flow->dtor = iosched_flow_dtor;
	}
	else if (tbc->last_edit < rulep->last_edit) { /* was the rule updated since we created the tbc for this flow? */
		mutex_lock(&tbc->mtx);
		tbc->token_bucket.capacity = rulep->tb_capacity;
		tbc->token_bucket.rate = rulep->tb_rate;
		tbc->token_bucket.tao = rulep->tb_tao;
		tbc->token_bucket.tokens = tbc->token_bucket.capacity; /* shall we really or shall we let it grow from 0? */
		tbc->last_edit = rulep->last_edit;
		mutex_unlock(&tbc->mtx);
	}

	if (op->op == IOSCHED_READ || op->op == IOSCHED_WRITE ) {

		atomic_add(1, &rulep->total_stats.total_ios);
		atomic_add(1, &rulep->interval_stats.total_ios);
		/* all bananas are safe after this */
		mutex_lock(&tbc->mtx);
		/* refresh our current tokens */
		get_tb_tokens(tbc);
		/* consume a token if possible, otherwise queue the IO */
		if (consume_token(tbc)) {
			atomic_add(1, &rulep->total_stats.total_ios_unqueued);
			atomic_add(1, &rulep->interval_stats.total_ios_unqueued);
			release_from_queue(rulep, tbc, false, &outq);
			kref_put(&rulep->ref_count, tb_release_rule);
			goto out_io_unlock;
		}
		else { /* we need to queue */
			atomic_add(1, &rulep->total_stats.total_ios_queued);
			atomic_add(1, &rulep->interval_stats.total_ios_queued);
			if (tb_scheduler_on) {
				atomic_add(1, &rulep->total_stats.current_qdepth);
				
				/* up the ref count to ensure that Heiko doesn't nuke my flow */
				iosched_acquire_flow(flow);
				
				/* 
				 * once we know, that our queue is not empty, we need to make sure our async task
				 * gets triggered.
				 */
				mutex_unlock(&tbc->mtx);
				
				/*
				 * add IO to our list, such that the async task knows what to do
				 */
				mutex_lock(&flows_queued_mtx);
				list_add_tail(&op->list, &flows_queued);
				mutex_unlock(&flows_queued_mtx);
				
				queue_delayed_work(iosched_wq, &iosched_queue_work, CHECK_QUEUES_INTERVAL);
				goto out;

			} /* tb_scheduler_on */

			else {

				kref_put(&rulep->ref_count, tb_release_rule);
				goto out_io_unlock;

			}

		}
	
	}

	goto out;

 out_io_unlock:
	mutex_unlock(&tbc->mtx);
	send_ops(&outq, false);
 out_io:
	/* we can safely call iosched_output without holding a lock, as we still are in the same thread context */
	return op->iosched_output(op, false); 
 out_nomem:
	kref_put(&rulep->ref_count, tb_release_rule);
	return -ENOMEM;
 out:	
	kref_put(&rulep->ref_count, tb_release_rule);
	return 0;
}


/*
 * this routine is the timer based work for the background thread;
 * the thread looks at the list of queued flows and calls 
 * release_from_flow for each flow which has been found.
 */
static void tb_queue_check(struct work_struct *work) {

	struct iosched_queue *queue;
	struct iosched_client *client;
	struct iosched_flow *flow;
	struct tb_sched_rule *rulep;
	struct tb_control *tbc;
	struct iosched_operation *op, *tmp;
	struct list_head outq = LIST_HEAD_INIT(outq);
	
	mutex_lock(&flows_queued_mtx);
	list_for_each_entry_safe(op, tmp, &flows_queued, list) {
		queue = op->queue;
		client = op->client;
		flow = op->flow;

		rulep=tb_find_rule(client->client_get_ident(client->client),
				   queue->queue_get_tgt_ident(queue->queue),
				   op->lun);

		mutex_lock(&tbc->mtx);
		tbc = (struct tb_control *) flow->priv;
		release_from_queue(rulep, tbc, false, &outq);
		mutex_unlock(&tbc->mtx);

		if (rulep)
			kref_put(&rulep->ref_count, tb_release_rule);
		iosched_release_flow(flow);
		list_del(&op->list);
	}
	mutex_unlock(&flows_queued_mtx);

	send_ops(&outq, true);
	queue_delayed_work(iosched_wq, &iosched_queue_work, CHECK_QUEUES_INTERVAL);
}

/*static void flush_queues(void) {

	struct flow_queued *fq, *n;
	struct iosched_queue *queue;
	struct iosched_client *client;
	struct iosched_flow *flow;
	struct tb_sched_rule *rulep;
	struct tb_control *tbc;
	struct iosched_operation *op;
	struct list_head outq = LIST_HEAD_INIT(outq);

	mutex_lock(&flows_queued_mtx);
	list_for_each_entry_safe(fq, n, &flows_queued, list) {
		tbc = (struct tb_control *) fq->flow->priv;
		mutex_lock(&tbc->mtx);
		if(!list_empty(&tbc->io_queue)) {
			op = list_first_entry(&tbc->io_queue, struct iosched_operation, list);
			queue=op->queue;
			client=op->client;
			flow=op->flow;
			rulep=tb_find_rule(client->client_get_ident(client->client),
					   queue->queue_get_tgt_ident(queue->queue),
					   op->lun);
			release_from_queue(rulep, tbc, true, &outq);
			if (rulep)
				kref_put(&rulep->ref_count, tb_release_rule);
		}
		if(list_empty(&tbc->io_queue)) {
			iosched_release_flow(fq->flow);
			list_del(&fq->list);
			mempool_free(fq, queued_flow_mempool);		
		} 
		mutex_unlock(&tbc->mtx);
	}

	mutex_unlock(&flows_queued_mtx);

 	send_ops(&outq, true);
}*/

/*
 * Dump stats to the syslog ever STATS_INTERVAL seconds
 *
 */
static void tb_stats(struct work_struct *work) {

	struct tb_sched_rule *r;

	mutex_lock(&tb_sched_rules_mtx);
        list_for_each_entry(r, &tb_sched_rules, list) {
		dprintk(KERN_INFO "%s: rule '%s' statistics: Total IOs=%d (queued=%d[current_qdepth=%d, released=%d], unqueued=%d, sanity='%s')\n",
			__func__,
			r->name,
			r->total_stats.total_ios.counter,
			r->total_stats.total_ios_queued.counter,
			r->total_stats.current_qdepth.counter,
			r->total_stats.num_released_from_queue.counter,
			r->total_stats.total_ios_unqueued.counter,
			(r->total_stats.total_ios.counter == (r->total_stats.total_ios_queued.counter + r->total_stats.total_ios_unqueued.counter)) ? "ok" : "oops");
	}	
	mutex_unlock(&tb_sched_rules_mtx);
	queue_delayed_work(iosched_wq, &iosched_stats_work, STATS_INTERVAL);
}

/*
 * Gather tb enforcement sucess stats for all rules configured;
 * make data available for pvd collection such that it can be shared with userland db.
 * The interval for the iosched_success_stats_work will be changed
 * dynamically, as new rules get pumped into the system.
 * minimum_tao will define the interval according to the min tao value found in all rules;
 * if now rules are configured, we will use 6000ms.
 *
 */
static void tb_success_stats(struct work_struct *work) {

	struct tb_sched_rule *r;
	uint32_t minimum_tao = SUCCESS_STATS_INTERVAL;
	s64 now;

	dprintk(KERN_INFO "%s: called\n",
		__func__);

	now = ktime_to_ms(ktime_get());
	mutex_lock(&tb_sched_rules_mtx);
        list_for_each_entry(r, &tb_sched_rules, list) {
		
		if (r->tb_tao < minimum_tao)
			minimum_tao = r->tb_tao;
		if ( (now - r->interval_stats.when_init) >= r->tb_tao ) {
			/* dump to pvd */
			/* TBD */

			/* reset */
			atomic_set(&r->interval_stats.total_ios, 0);
			atomic_set(&r->interval_stats.total_ios_queued, 0);
			atomic_set(&r->interval_stats.total_ios_unqueued, 0);
			r->interval_stats.when_init = now;
		}

	}
	mutex_unlock(&tb_sched_rules_mtx);

	queue_delayed_work(iosched_wq, &iosched_success_stats_work, minimum_tao);

}

/* 
 *    INIT/EXIT AND CONFIG SECTION
 */

static int tb_config_add_rule(char *opts, size_t *sizep) {

	int ret = EINVAL, res;
	char rule_name[ISCSI_NAME_MAX], client_name[ISCSI_NAME_MAX], tgt_name[ISCSI_NAME_MAX];
	uint32_t lun, capacity, rate, tao;
	int32_t on;

	res = sscanf(opts, "sched tb add %s %s %s %u %u %u %u %d", rule_name, client_name, tgt_name,
		     &lun, &capacity, &rate, &tao, &on);
	if (res != 8)
		goto out;
	ret = tb_add_rule(rule_name, client_name, tgt_name, (uint16_t) lun, capacity, rate, tao, (on > 0 ? true : false));
	if (!ret)
		*sizep = sprintf(opts, "added tb_sched rule %s\n", rule_name);

 out:	
	printk(KERN_INFO "%s: %s addition of rule '%s' for client '%s' / target '%s' / lun %u: capacity = %u, rate = %u, tao = %u, on = %s\n",
	       __func__, (!ret ? "successful" : "error occurred during"),
	       rule_name, client_name, tgt_name, lun, capacity, rate, tao, (on > 0 ? "true" : "false"));
	return ret;

}

static int tb_config_edit_rule(char *opts, size_t *sizep) {

	int ret = EINVAL, res;
	char rule_name[ISCSI_NAME_MAX];
	uint32_t capacity, rate, tao;
	int32_t on;

	res = sscanf(opts, "sched tb edit %s %u %u %u %d", rule_name, &capacity, &rate, &tao, &on);
	if (res != 5)
		goto out;
	ret = tb_update_rule(rule_name, capacity, rate, tao, (on > 0 ? true : false));
	if (!ret)
		*sizep = sprintf(opts, "updated tb_sched rule %s\n", rule_name);

 out:	
	printk(KERN_INFO "%s: %s update of rule '%s' capacity = %u, rate = %u, tao = %u, on = %s\n",
	       __func__, (!ret ? "successful" : "error occurred during"),
	       rule_name, capacity, rate, tao, (on > 0 ? "true" : "false"));
	return ret;

}

static int tb_config_del_rule(char *opts, size_t *sizep) {

	int ret = EINVAL, res;
	char rule_name[ISCSI_NAME_MAX];

	res = sscanf(opts, "sched tb del %s", rule_name);
	if (res != 1)
		goto out;
	mutex_lock(&tb_sched_rules_mtx);
	ret = tb_remove_rule(rule_name);
	mutex_unlock(&tb_sched_rules_mtx);
	if (!ret)
		*sizep = sprintf(opts, "removed tb_sched rule %s\n", rule_name);

 out:	
	printk(KERN_INFO "%s: %s removal of rule '%s'\n",
	       __func__, (!ret ? "successful" : "error occurred during"),
	       rule_name);
	return ret;

}

static int tb_config_sched_on(bool on) {

	bool toggled = false;

	if (tb_scheduler_on && !on) {
		tb_scheduler_on = false;
		toggled = true;
	}
	else if (!tb_scheduler_on && on) {
		tb_scheduler_on = true;
		toggled = true;
	}

	if (toggled) {
		printk(KERN_INFO "%s: tb_sched switched to %s\n",
		       __func__, (on ? "on" : "off"));
		return 0;
	}

	return -EINVAL;
}

int tb_configure_scheduler(char *opts, size_t *sizep) {

	int ret = -EINVAL;

	if (strstr(opts, "sched tb add")) 
		return tb_config_add_rule(opts, sizep);	
	if (strstr(opts, "sched tb edit")) 
		return tb_config_edit_rule(opts, sizep);
	if (strstr(opts, "sched tb del")) 
		return tb_config_del_rule(opts, sizep);
	if (strstr(opts, "sched tb on")) 
		return tb_config_sched_on(true);
	if (strstr(opts, "sched tb off")) 
		return tb_config_sched_on(false);

	return ret;
}

/*
 * initialize IO scheduler from a kernel perspective
 */
int iosched_init(void) {
	
	/* scheduler's queuing is per default turned off */
	tb_scheduler_on = false;

	ioflow_slab = kmem_cache_create("ioflow",
					sizeof(struct tb_control),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!ioflow_slab)
		goto out_nomem;

	ioflow_mempool = mempool_create_slab_pool(IOFLOW_POOLSIZE, ioflow_slab);
	if (!ioflow_mempool)
		goto out_nomem;

	queued_flow_slab = kmem_cache_create("queued_flow",
					   sizeof(struct flow_queued),
					   0, SLAB_HWCACHE_ALIGN,
					   NULL);
	if (!queued_flow_slab)
		goto out_nomem;
	
	queued_flow_mempool = mempool_create_slab_pool(QUEUED_FLOW_POOLSIZE, queued_flow_slab);
	if (!queued_flow_mempool)
		goto out_nomem;

	config_slab = kmem_cache_create("tb_sched_config",
					sizeof(struct tb_sched_rule),
					0, SLAB_HWCACHE_ALIGN,
					NULL);
	if (!config_slab)
		goto out_nomem;
	
	config_mempool = mempool_create_slab_pool(CONFIG_POOLSIZE, config_slab);
	if (!config_mempool)
		goto out_nomem;


	INIT_LIST_HEAD(&flows_queued);
	mutex_init(&flows_queued_mtx);

	mutex_init(&tb_sched_rules_mtx);
	INIT_LIST_HEAD(&tb_sched_rules);

	iosched_wq = create_workqueue("io_tb_sched");
	if (iosched_wq == NULL)
		goto out_nomem;

	INIT_DELAYED_WORK(&iosched_queue_work, tb_queue_check);
	INIT_DELAYED_WORK(&iosched_stats_work, tb_stats);
	INIT_DELAYED_WORK(&iosched_success_stats_work, tb_success_stats);
	queue_delayed_work(iosched_wq, &iosched_stats_work, STATS_INTERVAL);
	/* please see comment at routine tb_success_stats */
	queue_delayed_work(iosched_wq, &iosched_success_stats_work, SUCCESS_STATS_INTERVAL);

	iosched_register_scheduler(IO_SCHED_TB);
	
	return 0;

 out_nomem:
	iosched_exit();
	return -ENOMEM;

}

/*
 * exit IO scheduler
 */
void iosched_exit(void) {
	
	iosched_unregister_scheduler(IO_SCHED_TB);

	if (iosched_wq) {
		cancel_delayed_work_sync(&iosched_queue_work);
		cancel_delayed_work_sync(&iosched_success_stats_work);
		cancel_delayed_work_sync(&iosched_stats_work);
		destroy_workqueue(iosched_wq);
		iosched_wq = NULL;
	}
	if (false)
		flush_queues();
	mutex_destroy(&flows_queued_mtx);
	tb_empty_rules();
	mutex_destroy(&tb_sched_rules_mtx);
	if (ioflow_mempool)
		mempool_destroy(ioflow_mempool);
	if (ioflow_slab)
		kmem_cache_destroy(ioflow_slab);
	if (queued_flow_mempool)
		mempool_destroy(queued_flow_mempool);
	if (queued_flow_slab)
		kmem_cache_destroy(queued_flow_slab);
	if (config_mempool)
		mempool_destroy(config_mempool);
	if (config_slab)
		kmem_cache_destroy(config_slab);
 
}

