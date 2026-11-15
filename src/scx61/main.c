// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stage 1 of an extensible scheduler class for android14-6.1.
 *
 * The scheduler core orders its classes by address and walks a fixed array, so
 * a class that lives in module memory is never picked. This one shares the
 * idle class instead: it is the last slot, every task that is not the per-CPU
 * idle task is ours, and the ordering below fair comes for free. The idle
 * class methods are entered through kprobes that move the PC to the versions
 * here, which keeps this working on Samsung EL2 where kernel memory cannot be
 * written.
 *
 * The idle class has no enqueue_task, and the core calls it unconditionally.
 * The vendor hooks around that call lend the task to the stop class for the
 * length of the call, whose enqueue and dequeue only count nr_running, which
 * is the accounting wanted here anyway.
 *
 * Tasks wait in dispatch queues as in upstream sched_ext: one local queue per
 * CPU, a global one, and those a BPF scheduler creates. Without a scheduler
 * every task goes to the local queue of the CPU it woke on.
 */
#define pr_fmt(fmt) "droidspaces_scx: " fmt
#include <linux/module.h>
#include <linux/of.h>
#include <linux/utsname.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/irq_work.h>
#include <linux/timer.h>
#include <linux/hashtable.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bpf.h>
#include <linux/sched/task.h>
#include <linux/sched/cputime.h>
#include <trace/hooks/sched.h>
#include "kernel/sched/sched.h"
#include "core.h"
#include "hint.h"
#include "../gki-target.h"
#include "scx.h"

/* p->rt is unused while a task is not in the rt class, and fork resets it:
 * its run_list links the task into whichever queue holds it.
 */
#define SCX_MAGIC 0x5343583631UL

struct scx_rq {
	struct list_head queue;	/* the local DSQ, under the rq lock */
	unsigned int nr;
	/* tasks that count on this rq but wait in another DSQ */
	unsigned int nr_remote;
};
static DEFINE_PER_CPU(struct scx_rq, scx_rqs);

/* What the BPF scheduler is being asked right now, per CPU. The kfuncs act
 * on it, since they are told only the task and the queue.
 */
enum { SCX_CTX_NONE, SCX_CTX_SELECT, SCX_CTX_ENQUEUE, SCX_CTX_DISPATCH };
struct scx_ctx {
	int kind;
	struct rq *rq;
	struct task_struct *p;
	bool done;
};
static DEFINE_PER_CPU(struct scx_ctx, scx_ctxs);

static struct scx_dsq scx_global = {
	.lock = __RAW_SPIN_LOCK_UNLOCKED(scx_global.lock),
	.list = LIST_HEAD_INIT(scx_global.list),
	.id = SCX_DSQ_GLOBAL,
};
static DEFINE_HASHTABLE(scx_dsqs, 6);
static DEFINE_RAW_SPINLOCK(scx_dsqs_lock);

static const struct sched_class *idle_class, *stop_class, *fair_class;
static void (*cpuacct_charge_fn)(struct task_struct *, u64);
static void (*cgroup_account_fn)(struct cgroup *, u64);

static unsigned long nr_attaches, nr_picks, nr_enqueues, nr_pulls, nr_fallbacks, nr_kfunc_errors;
module_param(nr_kfunc_errors, ulong, 0400);
module_param(nr_fallbacks, ulong, 0400);
module_param(nr_pulls, ulong, 0400);
module_param(nr_attaches, ulong, 0400);
module_param(nr_picks, ulong, 0400);
module_param(nr_enqueues, ulong, 0400);

static bool scx_marked(struct task_struct *p)
{
	return p->rt.timeout == SCX_MAGIC;
}

static bool is_scx(struct task_struct *p)
{
	return scx_marked(p) && p->sched_class == idle_class;
}

static struct scx_rq *scx_rq_of(struct rq *rq)
{
	return &per_cpu(scx_rqs, cpu_of(rq));
}

/* The unexported accounting helpers may lack a kCFI type word. */
static __nocfi void scx_update_curr(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	struct scx_entity *ent = scx_ent(curr);
	u64 now = rq_clock_task(rq);
	s64 delta = now - curr->se.exec_start;
	struct cgroup *cgrp;

	if (delta <= 0)
		return;
	curr->se.exec_start = now;
	curr->se.sum_exec_runtime += delta;
	ent->slice -= min_t(u64, ent->slice, delta);
	account_group_exec_runtime(curr, delta);
	cpuacct_charge_fn(curr, delta);
	rcu_read_lock();
	cgrp = task_dfl_cgroup(curr);
	if (cgroup_parent(cgrp))
		cgroup_account_fn(cgrp, delta);
	rcu_read_unlock();
}

/* A task that has to wait may be runnable at once on a CPU that sleeps. The
 * rq lock is held at enqueue, so the poke goes through an irq_work, and the
 * CPU it wakes looks for work from its newidle hook below.
 */
static DEFINE_PER_CPU(struct irq_work, scx_kick);

static void scx_kick_fn(struct irq_work *work)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct rq *rq = cpu_rq(cpu);

		if (READ_ONCE(rq->curr) == rq->idle && !READ_ONCE(rq->nr_running)) {
			wake_up_if_idle(cpu);
			return;
		}
	}
}

static struct scx_dsq *find_dsq(u64 id)
{
	struct scx_dsq *dsq;

	if (id == SCX_DSQ_GLOBAL)
		return &scx_global;
	hash_for_each_possible_rcu(scx_dsqs, dsq, hash, id)
		if (dsq->id == id)
			return dsq;
	return NULL;
}

static void scx_local_add(struct rq *rq, struct task_struct *p, bool head)
{
	struct scx_rq *s = scx_rq_of(rq);

	if (head)
		list_add(&p->rt.run_list, &s->queue);
	else
		list_add_tail(&p->rt.run_list, &s->queue);
	s->nr++;
}

/* Put a task that counts on @rq, whose lock is held, into a queue. */
static void scx_dispatch_to(struct rq *rq, struct task_struct *p, u64 dsq_id,
			    u64 slice, u64 enq_flags)
{
	struct scx_entity *ent = scx_ent(p);
	struct scx_dsq *dsq;

	if (slice)
		ent->slice = slice;
	if (dsq_id == SCX_DSQ_LOCAL ||
	    dsq_id == (SCX_DSQ_LOCAL_ON | cpu_of(rq))) {
		scx_local_add(rq, p, enq_flags & SCX_ENQ_HEAD);
		return;
	}
	/* Another CPU's local queue needs a migration, which the consume path
	 * does. Until dispatch can do it too, such a task goes to the global
	 * queue, as does one sent to a queue that does not exist.
	 */
	rcu_read_lock();
	dsq = find_dsq(dsq_id) ?: &scx_global;
	raw_spin_lock(&dsq->lock);
	if (enq_flags & SCX_ENQ_HEAD)
		list_add(&p->rt.run_list, &dsq->list);
	else
		list_add_tail(&p->rt.run_list, &dsq->list);
	dsq->nr++;
	ent->dsq = dsq;
	raw_spin_unlock(&dsq->lock);
	rcu_read_unlock();
	scx_rq_of(rq)->nr_remote++;
	irq_work_queue(&per_cpu(scx_kick, cpu_of(rq)));
}

static void do_enqueue(struct rq *rq, struct task_struct *p, u64 enq_flags)
{
	struct scx_ctx *ctx = this_cpu_ptr(&scx_ctxs);
	struct scx_entity *ent = scx_ent(p);

	p->rt.watchdog_stamp = jiffies;
	nr_enqueues++;
	/* select_cpu already said where it goes, or we are moving it. */
	if (ent->flags & SCX_ENT_DDSP) {
		ent->flags &= ~SCX_ENT_DDSP;
		scx_dispatch_to(rq, p, ent->ddsp_dsq_id, ent->ddsp_slice, enq_flags);
		return;
	}
	ctx->kind = SCX_CTX_ENQUEUE;
	ctx->rq = rq;
	ctx->p = p;
	ctx->done = false;
	if (!scx_ops_enqueue(p, enq_flags)) {
		ctx->kind = SCX_CTX_NONE;
		scx_dispatch_to(rq, p, SCX_DSQ_LOCAL, 0, enq_flags);
		return;
	}
	ctx->kind = SCX_CTX_NONE;
	/* A scheduler that keeps tasks in its own maps is not supported yet. */
	if (!ctx->done)
		scx_dispatch_to(rq, p, SCX_DSQ_GLOBAL, 0, enq_flags);
}

static void rvh_enqueue(void *unused, struct rq *rq, struct task_struct *p, int flags)
{
	if (!is_scx(p))
		return;
	do_enqueue(rq, p, flags & ENQUEUE_HEAD ? SCX_ENQ_HEAD : 0);
	if (rq->curr != rq->idle && rq->curr != p)
		irq_work_queue(&per_cpu(scx_kick, cpu_of(rq)));
	p->sched_class = stop_class;
}

static void rvh_dequeue(void *unused, struct rq *rq, struct task_struct *p, int flags)
{
	struct scx_entity *ent;
	struct scx_dsq *dsq;

	if (!is_scx(p))
		return;
	if (rq->curr == p)
		scx_update_curr(rq);
	ent = scx_ent(p);
	dsq = ent->dsq;
	if (dsq) {
		/* consume takes this rq's lock before it unlinks, so dsq is stable */
		raw_spin_lock(&dsq->lock);
		list_del_init(&p->rt.run_list);
		dsq->nr--;
		raw_spin_unlock(&dsq->lock);
		ent->dsq = NULL;
		scx_rq_of(rq)->nr_remote--;
	} else if (!list_empty(&p->rt.run_list)) {
		list_del_init(&p->rt.run_list);
		scx_rq_of(rq)->nr--;
	}
	p->sched_class = stop_class;
}

/* Runs right after the stop class counted the task: hand it back. */
static void rvh_after(void *unused, struct rq *rq, struct task_struct *p, int flags)
{
	if (scx_marked(p) && p->sched_class == stop_class && p != rq->stop)
		p->sched_class = idle_class;
}

/* Move one task from @dsq to @cpu's local queue. Called with interrupts off
 * and no rq lock held. The task may count on any rq, so it is looked up
 * first and unlinked only once its rq is locked and it is seen to still be
 * there; a task on another rq then migrates the way fair's detach_task() and
 * attach_task() move one.
 */
static bool scx_consume(struct scx_dsq *dsq, int cpu)
{
	struct rq *this_rq = cpu_rq(cpu), *src;
	struct task_struct *p, *found;
	struct scx_entity *ent;
	int tries = 4;

	while (tries--) {
		found = NULL;
		raw_spin_lock(&dsq->lock);
		list_for_each_entry(p, &dsq->list, rt.run_list) {
			if (cpumask_test_cpu(cpu, p->cpus_ptr) && !is_migration_disabled(p)) {
				found = get_task_struct(p);
				break;
			}
		}
		raw_spin_unlock(&dsq->lock);
		if (!found)
			return false;
		p = found;
		ent = scx_ent(p);
		src = task_rq(p);
		raw_spin_rq_lock(src);
		if (task_rq(p) != src || !is_scx(p) || ent->dsq != dsq ||
		    !task_on_rq_queued(p)) {
			raw_spin_rq_unlock(src);
			put_task_struct(p);
			continue;
		}
		raw_spin_lock(&dsq->lock);
		list_del_init(&p->rt.run_list);
		dsq->nr--;
		raw_spin_unlock(&dsq->lock);
		ent->dsq = NULL;
		scx_rq_of(src)->nr_remote--;
		if (src == this_rq) {
			scx_local_add(src, p, false);
		} else {
			/* the enqueue on the other side must not ask BPF again */
			ent->flags |= SCX_ENT_DDSP;
			ent->ddsp_dsq_id = SCX_DSQ_LOCAL;
			ent->ddsp_slice = 0;
			update_rq_clock(src);
			deactivate_task(src, p, DEQUEUE_NOCLOCK);
			set_task_cpu(p, cpu);
			raw_spin_rq_unlock(src);
			raw_spin_rq_lock(this_rq);
			update_rq_clock(this_rq);
			activate_task(this_rq, p, ENQUEUE_NOCLOCK);
			nr_pulls++;
		}
		if (this_rq->curr == this_rq->idle)
			resched_curr(this_rq);
		raw_spin_rq_unlock(this_rq);
		put_task_struct(p);
		return true;
	}
	return false;
}

/* Find this CPU something to run: the global queue first, then whatever the
 * BPF scheduler moves over. Interrupts off, no rq lock held.
 */
static bool scx_dispatch_cpu(int cpu)
{
	struct scx_ctx *ctx = this_cpu_ptr(&scx_ctxs);

	if (READ_ONCE(scx_global.nr) && scx_consume(&scx_global, cpu))
		return true;
	ctx->kind = SCX_CTX_DISPATCH;
	ctx->done = false;
	scx_ops_dispatch(cpu);
	ctx->kind = SCX_CTX_NONE;
	return ctx->done;
}

/* Take one task of ours off @src_cpu's local queue that is not running and
 * may run on @dst_cpu. Interrupts off, no rq lock held.
 */
static struct task_struct *scx_detach_one(int src_cpu, int dst_cpu)
{
	struct scx_rq *s = &per_cpu(scx_rqs, src_cpu);
	struct rq *src = cpu_rq(src_cpu);
	struct task_struct *p, *found = NULL;

	raw_spin_rq_lock(src);
	list_for_each_entry(p, &s->queue, rt.run_list) {
		if (!task_current(src, p) && !p->on_cpu && task_on_rq_queued(p) &&
		    !is_migration_disabled(p) && cpumask_test_cpu(dst_cpu, p->cpus_ptr)) {
			found = p;
			break;
		}
	}
	if (found) {
		struct scx_entity *ent = scx_ent(found);

		ent->flags |= SCX_ENT_DDSP;
		ent->ddsp_dsq_id = SCX_DSQ_LOCAL;
		ent->ddsp_slice = 0;
		update_rq_clock(src);
		deactivate_task(src, found, DEQUEUE_NOCLOCK);
		set_task_cpu(found, dst_cpu);
	}
	raw_spin_rq_unlock(src);
	return found;
}

static void scx_attach_one(struct rq *dst, struct task_struct *p)
{
	update_rq_clock(dst);
	activate_task(dst, p, ENQUEUE_NOCLOCK);
	nr_pulls++;
}

/* This CPU is about to go idle. Ask the queues, then take a task of ours
 * that waits behind something else on another CPU. Dropping the rq lock
 * here is what fair's own newidle balance does, and -1 tells the core to
 * pick again from the top.
 */
static void rvh_newidle(void *unused, struct rq *this_rq, struct rq_flags *rf,
			int *pulled_task, int *done)
{
	int this_cpu = cpu_of(this_rq), cpu;
	struct task_struct *p = NULL;
	bool got;

	if (!READ_ONCE(nr_attaches) || !cpu_active(this_cpu))
		return;
	rq_unpin_lock(this_rq, rf);
	raw_spin_rq_unlock(this_rq);
	got = scx_dispatch_cpu(this_cpu);
	for_each_online_cpu(cpu) {
		if (got || p)
			break;
		if (cpu == this_cpu || READ_ONCE(per_cpu(scx_rqs, cpu).nr) <=
				       (is_scx(READ_ONCE(cpu_rq(cpu)->curr)) ? 1 : 0))
			continue;
		p = scx_detach_one(cpu, this_cpu);
	}
	raw_spin_rq_lock(this_rq);
	rq_repin_lock(this_rq, rf);
	if (p)
		scx_attach_one(this_rq, p);
	if (got || p) {
		*pulled_task = -1;
		*done = 1;
	}
}

/* Runs when this CPU's local queue ran dry while tasks that count on it wait
 * in other queues, and when a slice ran out. The second case also brings a
 * task over from a CPU that something of a higher class holds, which would
 * otherwise wait there for as long as that lasts.
 */
static DEFINE_PER_CPU(struct irq_work, scx_balance);

static void scx_balance_fn(struct irq_work *work)
{
	int this_cpu = smp_processor_id(), cpu;
	struct rq *this_rq = cpu_rq(this_cpu);
	unsigned long flags;

	local_irq_save(flags);
	if (scx_dispatch_cpu(this_cpu))
		goto out;
	for_each_online_cpu(cpu) {
		struct task_struct *p;

		if (cpu == this_cpu || !READ_ONCE(per_cpu(scx_rqs, cpu).nr) ||
		    is_scx(READ_ONCE(cpu_rq(cpu)->curr)))
			continue;
		p = scx_detach_one(cpu, this_cpu);
		if (p) {
			raw_spin_rq_lock(this_rq);
			scx_attach_one(this_rq, p);
			raw_spin_rq_unlock(this_rq);
			break;
		}
	}
out:
	local_irq_restore(flags);
}

/* The idle class has no yield_task either, so yield before the core looks. */
static void rvh_before_yield(void *unused, long *skip)
{
	struct task_struct *p = current;
	struct rq_flags rf;
	struct rq *rq;

	if (!is_scx(p))
		return;
	rq = task_rq_lock(p, &rf);
	if (is_scx(p) && !list_empty(&p->rt.run_list)) {
		update_rq_clock(rq);
		scx_update_curr(rq);
		scx_ent(p)->slice = 0;
		resched_curr(rq);
	}
	task_rq_unlock(rq, p, &rf);
	*skip = 1;
}

static void idle_set_next(struct rq *rq)
{
#ifdef CONFIG_SCHEDSTATS
	rq->sched_goidle++;
#endif
}

static void scx_start(struct rq *rq, struct task_struct *p)
{
	struct scx_entity *ent = scx_ent(p);

	if (!ent->slice)
		ent->slice = SCX_SLICE_DFL;
	p->se.exec_start = rq_clock_task(rq);
	scx_ops_running(p);
}

static struct task_struct *scx_pick_next_task(struct rq *rq)
{
	struct scx_rq *s = scx_rq_of(rq);
	struct task_struct *p;

	if (list_empty(&s->queue)) {
		/* The lock cannot be dropped here, so fetch from outside it. */
		if (s->nr_remote)
			irq_work_queue(&per_cpu(scx_balance, cpu_of(rq)));
		idle_set_next(rq);
		return rq->idle;
	}
	p = list_first_entry(&s->queue, struct task_struct, rt.run_list);
	scx_start(rq, p);
	nr_picks++;
	return p;
}

/* The running task stays at the head of the local queue. When it stops with
 * its slice used up and is still runnable, it goes through enqueue again,
 * which is where the scheduler decides its next turn.
 */
static void scx_put_prev_task(struct rq *rq, struct task_struct *p)
{
	bool runnable;

	if (p == rq->idle)
		return;
	scx_update_curr(rq);
	runnable = !list_empty(&p->rt.run_list) && !scx_ent(p)->dsq;
	scx_ops_stopping(p, runnable);
	if (runnable && !scx_ent(p)->slice) {
		list_del_init(&p->rt.run_list);
		scx_rq_of(rq)->nr--;
		do_enqueue(rq, p, 0);
	}
}

static void scx_set_next_task(struct rq *rq, struct task_struct *p, bool first)
{
	if (p == rq->idle)
		idle_set_next(rq);
	else
		scx_start(rq, p);
}

/* Only reached when curr and p share the slot: idle yields, a peer waits. */
static void scx_check_preempt_curr(struct rq *rq, struct task_struct *p, int flags)
{
	if (rq->curr == rq->idle)
		resched_curr(rq);
}

static void scx_task_tick(struct rq *rq, struct task_struct *p, int queued)
{
	if (p == rq->idle)
		return;
	scx_update_curr(rq);
	if (scx_ent(p)->slice)
		return;
	irq_work_queue(&per_cpu(scx_balance, cpu_of(rq)));
	resched_curr(rq);
}

static int scx_default_cpu(struct task_struct *p, int prev_cpu, bool *is_idle)
{
	unsigned int best_cost = UINT_MAX;
	int cpu, best = prev_cpu;

	for_each_cpu_and(cpu, p->cpus_ptr, cpu_active_mask) {
		struct rq *rq = cpu_rq(cpu);
		unsigned int nr = READ_ONCE(rq->nr_running);
		unsigned int ours = READ_ONCE(per_cpu(scx_rqs, cpu).nr);
		unsigned int cost = ours + (nr > ours ? 16 * (nr - ours) : 0);

		if (cost <= best_cost) {
			best_cost = cost;
			best = cpu;
		}
	}
	if (is_idle)
		*is_idle = !best_cost;
	return best;
}

/* Without a scheduler: the allowed CPU where the task waits behind the
 * least. A fair task always runs before ours, so it counts for more than a
 * peer. Ties go to the higher index, which is where the faster cores sit on
 * the phones this targets.
 */
static int scx_select_task_rq(struct task_struct *p, int prev_cpu, int flags)
{
	struct scx_ctx *ctx = this_cpu_ptr(&scx_ctxs);
	int cpu;

	ctx->kind = SCX_CTX_SELECT;
	ctx->p = p;
	cpu = scx_ops_select_cpu(p, prev_cpu, flags);
	ctx->kind = SCX_CTX_NONE;
	if (cpu >= 0)
		return cpu;
	return scx_default_cpu(p, prev_cpu, NULL);
}

static void scx_update_curr_cb(struct rq *rq)
{
	if (rq->curr != rq->idle)
		scx_update_curr(rq);
}

__diag_push();
__diag_ignore_all("-Wmissing-prototypes", "kfuncs are called from BPF only");

noinline void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags)
{
	struct scx_ctx *ctx = this_cpu_ptr(&scx_ctxs);
	struct scx_entity *ent;

	if (p != ctx->p || ctx->done) {
		nr_kfunc_errors++;
		return;
	}
	ent = scx_ent(p);
	if (ctx->kind == SCX_CTX_ENQUEUE) {
		scx_dispatch_to(ctx->rq, p, dsq_id, slice, enq_flags);
		ctx->done = true;
	} else if (ctx->kind == SCX_CTX_SELECT) {
		ent->flags |= SCX_ENT_DDSP;
		ent->ddsp_dsq_id = dsq_id;
		ent->ddsp_slice = slice;
	} else {
		nr_kfunc_errors++;
	}
}

noinline bool scx_bpf_consume(u64 dsq_id)
{
	struct scx_ctx *ctx = this_cpu_ptr(&scx_ctxs);
	struct scx_dsq *dsq;
	bool moved = false;

	if (ctx->kind != SCX_CTX_DISPATCH) {
		nr_kfunc_errors++;
		return false;
	}
	rcu_read_lock();
	dsq = find_dsq(dsq_id);
	if (dsq)
		moved = scx_consume(dsq, smp_processor_id());
	else
		nr_kfunc_errors++;
	rcu_read_unlock();
	ctx->done |= moved;
	return moved;
}

noinline s32 scx_bpf_create_dsq(u64 dsq_id, s32 node)
{
	struct scx_dsq *dsq;
	unsigned long flags;
	s32 ret = 0;

	if (dsq_id & SCX_DSQ_FLAG_BUILTIN)
		return -EINVAL;
	/* init is not sleepable on this kernel */
	dsq = kzalloc(sizeof(*dsq), GFP_ATOMIC);
	if (!dsq)
		return -ENOMEM;
	raw_spin_lock_init(&dsq->lock);
	INIT_LIST_HEAD(&dsq->list);
	dsq->id = dsq_id;
	raw_spin_lock_irqsave(&scx_dsqs_lock, flags);
	if (find_dsq(dsq_id))
		ret = -EEXIST;
	else
		hash_add_rcu(scx_dsqs, &dsq->hash, dsq_id);
	raw_spin_unlock_irqrestore(&scx_dsqs_lock, flags);
	if (ret)
		kfree(dsq);
	return ret;
}

noinline s32 scx_bpf_dsq_nr_queued(u64 dsq_id)
{
	struct scx_dsq *dsq;
	s32 ret = -ENOENT;

	rcu_read_lock();
	if (dsq_id == SCX_DSQ_LOCAL)
		ret = READ_ONCE(this_cpu_ptr(&scx_rqs)->nr);
	else if ((dsq = find_dsq(dsq_id)))
		ret = READ_ONCE(dsq->nr);
	rcu_read_unlock();
	return ret;
}

noinline s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
				    bool *is_idle)
{
	return scx_default_cpu(p, prev_cpu, is_idle);
}

noinline void scx_bpf_kick_cpu(s32 cpu, u64 flags)
{
	if (cpu >= 0 && cpu < nr_cpu_ids && cpu_online(cpu))
		irq_work_queue_on(&per_cpu(scx_balance, cpu), cpu);
}

noinline u32 scx_bpf_nr_cpu_ids(void)
{
	return nr_cpu_ids;
}

__diag_pop();

BTF_SET8_START(scx_kfunc_ids)
BTF_ID_FLAGS(func, scx_bpf_dispatch)
BTF_ID_FLAGS(func, scx_bpf_consume)
BTF_ID_FLAGS(func, scx_bpf_create_dsq)
BTF_ID_FLAGS(func, scx_bpf_dsq_nr_queued)
BTF_ID_FLAGS(func, scx_bpf_select_cpu_dfl)
BTF_ID_FLAGS(func, scx_bpf_kick_cpu)
BTF_ID_FLAGS(func, scx_bpf_nr_cpu_ids)
BTF_SET8_END(scx_kfunc_ids)

/* No owner: the loader resolves kfuncs against the merged BTF, where they
 * look like vmlinux's, so the verifier searches the vmlinux sets.
 */
static const struct btf_kfunc_id_set scx_kfunc_set = {
	.set = &scx_kfunc_ids,
};

int scx_register_kfuncs(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &scx_kfunc_set);
}

/* Put every task that waits in @dsq on the local queue of the rq it counts
 * on. Used when the scheduler that would have consumed it goes away.
 */
static void scx_drain(struct scx_dsq *dsq)
{
	struct task_struct *p;
	unsigned long flags;
	struct rq *rq;

	local_irq_save(flags);
	for (;;) {
		raw_spin_lock(&dsq->lock);
		p = list_first_entry_or_null(&dsq->list, struct task_struct, rt.run_list);
		if (p)
			get_task_struct(p);
		raw_spin_unlock(&dsq->lock);
		if (!p)
			break;
		rq = task_rq(p);
		raw_spin_rq_lock(rq);
		if (task_rq(p) == rq && is_scx(p) && scx_ent(p)->dsq == dsq) {
			raw_spin_lock(&dsq->lock);
			list_del_init(&p->rt.run_list);
			dsq->nr--;
			raw_spin_unlock(&dsq->lock);
			scx_ent(p)->dsq = NULL;
			scx_rq_of(rq)->nr_remote--;
			scx_local_add(rq, p, false);
			resched_curr(rq);
		}
		raw_spin_rq_unlock(rq);
		put_task_struct(p);
	}
	local_irq_restore(flags);
}

/* Called once no BPF callback can run any more. */
void scx_ops_gone(void)
{
	struct hlist_node *tmp;
	struct scx_dsq *dsq;
	unsigned long flags;
	int bkt;

	scx_drain(&scx_global);
	hash_for_each_safe(scx_dsqs, bkt, tmp, dsq, hash) {
		raw_spin_lock_irqsave(&scx_dsqs_lock, flags);
		hash_del_rcu(&dsq->hash);
		raw_spin_unlock_irqrestore(&scx_dsqs_lock, flags);
		synchronize_rcu();
		scx_drain(dsq);
		kfree(dsq);
	}
}

/* prio_changed_idle is a bare BUG() that a kprobe cannot sit on, and a nice
 * change calls it. Turning the request into "no change" makes the core return
 * before it gets there.
 */
static void rvh_set_user_nice(void *unused, struct task_struct *p, long *nice, bool *allowed)
{
	if (is_scx(p))
		*nice = task_nice(p);
}

static int scx_set_class(struct task_struct *p, bool attach)
{
	const struct sched_class *from = attach ? fair_class : idle_class;
	const struct sched_class *to = attach ? idle_class : fair_class;
	struct rq_flags rf;
	struct rq *rq;
	bool queued, running;
	int ret = 0;

	rq = task_rq_lock(p, &rf);
	update_rq_clock(rq);
	if (p->sched_class != from || is_idle_task(p) || (p->flags & PF_EXITING) ||
	    (!attach && !scx_marked(p))) {
		ret = -EINVAL;
		goto out;
	}
	queued = task_on_rq_queued(p);
	running = task_current(rq, p);
	if (queued)
		deactivate_task(rq, p, DEQUEUE_SAVE | DEQUEUE_MOVE | DEQUEUE_NOCLOCK);
	if (running)
		put_prev_task(rq, p);
	if (attach) {
		if (from->switched_from)
			from->switched_from(rq, p);
		INIT_LIST_HEAD(&p->rt.run_list);
		memset(scx_ent(p), 0, sizeof(struct scx_entity));
		scx_ent(p)->weight = 100;
		p->rt.timeout = SCX_MAGIC;
		nr_attaches++;
	} else {
		p->rt.timeout = 0;
		memset(scx_ent(p), 0, sizeof(struct scx_entity));
	}
	p->sched_class = to;
	if (queued)
		activate_task(rq, p, ENQUEUE_RESTORE | ENQUEUE_MOVE | ENQUEUE_NOCLOCK);
	if (running)
		set_next_task(rq, p);
	if (!attach)
		to->switched_to(rq, p);
	resched_curr(rq);
out:
	task_rq_unlock(rq, p, &rf);
	return ret;
}

/* The class sits below fair, so a task of ours on a CPU that fair or rt work
 * holds does not run, and one that cannot move away would wait for as long as
 * that lasts without even taking a SIGKILL. Give such a task back to fair
 * after a second of waiting, whichever queue it waits in.
 */
static struct timer_list scx_watchdog;

static struct task_struct *stalled_in(struct list_head *list, struct rq *rq)
{
	struct task_struct *p;

	list_for_each_entry(p, list, rt.run_list)
		if ((!rq || !task_current(rq, p)) &&
		    time_after(jiffies, p->rt.watchdog_stamp + HZ))
			return get_task_struct(p);
	return NULL;
}

static void scx_fallback(struct task_struct *p)
{
	if (!p)
		return;
	if (!scx_set_class(p, false))
		nr_fallbacks++;
	put_task_struct(p);
}

static void scx_watchdog_fn(struct timer_list *unused)
{
	struct task_struct *p;
	struct scx_dsq *dsq;
	unsigned long flags;
	int cpu, bkt;

	for_each_online_cpu(cpu) {
		struct scx_rq *s = &per_cpu(scx_rqs, cpu);
		struct rq *rq = cpu_rq(cpu);

		if (!READ_ONCE(s->nr))
			continue;
		raw_spin_rq_lock_irqsave(rq, flags);
		p = stalled_in(&s->queue, rq);
		raw_spin_rq_unlock_irqrestore(rq, flags);
		scx_fallback(p);
	}
	raw_spin_lock_irqsave(&scx_global.lock, flags);
	p = stalled_in(&scx_global.list, NULL);
	raw_spin_unlock_irqrestore(&scx_global.lock, flags);
	scx_fallback(p);
	rcu_read_lock();
	hash_for_each_rcu(scx_dsqs, bkt, dsq, hash) {
		raw_spin_lock_irqsave(&dsq->lock, flags);
		p = stalled_in(&dsq->list, NULL);
		raw_spin_unlock_irqrestore(&dsq->lock, flags);
		scx_fallback(p);
	}
	rcu_read_unlock();
	mod_timer(&scx_watchdog, jiffies + HZ / 4);
}

static int scx_param_set(const char *val, const struct kernel_param *kp)
{
	struct task_struct *p;
	int pid, ret;

	ret = kstrtoint(val, 0, &pid);
	if (ret)
		return ret;
	rcu_read_lock();
	p = find_task_by_vpid(pid);
	if (p)
		get_task_struct(p);
	rcu_read_unlock();
	if (!p)
		return -ESRCH;
	ret = scx_set_class(p, kp->arg);
	put_task_struct(p);
	return ret;
}
static const struct kernel_param_ops scx_param_ops = { .set = scx_param_set };
module_param_cb(attach, &scx_param_ops, (void *)1, 0200);
module_param_cb(detach, &scx_param_ops, NULL, 0200);

struct scx_kprobe {
	struct kprobe kp;
	unsigned long replacement;
};

static int kp_pre(struct kprobe *kp, struct pt_regs *regs)
{
	instruction_pointer_set(regs, container_of(kp, struct scx_kprobe, kp)->replacement);
	return 1;
}

#define SCX_KP(sym, fn) { .kp = { .symbol_name = sym, .pre_handler = kp_pre }, \
			  .replacement = (unsigned long)(fn) }
static struct scx_kprobe kps[] = {
	SCX_KP("pick_next_task_idle", scx_pick_next_task),
	SCX_KP("put_prev_task_idle", scx_put_prev_task),
	/* The first instruction is a static branch site, which kprobes refuse. */
	{ .kp = { .symbol_name = "set_next_task_idle", .offset = 4, .pre_handler = kp_pre },
	  .replacement = (unsigned long)scx_set_next_task },
	SCX_KP("check_preempt_curr_idle", scx_check_preempt_curr),
	SCX_KP("task_tick_idle", scx_task_tick),
	SCX_KP("select_task_rq_idle", scx_select_task_rq),
	SCX_KP("update_curr_idle", scx_update_curr_cb),
};

static int __init scx_init(void)
{
	struct kallrecon_hint hint = { .timeout_ms = 15000 };
	unsigned int i;
	int cpu, ret;

	if (!ds_gki_target_supported()) {
		pr_err("requires matching " DS_GKI_ANDROID "-" DS_GKI_VERSION " with gki=1 or the build VM\n");
		return -EOPNOTSUPP;
	}
	ret = kallrecon_supply(&hint);
	if (ret)
		return ret;
	find_kallsyms_base();
	if (!kallrecon_ready())
		return -ENODATA;
	idle_class = (void *)kallsyms_name_to_addr("idle_sched_class");
	stop_class = (void *)kallsyms_name_to_addr("stop_sched_class");
	fair_class = (void *)kallsyms_name_to_addr("fair_sched_class");
	cpuacct_charge_fn = (void *)kallsyms_name_to_addr("cpuacct_charge");
	cgroup_account_fn = (void *)kallsyms_name_to_addr("__cgroup_account_cputime");
	if (!idle_class || !stop_class || !fair_class || !cpuacct_charge_fn || !cgroup_account_fn)
		return -ENOENT;
	/* The whole design rests on idle being the slot right after fair. */
	if (idle_class != fair_class + 1 || idle_class->enqueue_task || idle_class->yield_task)
		return -EOPNOTSUPP;
	for_each_possible_cpu(cpu) {
		INIT_LIST_HEAD(&per_cpu(scx_rqs, cpu).queue);
		init_irq_work(&per_cpu(scx_kick, cpu), scx_kick_fn);
		init_irq_work(&per_cpu(scx_balance, cpu), scx_balance_fn);
	}

	/* Nothing is ours until a task is attached, so the order is free. */
	for (i = 0; i < ARRAY_SIZE(kps); i++) {
		ret = register_kprobe(&kps[i].kp);
		if (ret) {
			pr_err("kprobe %s: %d\n", kps[i].kp.symbol_name, ret);
			while (i--)
				unregister_kprobe(&kps[i].kp);
			return ret;
		}
	}
	/* Restricted hooks cannot be removed again, so neither can we. */
	__module_get(THIS_MODULE);
	ret = register_trace_android_rvh_enqueue_task(rvh_enqueue, NULL) ?:
	      register_trace_android_rvh_dequeue_task(rvh_dequeue, NULL) ?:
	      register_trace_android_rvh_after_enqueue_task(rvh_after, NULL) ?:
	      register_trace_android_rvh_after_dequeue_task(rvh_after, NULL) ?:
	      register_trace_android_rvh_before_do_sched_yield(rvh_before_yield, NULL) ?:
	      register_trace_android_rvh_set_user_nice(rvh_set_user_nice, NULL) ?:
	      register_trace_android_rvh_sched_newidle_balance(rvh_newidle, NULL);
	if (ret)
		pr_err("vendor hooks: %d, attach will misbehave\n", ret);
	timer_setup(&scx_watchdog, scx_watchdog_fn, 0);
	mod_timer(&scx_watchdog, jiffies + HZ / 4);
	pr_info("ext class sharing the idle slot is active\n");
	/* The class works without a BPF scheduler, so this is not fatal. */
	ret = scx_bpf_init();
	if (ret)
		pr_warn("no BPF schedulers: %d\n", ret);
	return 0;
}
module_init(scx_init);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Extensible scheduler class for android14-6.1, stage 1");
