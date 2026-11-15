// SPDX-License-Identifier: GPL-2.0-only
/*
 * Where upstream's ext.c meets the android14-6.1 scheduler core. Included at
 * the end of ext-port.c, so upstream's static functions are in reach.
 *
 * The class has no slot of its own in this kernel's class array, so it shares
 * the idle class's: the idle methods are entered through kprobes that move
 * the PC to the functions here (port-main.c), which call upstream's for a
 * task of ours and do what idle did for the idle task. Whatever else the
 * 6.12 core calls into ext.c from, a vendor hook at the same place does.
 */
#include <trace/hooks/sched.h>
#include <linux/irq_work.h>
#include "port.h"

DEFINE_PER_CPU(struct ds_scx_rq, ds_scx_rqs);

s64 update_curr_common(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	u64 now = rq_clock_task(rq);
	s64 delta_exec = now - curr->se.exec_start;

	if (unlikely(delta_exec <= 0))
		return delta_exec;
	curr->se.exec_start = now;
	curr->se.sum_exec_runtime += delta_exec;
	account_group_exec_runtime(curr, delta_exec);
	cgroup_account_cputime(curr, delta_exec);
	return delta_exec;
}

/* 6.12's helpers for taking a task off its rq around a change of class.
 * deactivate_task() and activate_task() stand in for the bare dequeue and
 * enqueue, which 6.1 keeps to core.c: they differ in p->on_rq, which is back
 * to queued once both have run.
 */
void sched_deq_and_put_task(struct task_struct *p, int queue_flags,
			    struct sched_enq_and_set_ctx *ctx)
{
	struct rq *rq = task_rq(p);

	lockdep_assert_rq_held(rq);
	*ctx = (struct sched_enq_and_set_ctx){
		.p = p,
		.queue_flags = queue_flags,
		.queued = task_on_rq_queued(p),
		.running = task_current(rq, p),
	};
	update_rq_clock(rq);
	if (ctx->queued)
		deactivate_task(rq, p, queue_flags | DEQUEUE_NOCLOCK);
	if (ctx->running)
		put_prev_task(rq, p);
}

void sched_enq_and_set_task(struct sched_enq_and_set_ctx *ctx)
{
	struct rq *rq = task_rq(ctx->p);

	lockdep_assert_rq_held(rq);
	if (ctx->queued)
		activate_task(rq, ctx->p, ctx->queue_flags | ENQUEUE_NOCLOCK);
	if (ctx->running)
		set_next_task(rq, ctx->p);
}

/* The idle slot's switched_to and prio_changed are the idle class's, which
 * BUG(), and it has no switched_from: for a task of ours upstream's are
 * called by name instead.
 */
void check_class_changing(struct rq *rq, struct task_struct *p,
			  const struct sched_class *prev_class)
{
	if (prev_class != p->sched_class && task_is_scx(p))
		ext_class.switching_to(rq, p);
}

void check_class_changed(struct rq *rq, struct task_struct *p,
			 const struct sched_class *prev_class, int oldprio)
{
	if (prev_class != p->sched_class) {
		if (prev_class == &ext_sched_class)
			ext_class.switched_from(rq, p);
		else if (prev_class->switched_from)
			prev_class->switched_from(rq, p);
		if (task_is_scx(p))
			ext_class.switched_to(rq, p);
		else
			p->sched_class->switched_to(rq, p);
	} else if (oldprio != p->prio || dl_task(p)) {
		if (task_is_scx(p))
			ext_class.prio_changed(rq, p, oldprio);
		else
			p->sched_class->prio_changed(rq, p, oldprio);
	}
}

/* 6.1 puts the previous task before it picks the next one, 6.12 after, and
 * upstream's put_prev_task_scx() wants to know the next. So a put of one of
 * our tasks is only noted here, and carried out when the next task is known:
 * by our own pick, by the schedule hook when a higher class picked, or, when
 * the put was not part of a pick at all, before anything else touches the rq.
 */
static DEFINE_PER_CPU(struct task_struct *, scx61_put);
/* The task the stop class is counting on our behalf, see scx61_rvh_enqueue. */
static DEFINE_PER_CPU(struct task_struct *, scx61_lent);
static DEFINE_PER_CPU(struct irq_work, scx61_resched);
/* Set while our pick runs upstream's balance, which moves tasks onto this rq
 * and may drop its lock: the put that is pending then is the pick's to carry
 * out, with the next task, and nobody else's.
 */
static DEFINE_PER_CPU(bool, scx61_picking);

static void scx61_flush_put(struct rq *rq, struct task_struct *next)
{
	struct task_struct **pending = &per_cpu(scx61_put, cpu_of(rq));
	struct task_struct *prev = *pending;

	if (!prev || per_cpu(scx61_picking, cpu_of(rq)))
		return;
	*pending = NULL;
	/* upstream dereferences next for a task that is still runnable */
	if (!next && (scx_ent(prev)->flags & SCX_TASK_QUEUED))
		next = rq->idle;
	put_prev_task_scx(rq, prev, next);
}

static void scx61_resched_fn(struct irq_work *work)
{
	struct rq *rq = this_rq();
	struct rq_flags rf;

	rq_lock_irqsave(rq, &rf);
	resched_curr(rq);
	rq_unlock_irqrestore(rq, &rf);
}

static void scx61_idle_set_next(struct rq *rq)
{
	scx_update_idle(rq, true, true);
#ifdef CONFIG_SCHEDSTATS
	rq->sched_goidle++;
#endif
}

/* pick_next_task_idle(). This is the last class the core asks, so it is where
 * upstream's balance and pick run. balance may drop the rq lock, which no
 * later class would notice here: if something of a higher class became
 * runnable meanwhile, have the CPU pick again.
 */
struct task_struct *scx61_pick_next_task(struct rq *rq)
{
	struct task_struct *prev = rq->curr, *p = NULL;

	if (scx_enabled()) {
		unsigned int updated = rq->clock_update_flags & RQCF_UPDATED;
		unsigned int nr_other = rq->nr_running - scx_rq(rq)->nr_running;

		per_cpu(scx61_picking, cpu_of(rq)) = true;
		balance_one(rq, prev);
		per_cpu(scx61_picking, cpu_of(rq)) = false;
		rq->clock_update_flags |= updated;
		if (rq->nr_running - scx_rq(rq)->nr_running > nr_other)
			irq_work_queue(&per_cpu(scx61_resched, cpu_of(rq)));
		p = pick_task_scx(rq);
	}
	if (p == prev)
		per_cpu(scx61_put, cpu_of(rq)) = NULL;
	else
		scx61_flush_put(rq, p ?: rq->idle);
	if (!p) {
		scx61_idle_set_next(rq);
		return rq->idle;
	}
	if (p != prev)
		set_next_task_scx(rq, p, true);
	return p;
}

/* put_prev_task_idle() */
void scx61_put_prev_task(struct rq *rq, struct task_struct *p)
{
	if (p == rq->idle) {
		scx_update_idle(rq, false, true);
		return;
	}
	scx61_flush_put(rq, NULL);
	if (!per_cpu(scx61_picking, cpu_of(rq)))
		per_cpu(scx61_put, cpu_of(rq)) = p;
}

/* set_next_task_idle() */
void scx61_set_next_task(struct rq *rq, struct task_struct *p, bool first)
{
	scx61_flush_put(rq, NULL);
	if (p == rq->idle)
		scx61_idle_set_next(rq);
	else
		set_next_task_scx(rq, p, first);
}

/* check_preempt_curr_idle(): reached when curr and p share the slot. */
void scx61_check_preempt_curr(struct rq *rq, struct task_struct *p, int flags)
{
	if (rq->curr == rq->idle)
		resched_curr(rq);
	else
		wakeup_preempt_scx(rq, p, flags);
}

/* task_tick_idle() */
void scx61_task_tick(struct rq *rq, struct task_struct *curr, int queued)
{
	if (curr != rq->idle)
		task_tick_scx(rq, curr, queued);
}

/* select_task_rq_idle() */
int scx61_select_task_rq(struct task_struct *p, int prev_cpu, int wake_flags)
{
	return select_task_rq_scx(p, prev_cpu, wake_flags);
}

/* update_curr_idle() */
void scx61_update_curr(struct rq *rq)
{
	if (task_is_scx(rq->curr))
		update_curr_scx(rq);
}

/* The idle class has no enqueue_task, and the core calls it unconditionally.
 * These hooks sit right before and after that call: the first does upstream's
 * enqueue and lends the task to the stop class for the length of the call,
 * whose enqueue only counts nr_running, and the second takes the task and
 * the count back, as upstream's enqueue has counted already.
 */
static void scx61_rvh_enqueue(void *unused, struct rq *rq, struct task_struct *p, int flags)
{
	/* also for a task that has just been moved to another class */
	scx61_flush_put(rq, NULL);
	if (!task_is_scx(p))
		return;
	enqueue_task_scx(rq, p, flags);
	per_cpu(scx61_lent, cpu_of(rq)) = p;
	p->sched_class = &stop_sched_class;
}

static void scx61_rvh_after_enqueue(void *unused, struct rq *rq, struct task_struct *p, int flags)
{
	if (per_cpu(scx61_lent, cpu_of(rq)) != p)
		return;
	per_cpu(scx61_lent, cpu_of(rq)) = NULL;
	p->sched_class = &ext_sched_class;
	sub_nr_running(rq, 1);
}

/* The same for dequeue, where the stop class takes one off the count: one is
 * added first, so that the count never dips below what is there.
 */
static void scx61_rvh_dequeue(void *unused, struct rq *rq, struct task_struct *p, int flags)
{
	if (!task_is_scx(p))
		return;
	add_nr_running(rq, 1);
	dequeue_task_scx(rq, p, flags);
	per_cpu(scx61_lent, cpu_of(rq)) = p;
	p->sched_class = &stop_sched_class;
}

static void scx61_rvh_after_dequeue(void *unused, struct rq *rq, struct task_struct *p, int flags)
{
	if (per_cpu(scx61_lent, cpu_of(rq)) != p)
		return;
	per_cpu(scx61_lent, cpu_of(rq)) = NULL;
	p->sched_class = &ext_sched_class;
}

/* A higher class picked the next task, so our pick did not run. */
static void scx61_rvh_schedule(void *unused, unsigned int sched_mode, struct task_struct *prev,
			       struct task_struct *next, struct rq *rq)
{
	scx61_flush_put(rq, next);
}

static void scx61_rvh_tick_entry(void *unused, struct rq *rq)
{
	if (scx_enabled())
		scx_tick(rq);
}

/* fork. Upstream is called at four points of copy_process(); the one hook
 * 6.1 offers for every new task, user or kernel, is at its first wakeup,
 * where sleeping is still allowed. A task that never gets there was never
 * seen here.
 */
static void scx61_rvh_wake_up_new_task(void *unused, struct task_struct *p)
{
	scx_pre_fork(p);
	init_scx_entity(scx_ent(p));
	if (scx_fork(p)) {
		scx_cancel_fork(p);
		return;
	}
	if (p->sched_class == &fair_sched_class && task_should_scx(p->policy))
		p->sched_class = &ext_sched_class;
	scx_post_fork(p);
}

static void scx61_vh_free_task(void *unused, struct task_struct *p)
{
	/* a task that failed before its first wakeup was never listed */
	if (scx_ent(p)->tasks_node.next)
		sched_ext_free(p);
}

/* The idle class has no yield_task. This hook runs before the core looks for
 * it and can tell the core to skip the rest, so sched_yield() is done here
 * the way do_sched_yield() does it.
 */
static void scx61_rvh_before_yield(void *unused, long *skip)
{
	struct rq_flags rf;
	struct rq *rq;

	if (!task_is_scx(current))
		return;
	rq = this_rq_lock_irq(&rf);
	yield_task_scx(rq);
	/* do_sched_yield() holds preemption off across the unlock to avoid
	 * scheduling twice. A module is not given that, and may schedule twice.
	 */
	rq_unlock_irq(rq, &rf);
	schedule();
	*skip = 1;
}

/* A nice change ends in the class's prio_changed, which for the idle slot is
 * a bare BUG(). Do the change here as set_user_nice() does it and hand the
 * core a request for the value the task now has, which makes it return early.
 */
static void scx61_rvh_set_user_nice(void *unused, struct task_struct *p, long *nice, bool *allowed)
{
	struct rq_flags rf;
	struct rq *rq;
	int prio;

	if (!task_is_scx(p) || *nice < MIN_NICE || *nice > MAX_NICE)
		return;
	rq = task_rq_lock(p, &rf);
	if (task_is_scx(p) && task_nice(p) != *nice) {
		update_rq_clock(rq);
		p->static_prio = NICE_TO_PRIO(*nice);
		prio = p->static_prio - MAX_RT_PRIO;
		p->se.load.weight = scale_load(sched_prio_to_weight[prio]);
		p->se.load.inv_weight = sched_prio_to_wmult[prio];
		p->normal_prio = p->static_prio;
		if (!rt_prio(p->prio))
			p->prio = p->normal_prio;
		reweight_task_scx(rq, p, &p->se.load);
	}
	task_rq_unlock(rq, p, &rf);
	*nice = task_nice(p);
}

/* struct_ops, see port-btf.c. The value type the BPF core wants beside the
 * ops type, and a member named scx for the BTF strings.
 */
enum ds_struct_ops_state { DS_STRUCT_OPS_INIT, DS_STRUCT_OPS_INUSE, DS_STRUCT_OPS_TOBEFREE };
struct bpf_struct_ops_sched_ext_ops {
	refcount_t refcnt;
	enum ds_struct_ops_state state;
	struct sched_ext_ops data ____cacheline_aligned_in_smp;
};
struct scx_btf_anchor {
	struct sched_ext_entity scx;
};

static struct scx61_struct_ops *scx61_st;

int scx61_register_struct_ops(struct scx61_struct_ops *st)
{
	scx61_st = st;
	return 0;
}

size_t scx61_ent_offset(void)
{
	BTF_TYPE_EMIT(struct bpf_struct_ops_sched_ext_ops);
	BTF_TYPE_EMIT(struct scx_btf_anchor);
	return SCX_ENT_OFFSET;
}

const struct bpf_verifier_ops *scx61_st_verifier_ops(void)
{
	return scx61_st->verifier_ops;
}

int scx61_st_init(struct btf *btf)
{
	return scx61_st->init(btf);
}

int scx61_st_check_member(const struct btf_type *t, const struct btf_member *member)
{
	/* 6.1 does not pass the program, which upstream asks only whether it
	 * is sleepable. No struct_ops program is, on this kernel.
	 */
	static struct bpf_prog_aux aux;
	static struct bpf_prog prog = { .aux = &aux };

	return scx61_st->check_member(t, member, &prog);
}

int scx61_st_init_member(const struct btf_type *t, const struct btf_member *member,
			 void *kdata, const void *udata)
{
	return scx61_st->init_member(t, member, kdata, udata);
}

int scx61_st_reg(void *kdata)
{
	return scx61_st->validate(kdata) ?: scx61_st->reg(kdata, NULL);
}

void scx61_st_unreg(void *kdata)
{
	scx61_st->unreg(kdata, NULL);
}

int __init scx61_glue_init(void)
{
	struct task_struct *g, *p;
	int cpu, i, ret;

	for_each_possible_cpu(cpu) {
		per_cpu(ds_scx_rqs, cpu).rq = cpu_rq(cpu);
		init_irq_work(&per_cpu(scx61_resched, cpu), scx61_resched_fn);
	}
	/* Our words of every task must be as fork left them. */
	rcu_read_lock();
	for_each_process_thread(g, p) {
		for (i = SCX_ENT_FIRST; i < SCX_ENT_FIRST + SCX_ENT_WORDS; i++) {
			if (p->android_vendor_data1[i]) {
				rcu_read_unlock();
				pr_err("vendor data word %d of %s[%d] is in use\n", i, p->comm, p->pid);
				return -EBUSY;
			}
		}
	}
	rcu_read_unlock();

	init_sched_ext_class();
	ret = scx_init();
	if (ret)
		return ret;

	/* Restricted hooks cannot be removed again. From here on every new task
	 * is listed by the fork hook; the ones that exist are listed below,
	 * with forks held off so that none is seen twice or not at all.
	 */
	ret = register_trace_android_rvh_wake_up_new_task(scx61_rvh_wake_up_new_task, NULL) ?:
	      register_trace_android_vh_free_task(scx61_vh_free_task, NULL) ?:
	      register_trace_android_rvh_enqueue_task(scx61_rvh_enqueue, NULL) ?:
	      register_trace_android_rvh_after_enqueue_task(scx61_rvh_after_enqueue, NULL) ?:
	      register_trace_android_rvh_dequeue_task(scx61_rvh_dequeue, NULL) ?:
	      register_trace_android_rvh_after_dequeue_task(scx61_rvh_after_dequeue, NULL) ?:
	      register_trace_android_rvh_schedule(scx61_rvh_schedule, NULL) ?:
	      register_trace_android_rvh_tick_entry(scx61_rvh_tick_entry, NULL) ?:
	      register_trace_android_rvh_before_do_sched_yield(scx61_rvh_before_yield, NULL) ?:
	      register_trace_android_rvh_set_user_nice(scx61_rvh_set_user_nice, NULL);
	if (ret)
		return ret;
	percpu_down_write(&scx_fork_rwsem);
	rcu_read_lock();
	for_each_process_thread(g, p) {
		if (scx_ent(p)->tasks_node.next)
			continue;
		init_scx_entity(scx_ent(p));
		spin_lock_irq(&scx_tasks_lock);
		list_add_tail(&scx_ent(p)->tasks_node, &scx_tasks);
		spin_unlock_irq(&scx_tasks_lock);
	}
	rcu_read_unlock();
	percpu_up_write(&scx_fork_rwsem);
	return 0;
}
