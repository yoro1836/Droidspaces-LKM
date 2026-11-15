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
#include <linux/llist.h>
#include <linux/cpufreq.h>
#include <linux/pm_qos.h>
#include <linux/cpuhotplug.h>
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
/* The running task that was set from the enqueue hook, see scx61_set_next_task(). */
static DEFINE_PER_CPU(struct task_struct *, scx61_set);
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
	/* A task that ran was taken off the runnable list by upstream's
	 * set_next_task. One that is still on it was run by something else,
	 * as Samsung's EMS did before it was kept from it: putting it would
	 * add it twice, which took the device down. Say so instead.
	 */
	if ((scx_ent(prev)->flags & SCX_TASK_QUEUED) &&
	    !list_empty(&scx_ent(prev)->runnable_node)) {
		WARN_ONCE(1, "sched_ext: %s[%d] ran without having been picked by the class\n",
			  prev->comm, prev->pid);
		return;
	}
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
	per_cpu(scx61_set, cpu_of(rq)) = NULL;
	if (!per_cpu(scx61_picking, cpu_of(rq)))
		per_cpu(scx61_put, cpu_of(rq)) = p;
}

/* set_next_task_idle(). Its first instruction is the schedstats static
 * branch, which a kprobe cannot sit on, so the probe is on the second, and
 * with schedstats on the function branches away before it gets there: a
 * Galaxy S24 ran a task the core had set this way without upstream being
 * told. The one case the core sets a task of ours itself, rather than through
 * our pick, is the running task after it was taken off the rq and put back
 * around a change, and there the enqueue of the running task comes first:
 * scx61_rvh_after_enqueue() sets the task then and notes it here, for when
 * the probe does fire.
 */
void scx61_set_next_task(struct rq *rq, struct task_struct *p, bool first)
{
	scx61_flush_put(rq, NULL);
	if (p == rq->idle) {
		scx61_idle_set_next(rq);
	} else if (per_cpu(scx61_set, cpu_of(rq)) == p) {
		per_cpu(scx61_set, cpu_of(rq)) = NULL;
	} else {
		set_next_task_scx(rq, p, first);
	}
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

/* Samsung's EMS, a scheduler module of its own on Exynos, tells a task's class
 * by its priority, so it takes ours for fair tasks. Its enqueue hook puts the
 * urgent ones, binder and foreground threads, on a per-rq "queue jump" list,
 * and its hook in pick_next_task_fair() replaces fair's pick with the first
 * task on that list: a task of ours was run as fair's choice, behind
 * upstream's back, and the device went down on a corrupted list when it was
 * put. EMS's hook runs before ours, so the task is taken off its list again
 * right there. The list node is found through EMS's own BTF, see port-main.c.
 */
static int scx61_ems_qjump = -1, scx61_ems_nr_tex;

void scx61_set_ems_qjump(int node_offset, int nr_tex_offset)
{
	scx61_ems_nr_tex = nr_tex_offset;
	scx61_ems_qjump = node_offset;
}

/* What EMS's tex_remove_from_qjump_list() does: unlink, and one less in the
 * count it keeps in the rq's vendor data, whose first word points to it.
 */
bool scx61_fair_pick_is_hooked(void)
{
	return rcu_access_pointer(__tracepoint_android_rvh_replace_next_task_fair.funcs);
}

static void scx61_ems_forget(struct rq *rq, struct task_struct *p)
{
	struct list_head *node;
	void *rq_data = (void *)rq->android_vendor_data1[0];

	if (scx61_ems_qjump < 0)
		return;
	node = (void *)p + scx61_ems_qjump;
	if (!node->next || list_empty(node))
		return;
	list_del_init(node);
	if (rq_data)
		*(int *)(rq_data + scx61_ems_nr_tex) -= 1;
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
	scx61_ems_forget(rq, p);
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
	/* see scx61_set_next_task() */
	if (p == rq->curr) {
		set_next_task_scx(rq, p, false);
		per_cpu(scx61_set, cpu_of(rq)) = p;
	}
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

/* set_cpus_allowed_common() serves every class and the idle slot has it as
 * its set_cpus_allowed, so upstream's set_cpus_allowed_scx() is never asked.
 * This hook is at the end of it, with the mask in place.
 */
static void scx61_rvh_set_cpus_allowed(void *unused, struct task_struct *p,
				       const struct cpumask *new_mask)
{
	if (task_is_scx(p) && SCX_HAS_OP(set_cpumask))
		SCX_CALL_OP_TASK(SCX_KF_REST, set_cpumask, p, (struct cpumask *)p->cpus_ptr);
}

/* sched_setscheduler() and priority inheritance choose a task's class in
 * core.c, which knows three: a task of ours it touches comes out as rt, dl or
 * fair, and nothing tells upstream, because the idle slot has no
 * switched_from. And a task that should come to us, say one going back from
 * rt to normal while every task is ours, is given to fair.
 *
 * Neither can be put right from inside those paths: their closing
 * check_class_changed() would enter the idle class's switched_to or
 * prio_changed, which are bare BUG()s that not even a kprobe can sit on. So
 * the task is looked at again right after: upstream is told of a task that
 * left, and a fair task that belongs to us is moved the way upstream's
 * enable path moves one.
 */
struct scx61_recon {
	struct llist_node node;
	struct task_struct *p;
};
static LLIST_HEAD(scx61_recon_list);
static struct irq_work scx61_recon_irq;

static void scx61_recon_workfn(struct work_struct *work)
{
	struct llist_node *list = llist_del_all(&scx61_recon_list);
	struct scx61_recon *r, *tmp;

	mutex_lock(&scx_ops_enable_mutex);
	llist_for_each_entry_safe(r, tmp, list, node) {
		struct task_struct *p = r->p;
		struct rq_flags rf;
		struct rq *rq;

		rq = task_rq_lock(p, &rf);
		if (scx_get_task_state(p) == SCX_TASK_ENABLED && !task_is_scx(p))
			switched_from_scx(rq, p);
		if (p->sched_class == &fair_sched_class && task_should_scx(p->policy) &&
		    scx_ops_enable_state() == SCX_OPS_ENABLED && !(p->flags & PF_EXITING) &&
		    scx_get_task_state(p) == SCX_TASK_READY) {
			const struct sched_class *old_class = p->sched_class;
			struct sched_enq_and_set_ctx ctx;

			sched_deq_and_put_task(p, DEQUEUE_SAVE | DEQUEUE_MOVE, &ctx);
			p->sched_class = &ext_sched_class;
			check_class_changing(rq, p, old_class);
			sched_enq_and_set_task(&ctx);
			check_class_changed(rq, p, old_class, p->prio);
		}
		task_rq_unlock(rq, p, &rf);
		put_task_struct(p);
		kfree(r);
	}
	mutex_unlock(&scx_ops_enable_mutex);
}
static DECLARE_WORK(scx61_recon_work, scx61_recon_workfn);

/* The hooks run under the rq lock, where a work item cannot be queued. */
static void scx61_recon_irqfn(struct irq_work *work)
{
	schedule_work(&scx61_recon_work);
}

static void scx61_reconcile_later(struct task_struct *p)
{
	struct scx61_recon *r;

	if (!scx_enabled())
		return;
	r = kmalloc(sizeof(*r), GFP_ATOMIC);
	if (!r)
		return;
	r->p = get_task_struct(p);
	llist_add(&r->node, &scx61_recon_list);
	irq_work_queue(&scx61_recon_irq);
}

static void scx61_rvh_setscheduler(void *unused, struct task_struct *p)
{
	scx61_reconcile_later(p);
}

static void scx61_rvh_rtmutex_setprio(void *unused, struct task_struct *p,
				      struct task_struct *pi_task)
{
	scx61_reconcile_later(p);
}

/* CPU hotplug. 6.12 calls these from sched_cpu_activate() and
 * sched_cpu_deactivate(); a dynamic hotplug state runs right after the first
 * and right before the second.
 */
static int scx61_cpu_online(unsigned int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	struct rq_flags rf;

	rq_lock_irqsave(rq, &rf);
	scx_rq_activate(rq);
	rq_online_scx(rq);
	rq_unlock_irqrestore(rq, &rf);
	return 0;
}

static int scx61_cpu_offline(unsigned int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	struct rq_flags rf;

	rq_lock_irqsave(rq, &rf);
	rq_offline_scx(rq);
	scx_rq_deactivate(rq);
	rq_unlock_irqrestore(rq, &rf);
	return 0;
}

/* The performance target. upstream's schedutil adds scx_cpuperf_target() to a
 * CPU's utilization, which with the default target of one means full speed
 * unless the scheduler asks for less. Here each cpufreq policy gets a floor
 * instead: the highest target among its CPUs, as a share of its top
 * frequency. Whatever caps the frequency from above still does.
 */
static DEFINE_PER_CPU(struct freq_qos_request, scx61_qos);
static DEFINE_PER_CPU(bool, scx61_qos_added);
static struct irq_work scx61_perf_irq;

static void scx61_perf_workfn(struct work_struct *work)
{
	int cpu, i;

	cpus_read_lock();
	for_each_online_cpu(cpu) {
		struct cpufreq_policy *policy = cpufreq_cpu_get(cpu);
		struct freq_qos_request *req = &per_cpu(scx61_qos, cpu);
		u32 target = 0;
		s32 freq;

		if (!policy)
			continue;
		if (policy->cpu == cpu) {
			if (scx_enabled())
				for_each_cpu(i, policy->cpus)
					target = max(target, scx_rq(cpu_rq(i))->cpuperf_target);
			freq = target ? mult_frac(policy->cpuinfo.max_freq, target, SCX_CPUPERF_ONE)
				      : FREQ_QOS_MIN_DEFAULT_VALUE;
			if (per_cpu(scx61_qos_added, cpu))
				freq_qos_update_request(req, freq);
			else if (freq_qos_add_request(&policy->constraints, req, FREQ_QOS_MIN, freq) >= 0)
				per_cpu(scx61_qos_added, cpu) = true;
		}
		cpufreq_cpu_put(policy);
	}
	cpus_read_unlock();
}
static DECLARE_WORK(scx61_perf_work, scx61_perf_workfn);

static void scx61_perf_irqfn(struct irq_work *work)
{
	schedule_work(&scx61_perf_work);
}

void scx61_cpuperf_kick(void)
{
	irq_work_queue(&scx61_perf_irq);
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
	int ret = scx61_st->validate(kdata) ?: scx61_st->reg(kdata, NULL);

	/* enabling set every CPU's target without announcing it */
	scx61_cpuperf_kick();
	return ret;
}

void scx61_st_unreg(void *kdata)
{
	scx61_st->unreg(kdata, NULL);
	scx61_cpuperf_kick();
}

int __init scx61_glue_init(void)
{
	struct task_struct *g, *p;
	int cpu, i, ret;

	for_each_possible_cpu(cpu) {
		per_cpu(ds_scx_rqs, cpu).rq = cpu_rq(cpu);
		init_irq_work(&per_cpu(scx61_resched, cpu), scx61_resched_fn);
	}
	init_irq_work(&scx61_recon_irq, scx61_recon_irqfn);
	init_irq_work(&scx61_perf_irq, scx61_perf_irqfn);
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
	      register_trace_android_rvh_set_user_nice(scx61_rvh_set_user_nice, NULL) ?:
	      register_trace_android_rvh_set_cpus_allowed_comm(scx61_rvh_set_cpus_allowed, NULL) ?:
	      register_trace_android_rvh_setscheduler(scx61_rvh_setscheduler, NULL) ?:
	      register_trace_android_rvh_rtmutex_prepare_setprio(scx61_rvh_rtmutex_setprio, NULL);
	if (ret)
		return ret;
	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "sched_ext:online",
					scx61_cpu_online, scx61_cpu_offline);
	if (ret < 0)
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
