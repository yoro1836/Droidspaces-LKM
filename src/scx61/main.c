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
 * The policy in this stage is fixed: a FIFO per CPU with a time slice.
 */
#define pr_fmt(fmt) "droidspaces_scx: " fmt
#include <linux/module.h>
#include <linux/of.h>
#include <linux/utsname.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/irq_work.h>
#include <linux/timer.h>
#include <linux/sched/task.h>
#include <linux/sched/cputime.h>
#include <trace/hooks/sched.h>
#include "kernel/sched/sched.h"
#include "core.h"
#include "hint.h"
#include "../gki-target.h"
#include "scx.h"

/* p->rt is unused while a task is not in the rt class, and fork resets it. */
#define SCX_MAGIC 0x5343583631UL
#define SCX_SLICE_TICKS 5

struct scx_rq {
	struct list_head queue;
	unsigned int nr;
};
static DEFINE_PER_CPU(struct scx_rq, scx_rqs);

static const struct sched_class *idle_class, *stop_class, *fair_class;
static void (*cpuacct_charge_fn)(struct task_struct *, u64);
static void (*cgroup_account_fn)(struct cgroup *, u64);

static unsigned long nr_attaches, nr_picks, nr_enqueues, nr_pulls, nr_fallbacks;
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
	u64 now = rq_clock_task(rq);
	s64 delta = now - curr->se.exec_start;
	struct cgroup *cgrp;

	if (delta <= 0)
		return;
	curr->se.exec_start = now;
	curr->se.sum_exec_runtime += delta;
	account_group_exec_runtime(curr, delta);
	cpuacct_charge_fn(curr, delta);
	rcu_read_lock();
	cgrp = task_dfl_cgroup(curr);
	if (cgroup_parent(cgrp))
		cgroup_account_fn(cgrp, delta);
	rcu_read_unlock();
}

/* A task that has to wait here may be runnable at once on a CPU that sleeps.
 * The rq lock is held at enqueue, so the poke goes through an irq_work, and
 * the CPU it wakes finds the task from its newidle hook below.
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

static void rvh_enqueue(void *unused, struct rq *rq, struct task_struct *p, int flags)
{
	struct scx_rq *s;

	if (!is_scx(p))
		return;
	s = scx_rq_of(rq);
	if (flags & ENQUEUE_HEAD)
		list_add(&p->rt.run_list, &s->queue);
	else
		list_add_tail(&p->rt.run_list, &s->queue);
	s->nr++;
	p->rt.watchdog_stamp = jiffies;
	nr_enqueues++;
	if (rq->curr != rq->idle && rq->curr != p)
		irq_work_queue(&per_cpu(scx_kick, cpu_of(rq)));
	p->sched_class = stop_class;
}

static void rvh_dequeue(void *unused, struct rq *rq, struct task_struct *p, int flags)
{
	if (!is_scx(p))
		return;
	if (rq->curr == p)
		scx_update_curr(rq);
	list_del_init(&p->rt.run_list);
	scx_rq_of(rq)->nr--;
	p->sched_class = stop_class;
}

/* Runs right after the stop class counted the task: hand it back. */
static void rvh_after(void *unused, struct rq *rq, struct task_struct *p, int flags)
{
	if (scx_marked(p) && p->sched_class == stop_class && p != rq->stop)
		p->sched_class = idle_class;
}

/* Take one task of ours off @src_cpu that is queued but not running and may
 * run on @dst_cpu. Called with interrupts off and no rq lock held. The task
 * comes back as migrating, the way fair's detach_task() leaves one.
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

/* This CPU is about to go idle. Take a task of ours that waits behind
 * something else on another CPU. Dropping the rq lock here is what fair's own
 * newidle balance does, and -1 tells the core to pick again from the top.
 */
static void rvh_newidle(void *unused, struct rq *this_rq, struct rq_flags *rf,
			int *pulled_task, int *done)
{
	int this_cpu = cpu_of(this_rq), cpu;

	if (!READ_ONCE(nr_attaches) || !cpu_active(this_cpu))
		return;
	for_each_online_cpu(cpu) {
		struct task_struct *p;

		if (cpu == this_cpu || READ_ONCE(per_cpu(scx_rqs, cpu).nr) <=
				       (is_scx(READ_ONCE(cpu_rq(cpu)->curr)) ? 1 : 0))
			continue;
		rq_unpin_lock(this_rq, rf);
		raw_spin_rq_unlock(this_rq);
		p = scx_detach_one(cpu, this_cpu);
		raw_spin_rq_lock(this_rq);
		rq_repin_lock(this_rq, rf);
		if (p) {
			scx_attach_one(this_rq, p);
			*pulled_task = -1;
			*done = 1;
			return;
		}
	}
}

/* A slice of ours ran out here. A task of ours on a CPU that something of a
 * higher class holds would otherwise wait for as long as that lasts, so bring
 * one over to take turns with the tasks here.
 */
static DEFINE_PER_CPU(struct irq_work, scx_balance);

static void scx_balance_fn(struct irq_work *work)
{
	int this_cpu = smp_processor_id(), cpu;
	struct rq *this_rq = cpu_rq(this_cpu);
	unsigned long flags;

	local_irq_save(flags);
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
		list_move_tail(&p->rt.run_list, &scx_rq_of(rq)->queue);
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

static struct task_struct *scx_pick_next_task(struct rq *rq)
{
	struct scx_rq *s = scx_rq_of(rq);
	struct task_struct *p;

	if (list_empty(&s->queue)) {
		idle_set_next(rq);
		return rq->idle;
	}
	p = list_first_entry(&s->queue, struct task_struct, rt.run_list);
	p->se.exec_start = rq_clock_task(rq);
	nr_picks++;
	return p;
}

static void scx_put_prev_task(struct rq *rq, struct task_struct *p)
{
	if (p == rq->idle)
		return;
	scx_update_curr(rq);
	p->rt.watchdog_stamp = jiffies;
}

static void scx_set_next_task(struct rq *rq, struct task_struct *p, bool first)
{
	if (p == rq->idle)
		idle_set_next(rq);
	else
		p->se.exec_start = rq_clock_task(rq);
}

/* Only reached when curr and p share the slot: idle yields, a peer waits. */
static void scx_check_preempt_curr(struct rq *rq, struct task_struct *p, int flags)
{
	if (rq->curr == rq->idle)
		resched_curr(rq);
}

static void scx_task_tick(struct rq *rq, struct task_struct *p, int queued)
{
	struct scx_rq *s;

	if (p == rq->idle)
		return;
	scx_update_curr(rq);
	if (--p->rt.time_slice)
		return;
	p->rt.time_slice = SCX_SLICE_TICKS;
	irq_work_queue(&per_cpu(scx_balance, cpu_of(rq)));
	s = scx_rq_of(rq);
	if (s->nr > 1 && !list_empty(&p->rt.run_list)) {
		list_move_tail(&p->rt.run_list, &s->queue);
		resched_curr(rq);
	}
}

/* The allowed CPU where the task waits behind the least. A fair task always
 * runs before ours, so it counts for more than a peer. Ties go to the higher
 * index, which is where the faster cores sit on the phones this targets.
 */
static int scx_select_task_rq(struct task_struct *p, int prev_cpu, int flags)
{
	unsigned int best_cost = UINT_MAX;
	int cpu, best = prev_cpu;

	cpu = scx_ops_select_cpu(p, prev_cpu, flags);
	if (cpu >= 0)
		return cpu;

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
	return best;
}

static void scx_update_curr_cb(struct rq *rq)
{
	if (rq->curr != rq->idle)
		scx_update_curr(rq);
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
		p->rt.time_slice = SCX_SLICE_TICKS;
		p->rt.timeout = SCX_MAGIC;
		nr_attaches++;
	} else {
		p->rt.timeout = 0;
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
 * after a second of waiting.
 */
static struct timer_list scx_watchdog;

static void scx_watchdog_fn(struct timer_list *unused)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct scx_rq *s = &per_cpu(scx_rqs, cpu);
		struct task_struct *p, *stalled = NULL;
		struct rq *rq = cpu_rq(cpu);
		unsigned long flags;

		if (!READ_ONCE(s->nr))
			continue;
		raw_spin_rq_lock_irqsave(rq, flags);
		list_for_each_entry(p, &s->queue, rt.run_list) {
			if (!task_current(rq, p) &&
			    time_after(jiffies, p->rt.watchdog_stamp + HZ)) {
				stalled = get_task_struct(p);
				break;
			}
		}
		raw_spin_rq_unlock_irqrestore(rq, flags);
		if (stalled) {
			if (!scx_set_class(stalled, false))
				nr_fallbacks++;
			put_task_struct(stalled);
		}
	}
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
