/* SPDX-License-Identifier: GPL-2.0-only */
/* What upstream's kernel/sched/ext.c expects around it that android14-6.1
 * does not have. Included by ext-port.c only, ahead of the generated file.
 */
#ifndef DS_SCX61_COMPAT_H
#define DS_SCX61_COMPAT_H

#define CONFIG_SCHED_CLASS_EXT 1
#include "upstream/sched_ext.h"

/* scx_rq->flags, protected by the rq lock */
enum scx_rq_flags {
	/*
	 * A hotplugged CPU starts scheduling before rq_online_scx(). Track
	 * ops.cpu_on/offline() state so that ops.enqueue/dispatch() are called
	 * only while the BPF scheduler considers the CPU to be online.
	 */
	SCX_RQ_ONLINE		= 1 << 0,
	SCX_RQ_CAN_STOP_TICK	= 1 << 1,
	SCX_RQ_BAL_PENDING	= 1 << 2, /* balance hasn't run yet */
	SCX_RQ_BAL_KEEP		= 1 << 3, /* balance decided to keep current */
	SCX_RQ_BYPASSING	= 1 << 4,

	SCX_RQ_IN_WAKEUP	= 1 << 16,
	SCX_RQ_IN_BALANCE	= 1 << 17,
};

struct scx_rq {
	struct scx_dispatch_q	local_dsq;
	struct list_head	runnable_list;		/* runnable tasks on this rq */
	struct list_head	ddsp_deferred_locals;	/* deferred ddsps from enq */
	u64			extra_enq_flags;	/* see move_task_to_local_dsq() */
	u32			nr_running;
	u32			flags;
	u32			cpuperf_target;		/* [0, SCHED_CAPACITY_SCALE] */
	bool			cpu_released;
	cpumask_var_t		cpus_to_kick;
	cpumask_var_t		cpus_to_kick_if_idle;
	cpumask_var_t		cpus_to_preempt;
	cpumask_var_t		cpus_to_wait;
	unsigned long		pnt_seq;
	struct balance_callback	deferred_bal_cb;
	struct irq_work		deferred_irq_work;
	struct irq_work		kick_cpus_irq_work;
};

/* struct rq has no scx member: one of these per CPU instead. */
struct ds_scx_rq {
	struct scx_rq scx;
	struct rq *rq;
};
DECLARE_PER_CPU(struct ds_scx_rq, ds_scx_rqs);

static inline struct scx_rq *scx_rq(struct rq *rq)
{
	return &per_cpu(ds_scx_rqs, cpu_of(rq)).scx;
}

static inline struct rq *scx_rq_owner(struct scx_rq *srq)
{
	return container_of(srq, struct ds_scx_rq, scx)->rq;
}

/* task_struct has no scx member. Upstream keeps one for every task of every
 * class at all times, so it cannot borrow a field some class uses. It goes
 * at the end of the vendor data Android reserves in task_struct for modules
 * like this one: 64 words that fork clears. Samsung's EMS uses the first 35.
 * The module refuses to load if any task has something in our 24.
 */
#define SCX_ENT_WORDS	(sizeof(struct sched_ext_entity) / sizeof(u64))
#define SCX_ENT_FIRST	(ARRAY_SIZE(((struct task_struct *)0)->android_vendor_data1) - SCX_ENT_WORDS)
#define SCX_ENT_OFFSET	(offsetof(struct task_struct, android_vendor_data1) + SCX_ENT_FIRST * sizeof(u64))

static inline struct sched_ext_entity *scx_ent(const struct task_struct *p)
{
	BUILD_BUG_ON(sizeof(struct sched_ext_entity) % sizeof(u64));
	BUILD_BUG_ON(sizeof(struct sched_ext_entity) > 28 * sizeof(u64));
	return (struct sched_ext_entity *)((void *)p + SCX_ENT_OFFSET);
}

static inline struct task_struct *scx_task_of(struct sched_ext_entity *ent)
{
	return (struct task_struct *)((void *)ent - SCX_ENT_OFFSET);
}

/* Walks of a list linked through a member of p->scx. */
#define __scx_task_at(ent, head, member)						\
	(list_entry_is_head(ent, head, member) ? NULL : scx_task_of(ent))
#define __scx_first(head, member)							\
	__scx_task_at(list_first_entry(head, struct sched_ext_entity, member), head, member)
#define __scx_last(head, member)							\
	__scx_task_at(list_last_entry(head, struct sched_ext_entity, member), head, member)
#define __scx_next(p, head, member)							\
	__scx_task_at(list_next_entry(scx_ent(p), member), head, member)
#define __scx_prev(p, head, member)							\
	__scx_task_at(list_prev_entry(scx_ent(p), member), head, member)

#define scx_for_each_task(p, head, member)						\
	for ((p) = __scx_first(head, member); (p); (p) = __scx_next(p, head, member))
#define scx_for_each_task_safe(p, n, head, member)					\
	for ((p) = __scx_first(head, member),						\
	     (n) = (p) ? __scx_next(p, head, member) : NULL; (p);			\
	     (p) = (n), (n) = (p) ? __scx_next(p, head, member) : NULL)
#define scx_for_each_task_safe_reverse(p, n, head, member)				\
	for ((p) = __scx_last(head, member),						\
	     (n) = (p) ? __scx_prev(p, head, member) : NULL; (p);			\
	     (p) = (n), (n) = (p) ? __scx_prev(p, head, member) : NULL)

#define scx_first_task_or_null(head, member) ({					\
	struct sched_ext_entity *__e =						\
		list_first_entry_or_null(head, struct sched_ext_entity, member);	\
	__e ? scx_task_of(__e) : NULL; })

/* The class lives in the idle class's slot (see main.c), so its address is
 * the idle class's, and a task is ours when it has that class without being
 * the idle task, which alone has pid 0.
 */
#define ext_sched_class idle_sched_class

static inline bool task_is_scx(const struct task_struct *p)
{
	return p->sched_class == &idle_sched_class && p->pid;
}

static inline bool scx_above_task(const struct task_struct *p)
{
	return p->sched_class == &idle_sched_class && !p->pid;
}

/* 6.12 core scheduler pieces ext.c refers to. */
#include <linux/rhashtable.h>
#include <linux/mmu_context.h>

#define SCHED_EXT		7
#define ENQUEUE_RQ_SELECTED	0x400	/* never set by this core */
#define struct_size_t(type, member, count) struct_size((type *)NULL, member, count)

DECLARE_STATIC_KEY_FALSE(__scx_ops_enabled);
DECLARE_STATIC_KEY_FALSE(__scx_switched_all);
#define scx_enabled()		static_branch_unlikely(&__scx_ops_enabled)
#define scx_switched_all()	static_branch_unlikely(&__scx_switched_all)

static inline void trace_sched_ext_dump(const char *line) {}
static inline bool trace_sched_ext_dump_enabled(void) { return false; }

bool task_should_scx(int policy);

static inline const struct sched_class *__setscheduler_class(int policy, int prio)
{
	if (dl_prio(prio))
		return &dl_sched_class;
	if (rt_prio(prio))
		return &rt_sched_class;
	if (task_should_scx(policy))
		return &ext_sched_class;
	return &fair_sched_class;
}

static inline struct task_struct *tryget_task_struct(struct task_struct *t)
{
	return refcount_inc_not_zero(&t->usage) ? t : NULL;
}

static inline bool task_allowed_on_cpu(struct task_struct *p, int cpu)
{
	if (!cpumask_test_cpu(cpu, p->cpus_ptr))
		return false;
	if (!(p->flags & PF_KTHREAD) && !task_cpu_possible(cpu, p))
		return false;
	return true;
}

static inline unsigned long sched_weight_to_cgroup(unsigned long weight)
{
	return clamp_t(unsigned long,
		       DIV_ROUND_CLOSEST_ULL(weight * CGROUP_WEIGHT_DFL, 1024),
		       CGROUP_WEIGHT_MIN, CGROUP_WEIGHT_MAX);
}

/* rt, dl, irq and thermal load tracking belong to fair's tick on 6.1. */
static inline bool update_other_load_avgs(struct rq *rq) { return false; }

s64 update_curr_common(struct rq *rq);

struct affinity_context {
	const struct cpumask *new_mask;
	u32 flags;
};
#define set_cpus_allowed_common(p, ac) set_cpus_allowed_common(p, (ac)->new_mask, (ac)->flags)

struct sched_enq_and_set_ctx {
	struct task_struct *p;
	int queue_flags;
	bool queued;
	bool running;
};
void sched_deq_and_put_task(struct task_struct *p, int queue_flags,
			    struct sched_enq_and_set_ctx *ctx);
void sched_enq_and_set_task(struct sched_enq_and_set_ctx *ctx);
void check_class_changing(struct rq *rq, struct task_struct *p,
			  const struct sched_class *prev_class);
void check_class_changed(struct rq *rq, struct task_struct *p,
			 const struct sched_class *prev_class, int oldprio);

/* The class's methods as 6.12 shapes them. upstream fills one of these and
 * the idle slot's entry points call through it.
 */
struct scx61_class {
	void (*enqueue_task)(struct rq *rq, struct task_struct *p, int flags);
	bool (*dequeue_task)(struct rq *rq, struct task_struct *p, int flags);
	void (*yield_task)(struct rq *rq);
	bool (*yield_to_task)(struct rq *rq, struct task_struct *p);
	void (*wakeup_preempt)(struct rq *rq, struct task_struct *p, int flags);
	int (*balance)(struct rq *rq, struct task_struct *prev, struct rq_flags *rf);
	struct task_struct *(*pick_task)(struct rq *rq);
	void (*put_prev_task)(struct rq *rq, struct task_struct *p, struct task_struct *next);
	void (*set_next_task)(struct rq *rq, struct task_struct *p, bool first);
	int (*select_task_rq)(struct task_struct *p, int task_cpu, int flags);
	void (*task_woken)(struct rq *this_rq, struct task_struct *task);
	void (*set_cpus_allowed)(struct task_struct *p, struct affinity_context *ctx);
	void (*rq_online)(struct rq *rq);
	void (*rq_offline)(struct rq *rq);
	void (*task_tick)(struct rq *rq, struct task_struct *p, int queued);
	void (*switching_to)(struct rq *this_rq, struct task_struct *task);
	void (*switched_from)(struct rq *this_rq, struct task_struct *task);
	void (*switched_to)(struct rq *this_rq, struct task_struct *task);
	void (*reweight_task)(struct rq *this_rq, struct task_struct *task, const struct load_weight *lw);
	void (*prio_changed)(struct rq *this_rq, struct task_struct *task, int oldprio);
	void (*update_curr)(struct rq *rq);
	int uclamp_enabled;
};

/* 6.12's schedutil reads the performance target a scheduler sets. No 6.1
 * governor does, so the target is applied as a frequency floor, from
 * ext-glue.c, each time upstream announces a change.
 */
void scx61_cpuperf_kick(void);
#define cpufreq_update_util(rq, flags) ({ cpufreq_update_util(rq, flags); scx61_cpuperf_kick(); })

#include "compat-bpf.h"

#define bpf_struct_ops_desc	bpf_struct_ops
#define bpf_base_func_proto(func_id, prog) bpf_base_func_proto(func_id)

struct bpf_link;
struct scx61_struct_ops;
int scx61_register_struct_ops(struct scx61_struct_ops *st);
struct scx61_struct_ops {
	const struct bpf_verifier_ops *verifier_ops;
	int (*init)(struct btf *btf);
	int (*check_member)(const struct btf_type *t, const struct btf_member *member,
			    const struct bpf_prog *prog);
	int (*init_member)(const struct btf_type *t, const struct btf_member *member,
			   void *kdata, const void *udata);
	int (*reg)(void *kdata, struct bpf_link *link);
	void (*unreg)(void *kdata, struct bpf_link *link);
	int (*update)(void *kdata, void *old_kdata, struct bpf_link *link);
	int (*validate)(void *kdata);
	void *cfi_stubs;
	struct module *owner;
	const char *name;
};

#endif
