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

/* task_struct has no scx member: the entity is laid over p->dl, which only a
 * deadline task uses. Leaving the class puts p->dl back as fork made it.
 */
#define SCX_ENT_OFFSET offsetof(struct task_struct, dl)

static inline struct sched_ext_entity *scx_ent(const struct task_struct *p)
{
	BUILD_BUG_ON(sizeof(struct sched_ext_entity) > sizeof(struct sched_dl_entity));
	return (struct sched_ext_entity *)&p->dl;
}

static inline struct task_struct *scx_task_of(struct sched_ext_entity *ent)
{
	return (struct task_struct *)((void *)ent - SCX_ENT_OFFSET);
}

#define scx_for_each_task(p, head, member)						\
	for (struct sched_ext_entity *__e =						\
		     list_first_entry(head, struct sched_ext_entity, member);		\
	     !list_entry_is_head(__e, head, member) && ((p) = scx_task_of(__e), true);	\
	     __e = list_next_entry(__e, member))

#define scx_for_each_task_safe_reverse(p, n, head, member)				\
	for (struct sched_ext_entity *__e =						\
		     list_last_entry(head, struct sched_ext_entity, member),		\
	     *__n = list_prev_entry(__e, member);					\
	     !list_entry_is_head(__e, head, member) && ((p) = scx_task_of(__e), true);	\
	     __e = __n, __n = list_prev_entry(__n, member))

/* 6.12 core scheduler pieces ext.c refers to. */
#define ENQUEUE_RQ_SELECTED	0x400	/* never set by this core */

DECLARE_STATIC_KEY_FALSE(__scx_ops_enabled);
DECLARE_STATIC_KEY_FALSE(__scx_switched_all);
#define scx_enabled()		static_branch_unlikely(&__scx_ops_enabled)
#define scx_switched_all()	static_branch_unlikely(&__scx_switched_all)

extern const struct sched_class ext_sched_class;

static inline void trace_sched_ext_dump(const char *line) {}

#endif
