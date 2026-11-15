/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DS_SCX61_H
#define DS_SCX61_H
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

/* Names and values as in upstream's include/linux/sched/ext.h and
 * kernel/sched/ext.c. They are enums rather than macros because upstream's
 * loader reads them out of the kernel's BTF by name at run time.
 */
enum scx_public_consts {
	SCX_OPS_NAME_LEN	= 128,
	SCX_SLICE_DFL		= 20 * 1000000,	/* 20ms */
	SCX_SLICE_INF		= U64_MAX,
};

enum scx_dsq_id_flags {
	SCX_DSQ_FLAG_BUILTIN	= 1LLU << 63,
	SCX_DSQ_FLAG_LOCAL_ON	= 1LLU << 62,
	SCX_DSQ_INVALID		= SCX_DSQ_FLAG_BUILTIN | 0,
	SCX_DSQ_GLOBAL		= SCX_DSQ_FLAG_BUILTIN | 1,
	SCX_DSQ_LOCAL		= SCX_DSQ_FLAG_BUILTIN | 2,
	SCX_DSQ_LOCAL_ON	= SCX_DSQ_FLAG_BUILTIN | SCX_DSQ_FLAG_LOCAL_ON,
	SCX_DSQ_LOCAL_CPU_MASK	= 0xffffffffLLU,
};

enum scx_enq_flags {
	SCX_ENQ_WAKEUP		= 1LLU << 0,
	SCX_ENQ_HEAD		= 1LLU << 4,
	SCX_ENQ_PREEMPT		= 1LLU << 32,
	SCX_ENQ_REENQ		= 1LLU << 40,
	SCX_ENQ_LAST		= 1LLU << 41,
};

enum scx_kick_flags {
	SCX_KICK_IDLE		= 1LLU << 0,
	SCX_KICK_PREEMPT	= 1LLU << 1,
	SCX_KICK_WAIT		= 1LLU << 2,
};

struct scx_dsq {
	raw_spinlock_t lock;
	struct list_head list;
	u32 nr;
	u64 id;
	struct hlist_node hash;
};

/* Per-task state. task_struct has no room of its own for it, and the slots
 * Android reserves for ABI fixes are in use (dmabuf accounting took one). It
 * lives in the seven parameter words of p->dl instead, which only a deadline
 * task reads: fork clears them, and becoming a deadline task rewrites them
 * all, by which time the task has left this class.
 */
struct sched_ext_entity {
	u64 slice;
	u64 dsq_vtime;
	struct scx_dsq *dsq;	/* the non-local queue it waits in, if any */
	u64 ddsp_dsq_id;
	u64 ddsp_slice;
	u32 weight;
	u32 flags;
};
#define SCX_ENT_DDSP	1	/* ddsp_* say where the next enqueue goes */

static inline struct sched_ext_entity *scx_ent(struct task_struct *p)
{
	BUILD_BUG_ON(sizeof(struct sched_ext_entity) > offsetof(struct sched_dl_entity, flags) -
						 offsetof(struct sched_dl_entity, dl_runtime));
	return (struct sched_ext_entity *)&p->dl.dl_runtime;
}

enum scx_exit_kind {
	SCX_EXIT_NONE,
	SCX_EXIT_DONE,
	SCX_EXIT_UNREG = 64,
	SCX_EXIT_UNREG_BPF,
	SCX_EXIT_UNREG_KERN,
	SCX_EXIT_SYSRQ,
	SCX_EXIT_ERROR = 1024,
	SCX_EXIT_ERROR_BPF,
	SCX_EXIT_ERROR_STALL,
};

struct scx_exit_info {
	enum scx_exit_kind kind;
	s64 exit_code;
	const char *reason;
	unsigned long *bt;
	u32 bt_len;
	char *msg;
	char *dump;
};

struct scx_cpu_acquire_args {};
struct scx_cpu_release_args {
	int reason;
	struct task_struct *task;
};
struct scx_init_task_args {
	bool fork;
	struct cgroup *cgroup;
};
struct scx_exit_task_args {
	bool cancelled;
};
struct scx_cgroup_init_args {
	u32 weight;
};
struct scx_dump_ctx {
	enum scx_exit_kind kind;
	s64 exit_code;
	const char *reason;
	u64 at_ns;
	u64 at_jiffies;
};

/* The operations a BPF scheduler implements: upstream's struct sched_ext_ops
 * member for member, because libbpf refuses a scheduler whose own copy of the
 * struct has a member the kernel's lacks. The ones this class calls so far
 * are select_cpu, enqueue, dispatch, running, stopping, enable, init and exit.
 */
struct sched_ext_ops {
	s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
	void (*enqueue)(struct task_struct *p, u64 enq_flags);
	void (*dequeue)(struct task_struct *p, u64 deq_flags);
	void (*dispatch)(s32 cpu, struct task_struct *prev);
	void (*tick)(struct task_struct *p);
	void (*runnable)(struct task_struct *p, u64 enq_flags);
	void (*running)(struct task_struct *p);
	void (*stopping)(struct task_struct *p, bool runnable);
	void (*quiescent)(struct task_struct *p, u64 deq_flags);
	bool (*yield)(struct task_struct *from, struct task_struct *to);
	bool (*core_sched_before)(struct task_struct *a, struct task_struct *b);
	void (*set_weight)(struct task_struct *p, u32 weight);
	void (*set_cpumask)(struct task_struct *p, const struct cpumask *cpumask);
	void (*update_idle)(s32 cpu, bool idle);
	void (*cpu_acquire)(s32 cpu, struct scx_cpu_acquire_args *args);
	void (*cpu_release)(s32 cpu, struct scx_cpu_release_args *args);
	s32 (*init_task)(struct task_struct *p, struct scx_init_task_args *args);
	void (*exit_task)(struct task_struct *p, struct scx_exit_task_args *args);
	void (*enable)(struct task_struct *p);
	void (*disable)(struct task_struct *p);
	void (*dump)(struct scx_dump_ctx *ctx);
	void (*dump_cpu)(struct scx_dump_ctx *ctx, s32 cpu, bool idle);
	void (*dump_task)(struct scx_dump_ctx *ctx, struct task_struct *p);
	s32 (*cgroup_init)(struct cgroup *cgrp, struct scx_cgroup_init_args *args);
	void (*cgroup_exit)(struct cgroup *cgrp);
	s32 (*cgroup_prep_move)(struct task_struct *p, struct cgroup *from, struct cgroup *to);
	void (*cgroup_move)(struct task_struct *p, struct cgroup *from, struct cgroup *to);
	void (*cgroup_cancel_move)(struct task_struct *p, struct cgroup *from, struct cgroup *to);
	void (*cgroup_set_weight)(struct cgroup *cgrp, u32 weight);
	void (*cpu_online)(s32 cpu);
	void (*cpu_offline)(s32 cpu);
	s32 (*init)(void);
	void (*exit)(struct scx_exit_info *info);
	u32 dispatch_max_batch;
	u64 flags;
	u32 timeout_ms;
	u32 exit_dump_len;
	u64 hotplug_seq;
	char name[128];
};

int scx_bpf_init(void);
int scx_register_kfuncs(void);
void scx_ops_gone(void);
/* The loaded scheduler's pick, or -1 when there is none or it has no say. */
s32 scx_ops_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
/* False when no scheduler implements the callback. */
bool scx_ops_enqueue(struct task_struct *p, u64 enq_flags);
bool scx_ops_dispatch(s32 cpu);
void scx_ops_running(struct task_struct *p);
void scx_ops_stopping(struct task_struct *p, bool runnable);
void scx_ops_enable(struct task_struct *p);
/* A kfunc was told something the scheduler must not go on after. */
void scx_ops_error(const char *msg);
#endif
