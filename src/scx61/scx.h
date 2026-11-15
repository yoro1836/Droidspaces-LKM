/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DS_SCX61_H
#define DS_SCX61_H
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

/* Values as in upstream's include/linux/sched/ext.h, so scheduler sources
 * that name them build unchanged.
 */
#define SCX_DSQ_FLAG_BUILTIN	(1LLU << 63)
#define SCX_DSQ_FLAG_LOCAL_ON	(1LLU << 62)
#define SCX_DSQ_INVALID		(SCX_DSQ_FLAG_BUILTIN | 0)
#define SCX_DSQ_GLOBAL		(SCX_DSQ_FLAG_BUILTIN | 1)
#define SCX_DSQ_LOCAL		(SCX_DSQ_FLAG_BUILTIN | 2)
#define SCX_DSQ_LOCAL_ON	(SCX_DSQ_FLAG_BUILTIN | SCX_DSQ_FLAG_LOCAL_ON)
#define SCX_SLICE_DFL		(20 * NSEC_PER_MSEC)
#define SCX_ENQ_HEAD		(1LLU << 4)

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
struct scx_entity {
	u64 slice;
	u64 dsq_vtime;
	struct scx_dsq *dsq;	/* the non-local queue it waits in, if any */
	u64 ddsp_dsq_id;
	u64 ddsp_slice;
	u32 weight;
	u32 flags;
};
#define SCX_ENT_DDSP	1	/* ddsp_* say where the next enqueue goes */

static inline struct scx_entity *scx_ent(struct task_struct *p)
{
	BUILD_BUG_ON(sizeof(struct scx_entity) > offsetof(struct sched_dl_entity, flags) -
						 offsetof(struct sched_dl_entity, dl_runtime));
	return (struct scx_entity *)&p->dl.dl_runtime;
}

/* The operations a BPF scheduler implements. Member names and prototypes
 * follow upstream's struct sched_ext_ops, so the same scheduler source binds
 * to it; members are added as the class learns to call them.
 */
struct sched_ext_ops {
	s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
	void (*enqueue)(struct task_struct *p, u64 enq_flags);
	void (*dispatch)(s32 cpu, struct task_struct *prev);
	void (*running)(struct task_struct *p);
	void (*stopping)(struct task_struct *p, bool runnable);
	s32 (*init)(void);
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
#endif
