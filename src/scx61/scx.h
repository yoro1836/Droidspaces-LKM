/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DS_SCX61_H
#define DS_SCX61_H
#include <linux/types.h>

struct task_struct;

/* The operations a BPF scheduler implements. Member names and prototypes
 * follow upstream's struct sched_ext_ops, so the same scheduler source binds
 * to it; members are added as the class learns to call them.
 */
struct sched_ext_ops {
	s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
	char name[128];
};

int scx_bpf_init(void);
/* The loaded scheduler's pick, or -1 when there is none or it has no say. */
s32 scx_ops_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
#endif
