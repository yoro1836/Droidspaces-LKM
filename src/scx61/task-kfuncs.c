// SPDX-License-Identifier: GPL-2.0
/* The task and RCU kfuncs of kernel/bpf/helpers.c that schedulers call and
 * android14-6.1 does not have yet (v6.2). They are a few lines each upstream,
 * and helpers.c is not something to bring in whole, so they are written out
 * here after 6.12's.
 */
#define pr_fmt(fmt) "droidspaces_scx: " fmt
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid_namespace.h>
#include <linux/rcupdate.h>
#include "compat-bpf.h"
#include "port.h"

__bpf_kfunc_start_defs();

__bpf_kfunc struct task_struct *bpf_task_acquire(struct task_struct *p)
{
	if (refcount_inc_not_zero(&p->rcu_users))
		return p;
	return NULL;
}

__bpf_kfunc void bpf_task_release(struct task_struct *p)
{
	put_task_struct_rcu_user(p);
}

__bpf_kfunc struct task_struct *bpf_task_from_pid(s32 pid)
{
	struct task_struct *p;

	rcu_read_lock();
	p = find_task_by_pid_ns(pid, &init_pid_ns);
	if (p)
		p = bpf_task_acquire(p);
	rcu_read_unlock();
	return p;
}

/* 6.2's verifier follows these two to know which pointers RCU protects.
 * 6.1's sees two calls, and the read-side section is real all the same.
 */
__bpf_kfunc void bpf_rcu_read_lock(void)
{
	rcu_read_lock();
}

__bpf_kfunc void bpf_rcu_read_unlock(void)
{
	rcu_read_unlock();
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(scx61_task_kfunc_ids)
BTF_ID_FLAGS(func, bpf_task_acquire, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_task_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_task_from_pid, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_rcu_read_lock)
BTF_ID_FLAGS(func, bpf_rcu_read_unlock)
BTF_KFUNCS_END(scx61_task_kfunc_ids)

/* No owner: found through the merged vmlinux BTF, see btf.c. */
static const struct btf_kfunc_id_set scx61_task_kfunc_set = {
	.set = &scx61_task_kfunc_ids,
};

int __init scx61_task_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &scx61_task_kfunc_set) ?:
	       register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &scx61_task_kfunc_set) ?:
	       register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &scx61_task_kfunc_set);
}
