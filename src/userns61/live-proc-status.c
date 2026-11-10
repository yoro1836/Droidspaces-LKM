// SPDX-License-Identifier: GPL-2.0
/*
 * /proc/<pid>/status from the Samsung S5E9945 vendor kernel (6.1),
 * fs/proc/array.c, compiled with CONFIG_USER_NS (and this module's
 * CONFIG_PID_NS) so Uid, Gid and Groups are shown as seen from the
 * opener's user namespace and the NS* pid lines appear, as upstream.
 * proc_pid_status() and the static helpers it inlines are copied
 * verbatim; proc_task_name(), render_sigset_t(), task_mem() and
 * cpuset_task_status_allowed() stay native. The native function is
 * redirected here (port61/hooks.c). For an opener in init_user_ns the
 * conversions are identity, so the only change there is the NS* lines.
 *
 *  Copyright (C) 1992  by Linus Torvalds
 *  based on ideas by Darren Senn
 */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/time_namespace.h>
#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/tty.h>
#include <linux/string.h>
#include <linux/mman.h>
#include <linux/sched/mm.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/task.h>
#include <linux/sched/cputime.h>
#include <linux/proc_fs.h>
#include <linux/ioport.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/smp.h>
#include <linux/signal.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/times.h>
#include <linux/cpuset.h>
#include <linux/rcupdate.h>
#include <linux/delayacct.h>
#include <linux/seq_file.h>
#include <linux/pid_namespace.h>
#include <linux/prctl.h>
#include <linux/ptrace.h>
#include <linux/string_helpers.h>
#include <linux/user_namespace.h>
#include <linux/fs_struct.h>
#include <linux/kthread.h>

#include <asm/processor.h>
#include "internal.h"

#include "userns61.h"

/*
 * The task state array is a strange "bitmap" of
 * reasons to sleep. Thus "running" is zero, and
 * you can test for combinations of others with
 * simple bit tests.
 */
static const char * const task_state_array[] = {

	/* states in TASK_REPORT: */
	"R (running)",		/* 0x00 */
	"S (sleeping)",		/* 0x01 */
	"D (disk sleep)",	/* 0x02 */
	"T (stopped)",		/* 0x04 */
	"t (tracing stop)",	/* 0x08 */
	"X (dead)",		/* 0x10 */
	"Z (zombie)",		/* 0x20 */
	"P (parked)",		/* 0x40 */

	/* states beyond TASK_REPORT: */
	"I (idle)",		/* 0x80 */
};

static inline const char *get_task_state(struct task_struct *tsk)
{
	BUILD_BUG_ON(1 + ilog2(TASK_REPORT_MAX) != ARRAY_SIZE(task_state_array));
	return task_state_array[task_state_index(tsk)];
}

static inline void task_state(struct seq_file *m, struct pid_namespace *ns,
				struct pid *pid, struct task_struct *p)
{
	struct user_namespace *user_ns = seq_user_ns(m);
	struct group_info *group_info;
	int g, umask = -1;
	struct task_struct *tracer;
	const struct cred *cred;
	pid_t ppid, tpid = 0, tgid, ngid;
	unsigned int max_fds = 0;

	rcu_read_lock();
	ppid = pid_alive(p) ?
		task_tgid_nr_ns(rcu_dereference(p->real_parent), ns) : 0;

	tracer = ptrace_parent(p);
	if (tracer)
		tpid = task_pid_nr_ns(tracer, ns);

	tgid = task_tgid_nr_ns(p, ns);
	ngid = task_numa_group_id(p);
	cred = get_task_cred(p);

	task_lock(p);
	if (p->fs)
		umask = p->fs->umask;
	if (p->files)
		max_fds = files_fdtable(p->files)->max_fds;
	task_unlock(p);
	rcu_read_unlock();

	if (umask >= 0)
		seq_printf(m, "Umask:\t%#04o\n", umask);
	seq_puts(m, "State:\t");
	seq_puts(m, get_task_state(p));

	seq_put_decimal_ull(m, "\nTgid:\t", tgid);
	seq_put_decimal_ull(m, "\nNgid:\t", ngid);
	seq_put_decimal_ull(m, "\nPid:\t", pid_nr_ns(pid, ns));
	seq_put_decimal_ull(m, "\nPPid:\t", ppid);
	seq_put_decimal_ull(m, "\nTracerPid:\t", tpid);
	seq_put_decimal_ull(m, "\nUid:\t", from_kuid_munged(user_ns, cred->uid));
	seq_put_decimal_ull(m, "\t", from_kuid_munged(user_ns, cred->euid));
	seq_put_decimal_ull(m, "\t", from_kuid_munged(user_ns, cred->suid));
	seq_put_decimal_ull(m, "\t", from_kuid_munged(user_ns, cred->fsuid));
	seq_put_decimal_ull(m, "\nGid:\t", from_kgid_munged(user_ns, cred->gid));
	seq_put_decimal_ull(m, "\t", from_kgid_munged(user_ns, cred->egid));
	seq_put_decimal_ull(m, "\t", from_kgid_munged(user_ns, cred->sgid));
	seq_put_decimal_ull(m, "\t", from_kgid_munged(user_ns, cred->fsgid));
	seq_put_decimal_ull(m, "\nFDSize:\t", max_fds);

	seq_puts(m, "\nGroups:\t");
	group_info = cred->group_info;
	for (g = 0; g < group_info->ngroups; g++)
		seq_put_decimal_ull(m, g ? " " : "",
				from_kgid_munged(user_ns, group_info->gid[g]));
	put_cred(cred);
	/* Trailing space shouldn't have been added in the first place. */
	seq_putc(m, ' ');

#ifdef CONFIG_PID_NS
	seq_puts(m, "\nNStgid:");
	for (g = ns->level; g <= pid->level; g++)
		seq_put_decimal_ull(m, "\t", task_tgid_nr_ns(p, pid->numbers[g].ns));
	seq_puts(m, "\nNSpid:");
	for (g = ns->level; g <= pid->level; g++)
		seq_put_decimal_ull(m, "\t", task_pid_nr_ns(p, pid->numbers[g].ns));
	seq_puts(m, "\nNSpgid:");
	for (g = ns->level; g <= pid->level; g++)
		seq_put_decimal_ull(m, "\t", task_pgrp_nr_ns(p, pid->numbers[g].ns));
	seq_puts(m, "\nNSsid:");
	for (g = ns->level; g <= pid->level; g++)
		seq_put_decimal_ull(m, "\t", task_session_nr_ns(p, pid->numbers[g].ns));
#endif
	seq_putc(m, '\n');
}


static void collect_sigign_sigcatch(struct task_struct *p, sigset_t *sigign,
				    sigset_t *sigcatch)
{
	struct k_sigaction *k;
	int i;

	k = p->sighand->action;
	for (i = 1; i <= _NSIG; ++i, ++k) {
		if (k->sa.sa_handler == SIG_IGN)
			sigaddset(sigign, i);
		else if (k->sa.sa_handler != SIG_DFL)
			sigaddset(sigcatch, i);
	}
}

static inline void task_sig(struct seq_file *m, struct task_struct *p)
{
	unsigned long flags;
	sigset_t pending, shpending, blocked, ignored, caught;
	int num_threads = 0;
	unsigned int qsize = 0;
	unsigned long qlim = 0;

	sigemptyset(&pending);
	sigemptyset(&shpending);
	sigemptyset(&blocked);
	sigemptyset(&ignored);
	sigemptyset(&caught);

	if (lock_task_sighand(p, &flags)) {
		pending = p->pending.signal;
		shpending = p->signal->shared_pending.signal;
		blocked = p->blocked;
		collect_sigign_sigcatch(p, &ignored, &caught);
		num_threads = get_nr_threads(p);
		rcu_read_lock();  /* FIXME: is this correct? */
		qsize = get_rlimit_value(task_ucounts(p), UCOUNT_RLIMIT_SIGPENDING);
		rcu_read_unlock();
		qlim = task_rlimit(p, RLIMIT_SIGPENDING);
		unlock_task_sighand(p, &flags);
	}

	seq_put_decimal_ull(m, "Threads:\t", num_threads);
	seq_put_decimal_ull(m, "\nSigQ:\t", qsize);
	seq_put_decimal_ull(m, "/", qlim);

	/* render them all */
	render_sigset_t(m, "\nSigPnd:\t", &pending);
	render_sigset_t(m, "ShdPnd:\t", &shpending);
	render_sigset_t(m, "SigBlk:\t", &blocked);
	render_sigset_t(m, "SigIgn:\t", &ignored);
	render_sigset_t(m, "SigCgt:\t", &caught);
}

static void render_cap_t(struct seq_file *m, const char *header,
			kernel_cap_t *a)
{
	unsigned __capi;

	seq_puts(m, header);
	CAP_FOR_EACH_U32(__capi) {
		seq_put_hex_ll(m, NULL,
			   a->cap[CAP_LAST_U32 - __capi], 8);
	}
	seq_putc(m, '\n');
}

static inline void task_cap(struct seq_file *m, struct task_struct *p)
{
	const struct cred *cred;
	kernel_cap_t cap_inheritable, cap_permitted, cap_effective,
			cap_bset, cap_ambient;

	rcu_read_lock();
	cred = __task_cred(p);
	cap_inheritable	= cred->cap_inheritable;
	cap_permitted	= cred->cap_permitted;
	cap_effective	= cred->cap_effective;
	cap_bset	= cred->cap_bset;
	cap_ambient	= cred->cap_ambient;
	rcu_read_unlock();

	render_cap_t(m, "CapInh:\t", &cap_inheritable);
	render_cap_t(m, "CapPrm:\t", &cap_permitted);
	render_cap_t(m, "CapEff:\t", &cap_effective);
	render_cap_t(m, "CapBnd:\t", &cap_bset);
	render_cap_t(m, "CapAmb:\t", &cap_ambient);
}

static inline void task_seccomp(struct seq_file *m, struct task_struct *p)
{
	seq_put_decimal_ull(m, "NoNewPrivs:\t", task_no_new_privs(p));
#ifdef CONFIG_SECCOMP
	seq_put_decimal_ull(m, "\nSeccomp:\t", p->seccomp.mode);
#ifdef CONFIG_SECCOMP_FILTER
	seq_put_decimal_ull(m, "\nSeccomp_filters:\t",
			    atomic_read(&p->seccomp.filter_count));
#endif
#endif
	seq_puts(m, "\nSpeculation_Store_Bypass:\t");
	switch (arch_prctl_spec_ctrl_get(p, PR_SPEC_STORE_BYPASS)) {
	case -EINVAL:
		seq_puts(m, "unknown");
		break;
	case PR_SPEC_NOT_AFFECTED:
		seq_puts(m, "not vulnerable");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE:
		seq_puts(m, "thread force mitigated");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_DISABLE:
		seq_puts(m, "thread mitigated");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_ENABLE:
		seq_puts(m, "thread vulnerable");
		break;
	case PR_SPEC_DISABLE:
		seq_puts(m, "globally mitigated");
		break;
	default:
		seq_puts(m, "vulnerable");
		break;
	}

	seq_puts(m, "\nSpeculationIndirectBranch:\t");
	switch (arch_prctl_spec_ctrl_get(p, PR_SPEC_INDIRECT_BRANCH)) {
	case -EINVAL:
		seq_puts(m, "unsupported");
		break;
	case PR_SPEC_NOT_AFFECTED:
		seq_puts(m, "not affected");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE:
		seq_puts(m, "conditional force disabled");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_DISABLE:
		seq_puts(m, "conditional disabled");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_ENABLE:
		seq_puts(m, "conditional enabled");
		break;
	case PR_SPEC_ENABLE:
		seq_puts(m, "always enabled");
		break;
	case PR_SPEC_DISABLE:
		seq_puts(m, "always disabled");
		break;
	default:
		seq_puts(m, "unknown");
		break;
	}
	seq_putc(m, '\n');
}

static inline void task_context_switch_counts(struct seq_file *m,
						struct task_struct *p)
{
	seq_put_decimal_ull(m, "voluntary_ctxt_switches:\t", p->nvcsw);
	seq_put_decimal_ull(m, "\nnonvoluntary_ctxt_switches:\t", p->nivcsw);
	seq_putc(m, '\n');
}

static void task_cpus_allowed(struct seq_file *m, struct task_struct *task)
{
	seq_printf(m, "Cpus_allowed:\t%*pb\n",
		   cpumask_pr_args(&task->cpus_mask));
	seq_printf(m, "Cpus_allowed_list:\t%*pbl\n",
		   cpumask_pr_args(&task->cpus_mask));
}

static inline void task_core_dumping(struct seq_file *m, struct task_struct *task)
{
	seq_put_decimal_ull(m, "CoreDumping:\t", !!task->signal->core_state);
	seq_putc(m, '\n');
}

static inline void task_thp_status(struct seq_file *m, struct mm_struct *mm)
{
	bool thp_enabled = IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE);

	if (thp_enabled)
		thp_enabled = !test_bit(MMF_DISABLE_THP, &mm->flags);
	seq_printf(m, "THP_enabled:\t%d\n", thp_enabled);
}

int ds_proc_pid_status(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	struct mm_struct *mm = get_task_mm(task);

	seq_puts(m, "Name:\t");
	proc_task_name(m, task, true);
	seq_putc(m, '\n');

	task_state(m, ns, pid, task);

	if (mm) {
		task_mem(m, mm);
		task_core_dumping(m, task);
		task_thp_status(m, mm);
		mmput(mm);
	}
	task_sig(m, task);
	task_cap(m, task);
	task_seccomp(m, task);
	task_cpus_allowed(m, task);
	cpuset_task_status_allowed(m, task);
	task_context_switch_counts(m, task);
	return 0;
}
