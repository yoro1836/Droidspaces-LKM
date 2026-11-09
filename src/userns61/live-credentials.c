// SPDX-License-Identifier: GPL-2.0-only
/*
 * copy_creds() from the Samsung S5E9945 vendor kernel/cred.c (6.1), verbatim
 * apart from the name, compiled with CONFIG_USER_NS so clone(CLONE_NEWUSER)
 * reaches this port's create_user_ns(). The Samsung KDP branch is unchanged:
 * with kdp_enable the child's cred is sealed by the vendor's
 * prepare_ro_creds(new, CMD_COPY_CREDS, p). The kprobe on the native
 * copy_creds redirects here only when clone_flags has CLONE_NEWUSER; every
 * other fork keeps running the native function.
 */
#include <linux/cred.h>
#include <linux/kdp.h>
#include <linux/key.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/security.h>
#include <linux/user_namespace.h>
#include "userns61.h"

/* CONFIG_DEBUG_CREDENTIALS is off on this device: as in kernel/cred.c. */
#define kdebug(FMT, ...) do { if (0) no_printk(FMT, ##__VA_ARGS__); } while (0)
static inline void alter_cred_subscribers(const struct cred *_cred, int n) { }
static inline int read_cred_subscribers(const struct cred *cred) { return 0; }

extern int install_thread_keyring_to_cred(struct cred *cred);

int ds_copy_creds(struct task_struct *p, unsigned long clone_flags)
{
	struct cred *new;
	int ret;

#ifdef CONFIG_KEYS_REQUEST_CACHE
	p->cached_requested_key = NULL;
#endif

#ifdef CONFIG_KDP_CRED
	if (!kdp_enable){
#endif
	if (
#ifdef CONFIG_KEYS
		!p->cred->thread_keyring &&
#endif
		clone_flags & CLONE_THREAD
	    ) {
		p->real_cred = get_cred(p->cred);
		get_cred(p->cred);
		alter_cred_subscribers(p->cred, 2);
		kdebug("share_creds(%p{%d,%d})",
		       p->cred, atomic_read(&p->cred->usage),
		       read_cred_subscribers(p->cred));
		inc_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
		return 0;
	}
#ifdef CONFIG_KDP_CRED
	}
#endif

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	if (clone_flags & CLONE_NEWUSER) {
		ret = create_user_ns(new);
		if (ret < 0)
			goto error_put;
		ret = set_cred_ucounts(new);
		if (ret < 0)
			goto error_put;
	}

#ifdef CONFIG_KEYS
	/* new threads get their own thread keyrings if their parent already
	 * had one */
	if (new->thread_keyring) {
		key_put(new->thread_keyring);
		new->thread_keyring = NULL;
		if (clone_flags & CLONE_THREAD)
			install_thread_keyring_to_cred(new);
	}

	/* The process keyring is only shared between the threads in a process;
	 * anything outside of those threads doesn't inherit.
	 */
	if (!(clone_flags & CLONE_THREAD)) {
		key_put(new->process_keyring);
		new->process_keyring = NULL;
	}
#endif

#ifdef CONFIG_KDP_CRED
	if (kdp_enable) {
		p->cred = p->real_cred = prepare_ro_creds(new, CMD_COPY_CREDS, (u64)p);
		inc_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
		put_cred(new);
	} else {
		p->cred = p->real_cred = get_cred(new);
		inc_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
		alter_cred_subscribers(new, 2);
		validate_creds(new);
	}
#else
	p->cred = p->real_cred = get_cred(new);
	inc_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
	alter_cred_subscribers(new, 2);
	validate_creds(new);
#endif
	return 0;

error_put:
	put_cred(new);
	return ret;
}
