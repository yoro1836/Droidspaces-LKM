/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fs/fuse/fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/statfs.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/exportfs.h>
#include <linux/posix_acl.h>
#include <linux/pid_namespace.h>
#include <uapi/linux/magic.h>

#define FUSE_DEFAULT_MAX_BACKGROUND 12
#define FUSE_DEFAULT_CONGESTION_THRESHOLD (FUSE_DEFAULT_MAX_BACKGROUND * 3 / 4)

static void fuse_iqueue_init(struct fuse_iqueue *fiq,
			     const struct fuse_iqueue_ops *ops,
			     void *priv)
{
	memset(fiq, 0, sizeof(struct fuse_iqueue));
	spin_lock_init(&fiq->lock);
	init_waitqueue_head(&fiq->waitq);
	INIT_LIST_HEAD(&fiq->pending);
	INIT_LIST_HEAD(&fiq->interrupts);
	fiq->forget_list_tail = &fiq->forget_list_head;
	fiq->connected = 1;
	fiq->ops = ops;
	fiq->priv = priv;
}

void ds_fuse_conn_init(struct fuse_conn *fc, struct fuse_mount *fm,
		    struct user_namespace *user_ns,
		    const struct fuse_iqueue_ops *fiq_ops, void *fiq_priv)
{
	memset(fc, 0, sizeof(*fc));
	spin_lock_init(&fc->lock);
	spin_lock_init(&fc->bg_lock);
	spin_lock_init(&fc->passthrough_req_lock);
	init_rwsem(&fc->killsb);
	refcount_set(&fc->count, 1);
	atomic_set(&fc->dev_count, 1);
	init_waitqueue_head(&fc->blocked_waitq);
	fuse_iqueue_init(&fc->iq, fiq_ops, fiq_priv);
	INIT_LIST_HEAD(&fc->bg_queue);
	INIT_LIST_HEAD(&fc->entry);
	INIT_LIST_HEAD(&fc->devices);
	idr_init(&fc->passthrough_req);
	atomic_set(&fc->num_waiting, 0);
	fc->max_background = FUSE_DEFAULT_MAX_BACKGROUND;
	fc->congestion_threshold = FUSE_DEFAULT_CONGESTION_THRESHOLD;
	atomic64_set(&fc->khctr, 0);
	fc->polled_files = RB_ROOT;
	fc->blocked = 0;
	fc->initialized = 0;
	fc->connected = 1;
	atomic64_set(&fc->attr_version, 1);
	get_random_bytes(&fc->scramble_key, sizeof(fc->scramble_key));
	fc->pid_ns = get_pid_ns(task_active_pid_ns(current));
#ifdef DS_USERNS_LIVE
	/*
	 * Built without USER_NS, the native callers' user_ns argument is dead
	 * and may not be passed at all; never read it. fuse_conn_init() runs
	 * in the mounting (or /dev/cuse opening) task, so take the owner from
	 * its credentials instead. That is the namespace live-mount.c gives
	 * the fs_context and super_block (fs_context_owner lists fuse), so
	 * fc->user_ns matches sb->s_user_ns as upstream. A non-initial
	 * current_user_ns() can only be a namespace this module created; for
	 * everything else (Android's /storage) the owner stays init_user_ns
	 * and get_user_ns() takes no reference. ds_fuse_delayed_release drops
	 * the reference.
	 */
	(void)user_ns;
	fc->user_ns = get_user_ns(current_user_ns());
#else
	fc->user_ns = get_user_ns(user_ns);
#endif
	fc->max_pages = FUSE_DEFAULT_MAX_PAGES_PER_REQ;
	fc->max_pages_limit = FUSE_MAX_MAX_PAGES;

	INIT_LIST_HEAD(&fc->mounts);
	list_add(&fm->fc_entry, &fc->mounts);
	fm->fc = fc;
}

/*
 * The 6.6 compiler inlines fuse_conn_put() into fuse_dev_free() and
 * fuse_mount_destroy(). All final releases still use this RCU callback.
 * Drop our namespace reference here, after the last connection reference,
 * so both out-of-line and inlined native paths release it exactly once.
 * Pre-activation connections belong to init_pid_ns, whose put is a no-op.
 */
void ds_fuse_delayed_release(struct rcu_head *p)
{
	struct fuse_conn *fc = container_of(p, struct fuse_conn, rcu);

	put_pid_ns(fc->pid_ns);
	put_user_ns(fc->user_ns);
	fc->release(fc);
}

#ifdef DS_USERNS_LIVE
#include "core.h"

static bool *ds_fuse_sys_admin_access;

/* Optional: without the symbol, behave as with the parameter off (default). */
void ds_fuse_prepare(void)
{
	ds_fuse_sys_admin_access = (bool *)kallsyms_name_to_addr("allow_sys_admin_access");
}

/*
 * Replaces the native fuse_allow_current_process(), vendor fs/fuse/dir.c.
 * Built without USER_NS, its current_in_userns() is constant true, so an
 * allow_other mount owned by a child namespace would admit every task.
 * Upstream admits only tasks inside the connection's user namespace; for
 * init-owned connections that is everyone, as natively.
 */
int ds_fuse_allow_current_process(struct fuse_conn *fc)
{
	const struct cred *cred;

	if (ds_fuse_sys_admin_access && READ_ONCE(*ds_fuse_sys_admin_access) &&
	    capable(CAP_SYS_ADMIN))
		return 1;

	if (fc->allow_other)
		return current_in_userns(fc->user_ns);

	cred = current_cred();
	if (uid_eq(cred->euid, fc->user_id) &&
	    uid_eq(cred->suid, fc->user_id) &&
	    uid_eq(cred->uid,  fc->user_id) &&
	    gid_eq(cred->egid, fc->group_id) &&
	    gid_eq(cred->sgid, fc->group_id) &&
	    gid_eq(cred->gid,  fc->group_id))
		return 1;

	return 0;
}
#endif
