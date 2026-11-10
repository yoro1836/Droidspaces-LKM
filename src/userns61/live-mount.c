// SPDX-License-Identifier: GPL-2.0-only
/*
 * Mount ownership for user namespaces on a kernel built without USER_NS.
 *
 * Natively get_user_ns() ignores its argument and returns init_user_ns, so
 * every mount namespace, fs_context and super_block records init_user_ns as
 * its owner and may_mount()/mount_capable() demand capabilities there. The
 * vendor allocators are left untouched; kretprobes on functions whose
 * arguments are reliable rewrite the owner of freshly created objects and
 * take a module reference:
 *
 *   copy_mnt_ns  (called by this module's create_new_namespaces)
 *   fs_context_for_mount / fs_context_for_reconfigure, sget_fc  (exported)
 *
 * Static helpers such as alloc_mnt_ns or alloc_super are not used: in this
 * build their user_ns argument is dead and may not be passed at all.
 *
 * Destructors stay native, and native put_user_ns() is a no-op, so these
 * references are never dropped; with DS_USERNS_PIN namespaces live until
 * reboot anyway (stage 2 replaces both). Objects created before activation,
 * and anything owned by init_user_ns, are never touched.
 *
 * fs_context owners are rewritten, as upstream, only for tmpfs, ramfs,
 * devpts and fuse (creator's namespace), sysfs (network namespace owner),
 * mqueue (IPC namespace owner) and cgroup2 (cgroup namespace owner). proc
 * sets its own owner in this module's proc_init_fs_context; fuse connections
 * take the same owner in port61/fuse.c (ds_fuse_conn_init), and
 * ds_fuse_allow_current_process confines allow_other to that namespace.
 * FUSE request and attribute ids are still converted by native code, where
 * from_kuid/make_kuid are identity. Everything else, including fuseblk and
 * overlayfs, keeps init_user_ns and stays unmountable from a child user
 * namespace. New UTS, cgroup and time namespaces get their creator's
 * user namespace as owner; network namespaces already do natively
 * (setup_net assigns net->user_ns directly).
 */
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/kprobes.h>
#include <linux/proc_ns.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/cred.h>
#include <linux/cgroup.h>
#include <linux/ipc_namespace.h>
#include <linux/nsproxy.h>
#include <linux/time_namespace.h>
#include <linux/utsname.h>
#include <net/net_namespace.h>
#include "mount.h"
#include "userns61.h"

static bool mount_live;
#ifdef DS_USERNS_FUSE
extern bool ds_fuse_guard_live;
#endif

/* A non-initial user namespace created by this module, or NULL. */
static struct user_namespace *child_userns(struct user_namespace *ns)
{
	const struct proc_ns_operations *ops;

	if (!ns || ns == &init_user_ns ||
	    copy_from_kernel_nofault(&ops, &ns->ns.ops, sizeof(ops)) ||
	    ops != &userns_operations)
		return NULL;
	return ns;
}

/*
 * The owner a new fs_context of this type gets upstream, read from the
 * namespace that the filesystem's init_fs_context consulted (natively each
 * stored init_user_ns through the no-op get_user_ns). NULL: leave it.
 */
static struct user_namespace *fs_context_owner(const struct fs_context *fc)
{
	const char *name = fc->fs_type->name;
	struct nsproxy *nsp = current->nsproxy;

	if (fc->purpose == FS_CONTEXT_FOR_RECONFIGURE)
		return fc->root ? child_userns(fc->root->d_sb->s_user_ns) : NULL;
	if (fc->purpose != FS_CONTEXT_FOR_MOUNT || !nsp)
		return NULL;
	if (!strcmp(name, "tmpfs") || !strcmp(name, "ramfs") || !strcmp(name, "devpts"))
		return child_userns(fc->cred->user_ns);
#ifdef DS_USERNS_FUSE
	/* Refused unless the passthrough guard (live-fuse.c) is armed. */
	if (!strcmp(name, "fuse"))
		return READ_ONCE(ds_fuse_guard_live) ? child_userns(fc->cred->user_ns) : NULL;
#endif
	if (!strcmp(name, "sysfs"))
		return child_userns(nsp->net_ns->user_ns);
	if (!strcmp(name, "mqueue"))
		return child_userns(nsp->ipc_ns->user_ns);
	if (!strcmp(name, "cgroup2"))
		return child_userns(nsp->cgroup_ns->user_ns);
	return NULL;
}

/* copy_mnt_ns(flags, ns, user_ns, new_fs) */
struct copy_mnt_ns_args {
	unsigned long flags;
	struct user_namespace *user_ns;
};

static int copy_mnt_ns_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct copy_mnt_ns_args *a = (void *)ri->data;

	a->flags = regs->regs[0];
	a->user_ns = (struct user_namespace *)regs->regs[2];
	return 0;
}

static int copy_mnt_ns_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct copy_mnt_ns_args *a = (void *)ri->data;
	struct mnt_namespace *new_ns = (void *)regs_return_value(regs);
	struct user_namespace *ns;

	if (!READ_ONCE(mount_live) || !(a->flags & CLONE_NEWNS) || IS_ERR_OR_NULL(new_ns))
		return 0;
	ns = child_userns(a->user_ns);
	if (ns && new_ns->user_ns == &init_user_ns)
		new_ns->user_ns = get_user_ns(ns);
	return 0;
}

static struct kretprobe copy_mnt_ns_probe = {
	.kp.symbol_name = "copy_mnt_ns",
	.entry_handler = copy_mnt_ns_entry,
	.handler = copy_mnt_ns_return,
	.data_size = sizeof(struct copy_mnt_ns_args),
	.maxactive = 32,
};

/* fs_context_for_mount / fs_context_for_reconfigure: fix the returned context. */
static int fs_context_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct fs_context *fc = (void *)regs_return_value(regs);
	struct user_namespace *ns;

	if (!READ_ONCE(mount_live) || IS_ERR_OR_NULL(fc) || fc->user_ns != &init_user_ns)
		return 0;
	ns = fs_context_owner(fc);
	if (ns)
		fc->user_ns = get_user_ns(ns);
	return 0;
}

static struct kretprobe fs_context_mount_probe = {
	.kp.symbol_name = "fs_context_for_mount",
	.handler = fs_context_return,
	.maxactive = 32,
};

static struct kretprobe fs_context_reconfigure_probe = {
	.kp.symbol_name = "fs_context_for_reconfigure",
	.handler = fs_context_return,
	.maxactive = 32,
};

/* sget_fc(fc, test, set): a new super_block takes the context's owner. */
static int sget_fc_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	*(struct fs_context **)ri->data = (struct fs_context *)regs->regs[0];
	return 0;
}

static int sget_fc_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct fs_context *fc = *(struct fs_context **)ri->data;
	struct super_block *s = (void *)regs_return_value(regs);
	struct user_namespace *ns;

	if (!READ_ONCE(mount_live) || IS_ERR_OR_NULL(s) || fc->global)
		return 0;
	ns = child_userns(fc->user_ns);
	/*
	 * mq_create_mount() makes each IPC namespace's internal mqueue
	 * super_block and sets fc->user_ns after fs_context_for_mount()
	 * returns, through the no-op native get_user_ns(). Take the owner
	 * from the IPC namespace (fc->s_fs_info for mqueue) as upstream
	 * does, or a later mount inside the namespace finds a mismatching
	 * owner and fails with EBUSY.
	 */
	if (!ns && fc->s_fs_info && !strcmp(fc->fs_type->name, "mqueue"))
		ns = child_userns(((struct ipc_namespace *)fc->s_fs_info)->user_ns);
	/*
	 * An existing super_block is only returned when its owner already
	 * equals fc->user_ns; a new one still carries init_user_ns. Apply
	 * what alloc_super() does for a non-initial owner.
	 */
	if (ns && s->s_user_ns == &init_user_ns) {
		s->s_user_ns = get_user_ns(ns);
		s->s_iflags |= SB_I_NODEV;
	}
	return 0;
}

static struct kretprobe sget_fc_probe = {
	.kp.symbol_name = "sget_fc",
	.entry_handler = sget_fc_entry,
	.handler = sget_fc_return,
	.data_size = sizeof(struct fs_context *),
	.maxactive = 32,
};

/*
 * copy_utsname / copy_cgroup_ns / copy_time_ns (flags, user_ns, old_ns),
 * called by this module's create_new_namespaces: a new namespace takes the
 * creating user namespace as owner (hostname, cgroup and time changes are
 * checked against it).
 */
struct copy_ns_args {
	unsigned long flags;
	struct user_namespace *user_ns;
};

static int copy_ns_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct copy_ns_args *a = (void *)ri->data;

	a->flags = regs->regs[0];
	a->user_ns = (struct user_namespace *)regs->regs[1];
	return 0;
}

#define NS_OWNER_RETURN(fn, type, flag)						\
static int fn##_return(struct kretprobe_instance *ri, struct pt_regs *regs)	\
{										\
	struct copy_ns_args *a = (void *)ri->data;				\
	type *new_ns = (void *)regs_return_value(regs);				\
	struct user_namespace *ns;						\
										\
	if (!READ_ONCE(mount_live) || !(a->flags & (flag)) || IS_ERR_OR_NULL(new_ns)) \
		return 0;							\
	ns = child_userns(a->user_ns);						\
	if (ns && new_ns->user_ns == &init_user_ns)				\
		new_ns->user_ns = get_user_ns(ns);				\
	return 0;								\
}										\
static struct kretprobe fn##_probe = {						\
	.kp.symbol_name = #fn,							\
	.entry_handler = copy_ns_entry,						\
	.handler = fn##_return,							\
	.data_size = sizeof(struct copy_ns_args),				\
	.maxactive = 32,							\
}

NS_OWNER_RETURN(copy_utsname, struct uts_namespace, CLONE_NEWUTS);
NS_OWNER_RETURN(copy_cgroup_ns, struct cgroup_namespace, CLONE_NEWCGROUP);
NS_OWNER_RETURN(copy_time_ns, struct time_namespace, CLONE_NEWTIME);

#ifdef DS_USERNS_FUSE
extern struct kretprobe ds_fuse_get_req_probe;
extern struct kretprobe ds_fuse_do_getattr_probe;
int ds_fuse_register_init_guard(void);
#endif

static struct kretprobe *const mount_probes[] = {
	&copy_mnt_ns_probe, &fs_context_mount_probe,
	&fs_context_reconfigure_probe, &sget_fc_probe,
	&copy_utsname_probe, &copy_cgroup_ns_probe, &copy_time_ns_probe,
#ifdef DS_USERNS_FUSE
	&ds_fuse_get_req_probe, &ds_fuse_do_getattr_probe,
#endif
};

int ds_userns_mount_register(void)
{
	unsigned int i, ok = 0;

	/* Each probe is independent: a missing symbol only loses its own fix. */
	for (i = 0; i < ARRAY_SIZE(mount_probes); i++) {
		int ret = register_kretprobe(mount_probes[i]);

		if (ret)
			pr_warn("userns: %s owner probe unavailable (%d)\n",
				mount_probes[i]->kp.symbol_name, ret);
		else
			ok++;
	}
	if (!ok)
		return -ENOENT;
#ifdef DS_USERNS_FUSE
	{
		int ret = ds_fuse_register_init_guard();

		if (ret)
			pr_warn("userns: FUSE passthrough guard unavailable (%d)\n", ret);
	}
#endif
#ifdef DS_USERNS_IDENT
	{
		int ret = ds_sock_creds_register();

		if (ret)
			pr_warn("userns: SCM_CREDENTIALS mapping unavailable (%d)\n", ret);
		ret = ds_seccomp_register();
		if (ret)
			pr_warn("userns: seccomp namespace capability check unavailable (%d)\n", ret);
	}
#endif
	WRITE_ONCE(mount_live, true);
	pr_info("userns: %u/%zu namespace and mount owner probes active\n",
		ok, ARRAY_SIZE(mount_probes));
	return 0;
}
