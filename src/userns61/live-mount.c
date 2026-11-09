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
 * fs_context owners are rewritten only for filesystems whose user namespace
 * semantics need nothing else from this port: tmpfs, ramfs, devpts, sysfs.
 * proc sets its own owner in this module's proc_init_fs_context. Everything
 * else, including FUSE and overlayfs, keeps init_user_ns and stays
 * unmountable from a child user namespace.
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
#include "mount.h"
#include "userns61.h"

static bool mount_live;

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

static bool owner_follows_namespace(const struct file_system_type *type)
{
	static const char *const names[] = { "tmpfs", "ramfs", "devpts", "sysfs" };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(names); i++)
		if (!strcmp(type->name, names[i]))
			return true;
	return false;
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
	struct user_namespace *ns = NULL;

	if (!READ_ONCE(mount_live) || IS_ERR_OR_NULL(fc) || fc->user_ns != &init_user_ns ||
	    !owner_follows_namespace(fc->fs_type))
		return 0;
	if (fc->purpose == FS_CONTEXT_FOR_MOUNT)
		ns = child_userns(fc->cred->user_ns);
	else if (fc->purpose == FS_CONTEXT_FOR_RECONFIGURE && fc->root)
		ns = child_userns(fc->root->d_sb->s_user_ns);
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

static struct kretprobe *const mount_probes[] = {
	&copy_mnt_ns_probe, &fs_context_mount_probe,
	&fs_context_reconfigure_probe, &sget_fc_probe,
};

int ds_userns_mount_register(void)
{
	int ret = register_kretprobes((struct kretprobe **)mount_probes, ARRAY_SIZE(mount_probes));

	if (ret) {
		pr_warn("userns: mount ownership probes unavailable (%d); mounts stay limited to init_user_ns\n", ret);
		return ret;
	}
	WRITE_ONCE(mount_live, true);
	pr_info("userns: mount namespace, fs_context and super_block owners follow user namespaces\n");
	return 0;
}
