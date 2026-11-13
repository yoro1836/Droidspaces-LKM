// SPDX-License-Identifier: GPL-2.0-only
/*
 * Two more places where ids cross the user boundary untranslated on a kernel
 * built without USER_NS: POSIX ACL xattrs and /proc/<pid>/loginuid.
 *
 * do_getxattr() (fs/xattr.c), proc_loginuid_read() and
 * proc_loginuid_write() (fs/proc/base.c) are carried over from
 * android14-6.1 unchanged. The ACL fix-ups they call compile to nothing in
 * that kernel (include/linux/posix_acl_xattr.h), so those come along from
 * fs/posix_acl.c too. Without them setfacl -m u:1000 in a container names
 * host uid 1000, and pam_loginuid records a host uid for the session.
 */
#include <linux/audit.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/posix_acl_xattr.h>
#include <linux/proc_fs.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/xattr.h>
#include "fs/internal.h"
#include "fs/proc/internal.h"
#include "userns61.h"

static inline bool is_posix_acl_xattr(const char *name)
{
	return (strcmp(name, XATTR_NAME_POSIX_ACL_ACCESS) == 0) ||
	       (strcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT) == 0);
}

static int acl_xattr_entries(const void *value, size_t size)
{
	const struct posix_acl_xattr_header *header = value;
	int count;

	if (!header)
		return -EINVAL;
	if (size < sizeof(struct posix_acl_xattr_header))
		return -EINVAL;
	if (header->a_version != cpu_to_le32(POSIX_ACL_XATTR_VERSION))
		return -EOPNOTSUPP;

	count = posix_acl_xattr_count(size);
	if (count < 0)
		return -EINVAL;
	return count;
}

static void acl_xattr_between(struct user_namespace *to, struct user_namespace *from,
			      void *value, size_t size)
{
	struct posix_acl_xattr_header *header = value;
	struct posix_acl_xattr_entry *entry = (void *)(header + 1), *end;
	int count;
	kuid_t uid;
	kgid_t gid;

	if (to == from)
		return;
	count = acl_xattr_entries(value, size);
	if (count <= 0)
		return;

	for (end = entry + count; entry != end; entry++) {
		switch (le16_to_cpu(entry->e_tag)) {
		case ACL_USER:
			uid = make_kuid(from, le32_to_cpu(entry->e_id));
			entry->e_id = cpu_to_le32(from_kuid(to, uid));
			break;
		case ACL_GROUP:
			gid = make_kgid(from, le32_to_cpu(entry->e_id));
			entry->e_id = cpu_to_le32(from_kgid(to, gid));
			break;
		default:
			break;
		}
	}
}

/*
 * Writes are caught at vfs_setxattr(), not at do_setxattr() as upstream
 * does: the compiler folds do_setxattr() into the setxattr syscalls, and a
 * patched copy of it is never reached. Every other caller that passes an
 * ACL is a kernel thread (nfsd, ksmbd) or runs on the filesystem mounter's
 * credentials (overlayfs), so the namespace test leaves those alone. The
 * syscall's value is its own kvmalloc() copy and may be edited in place.
 */
static int vfs_setxattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	const char *name = (const char *)regs->regs[2];
	void *value = (void *)regs->regs[3];
	size_t size = regs->regs[4];
	struct user_namespace *ns = current_user_ns();

	if (ns != &init_user_ns && !(current->flags & PF_KTHREAD) &&
	    value && size && is_posix_acl_xattr(name))
		acl_xattr_between(&init_user_ns, ns, value, size);
	return 1;	/* nothing to do on return */
}

struct kretprobe ds_acl_setxattr_probe = {
	.kp.symbol_name = "vfs_setxattr",
	.entry_handler = vfs_setxattr_entry,
	.maxactive = 32,
};

ssize_t ds_do_getxattr(struct user_namespace *mnt_userns, struct dentry *d,
		       struct xattr_ctx *ctx)
{
	ssize_t error;
	char *kname = ctx->kname->name;

	if (ctx->size) {
		if (ctx->size > XATTR_SIZE_MAX)
			ctx->size = XATTR_SIZE_MAX;
		ctx->kvalue = kvzalloc(ctx->size, GFP_KERNEL);
		if (!ctx->kvalue)
			return -ENOMEM;
	}

	error = vfs_getxattr(mnt_userns, d, kname, ctx->kvalue, ctx->size);
	if (error > 0) {
		if (is_posix_acl_xattr(kname))
			acl_xattr_between(current_user_ns(), &init_user_ns, ctx->kvalue, error);
		if (ctx->size && copy_to_user(ctx->value, ctx->kvalue, error))
			error = -EFAULT;
	} else if (error == -ERANGE && ctx->size >= XATTR_SIZE_MAX) {
		/* The file system tried to returned a value bigger
		   than XATTR_SIZE_MAX bytes. Not possible. */
		error = -E2BIG;
	}

	return error;
}

#define TMPBUFLEN 11
ssize_t ds_proc_loginuid_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	struct task_struct *task = get_proc_task(inode);
	ssize_t length;
	char tmpbuf[TMPBUFLEN];

	if (!task)
		return -ESRCH;
	length = scnprintf(tmpbuf, TMPBUFLEN, "%u",
			   from_kuid(file->f_cred->user_ns,
				     audit_get_loginuid(task)));
	put_task_struct(task);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

ssize_t ds_proc_loginuid_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	uid_t loginuid;
	kuid_t kloginuid;
	int rv;

	/* Don't let kthreads write their own loginuid */
	if (current->flags & PF_KTHREAD)
		return -EPERM;

	rcu_read_lock();
	if (current != pid_task(proc_pid(inode), PIDTYPE_PID)) {
		rcu_read_unlock();
		return -EPERM;
	}
	rcu_read_unlock();

	if (*ppos != 0) {
		/* No partial writes. */
		return -EINVAL;
	}

	rv = kstrtou32_from_user(buf, count, 10, &loginuid);
	if (rv < 0)
		return rv;

	/* is userspace tring to explicitly UNSET the loginuid? */
	if (loginuid == AUDIT_UID_UNSET) {
		kloginuid = INVALID_UID;
	} else {
		kloginuid = make_kuid(file->f_cred->user_ns, loginuid);
		if (!uid_valid(kloginuid))
			return -EINVAL;
	}

	rv = audit_set_loginuid(kloginuid);
	if (rv < 0)
		return rv;
	return count;
}
