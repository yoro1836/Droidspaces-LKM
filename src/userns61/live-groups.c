// SPDX-License-Identifier: GPL-2.0-only
/*
 * getgroups/setgroups from the Samsung S5E9945 vendor kernel/groups.c (6.1),
 * compiled with CONFIG_USER_NS so group ids are mapped through the caller's
 * user namespace. set_current_groups() stays the vendor's (KDP-sealed creds).
 */
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include "userns61.h"

static int groups_to_user(gid_t __user *grouplist,
			  const struct group_info *group_info)
{
	struct user_namespace *user_ns = current_user_ns();
	int i;
	unsigned int count = group_info->ngroups;

	for (i = 0; i < count; i++) {
		gid_t gid;
		gid = from_kgid_munged(user_ns, group_info->gid[i]);
		if (put_user(gid, grouplist+i))
			return -EFAULT;
	}
	return 0;
}

static int groups_from_user(struct group_info *group_info,
    gid_t __user *grouplist)
{
	struct user_namespace *user_ns = current_user_ns();
	int i;
	unsigned int count = group_info->ngroups;

	for (i = 0; i < count; i++) {
		gid_t gid;
		kgid_t kgid;
		if (get_user(gid, grouplist+i))
			return -EFAULT;

		kgid = make_kgid(user_ns, gid);
		if (!gid_valid(kgid))
			return -EINVAL;

		group_info->gid[i] = kgid;
	}
	return 0;
}

SYSCALL_DEFINE2(ds_getgroups, int, gidsetsize, gid_t __user *, grouplist)
{
	const struct cred *cred = current_cred();
	int i;

	if (gidsetsize < 0)
		return -EINVAL;

	/* no need to grab task_lock here; it cannot change */
	i = cred->group_info->ngroups;
	if (gidsetsize) {
		if (i > gidsetsize) {
			i = -EINVAL;
			goto out;
		}
		if (groups_to_user(grouplist, cred->group_info)) {
			i = -EFAULT;
			goto out;
		}
	}
out:
	return i;
}

/*
 * Replaces the native may_setgroups(). The native compat setgroups16 path
 * still converts ids without a user namespace, so a compat task inside a
 * noninitial user namespace may not set groups at all.
 */
bool ds_identity_may_setgroups(void)
{
	struct user_namespace *user_ns = current_user_ns();

	if (in_compat_syscall() && user_ns != &init_user_ns)
		return false;
	return ns_capable_setid(user_ns, CAP_SETGID) &&
		userns_may_setgroups(user_ns);
}

SYSCALL_DEFINE2(ds_setgroups, int, gidsetsize, gid_t __user *, grouplist)
{
	struct group_info *group_info;
	int retval;

	if (!ds_identity_may_setgroups())
		return -EPERM;
	if ((unsigned)gidsetsize > NGROUPS_MAX)
		return -EINVAL;

	group_info = groups_alloc(gidsetsize);
	if (!group_info)
		return -ENOMEM;
	retval = groups_from_user(group_info, grouplist);
	if (retval) {
		put_group_info(group_info);
		return retval;
	}

	groups_sort(group_info);
	retval = set_current_groups(group_info);
	put_group_info(group_info);

	return retval;
}
