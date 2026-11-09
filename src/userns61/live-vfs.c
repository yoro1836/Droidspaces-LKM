// SPDX-License-Identifier: GPL-2.0-only
/*
 * Inode capability and ownership checks from the Samsung S5E9945 vendor
 * kernel/capability.c, fs/inode.c and fs/open.c (6.1), compiled with
 * CONFIG_USER_NS. Natively current_user_ns() is init_user_ns and
 * kuid_has_mapping() is always true, so namespace root could not act even on
 * files it owns; these copies check capabilities in the caller's namespace
 * and only over inodes whose owner and group are mapped there.
 * access_override_creds() keeps the vendor's prepare_creds/override_creds
 * (KDP) and is compiled from the vendor headers.
 */
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/mnt_idmapping.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/securebits.h>
#include <linux/user_namespace.h>
#include "userns61.h"

bool ds_privileged_wrt_inode_uidgid(struct user_namespace *ns,
				 struct user_namespace *mnt_userns,
				 const struct inode *inode)
{
	return kuid_has_mapping(ns, i_uid_into_mnt(mnt_userns, inode)) &&
	       kgid_has_mapping(ns, i_gid_into_mnt(mnt_userns, inode));
}

bool ds_capable_wrt_inode_uidgid(struct user_namespace *mnt_userns,
			      const struct inode *inode, int cap)
{
	struct user_namespace *ns = current_user_ns();

	return ns_capable(ns, cap) &&
	       ds_privileged_wrt_inode_uidgid(ns, mnt_userns, inode);
}

bool ds_inode_owner_or_capable(struct user_namespace *mnt_userns,
			    const struct inode *inode)
{
	kuid_t i_uid;
	struct user_namespace *ns;

	i_uid = i_uid_into_mnt(mnt_userns, inode);
	if (uid_eq(current_fsuid(), i_uid))
		return true;

	ns = current_user_ns();
	if (kuid_has_mapping(ns, i_uid) && ns_capable(ns, CAP_FOWNER))
		return true;
	return false;
}

static inline bool setattr_vfsuid(struct iattr *attr, kuid_t kuid)
{
	if (!uid_valid(kuid))
		return false;
	attr->ia_valid |= ATTR_UID;
	attr->ia_vfsuid = VFSUIDT_INIT(kuid);
	return true;
}

static inline bool setattr_vfsgid(struct iattr *attr, kgid_t kgid)
{
	if (!gid_valid(kgid))
		return false;
	attr->ia_valid |= ATTR_GID;
	attr->ia_vfsgid = VFSGIDT_INIT(kgid);
	return true;
}

int ds_chown_common(const struct path *path, uid_t user, gid_t group)
{
	struct user_namespace *mnt_userns, *fs_userns;
	struct inode *inode = path->dentry->d_inode;
	struct inode *delegated_inode = NULL;
	int error;
	struct iattr newattrs;
	kuid_t uid;
	kgid_t gid;

	uid = make_kuid(current_user_ns(), user);
	gid = make_kgid(current_user_ns(), group);

	mnt_userns = mnt_user_ns(path->mnt);
	fs_userns = i_user_ns(inode);

retry_deleg:
	newattrs.ia_vfsuid = INVALID_VFSUID;
	newattrs.ia_vfsgid = INVALID_VFSGID;
	newattrs.ia_valid =  ATTR_CTIME;
	if ((user != (uid_t)-1) && !setattr_vfsuid(&newattrs, uid))
		return -EINVAL;
	if ((group != (gid_t)-1) && !setattr_vfsgid(&newattrs, gid))
		return -EINVAL;
	inode_lock(inode);
	if (!S_ISDIR(inode->i_mode))
		newattrs.ia_valid |= ATTR_KILL_SUID | ATTR_KILL_PRIV |
				     setattr_should_drop_sgid(mnt_userns, inode);
	/* Continue to send actual fs values, not the mount values. */
	error = security_path_chown(
		path,
		from_vfsuid(mnt_userns, fs_userns, newattrs.ia_vfsuid),
		from_vfsgid(mnt_userns, fs_userns, newattrs.ia_vfsgid));
	if (!error)
		error = notify_change(mnt_userns, path->dentry, &newattrs,
				      &delegated_inode);
	inode_unlock(inode);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	return error;
}

static const struct cred *access_override_creds(void)
{
	const struct cred *old_cred;
	struct cred *override_cred;

	override_cred = prepare_creds();
	if (!override_cred)
		return NULL;

	override_cred->fsuid = override_cred->uid;
	override_cred->fsgid = override_cred->gid;

	if (!issecure(SECURE_NO_SETUID_FIXUP)) {
		/* Clear the capabilities if we switch to a non-root user */
		kuid_t root_uid = make_kuid(override_cred->user_ns, 0);
		if (!uid_eq(override_cred->uid, root_uid))
			cap_clear(override_cred->cap_effective);
		else
			override_cred->cap_effective =
				override_cred->cap_permitted;
	}

	/*
	 * The new set of credentials can *only* be used in
	 * task-synchronous circumstances, and does not need
	 * RCU freeing, unless somebody then takes a separate
	 * reference to it.
	 *
	 * NOTE! This is _only_ true because this credential
	 * is used purely for override_creds() that installs
	 * it as the subjective cred. Other threads will be
	 * accessing ->real_cred, not the subjective cred.
	 *
	 * If somebody _does_ make a copy of this (using the
	 * 'get_current_cred()' function), that will clear the
	 * non_rcu field, because now that other user may be
	 * expecting RCU freeing. But normal thread-synchronous
	 * cred accesses will keep things non-RCY.
	 */
	override_cred->non_rcu = 1;

	old_cred = override_creds(override_cred);

	/* override_cred() gets its own ref */
	put_cred(override_cred);

	return old_cred;
}

long ds_do_faccessat(int dfd, const char __user *filename, int mode, int flags)
{
	struct path path;
	struct inode *inode;
	int res;
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	const struct cred *old_cred = NULL;

	if (mode & ~S_IRWXO)	/* where's F_OK, X_OK, W_OK, R_OK? */
		return -EINVAL;

	if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
		return -EINVAL;

	if (flags & AT_SYMLINK_NOFOLLOW)
		lookup_flags &= ~LOOKUP_FOLLOW;
	if (flags & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;

	if (!(flags & AT_EACCESS)) {
		old_cred = access_override_creds();
		if (!old_cred)
			return -ENOMEM;
	}

retry:
	res = user_path_at(dfd, filename, lookup_flags, &path);
	if (res)
		goto out;

	inode = d_backing_inode(path.dentry);

	if ((mode & MAY_EXEC) && S_ISREG(inode->i_mode)) {
		/*
		 * MAY_EXEC on regular files is denied if the fs is mounted
		 * with the "noexec" flag.
		 */
		res = -EACCES;
		if (path_noexec(&path))
			goto out_path_release;
	}

	res = inode_permission(mnt_user_ns(path.mnt), inode, mode | MAY_ACCESS);
	/* SuS v2 requires we report a read only fs too */
	if (res || !(mode & S_IWOTH) || special_file(inode->i_mode))
		goto out_path_release;
	/*
	 * This is a rare case where using __mnt_is_readonly()
	 * is OK without a mnt_want/drop_write() pair.  Since
	 * no actual write to the fs is performed here, we do
	 * not need to telegraph to that to anyone.
	 *
	 * By doing this, we accept that this access is
	 * inherently racy and know that the fs may change
	 * state before we even see this result.
	 */
	if (__mnt_is_readonly(path.mnt))
		res = -EROFS;

out_path_release:
	path_put(&path);
	if (retry_estale(res, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	if (old_cred)
		revert_creds(old_cred);

	return res;
}
