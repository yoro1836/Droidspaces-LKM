// SPDX-License-Identifier: GPL-2.0-only
/*
 * Capability transitions from the Samsung S5E9945 vendor security/commoncap.c
 * (6.1), compiled with CONFIG_USER_NS: cap_task_fix_setuid() and
 * cap_bprm_creds_from_file() with their helpers. Both only edit the prepared,
 * not yet committed cred they are handed, so Samsung KDP is not involved.
 */
#include <linux/audit.h>
#include <linux/binfmts.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mnt_idmapping.h>
#include <linux/mount.h>
#include <linux/personality.h>
#include <linux/sched.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/user_namespace.h>
#include <linux/xattr.h>
#include "userns61.h"

/*
 * The vendor's bprm_fill_uid(), inlined into begin_new_exec(), ran with
 * kuid_has_mapping()/kgid_has_mapping() compiled as always true. Upstream
 * ignores set-id bits unless both the owner and the group are mapped in the
 * new credentials' user namespace; restore that by undoing the ids it set.
 * This hook runs right after it, on the prepared exec cred.
 */
static void ds_fix_bprm_setid(struct linux_binprm *bprm, struct file *file)
{
	struct cred *new = bprm->cred;
	const struct cred *old = current_cred();
	struct inode *inode = file_inode(file);
	struct user_namespace *mnt_userns = file_mnt_user_ns(file);
	umode_t mode;
	kuid_t uid;
	kgid_t gid;

	if (new->user_ns == &init_user_ns)
		return;
	inode_lock(inode);
	mode = inode->i_mode;
	uid = i_uid_into_mnt(mnt_userns, inode);
	gid = i_gid_into_mnt(mnt_userns, inode);
	inode_unlock(inode);
	if (!(mode & (S_ISUID | S_ISGID)))
		return;
	if (kuid_has_mapping(new->user_ns, uid) && kgid_has_mapping(new->user_ns, gid))
		return;
	new->euid = old->euid;
	new->egid = old->egid;
}

static void warn_setuid_and_fcaps_mixed(const char *fname)
{
	static int warned;
	if (!warned) {
		printk(KERN_INFO "warning: `%s' has both setuid-root and"
			" effective capabilities. Therefore not raising all"
			" capabilities.\n", fname);
		warned = 1;
	}
}

static inline int bprm_caps_from_vfs_caps(struct cpu_vfs_cap_data *caps,
					  struct linux_binprm *bprm,
					  bool *effective,
					  bool *has_fcap)
{
	struct cred *new = bprm->cred;
	unsigned i;
	int ret = 0;

	if (caps->magic_etc & VFS_CAP_FLAGS_EFFECTIVE)
		*effective = true;

	if (caps->magic_etc & VFS_CAP_REVISION_MASK)
		*has_fcap = true;

	CAP_FOR_EACH_U32(i) {
		__u32 permitted = caps->permitted.cap[i];
		__u32 inheritable = caps->inheritable.cap[i];

		/*
		 * pP' = (X & fP) | (pI & fI)
		 * The addition of pA' is handled later.
		 */
		new->cap_permitted.cap[i] =
			(new->cap_bset.cap[i] & permitted) |
			(new->cap_inheritable.cap[i] & inheritable);

		if (permitted & ~new->cap_permitted.cap[i])
			/* insufficient to execute correctly */
			ret = -EPERM;
	}

	/*
	 * For legacy apps, with no internal support for recognizing they
	 * do not have enough capabilities, we return an error if they are
	 * missing some "forced" (aka file-permitted) capabilities.
	 */
	return *effective ? ret : 0;
}

static int get_file_caps(struct linux_binprm *bprm, struct file *file,
			 bool *effective, bool *has_fcap)
{
	int rc = 0;
	struct cpu_vfs_cap_data vcaps;

	cap_clear(bprm->cred->cap_permitted);

	if (!file_caps_enabled)
		return 0;

	if (!mnt_may_suid(file->f_path.mnt))
		return 0;

	/*
	 * This check is redundant with mnt_may_suid() but is kept to make
	 * explicit that capability bits are limited to s_user_ns and its
	 * descendants.
	 */
	if (!current_in_userns(file->f_path.mnt->mnt_sb->s_user_ns))
		return 0;

	rc = get_vfs_caps_from_disk(file_mnt_user_ns(file),
				    file->f_path.dentry, &vcaps);
	if (rc < 0) {
		if (rc == -EINVAL)
			printk(KERN_NOTICE "Invalid argument reading file caps for %s\n",
					bprm->filename);
		else if (rc == -ENODATA)
			rc = 0;
		goto out;
	}

	rc = bprm_caps_from_vfs_caps(&vcaps, bprm, effective, has_fcap);

out:
	if (rc)
		cap_clear(bprm->cred->cap_permitted);

	return rc;
}

static inline bool root_privileged(void) { return !issecure(SECURE_NOROOT); }

static inline bool __is_real(kuid_t uid, struct cred *cred)
{ return uid_eq(cred->uid, uid); }

static inline bool __is_eff(kuid_t uid, struct cred *cred)
{ return uid_eq(cred->euid, uid); }

static inline bool __is_suid(kuid_t uid, struct cred *cred)
{ return !__is_real(uid, cred) && __is_eff(uid, cred); }

/*
 * handle_privileged_root - Handle case of privileged root
 * @bprm: The execution parameters, including the proposed creds
 * @has_fcap: Are any file capabilities set?
 * @effective: Do we have effective root privilege?
 * @root_uid: This namespace' root UID WRT initial USER namespace
 *
 * Handle the case where root is privileged and hasn't been neutered by
 * SECURE_NOROOT.  If file capabilities are set, they won't be combined with
 * set UID root and nothing is changed.  If we are root, cap_permitted is
 * updated.  If we have become set UID root, the effective bit is set.
 */
static void handle_privileged_root(struct linux_binprm *bprm, bool has_fcap,
				   bool *effective, kuid_t root_uid)
{
	const struct cred *old = current_cred();
	struct cred *new = bprm->cred;

	if (!root_privileged())
		return;
	/*
	 * If the legacy file capability is set, then don't set privs
	 * for a setuid root binary run by a non-root user.  Do set it
	 * for a root user just to cause least surprise to an admin.
	 */
	if (has_fcap && __is_suid(root_uid, new)) {
		warn_setuid_and_fcaps_mixed(bprm->filename);
		return;
	}
	/*
	 * To support inheritance of root-permissions and suid-root
	 * executables under compatibility mode, we override the
	 * capability sets for the file.
	 */
	if (__is_eff(root_uid, new) || __is_real(root_uid, new)) {
		/* pP' = (cap_bset & ~0) | (pI & ~0) */
		new->cap_permitted = cap_combine(old->cap_bset,
						 old->cap_inheritable);
	}
	/*
	 * If only the real uid is 0, we do not set the effective bit.
	 */
	if (__is_eff(root_uid, new))
		*effective = true;
}

#define __cap_gained(field, target, source) \
	!cap_issubset(target->cap_##field, source->cap_##field)
#define __cap_grew(target, source, cred) \
	!cap_issubset(cred->cap_##target, cred->cap_##source)
#define __cap_full(field, cred) \
	cap_issubset(CAP_FULL_SET, cred->cap_##field)

static inline bool __is_setuid(struct cred *new, const struct cred *old)
{ return !uid_eq(new->euid, old->uid); }

static inline bool __is_setgid(struct cred *new, const struct cred *old)
{ return !gid_eq(new->egid, old->gid); }

/*
 * 1) Audit candidate if current->cap_effective is set
 *
 * We do not bother to audit if 3 things are true:
 *   1) cap_effective has all caps
 *   2) we became root *OR* are were already root
 *   3) root is supposed to have all caps (SECURE_NOROOT)
 * Since this is just a normal root execing a process.
 *
 * Number 1 above might fail if you don't have a full bset, but I think
 * that is interesting information to audit.
 *
 * A number of other conditions require logging:
 * 2) something prevented setuid root getting all caps
 * 3) non-setuid root gets fcaps
 * 4) non-setuid root gets ambient
 */
static inline bool nonroot_raised_pE(struct cred *new, const struct cred *old,
				     kuid_t root, bool has_fcap)
{
	bool ret = false;

	if ((__cap_grew(effective, ambient, new) &&
	     !(__cap_full(effective, new) &&
	       (__is_eff(root, new) || __is_real(root, new)) &&
	       root_privileged())) ||
	    (root_privileged() &&
	     __is_suid(root, new) &&
	     !__cap_full(effective, new)) ||
	    (!__is_setuid(new, old) &&
	     ((has_fcap &&
	       __cap_gained(permitted, new, old)) ||
	      __cap_gained(ambient, new, old))))

		ret = true;

	return ret;
}

/**
 * cap_bprm_creds_from_file - Set up the proposed credentials for execve().
 * @bprm: The execution parameters, including the proposed creds
 * @file: The file to pull the credentials from
 *
 * Set up the proposed credentials for a new execution context being
 * constructed by execve().  The proposed creds in @bprm->cred is altered,
 * which won't take effect immediately.
 *
 * Return: 0 if successful, -ve on error.
 */
int ds_cap_bprm_creds_from_file(struct linux_binprm *bprm, struct file *file)
{
	/* Process setpcap binaries and capabilities for uid 0 */
	const struct cred *old = current_cred();
	struct cred *new = bprm->cred;
	bool effective = false, has_fcap = false, is_setid;
	int ret;
	kuid_t root_uid;

	ds_fix_bprm_setid(bprm, file);

	if (WARN_ON(!cap_ambient_invariant_ok(old)))
		return -EPERM;

	ret = get_file_caps(bprm, file, &effective, &has_fcap);
	if (ret < 0)
		return ret;

	root_uid = make_kuid(new->user_ns, 0);

	handle_privileged_root(bprm, has_fcap, &effective, root_uid);

	/* if we have fs caps, clear dangerous personality flags */
	if (__cap_gained(permitted, new, old))
		bprm->per_clear |= PER_CLEAR_ON_SETID;

	/* Don't let someone trace a set[ug]id/setpcap binary with the revised
	 * credentials unless they have the appropriate permit.
	 *
	 * In addition, if NO_NEW_PRIVS, then ensure we get no new privs.
	 */
	is_setid = __is_setuid(new, old) || __is_setgid(new, old);

	if ((is_setid || __cap_gained(permitted, new, old)) &&
	    ((bprm->unsafe & ~LSM_UNSAFE_PTRACE) ||
	     !ptracer_capable(current, new->user_ns))) {
		/* downgrade; they get no more than they had, and maybe less */
		if (!ns_capable(new->user_ns, CAP_SETUID) ||
		    (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS)) {
			new->euid = new->uid;
			new->egid = new->gid;
		}
		new->cap_permitted = cap_intersect(new->cap_permitted,
						   old->cap_permitted);
	}

	new->suid = new->fsuid = new->euid;
	new->sgid = new->fsgid = new->egid;

	/* File caps or setid cancels ambient. */
	if (has_fcap || is_setid)
		cap_clear(new->cap_ambient);

	/*
	 * Now that we've computed pA', update pP' to give:
	 *   pP' = (X & fP) | (pI & fI) | pA'
	 */
	new->cap_permitted = cap_combine(new->cap_permitted, new->cap_ambient);

	/*
	 * Set pE' = (fE ? pP' : pA').  Because pA' is zero if fE is set,
	 * this is the same as pE' = (fE ? pP' : 0) | pA'.
	 */
	if (effective)
		new->cap_effective = new->cap_permitted;
	else
		new->cap_effective = new->cap_ambient;

	if (WARN_ON(!cap_ambient_invariant_ok(new)))
		return -EPERM;

	if (nonroot_raised_pE(new, old, root_uid, has_fcap)) {
		ret = audit_log_bprm_fcaps(bprm, new, old);
		if (ret < 0)
			return ret;
	}

	new->securebits &= ~issecure_mask(SECURE_KEEP_CAPS);

	if (WARN_ON(!cap_ambient_invariant_ok(new)))
		return -EPERM;

	/* Check for privilege-elevated exec. */
	if (is_setid ||
	    (!__is_real(root_uid, new) &&
	     (effective ||
	      __cap_grew(permitted, ambient, new))))
		bprm->secureexec = 1;

	return 0;
}

static inline void cap_emulate_setxuid(struct cred *new, const struct cred *old)
{
	kuid_t root_uid = make_kuid(old->user_ns, 0);

	if ((uid_eq(old->uid, root_uid) ||
	     uid_eq(old->euid, root_uid) ||
	     uid_eq(old->suid, root_uid)) &&
	    (!uid_eq(new->uid, root_uid) &&
	     !uid_eq(new->euid, root_uid) &&
	     !uid_eq(new->suid, root_uid))) {
		if (!issecure(SECURE_KEEP_CAPS)) {
			cap_clear(new->cap_permitted);
			cap_clear(new->cap_effective);
		}

		/*
		 * Pre-ambient programs expect setresuid to nonroot followed
		 * by exec to drop capabilities.  We should make sure that
		 * this remains the case.
		 */
		cap_clear(new->cap_ambient);
	}
	if (uid_eq(old->euid, root_uid) && !uid_eq(new->euid, root_uid))
		cap_clear(new->cap_effective);
	if (!uid_eq(old->euid, root_uid) && uid_eq(new->euid, root_uid))
		new->cap_effective = new->cap_permitted;
}

/**
 * cap_task_fix_setuid - Fix up the results of setuid() call
 * @new: The proposed credentials
 * @old: The current task's current credentials
 * @flags: Indications of what has changed
 *
 * Fix up the results of setuid() call before the credential changes are
 * actually applied.
 *
 * Return: 0 to grant the changes, -ve to deny them.
 */
int ds_cap_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	switch (flags) {
	case LSM_SETID_RE:
	case LSM_SETID_ID:
	case LSM_SETID_RES:
		/* juggle the capabilities to follow [RES]UID changes unless
		 * otherwise suppressed */
		if (!issecure(SECURE_NO_SETUID_FIXUP))
			cap_emulate_setxuid(new, old);
		break;

	case LSM_SETID_FS:
		/* juggle the capabilties to follow FSUID changes, unless
		 * otherwise suppressed
		 *
		 * FIXME - is fsuser used for all CAP_FS_MASK capabilities?
		 *          if not, we might be a bit too harsh here.
		 */
		if (!issecure(SECURE_NO_SETUID_FIXUP)) {
			kuid_t root_uid = make_kuid(old->user_ns, 0);
			if (uid_eq(old->fsuid, root_uid) && !uid_eq(new->fsuid, root_uid))
				new->cap_effective =
					cap_drop_fs_set(new->cap_effective);

			if (!uid_eq(old->fsuid, root_uid) && uid_eq(new->fsuid, root_uid))
				new->cap_effective =
					cap_raise_fs_set(new->cap_effective,
							 new->cap_permitted);
		}
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

/*
 * prctl() capability operations (vendor security/commoncap.c). Natively
 * cap_prctl_drop() checks CAP_SETPCAP against init_user_ns, so a container
 * runtime inside a user namespace cannot drop bounding-set capabilities.
 * The other prctl paths only edit a prepared cred and commit it through the
 * vendor's commit_creds().
 */
static int cap_prctl_drop(unsigned long cap)
{
	struct cred *new;

	if (!ns_capable(current_user_ns(), CAP_SETPCAP))
		return -EPERM;
	if (!cap_valid(cap))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	cap_lower(new->cap_bset, cap);
	return commit_creds(new);
}

/**
 * cap_task_prctl - Implement process control functions for this security module
 * @option: The process control function requested
 * @arg2: The argument data for this function
 * @arg3: The argument data for this function
 * @arg4: The argument data for this function
 * @arg5: The argument data for this function
 *
 * Allow process control functions (sys_prctl()) to alter capabilities; may
 * also deny access to other functions not otherwise implemented here.
 *
 * Return: 0 or +ve on success, -ENOSYS if this function is not implemented
 * here, other -ve on error.  If -ENOSYS is returned, sys_prctl() and other LSM
 * modules will consider performing the function.
 */
int ds_cap_task_prctl(int option, unsigned long arg2, unsigned long arg3,
		   unsigned long arg4, unsigned long arg5)
{
	const struct cred *old = current_cred();
	struct cred *new;

	switch (option) {
	case PR_CAPBSET_READ:
		if (!cap_valid(arg2))
			return -EINVAL;
		return !!cap_raised(old->cap_bset, arg2);

	case PR_CAPBSET_DROP:
		return cap_prctl_drop(arg2);

	/*
	 * The next four prctl's remain to assist with transitioning a
	 * system from legacy UID=0 based privilege (when filesystem
	 * capabilities are not in use) to a system using filesystem
	 * capabilities only - as the POSIX.1e draft intended.
	 *
	 * Note:
	 *
	 *  PR_SET_SECUREBITS =
	 *      issecure_mask(SECURE_KEEP_CAPS_LOCKED)
	 *    | issecure_mask(SECURE_NOROOT)
	 *    | issecure_mask(SECURE_NOROOT_LOCKED)
	 *    | issecure_mask(SECURE_NO_SETUID_FIXUP)
	 *    | issecure_mask(SECURE_NO_SETUID_FIXUP_LOCKED)
	 *
	 * will ensure that the current process and all of its
	 * children will be locked into a pure
	 * capability-based-privilege environment.
	 */
	case PR_SET_SECUREBITS:
		if ((((old->securebits & SECURE_ALL_LOCKS) >> 1)
		     & (old->securebits ^ arg2))			/*[1]*/
		    || ((old->securebits & SECURE_ALL_LOCKS & ~arg2))	/*[2]*/
		    || (arg2 & ~(SECURE_ALL_LOCKS | SECURE_ALL_BITS))	/*[3]*/
		    || (cap_capable(current_cred(),
				    current_cred()->user_ns,
				    CAP_SETPCAP,
				    CAP_OPT_NONE) != 0)			/*[4]*/
			/*
			 * [1] no changing of bits that are locked
			 * [2] no unlocking of locks
			 * [3] no setting of unsupported bits
			 * [4] doing anything requires privilege (go read about
			 *     the "sendmail capabilities bug")
			 */
		    )
			/* cannot change a locked bit */
			return -EPERM;

		new = prepare_creds();
		if (!new)
			return -ENOMEM;
		new->securebits = arg2;
		return commit_creds(new);

	case PR_GET_SECUREBITS:
		return old->securebits;

	case PR_GET_KEEPCAPS:
		return !!issecure(SECURE_KEEP_CAPS);

	case PR_SET_KEEPCAPS:
		if (arg2 > 1) /* Note, we rely on arg2 being unsigned here */
			return -EINVAL;
		if (issecure(SECURE_KEEP_CAPS_LOCKED))
			return -EPERM;

		new = prepare_creds();
		if (!new)
			return -ENOMEM;
		if (arg2)
			new->securebits |= issecure_mask(SECURE_KEEP_CAPS);
		else
			new->securebits &= ~issecure_mask(SECURE_KEEP_CAPS);
		return commit_creds(new);

	case PR_CAP_AMBIENT:
		if (arg2 == PR_CAP_AMBIENT_CLEAR_ALL) {
			if (arg3 | arg4 | arg5)
				return -EINVAL;

			new = prepare_creds();
			if (!new)
				return -ENOMEM;
			cap_clear(new->cap_ambient);
			return commit_creds(new);
		}

		if (((!cap_valid(arg3)) | arg4 | arg5))
			return -EINVAL;

		if (arg2 == PR_CAP_AMBIENT_IS_SET) {
			return !!cap_raised(current_cred()->cap_ambient, arg3);
		} else if (arg2 != PR_CAP_AMBIENT_RAISE &&
			   arg2 != PR_CAP_AMBIENT_LOWER) {
			return -EINVAL;
		} else {
			if (arg2 == PR_CAP_AMBIENT_RAISE &&
			    (!cap_raised(current_cred()->cap_permitted, arg3) ||
			     !cap_raised(current_cred()->cap_inheritable,
					 arg3) ||
			     issecure(SECURE_NO_CAP_AMBIENT_RAISE)))
				return -EPERM;

			new = prepare_creds();
			if (!new)
				return -ENOMEM;
			if (arg2 == PR_CAP_AMBIENT_RAISE)
				cap_raise(new->cap_ambient, arg3);
			else
				cap_lower(new->cap_ambient, arg3);
			return commit_creds(new);
		}

	default:
		/* No functionality available - continue with default */
		return -ENOSYS;
	}
}
