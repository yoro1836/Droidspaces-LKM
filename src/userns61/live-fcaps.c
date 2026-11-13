// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * File capabilities (security.capability) for user namespaces on a kernel
 * built without USER_NS.
 *
 * From security/commoncap.c (android14-6.1): cap_inode_getsecurity(),
 * cap_convert_nscap() and get_vfs_caps_from_disk() with their helpers,
 * unchanged apart from the ds_ prefix. Compiled here, current_user_ns(),
 * make_kuid() and from_kuid() are the module's real ones. The native copies
 * take every caller for init_user_ns: setcap in a container records the
 * host's root as the owner, and exec then honours such a file for anybody,
 * while one owned by the container's root is ignored.
 */
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mnt_idmapping.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <linux/xattr.h>
#include "userns61.h"

static bool rootid_owns_currentns(kuid_t kroot)
{
	struct user_namespace *ns;

	if (!uid_valid(kroot))
		return false;

	for (ns = current_user_ns(); ; ns = ns->parent) {
		if (from_kuid(ns, kroot) == 0)
			return true;
		if (ns == &init_user_ns)
			break;
	}

	return false;
}

static __u32 sansflags(__u32 m)
{
	return m & ~VFS_CAP_FLAGS_EFFECTIVE;
}

static bool is_v2header(size_t size, const struct vfs_cap_data *cap)
{
	if (size != XATTR_CAPS_SZ_2)
		return false;
	return sansflags(le32_to_cpu(cap->magic_etc)) == VFS_CAP_REVISION_2;
}

static bool is_v3header(size_t size, const struct vfs_cap_data *cap)
{
	if (size != XATTR_CAPS_SZ_3)
		return false;
	return sansflags(le32_to_cpu(cap->magic_etc)) == VFS_CAP_REVISION_3;
}

/*
 * getsecurity: We are called for security.* before any attempt to read the
 * xattr from the inode itself.
 *
 * This gives us a chance to read the on-disk value and convert it.  If we
 * return -EOPNOTSUPP, then vfs_getxattr() will call the i_op handler.
 *
 * Note we are not called by vfs_getxattr_alloc(), but that is only called
 * by the integrity subsystem, which really wants the unconverted values -
 * so that's good.
 */
int ds_cap_inode_getsecurity(struct user_namespace *mnt_userns,
			  struct inode *inode, const char *name, void **buffer,
			  bool alloc)
{
	int size, ret;
	kuid_t kroot;
	u32 nsmagic, magic;
	uid_t root, mappedroot;
	char *tmpbuf = NULL;
	struct vfs_cap_data *cap;
	struct vfs_ns_cap_data *nscap = NULL;
	struct dentry *dentry;
	struct user_namespace *fs_ns;

	if (strcmp(name, "capability") != 0)
		return -EOPNOTSUPP;

	dentry = d_find_any_alias(inode);
	if (!dentry)
		return -EINVAL;

	size = sizeof(struct vfs_ns_cap_data);
	ret = (int)vfs_getxattr_alloc(mnt_userns, dentry, XATTR_NAME_CAPS,
				      &tmpbuf, size, GFP_NOFS);
	dput(dentry);

	if (ret < 0 || !tmpbuf) {
		size = ret;
		goto out_free;
	}

	fs_ns = inode->i_sb->s_user_ns;
	cap = (struct vfs_cap_data *) tmpbuf;
	if (is_v2header((size_t) ret, cap)) {
		root = 0;
	} else if (is_v3header((size_t) ret, cap)) {
		nscap = (struct vfs_ns_cap_data *) tmpbuf;
		root = le32_to_cpu(nscap->rootid);
	} else {
		size = -EINVAL;
		goto out_free;
	}

	kroot = make_kuid(fs_ns, root);

	/* If this is an idmapped mount shift the kuid. */
	kroot = mapped_kuid_fs(mnt_userns, fs_ns, kroot);

	/* If the root kuid maps to a valid uid in current ns, then return
	 * this as a nscap. */
	mappedroot = from_kuid(current_user_ns(), kroot);
	if (mappedroot != (uid_t)-1 && mappedroot != (uid_t)0) {
		size = sizeof(struct vfs_ns_cap_data);
		if (alloc) {
			if (!nscap) {
				/* v2 -> v3 conversion */
				nscap = kzalloc(size, GFP_ATOMIC);
				if (!nscap) {
					size = -ENOMEM;
					goto out_free;
				}
				nsmagic = VFS_CAP_REVISION_3;
				magic = le32_to_cpu(cap->magic_etc);
				if (magic & VFS_CAP_FLAGS_EFFECTIVE)
					nsmagic |= VFS_CAP_FLAGS_EFFECTIVE;
				memcpy(&nscap->data, &cap->data, sizeof(__le32) * 2 * VFS_CAP_U32);
				nscap->magic_etc = cpu_to_le32(nsmagic);
			} else {
				/* use allocated v3 buffer */
				tmpbuf = NULL;
			}
			nscap->rootid = cpu_to_le32(mappedroot);
			*buffer = nscap;
		}
		goto out_free;
	}

	if (!rootid_owns_currentns(kroot)) {
		size = -EOVERFLOW;
		goto out_free;
	}

	/* This comes from a parent namespace.  Return as a v2 capability */
	size = sizeof(struct vfs_cap_data);
	if (alloc) {
		if (nscap) {
			/* v3 -> v2 conversion */
			cap = kzalloc(size, GFP_ATOMIC);
			if (!cap) {
				size = -ENOMEM;
				goto out_free;
			}
			magic = VFS_CAP_REVISION_2;
			nsmagic = le32_to_cpu(nscap->magic_etc);
			if (nsmagic & VFS_CAP_FLAGS_EFFECTIVE)
				magic |= VFS_CAP_FLAGS_EFFECTIVE;
			memcpy(&cap->data, &nscap->data, sizeof(__le32) * 2 * VFS_CAP_U32);
			cap->magic_etc = cpu_to_le32(magic);
		} else {
			/* use unconverted v2 */
			tmpbuf = NULL;
		}
		*buffer = cap;
	}
out_free:
	kfree(tmpbuf);
	return size;
}

static kuid_t rootid_from_xattr(const void *value, size_t size,
				struct user_namespace *task_ns,
				struct user_namespace *mnt_userns,
				struct user_namespace *fs_userns)
{
	const struct vfs_ns_cap_data *nscap = value;
	kuid_t rootkid;
	uid_t rootid = 0;

	if (size == XATTR_CAPS_SZ_3)
		rootid = le32_to_cpu(nscap->rootid);

	rootkid = make_kuid(task_ns, rootid);
	return mapped_kuid_user(mnt_userns, fs_userns, rootkid);
}

static bool validheader(size_t size, const struct vfs_cap_data *cap)
{
	return is_v2header(size, cap) || is_v3header(size, cap);
}

/**
 * cap_convert_nscap - check vfs caps
 *
 * @mnt_userns:	user namespace of the mount the inode was found from
 * @dentry:	used to retrieve inode to check permissions on
 * @ivalue:	vfs caps value which may be modified by this function
 * @size:	size of @ivalue
 *
 * User requested a write of security.capability.  If needed, update the
 * xattr to change from v2 to v3, or to fixup the v3 rootid.
 *
 * If the inode has been found through an idmapped mount the user namespace of
 * the vfsmount must be passed through @mnt_userns. This function will then
 * take care to map the inode according to @mnt_userns before checking
 * permissions. On non-idmapped mounts or if permission checking is to be
 * performed on the raw inode simply passs init_user_ns.
 *
 * Return: On success, return the new size; on error, return < 0.
 */
int ds_cap_convert_nscap(struct user_namespace *mnt_userns, struct dentry *dentry,
		      const void **ivalue, size_t size)
{
	struct vfs_ns_cap_data *nscap;
	uid_t nsrootid;
	const struct vfs_cap_data *cap = *ivalue;
	__u32 magic, nsmagic;
	struct inode *inode = d_backing_inode(dentry);
	struct user_namespace *task_ns = current_user_ns(),
		*fs_ns = inode->i_sb->s_user_ns;
	kuid_t rootid;
	size_t newsize;

	if (!*ivalue)
		return -EINVAL;
	if (!validheader(size, cap))
		return -EINVAL;
	if (!ds_capable_wrt_inode_uidgid(mnt_userns, inode, CAP_SETFCAP))
		return -EPERM;
	if (size == XATTR_CAPS_SZ_2 && (mnt_userns == fs_ns))
		if (ns_capable(inode->i_sb->s_user_ns, CAP_SETFCAP))
			/* user is privileged, just write the v2 */
			return size;

	rootid = rootid_from_xattr(*ivalue, size, task_ns, mnt_userns, fs_ns);
	if (!uid_valid(rootid))
		return -EINVAL;

	nsrootid = from_kuid(fs_ns, rootid);
	if (nsrootid == -1)
		return -EINVAL;

	newsize = sizeof(struct vfs_ns_cap_data);
	nscap = kmalloc(newsize, GFP_ATOMIC);
	if (!nscap)
		return -ENOMEM;
	nscap->rootid = cpu_to_le32(nsrootid);
	nsmagic = VFS_CAP_REVISION_3;
	magic = le32_to_cpu(cap->magic_etc);
	if (magic & VFS_CAP_FLAGS_EFFECTIVE)
		nsmagic |= VFS_CAP_FLAGS_EFFECTIVE;
	nscap->magic_etc = cpu_to_le32(nsmagic);
	memcpy(&nscap->data, &cap->data, sizeof(__le32) * 2 * VFS_CAP_U32);

	*ivalue = nscap;
	return newsize;
}

/**
 * get_vfs_caps_from_disk - retrieve vfs caps from disk
 *
 * @mnt_userns:	user namespace of the mount the inode was found from
 * @dentry:	dentry from which @inode is retrieved
 * @cpu_caps:	vfs capabilities
 *
 * Extract the on-exec-apply capability sets for an executable file.
 *
 * If the inode has been found through an idmapped mount the user namespace of
 * the vfsmount must be passed through @mnt_userns. This function will then
 * take care to map the inode according to @mnt_userns before checking
 * permissions. On non-idmapped mounts or if permission checking is to be
 * performed on the raw inode simply passs init_user_ns.
 */
int ds_get_vfs_caps_from_disk(struct user_namespace *mnt_userns,
			   const struct dentry *dentry,
			   struct cpu_vfs_cap_data *cpu_caps)
{
	struct inode *inode = d_backing_inode(dentry);
	__u32 magic_etc;
	unsigned tocopy, i;
	int size;
	struct vfs_ns_cap_data data, *nscaps = &data;
	struct vfs_cap_data *caps = (struct vfs_cap_data *) &data;
	kuid_t rootkuid;
	struct user_namespace *fs_ns;

	memset(cpu_caps, 0, sizeof(struct cpu_vfs_cap_data));

	if (!inode)
		return -ENODATA;

	fs_ns = inode->i_sb->s_user_ns;
	size = __vfs_getxattr((struct dentry *)dentry, inode,
			      XATTR_NAME_CAPS, &data, XATTR_CAPS_SZ);
	if (size == -ENODATA || size == -EOPNOTSUPP)
		/* no data, that's ok */
		return -ENODATA;

	if (size < 0)
		return size;

	if (size < sizeof(magic_etc))
		return -EINVAL;

	cpu_caps->magic_etc = magic_etc = le32_to_cpu(caps->magic_etc);

	rootkuid = make_kuid(fs_ns, 0);
	switch (magic_etc & VFS_CAP_REVISION_MASK) {
	case VFS_CAP_REVISION_1:
		if (size != XATTR_CAPS_SZ_1)
			return -EINVAL;
		tocopy = VFS_CAP_U32_1;
		break;
	case VFS_CAP_REVISION_2:
		if (size != XATTR_CAPS_SZ_2)
			return -EINVAL;
		tocopy = VFS_CAP_U32_2;
		break;
	case VFS_CAP_REVISION_3:
		if (size != XATTR_CAPS_SZ_3)
			return -EINVAL;
		tocopy = VFS_CAP_U32_3;
		rootkuid = make_kuid(fs_ns, le32_to_cpu(nscaps->rootid));
		break;

	default:
		return -EINVAL;
	}
	/* Limit the caps to the mounter of the filesystem
	 * or the more limited uid specified in the xattr.
	 */
	rootkuid = mapped_kuid_fs(mnt_userns, fs_ns, rootkuid);
	if (!rootid_owns_currentns(rootkuid))
		return -ENODATA;

	CAP_FOR_EACH_U32(i) {
		if (i >= tocopy)
			break;
		cpu_caps->permitted.cap[i] = le32_to_cpu(caps->data[i].permitted);
		cpu_caps->inheritable.cap[i] = le32_to_cpu(caps->data[i].inheritable);
	}

	cpu_caps->permitted.cap[CAP_LAST_U32] &= CAP_LAST_U32_VALID_MASK;
	cpu_caps->inheritable.cap[CAP_LAST_U32] &= CAP_LAST_U32_VALID_MASK;

	cpu_caps->rootid = rootkuid;

	return 0;
}
