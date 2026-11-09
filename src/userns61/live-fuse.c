// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE attribute conversions from the Samsung S5E9945 vendor kernel (6.1),
 * fs/fuse/inode.c and fs/fuse/dir.c, compiled with CONFIG_USER_NS so file
 * ids are mapped through the connection's user namespace.
 *
 * Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
 *
 * The native build has CONFIG_USER_NS off, so make_kuid()/make_kgid() in
 * fuse_change_attributes_common() and fuse_fillattr() are identity: a file
 * the daemon reports as uid 0 in a child namespace becomes host uid 0, so
 * inode_permission() on a child-owned mount denies the namespace's own
 * tasks. These copies run with real mapping and are redirected onto the
 * native functions (port61/hooks.c). Only connections owned by a child
 * namespace differ; for init_user_ns the mapping is identity, matching
 * native behaviour, so Android's own FUSE mounts are unchanged.
 */
#include "fs/fuse/fuse_i.h"
#include <linux/user_namespace.h>
#include "userns61.h"

/*
 * ino_t is 32-bits on 32-bit arch. We have to squash the 64-bit value down
 * so that it will fit.
 */
static ino_t fuse_squash_ino(u64 ino64)
{
	ino_t ino = (ino_t) ino64;
	if (sizeof(ino_t) < sizeof(u64))
		ino ^= ino64 >> (sizeof(u64) - sizeof(ino_t)) * 8;
	return ino;
}

void ds_fuse_change_attributes_common(struct inode *inode, struct fuse_attr *attr,
				      u64 attr_valid, u32 cache_mask)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	lockdep_assert_held(&fi->lock);

	fi->attr_version = atomic64_inc_return(&fc->attr_version);
	fi->i_time = attr_valid;
	WRITE_ONCE(fi->inval_mask, 0);

	inode->i_ino     = fuse_squash_ino(attr->ino);
	inode->i_mode    = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	set_nlink(inode, attr->nlink);
	inode->i_uid     = make_kuid(fc->user_ns, attr->uid);
	inode->i_gid     = make_kgid(fc->user_ns, attr->gid);
	inode->i_blocks  = attr->blocks;

	/* Sanitize nsecs */
	attr->atimensec = min_t(u32, attr->atimensec, NSEC_PER_SEC - 1);
	attr->mtimensec = min_t(u32, attr->mtimensec, NSEC_PER_SEC - 1);
	attr->ctimensec = min_t(u32, attr->ctimensec, NSEC_PER_SEC - 1);

	inode->i_atime.tv_sec   = attr->atime;
	inode->i_atime.tv_nsec  = attr->atimensec;
	/* mtime from server may be stale due to local buffered write */
	if (!(cache_mask & STATX_MTIME)) {
		inode->i_mtime.tv_sec   = attr->mtime;
		inode->i_mtime.tv_nsec  = attr->mtimensec;
	}
	if (!(cache_mask & STATX_CTIME)) {
		inode->i_ctime.tv_sec   = attr->ctime;
		inode->i_ctime.tv_nsec  = attr->ctimensec;
	}

	if (attr->blksize != 0)
		inode->i_blkbits = ilog2(attr->blksize);
	else
		inode->i_blkbits = inode->i_sb->s_blocksize_bits;

	/*
	 * Don't set the sticky bit in i_mode, unless we want the VFS
	 * to check permissions.  This prevents failures due to the
	 * check in may_delete().
	 */
	fi->orig_i_mode = inode->i_mode;
	if (!fc->default_permissions)
		inode->i_mode &= ~S_ISVTX;

	fi->orig_ino = attr->ino;

	/*
	 * We are refreshing inode data and it is possible that another
	 * client set suid/sgid or security.capability xattr. So clear
	 * S_NOSEC. Ideally, we could have cleared it only if suid/sgid
	 * was set or if security.capability xattr was set. But we don't
	 * know if security.capability has been set or not. So clear it
	 * anyway. Its less efficient but should be safe.
	 */
	inode->i_flags &= ~S_NOSEC;
}

void ds_fuse_fillattr(struct inode *inode, struct fuse_attr *attr,
		      struct kstat *stat)
{
	unsigned int blkbits;
	struct fuse_conn *fc = get_fuse_conn(inode);

	stat->dev = inode->i_sb->s_dev;
	stat->ino = attr->ino;
	stat->mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	stat->nlink = attr->nlink;
	stat->uid = make_kuid(fc->user_ns, attr->uid);
	stat->gid = make_kgid(fc->user_ns, attr->gid);
	stat->rdev = inode->i_rdev;
	stat->atime.tv_sec = attr->atime;
	stat->atime.tv_nsec = attr->atimensec;
	stat->mtime.tv_sec = attr->mtime;
	stat->mtime.tv_nsec = attr->mtimensec;
	stat->ctime.tv_sec = attr->ctime;
	stat->ctime.tv_nsec = attr->ctimensec;
	stat->size = attr->size;
	stat->blocks = attr->blocks;

	if (attr->blksize != 0)
		blkbits = ilog2(attr->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;

	stat->blksize = 1 << blkbits;
}
