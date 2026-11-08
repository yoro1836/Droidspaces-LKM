// SPDX-License-Identifier: GPL-2.0
/*
 * devtmpfs - kernel-maintained tmpfs-based /dev
 *
 * Copyright (C) 2009, Kay Sievers <kay.sievers@vrfy.org>
 *
 * During bootup, before any driver core device is registered,
 * devtmpfs, a tmpfs-based filesystem is created. Every driver-core
 * device which requests a device node, will add a node in this
 * filesystem.
 * By default, all devices are named after the name of the device,
 * owned by root and have a default mode of 0600. Subsystems can
 * overwrite the default setting if needed.
 */

#define pr_fmt(fmt) "droidspaces_devtmpfs: " fmt

#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/shmem_fs.h>
#include <linux/ramfs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/init_syscalls.h>
#include <uapi/linux/mount.h>
#include "drivers/base/base.h"
#include <linux/fs_struct.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/sched/task.h>
#include "port.h"

/* 6.1 keeps this helper local to drivers/base/devtmpfs.c. */
#ifdef CONFIG_BLOCK
static inline int is_blockdev(struct device *dev)
{
	return dev->class == &block_class;
}
#else
static inline int is_blockdev(struct device *dev) { return 0; }
#endif

static struct task_struct *thread;
static const struct cred *node_cred;

static DEFINE_SPINLOCK(req_lock);

static struct req {
	struct req *next;
	struct completion done;
	int err;
	const char *name;
	umode_t mode;	/* 0 => delete */
	kuid_t uid;
	kgid_t gid;
	struct device *dev;
} *requests;

static struct vfsmount *mnt;

static struct dentry *public_dev_mount(struct file_system_type *fs_type, int flags,
		      const char *dev_name, void *data)
{
	struct super_block *s = mnt->mnt_sb;
	int err;

	atomic_inc(&s->s_active);
	down_write(&s->s_umount);
	err = reconfigure_single(s, flags, data);
	if (err < 0) {
		deactivate_locked_super(s);
		return ERR_PTR(err);
	}
	return dget(s->s_root);
}

static struct file_system_type internal_fs_type = {
	.name = "devtmpfs",
#ifdef CONFIG_TMPFS
	.init_fs_context = shmem_init_fs_context,
#else
	.init_fs_context = ramfs_init_fs_context,
#endif
	.kill_sb = kill_litter_super,
};

static struct file_system_type dev_fs_type = {
	.owner = THIS_MODULE,
	.name = "devtmpfs",
	.mount = public_dev_mount,
};

static int devtmpfs_submit_req(struct req *req, const char *tmp)
{
	init_completion(&req->done);

	spin_lock(&req_lock);
	req->next = requests;
	requests = req;
	spin_unlock(&req_lock);

	wake_up_process(thread);
	wait_for_completion(&req->done);

	kfree(tmp);

	return req->err;
}

int ds_devtmpfs_create_node(struct device *dev)
{
	const char *tmp = NULL;
	struct req req;

	if (!thread)
		return 0;

	req.mode = 0;
	req.uid = GLOBAL_ROOT_UID;
	req.gid = GLOBAL_ROOT_GID;
	req.name = device_get_devnode(dev, &req.mode, &req.uid, &req.gid, &tmp);
	if (!req.name)
		return -ENOMEM;

	if (req.mode == 0)
		req.mode = 0600;
	if (is_blockdev(dev))
		req.mode |= S_IFBLK;
	else
		req.mode |= S_IFCHR;

	req.dev = dev;

	return devtmpfs_submit_req(&req, tmp);
}

int ds_devtmpfs_delete_node(struct device *dev)
{
	const char *tmp = NULL;
	struct req req;

	if (!thread)
		return 0;

	req.name = device_get_devnode(dev, NULL, NULL, NULL, &tmp);
	if (!req.name)
		return -ENOMEM;

	req.mode = 0;
	req.dev = dev;

	return devtmpfs_submit_req(&req, tmp);
}

static int dev_mkdir(const char *name, umode_t mode)
{
	struct dentry *dentry;
	struct path path;
	int err;

	dentry = kern_path_create(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	err = vfs_mkdir(&init_user_ns, d_inode(path.dentry), dentry, mode);
	if (!err)
		/* mark as kernel-created inode */
		d_inode(dentry)->i_private = &thread;
	done_path_create(&path, dentry);
	return err;
}

static int create_path(const char *nodepath)
{
	char *path;
	char *s;
	int err = 0;

	/* parent directories do not exist, create them */
	path = kstrdup(nodepath, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	s = path;
	for (;;) {
		s = strchr(s, '/');
		if (!s)
			break;
		s[0] = '\0';
		err = dev_mkdir(path, 0755);
		if (err && err != -EEXIST)
			break;
		s[0] = '/';
		s++;
	}
	kfree(path);
	return err;
}

static int handle_create(const char *nodename, umode_t mode, kuid_t uid,
			 kgid_t gid, struct device *dev)
{
	struct dentry *dentry;
	struct path path;
	int err;

	dentry = kern_path_create(AT_FDCWD, nodename, &path, 0);
	if (dentry == ERR_PTR(-ENOENT)) {
		create_path(nodename);
		dentry = kern_path_create(AT_FDCWD, nodename, &path, 0);
	}
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	err = vfs_mknod(&init_user_ns, d_inode(path.dentry), dentry, mode,
			dev->devt);
	if (!err) {
		struct iattr newattrs;

		newattrs.ia_mode = mode;
		newattrs.ia_uid = uid;
		newattrs.ia_gid = gid;
		newattrs.ia_valid = ATTR_MODE|ATTR_UID|ATTR_GID;
		inode_lock(d_inode(dentry));
		notify_change(&init_user_ns, dentry, &newattrs, NULL);
		inode_unlock(d_inode(dentry));

		/* mark as kernel-created inode */
		d_inode(dentry)->i_private = &thread;
	}
	done_path_create(&path, dentry);
	return err;
}

static int dev_rmdir(const char *name)
{
	struct path parent;
	struct dentry *dentry;
	int err;

	dentry = kern_path_locked(name, &parent);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	if (d_really_is_positive(dentry)) {
		if (d_inode(dentry)->i_private == &thread)
			err = vfs_rmdir(&init_user_ns, d_inode(parent.dentry),
					dentry);
		else
			err = -EPERM;
	} else {
		err = -ENOENT;
	}
	dput(dentry);
	inode_unlock(d_inode(parent.dentry));
	path_put(&parent);
	return err;
}

static int delete_path(const char *nodepath)
{
	char *path;
	int err = 0;

	path = kstrdup(nodepath, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	for (;;) {
		char *base;

		base = strrchr(path, '/');
		if (!base)
			break;
		base[0] = '\0';
		err = dev_rmdir(path);
		if (err)
			break;
	}

	kfree(path);
	return err;
}

static int dev_mynode(struct device *dev, struct inode *inode, struct kstat *stat)
{
	/* did we create it */
	if (inode->i_private != &thread)
		return 0;

	/* does the dev_t match */
	if (is_blockdev(dev)) {
		if (!S_ISBLK(stat->mode))
			return 0;
	} else {
		if (!S_ISCHR(stat->mode))
			return 0;
	}
	if (stat->rdev != dev->devt)
		return 0;

	/* ours */
	return 1;
}

static int handle_remove(const char *nodename, struct device *dev)
{
	struct path parent;
	struct dentry *dentry;
	int deleted = 0;
	int err;

	dentry = kern_path_locked(nodename, &parent);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (d_really_is_positive(dentry)) {
		struct kstat stat;
		struct path p = {.mnt = parent.mnt, .dentry = dentry};
		err = vfs_getattr(&p, &stat, STATX_TYPE | STATX_MODE,
				  AT_STATX_SYNC_AS_STAT);
		if (!err && dev_mynode(dev, d_inode(dentry), &stat)) {
			struct iattr newattrs;
			/*
			 * before unlinking this node, reset permissions
			 * of possible references like hardlinks
			 */
			newattrs.ia_uid = GLOBAL_ROOT_UID;
			newattrs.ia_gid = GLOBAL_ROOT_GID;
			newattrs.ia_mode = stat.mode & ~0777;
			newattrs.ia_valid =
				ATTR_UID|ATTR_GID|ATTR_MODE;
			inode_lock(d_inode(dentry));
			notify_change(&init_user_ns, dentry, &newattrs, NULL);
			inode_unlock(d_inode(dentry));
			err = vfs_unlink(&init_user_ns, d_inode(parent.dentry),
					 dentry, NULL);
			if (!err || err == -ENOENT)
				deleted = 1;
		}
	} else {
		err = -ENOENT;
	}
	dput(dentry);
	inode_unlock(d_inode(parent.dentry));

	path_put(&parent);
	if (deleted && strchr(nodename, '/'))
		delete_path(nodename);
	return err;
}

static DECLARE_COMPLETION(setup_done);

static int handle(const char *name, umode_t mode, kuid_t uid, kgid_t gid,
		  struct device *dev)
{
	if (mode)
		return handle_create(name, mode, uid, gid, dev);
	else
		return handle_remove(name, dev);
}

static void devtmpfs_work_loop(void)
{
	while (1) {
		spin_lock(&req_lock);
		while (requests) {
			struct req *req = requests;
			requests = NULL;
			spin_unlock(&req_lock);
			while (req) {
				struct req *next = req->next;
				req->err = handle(req->name, req->mode,
						  req->uid, req->gid, req->dev);
				complete(&req->done);
				req = next;
			}
			spin_lock(&req_lock);
		}
		if (kthread_should_stop()) {
			spin_unlock(&req_lock);
			return;
		}
		__set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock(&req_lock);
		schedule();
	}
}

static int devtmpfsd(void *p)
{
	struct path root = { .mnt = mnt, .dentry = mnt->mnt_root };
	const struct cred *old_cred = override_creds(node_cred);
	int err = unshare_fs_struct();

	/* Boot-only init_mount/chroot code has already been freed on a live device. */
	if (!err) {
		set_fs_root(current->fs, &root);
		set_fs_pwd(current->fs, &root);
	}
	*(int *)p = err;
	complete(&setup_done);
	if (!err)
		devtmpfs_work_loop();
	revert_creds(old_cred);
	return err;
}

int ds_devtmpfs_start(void)
{
	char opts[] = "mode=0755";
	int err;

	mnt = vfs_kern_mount(&internal_fs_type, 0, "devtmpfs", opts);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);
	/* Android's kernel domain need not have mknod permission after boot.
	 * Use the authorized loader's existing credentials for this private /dev. */
	node_cred = get_current_cred();
	thread = kthread_create(devtmpfsd, &err, "ds_devtmpfs");
	if (IS_ERR(thread)) {
		err = PTR_ERR(thread);
		thread = NULL;
		put_cred(node_cred);
		goto drop_mount;
	}
	get_task_struct(thread);
	wake_up_process(thread);
	wait_for_completion(&setup_done);
	if (err)
		goto stop_thread;
	err = register_filesystem(&dev_fs_type);
	if (!err)
		return 0;
stop_thread:
	kthread_stop(thread);
	put_task_struct(thread);
	put_cred(node_cred);
	thread = NULL;
drop_mount:
	mntput(mnt);
	return err;
}

/* Called only before device hooks become reachable. */
void ds_devtmpfs_stop(void)
{
	unregister_filesystem(&dev_fs_type);
	kthread_stop(thread);
	put_task_struct(thread);
	put_cred(node_cred);
	thread = NULL;
	mntput(mnt);
}
