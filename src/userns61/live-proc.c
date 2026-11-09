// SPDX-License-Identifier: GPL-2.0-only
/* Native map handlers from fs/proc/base.c; retain existing native directory entries. */
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/user_namespace.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include "internal.h"
#include "core.h"
#include "userns61.h"

struct pid_entry {
    const char *name;
    unsigned int len;
    umode_t mode;
    const struct inode_operations *iop;
    const struct file_operations *fop;
    union proc_op op;
};
extern struct dentry *proc_pident_lookup(struct inode *, struct dentry *,
    const struct pid_entry *, const struct pid_entry *);
extern int proc_pident_readdir(struct file *, struct dir_context *,
    const struct pid_entry *, unsigned int);

static int proc_id_map_open(struct inode *inode, struct file *file,
	const struct seq_operations *seq_ops)
{
	struct user_namespace *ns = NULL;
	struct task_struct *task;
	struct seq_file *seq;
	int ret = -EINVAL;

	task = get_proc_task(inode);
	if (task) {
		rcu_read_lock();
		ns = get_user_ns(task_cred_xxx(task, user_ns));
		rcu_read_unlock();
		put_task_struct(task);
	}
	if (!ns)
		goto err;

	ret = seq_open(file, seq_ops);
	if (ret)
		goto err_put_ns;

	seq = file->private_data;
	seq->private = ns;

	return 0;
err_put_ns:
	put_user_ns(ns);
err:
	return ret;
}

static int proc_id_map_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct user_namespace *ns = seq->private;
	put_user_ns(ns);
	return seq_release(inode, file);
}

static int proc_uid_map_open(struct inode *inode, struct file *file)
{
	return proc_id_map_open(inode, file, &proc_uid_seq_operations);
}

static int proc_gid_map_open(struct inode *inode, struct file *file)
{
	return proc_id_map_open(inode, file, &proc_gid_seq_operations);
}

static int proc_projid_map_open(struct inode *inode, struct file *file)
{
	return proc_id_map_open(inode, file, &proc_projid_seq_operations);
}

static const struct file_operations proc_uid_map_operations = {
	.open		= proc_uid_map_open,
	.write		= proc_uid_map_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= proc_id_map_release,
};

static const struct file_operations proc_gid_map_operations = {
	.open		= proc_gid_map_open,
	.write		= proc_gid_map_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= proc_id_map_release,
};

static const struct file_operations proc_projid_map_operations = {
	.open		= proc_projid_map_open,
	.write		= proc_projid_map_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= proc_id_map_release,
};

static int proc_setgroups_open(struct inode *inode, struct file *file)
{
	struct user_namespace *ns = NULL;
	struct task_struct *task;
	int ret;

	ret = -ESRCH;
	task = get_proc_task(inode);
	if (task) {
		rcu_read_lock();
		ns = get_user_ns(task_cred_xxx(task, user_ns));
		rcu_read_unlock();
		put_task_struct(task);
	}
	if (!ns)
		goto err;

	if (file->f_mode & FMODE_WRITE) {
		ret = -EACCES;
		if (!ns_capable(ns, CAP_SYS_ADMIN))
			goto err_put_ns;
	}

	ret = single_open(file, &proc_setgroups_show, ns);
	if (ret)
		goto err_put_ns;

	return 0;
err_put_ns:
	put_user_ns(ns);
err:
	return ret;
}

static int proc_setgroups_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct user_namespace *ns = seq->private;
	int ret = single_release(inode, file);
	put_user_ns(ns);
	return ret;
}

static const struct file_operations proc_setgroups_operations = {
	.open		= proc_setgroups_open,
	.write		= proc_setgroups_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= proc_setgroups_release,
};
#define MAP_ENTRY(n, f) { .name = n, .len = sizeof(n)-1, .mode = S_IFREG|0644, .fop = &f }
static const struct pid_entry new_entries[] = {
    MAP_ENTRY("uid_map", proc_uid_map_operations),
    MAP_ENTRY("gid_map", proc_gid_map_operations),
    MAP_ENTRY("projid_map", proc_projid_map_operations),
    MAP_ENTRY("setgroups", proc_setgroups_operations),
};
static struct pid_entry *tgid_entries, *tid_entries;
static unsigned int tgid_count, tid_count;

static int prepare_entries(const char *name, struct pid_entry **out, unsigned int *count)
{
    unsigned long address = kallsyms_name_to_addr(name), size = 0, offset = 0;
    struct pid_entry *entries;
    unsigned int i, n;
    if (!address || !kallsyms_lookup_size_offset(address, &size, &offset) || offset ||
        size < sizeof(*entries) || size > 256 * sizeof(*entries)) {
        pr_err("userns: table %s size=%lu offset=%lu entry=%zu\n", name, size, offset, sizeof(*entries));
        return -EINVAL;
    }
    n = size / sizeof(*entries);
    entries = kmalloc(size + sizeof(new_entries), GFP_KERNEL);
    if (!entries) return -ENOMEM;
    if (safe_read(entries, (void *)address, size)) { kfree(entries); return -EFAULT; }
    for (i = 0; i < n; i++) {
        char namebuf[64];
        /* kallsyms reports the distance to the next symbol, including the
         * cacheline padding after this array. Accept only a zero-filled tail. */
        if (size - i * sizeof(*entries) < 64 &&
            !memchr_inv(entries + i, 0, size - i * sizeof(*entries))) {
            n = i;
            break;
        }
        if (!entries[i].len || entries[i].len >= sizeof(namebuf) ||
            safe_read(namebuf, entries[i].name, entries[i].len + 1) ||
            namebuf[entries[i].len] || !strcmp(namebuf, "uid_map")) {
            pr_err("userns: invalid %s entry %u of %u len=%u\n", name, i, n, entries[i].len);
            kfree(entries);
            return -EINVAL;
        }
    }
    if (!n || memchr_inv(entries + n, 0, size - n * sizeof(*entries))) {
        kfree(entries);
        return -EINVAL;
    }
    pr_info("userns: %s preserves %u native entries, adds %zu mapping entries\n",
            name, n, ARRAY_SIZE(new_entries));
    memcpy(entries + n, new_entries, sizeof(new_entries));
    *out = entries;
    *count = n + ARRAY_SIZE(new_entries);
    return 0;
}
int ds_userns_proc_prepare(void)
{
    int ret = prepare_entries("tgid_base_stuff", &tgid_entries, &tgid_count);
    if (ret) return ret;
    ret = prepare_entries("tid_base_stuff", &tid_entries, &tid_count);
    if (ret) { kfree(tgid_entries); tgid_entries = NULL; }
    return ret;
}
void ds_userns_proc_cleanup(void)
{
    kfree(tgid_entries);
    kfree(tid_entries);
    tgid_entries = tid_entries = NULL;
}
struct dentry *ds_userns_tgid_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    return proc_pident_lookup(dir, dentry, tgid_entries, tgid_entries + tgid_count);
}
struct dentry *ds_userns_tid_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    return proc_pident_lookup(dir, dentry, tid_entries, tid_entries + tid_count);
}
int ds_userns_tgid_readdir(struct file *file, struct dir_context *ctx)
{
    return proc_pident_readdir(file, ctx, tgid_entries, tgid_count);
}
int ds_userns_tid_readdir(struct file *file, struct dir_context *ctx)
{
    return proc_pident_readdir(file, ctx, tid_entries, tid_count);
}
