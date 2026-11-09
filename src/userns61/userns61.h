/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DS_USERNS61_H
#define DS_USERNS61_H
struct inode;
struct dentry;
struct file;
struct dir_context;
int ds_userns_core_init(void);
void ds_userns_core_drain(void);
int ds_userns_core_live(void);
void ds_userns_core_exit(void);
int ds_userns_proc_prepare(void);
void ds_userns_proc_cleanup(void);
struct dentry *ds_userns_tgid_lookup(struct inode *, struct dentry *, unsigned int);
struct dentry *ds_userns_tid_lookup(struct inode *, struct dentry *, unsigned int);
int ds_userns_tgid_readdir(struct file *, struct dir_context *);
int ds_userns_tid_readdir(struct file *, struct dir_context *);
#endif
