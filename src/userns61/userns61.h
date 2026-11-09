/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DS_USERNS61_H
#define DS_USERNS61_H
struct inode;
struct dentry;
struct file;
struct dir_context;
#include <linux/types.h>
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
struct cred;
struct linux_binprm;
long ds_identity_setregid(gid_t rgid, gid_t egid);
long ds_identity_setgid(gid_t gid);
long ds_identity_setreuid(uid_t ruid, uid_t euid);
long ds_identity_setuid(uid_t uid);
long ds_identity_setresuid(uid_t ruid, uid_t euid, uid_t suid);
long ds_identity_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
long ds_identity_setfsuid(uid_t uid);
long ds_identity_setfsgid(gid_t gid);
bool ds_identity_may_setgroups(void);
int ds_cap_task_fix_setuid(struct cred *new, const struct cred *old, int flags);
int ds_cap_bprm_creds_from_file(struct linux_binprm *bprm, struct file *file);
#endif
