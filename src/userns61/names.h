/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DS_USERNS61_NAMES_H
#define DS_USERNS61_NAMES_H
/* Native cred lifecycle (prepare_creds, commit_creds, __put_cred, copy_creds)
 * is NOT renamed: on Samsung KDP it must stay the vendor's implementation. */
#define create_user_ns ds_un_create_user_ns
#define unshare_userns ds_un_unshare_userns
#define __put_user_ns ds_un___put_user_ns
#define map_id_down ds_un_map_id_down
#define map_id_up ds_un_map_id_up
#define make_kuid ds_un_make_kuid
#define from_kuid ds_un_from_kuid
#define from_kuid_munged ds_un_from_kuid_munged
#define make_kgid ds_un_make_kgid
#define from_kgid ds_un_from_kgid
#define from_kgid_munged ds_un_from_kgid_munged
#define make_kprojid ds_un_make_kprojid
#define from_kprojid ds_un_from_kprojid
#define from_kprojid_munged ds_un_from_kprojid_munged
#define proc_uid_seq_operations ds_un_proc_uid_seq_operations
#define proc_gid_seq_operations ds_un_proc_gid_seq_operations
#define proc_projid_seq_operations ds_un_proc_projid_seq_operations
#define proc_uid_map_write ds_un_proc_uid_map_write
#define proc_gid_map_write ds_un_proc_gid_map_write
#define proc_projid_map_write ds_un_proc_projid_map_write
#define proc_setgroups_show ds_un_proc_setgroups_show
#define proc_setgroups_write ds_un_proc_setgroups_write
#define userns_may_setgroups ds_un_userns_may_setgroups
#define in_userns ds_un_in_userns
#define current_in_userns ds_un_current_in_userns
#define ns_get_owner ds_un_ns_get_owner
#define userns_operations ds_un_userns_operations
#endif
