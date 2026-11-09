// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include <linux/syscalls.h>
SYSCALL_DEFINE0(ds_getuid) { return from_kuid_munged(current_user_ns(), current_uid()); }
SYSCALL_DEFINE0(ds_geteuid) { return from_kuid_munged(current_user_ns(), current_euid()); }
SYSCALL_DEFINE0(ds_getgid) { return from_kgid_munged(current_user_ns(), current_gid()); }
SYSCALL_DEFINE0(ds_getegid) { return from_kgid_munged(current_user_ns(), current_egid()); }
