// SPDX-License-Identifier: GPL-2.0
/* Upstream's kernel/sched/ext.c, compiled for android14-6.1. The code is in
 * ext-gen.c, generated from upstream/ext.c; this file only sets the scene the
 * way kernel/sched/build_policy.c does upstream.
 */
#define pr_fmt(fmt) "sched_ext: " fmt
#include <linux/module.h>
#include <linux/sched/cputime.h>
#include <linux/sched/isolation.h>
#include <linux/cpuidle.h>
#include <linux/kthread.h>
#include <linux/suspend.h>
#include <linux/sysrq.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include "kernel/sched/sched.h"
#include "compat.h"
#include "ext-gen.h"
/* upstream calls into the BPF scheduler through function pointers that hold
 * BPF trampolines, which carry no kCFI type word. Checking is off for the
 * calls made from this file; its own functions keep their type words.
 */
#pragma clang attribute push(__attribute__((no_sanitize("kcfi"))), apply_to = function)
#include "ext-gen.c"

#include "ext-glue.c"
#pragma clang attribute pop
