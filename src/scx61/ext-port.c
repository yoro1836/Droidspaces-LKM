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
#include "ext-gen.c"

/* upstream registers itself from an initcall; a module has one of its own. */
int __init scx61_core_init(void)
{
	return scx_init();
}
