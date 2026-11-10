// SPDX-License-Identifier: GPL-2.0-only
/*
 * Seccomp filters without no_new_privs for a task that has CAP_SYS_ADMIN
 * in its own user namespace.
 *
 * seccomp_prepare_filter() (vendor kernel/seccomp.c) requires
 *
 *	task_no_new_privs(current) ||
 *	ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN)
 *
 * and natively current_user_ns() is the constant &init_user_ns, so root in
 * a child namespace got EACCES unless it set no_new_privs (rootless
 * container runtimes with a seccomp profile). The check is inlined into
 * do_seccomp() on android14-6.1, and seccomp.c is not copied.
 *
 * A kprobe on ns_capable_noaudit() rewrites its first argument from
 * &init_user_ns to the caller's user namespace for exactly that call: the
 * capability is CAP_SYS_ADMIN and the return address lies in one of the
 * seccomp functions the check can be compiled into. The native function
 * then evaluates what upstream evaluates. Every other caller, and every
 * task in init_user_ns, is left alone.
 */
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/user_namespace.h>
#include "core.h"
#include "userns61.h"

static const char *const seccomp_callers[] = {
	"do_seccomp", "seccomp_set_mode_filter",
	"seccomp_prepare_user_filter", "seccomp_prepare_filter",
};
static struct { unsigned long start, size; } seccomp_ranges[ARRAY_SIZE(seccomp_callers)];
static unsigned int seccomp_range_count;

static int ns_capable_noaudit_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct user_namespace *ns;
	unsigned int i;

	if ((int)regs->regs[1] != CAP_SYS_ADMIN ||
	    (struct user_namespace *)regs->regs[0] != &init_user_ns)
		return 0;
	ns = current_user_ns();
	if (ns == &init_user_ns)
		return 0;
	/* At the entry x30 still holds the plain return address. */
	for (i = 0; i < seccomp_range_count; i++) {
		if (regs->regs[30] - seccomp_ranges[i].start < seccomp_ranges[i].size) {
			regs->regs[0] = (unsigned long)ns;
			break;
		}
	}
	return 0;
}

static struct kprobe ns_capable_noaudit_probe = {
	.symbol_name = "ns_capable_noaudit",
	.pre_handler = ns_capable_noaudit_pre,
};

int ds_seccomp_register(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(seccomp_callers); i++) {
		unsigned long address = kallsyms_name_to_addr(seccomp_callers[i]);
		unsigned long size = 0, offset = 0;

		if (!address || !kallsyms_lookup_size_offset(address, &size, &offset) ||
		    offset || !size)
			continue;
		seccomp_ranges[seccomp_range_count].start = address;
		seccomp_ranges[seccomp_range_count].size = size;
		seccomp_range_count++;
	}
	if (!seccomp_range_count)
		return -ENOENT;
	return register_kprobe(&ns_capable_noaudit_probe);
}
