// SPDX-License-Identifier: GPL-2.0-only
/* Preserve the host reboot handler; child namespaces use the upstream PID helper. */
#include <linux/capability.h>
#include <linux/pid_namespace.h>
#include <linux/reboot.h>
#include <asm/ptrace.h>

long (*ds_native_reboot)(const struct pt_regs *regs);
extern bool ds_kprobe_hooks;
extern long ds_kp_reboot(const struct pt_regs *regs);

asmlinkage long __arm64_sys_ds_reboot(const struct pt_regs *regs)
{
	struct pid_namespace *ns = task_active_pid_ns(current);
	int magic1 = regs->regs[0], magic2 = regs->regs[1];
	unsigned int cmd = regs->regs[2];

	if (ns == &init_pid_ns)
		return ds_kprobe_hooks ? ds_kp_reboot(regs) : ds_native_reboot(regs);
	if (!ns_capable(ns->user_ns, CAP_SYS_BOOT))
		return -EPERM;
	if (magic1 != LINUX_REBOOT_MAGIC1 ||
	    (magic2 != LINUX_REBOOT_MAGIC2 && magic2 != LINUX_REBOOT_MAGIC2A &&
	     magic2 != LINUX_REBOOT_MAGIC2B && magic2 != LINUX_REBOOT_MAGIC2C))
		return -EINVAL;
	return reboot_pid_ns(ns, cmd);
}
