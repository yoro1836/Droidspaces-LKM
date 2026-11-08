// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "droidspaces_ns: " fmt
#include <linux/module.h>
#include <linux/utsname.h>
#include <linux/of.h>
#include "core.h"
#include "hint.h"
#include "port.h"
#include "ipc-backend.h"
#include "../gki-target.h"

extern void (*ds_proc_exit_connector)(struct task_struct *task);

static bool plc110_test;
module_param(plc110_test, bool, 0400);
MODULE_PARM_DESC(plc110_test, "Opt in to PLC110 testing on the exact recorded 6.6.118 kernel");

static bool activate;
module_param(activate, bool, 0400);
MODULE_PARM_DESC(activate, "Install experimental hooks on a recorded 6.6 kernel");

static int live_count_get(char *buffer, const struct kernel_param *param)
{
	return scnprintf(buffer, PAGE_SIZE, "%d\n",
			 atomic_read((const atomic_t *)param->arg));
}

static const struct kernel_param_ops live_count_ops = {
	.get = live_count_get,
};
module_param_cb(pid_live, &live_count_ops, &ds_pid_live, 0400);
module_param_cb(ipc_live, &live_count_ops, &ds_ipc_live, 0400);
module_param_cb(ipc_tasks, &live_count_ops, &ds_ipc_task_live, 0400);

static int __init ds_port_init(void)
{
	/* TCG discovery can exceed five seconds under host CPU contention. */
	struct kallrecon_hint hint = { .timeout_ms = 15000 };
#ifndef DS_GKI_ANDROID
	bool vm = of_machine_is_compatible("linux,dummy-virt");
	bool plc110_kernel = !strcmp(utsname()->release,
		"6.6.118-android15-8-ge58033dc8ea6-abogki498046332-4k");
#endif
	int ret;

#ifdef DS_GKI_ANDROID
	if (!ds_gki_target_supported()) {
		pr_err("requires matching " DS_GKI_ANDROID "-" DS_GKI_VERSION " with gki=1 or the build VM\n");
		return -EOPNOTSUPP;
	}
#else
	/* Android model/BTF checks live in the supplied device test loader. */
	if ((!plc110_kernel && (!vm || strcmp(utsname()->release,
		"6.6.127-4k-g46a034eca005-dirty"))) ||
	    (!vm && !plc110_test)) {
		pr_err("requires a recorded QEMU kernel or PLC110 6.6.118 with plc110_test=1; got %s\n",
		       utsname()->release);
		return -EOPNOTSUPP;
	}
	if (!vm)
		pr_info("PLC110 device test opted in; kernel=%s\n", utsname()->release);
#endif
	ret = kallrecon_supply(&hint);
	if (ret)
		return ret;
	find_kallsyms_base();
	if (!kallrecon_ready()) {
		pr_err("KallRecon discovery failed: reason=%d symbols=%u\n",
		       kallrecon_fail_reason(), klnum_val);
		return -ENODATA;
	}
	if (kallsyms_name_to_addr("pidns_operations") ||
	    !kallsyms_name_to_addr("ipcns_operations") ||
	    kallsyms_name_to_addr("msg_init_ns")) {
		pr_err("this profile requires missing PID/SysV IPC and native IPC namespaces\n");
		return -EOPNOTSUPP;
	}
	ds_proc_exit_connector = (void *)kallsyms_name_to_addr("proc_exit_connector");
	if (!ds_proc_exit_connector &&
	    !strcmp(utsname()->release, "6.6.127-4k-g46a034eca005-dirty"))
		return -ENOENT;
	ret = ds_hooks_prepare();
	if (ret)
		return ret;
	ret = ds_pid_init();
	if (ret)
		return ret;
	ret = ds_ipc_backend_init();
	if (ret) {
		ds_pid_exit();
		return ret;
	}
	ret = ds_port_selftest();
	if (ret) {
		ds_ipc_backend_exit();
		ds_ipc_flush();
		ds_pid_exit();
		return ret;
	}
	if (activate) {
		ret = ds_hooks_install();
		if (ret) {
			ds_ipc_backend_exit();
			ds_pid_exit();
			return ret;
		}
		pr_info("experimental namespace hooks active; module stays pinned until reboot\n");
	} else {
		pr_info("namespace core selftests passed; syscall hooks are not installed\n");
	}
	return 0;
}

static void __exit ds_port_exit(void)
{
	ds_ipc_backend_exit();
	ds_ipc_flush();
	ds_pid_exit();
	pr_info("unloaded\n");
}

module_init(ds_port_init);
module_exit(ds_port_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Experimental PID/IPC namespace port for recorded 6.6 kernels and PLC110 testing");
