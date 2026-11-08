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

static bool activate;
module_param(activate, bool, 0400);
MODULE_PARM_DESC(activate, "Install experimental hooks on the validated target kernel");

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
	bool device_kernel = !strcmp(utsname()->release,
		"6.12.69-android16-6-g242e1a07f878-ab15865446-4k");
	bool device = device_kernel && of_machine_is_compatible("qcom,canoe");
#endif
	int ret;

#ifdef DS_GKI_ANDROID
	if (!ds_gki_target_supported()) {
		pr_err("requires matching " DS_GKI_ANDROID "-" DS_GKI_VERSION " with gki=1 or the build VM\n");
		return -EOPNOTSUPP;
	}
#else
	if (strncmp(utsname()->release, "6.12.", 5))
		return -EOPNOTSUPP;
	if ((!device_kernel && (!vm || strcmp(utsname()->release,
		"6.12.76-4k-gae4e2f4f997e-dirty"))) || (!vm && !device)) {
		pr_err("this build supports only the recorded canoe device and QEMU kernels\n");
		return -EOPNOTSUPP;
	}
#endif
	ret = kallrecon_supply(&hint);
	if (ret)
		return ret;
	find_kallsyms_base();
	if (!kallrecon_ready())
		return -ENODATA;
	if (kallsyms_name_to_addr("pidns_operations") ||
	    kallsyms_name_to_addr("ipcns_operations")) {
		pr_err("this prototype requires native PID/IPC namespaces to be absent\n");
		return -EOPNOTSUPP;
	}
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
MODULE_DESCRIPTION("Experimental PID/IPC namespace port with target-specific hooks");
