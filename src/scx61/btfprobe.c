// SPDX-License-Identifier: GPL-2.0-only
/* Answers one question on a device before the scheduler depends on it: does
 * this kernel take a module whose BTF was generated against a copy of
 * /sys/kernel/btf/vmlinux, and can that module register kfuncs for struct_ops
 * and tracing programs. Loads, reports and can be removed again.
 */
#define pr_fmt(fmt) "droidspaces_btfprobe: " fmt
#include <linux/module.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bpf.h>
#include <linux/sched.h>

__diag_push();
__diag_ignore_all("-Wmissing-prototypes", "kfuncs are called from BPF only");
noinline int ds_btfprobe_task_cpu(struct task_struct *p)
{
	return task_cpu(p);
}
__diag_pop();

BTF_SET8_START(ds_btfprobe_ids)
BTF_ID_FLAGS(func, ds_btfprobe_task_cpu)
BTF_SET8_END(ds_btfprobe_ids)

static const struct btf_kfunc_id_set ds_btfprobe_set = {
	.owner = THIS_MODULE,
	.set = &ds_btfprobe_ids,
};

static int struct_ops_ret, tracing_ret;
module_param(struct_ops_ret, int, 0400);
module_param(tracing_ret, int, 0400);

static int __init ds_btfprobe_init(void)
{
	struct_ops_ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &ds_btfprobe_set);
	tracing_ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &ds_btfprobe_set);
	pr_info("kfunc sets: struct_ops=%d tracing=%d\n", struct_ops_ret, tracing_ret);
	return 0;
}

static void __exit ds_btfprobe_exit(void)
{
}
module_init(ds_btfprobe_init);
module_exit(ds_btfprobe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Module BTF and kfunc registration probe");
