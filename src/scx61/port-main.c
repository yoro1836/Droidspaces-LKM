// SPDX-License-Identifier: GPL-2.0-only
/*
 * sched_ext for android14-6.1: upstream's kernel/sched/ext.c as a module.
 *
 * ext-port.c is upstream's code with its 6.1 glue, port-btf.c makes the
 * kernel's struct_ops and BTF accept it. This file loads them and puts the
 * class into the idle class's slot: the scheduler core orders its classes by
 * address and walks a fixed array, so a class in module memory would never
 * be picked, while the idle slot is the last one, which is where ext sits
 * upstream, just above idle. The idle methods are entered through kprobes
 * that move the PC to the glue, so nothing writes kernel memory and the same
 * module works under Samsung EL2.
 */
#define pr_fmt(fmt) "droidspaces_scx: " fmt
#include <linux/module.h>
#include <linux/of.h>
#include <linux/utsname.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include "core.h"
#include "hint.h"
#include "../gki-target.h"
#include "port.h"

struct rq;
struct task_struct *scx61_pick_next_task(struct rq *rq);
void scx61_put_prev_task(struct rq *rq, struct task_struct *p);
void scx61_set_next_task(struct rq *rq, struct task_struct *p, bool first);
void scx61_check_preempt_curr(struct rq *rq, struct task_struct *p, int flags);
void scx61_task_tick(struct rq *rq, struct task_struct *curr, int queued);
int scx61_select_task_rq(struct task_struct *p, int prev_cpu, int wake_flags);
void scx61_update_curr(struct rq *rq);

struct scx_kprobe {
	struct kprobe kp;
	unsigned long replacement;
};

static int kp_pre(struct kprobe *kp, struct pt_regs *regs)
{
	instruction_pointer_set(regs, container_of(kp, struct scx_kprobe, kp)->replacement);
	return 1;
}

#define SCX_KP(sym, fn) { .kp = { .symbol_name = sym, .pre_handler = kp_pre }, \
			  .replacement = (unsigned long)(fn) }
static struct scx_kprobe kps[] = {
	SCX_KP("pick_next_task_idle", scx61_pick_next_task),
	SCX_KP("put_prev_task_idle", scx61_put_prev_task),
	/* The first instruction is a static branch site, which kprobes refuse. */
	{ .kp = { .symbol_name = "set_next_task_idle", .offset = 4, .pre_handler = kp_pre },
	  .replacement = (unsigned long)scx61_set_next_task },
	SCX_KP("check_preempt_curr_idle", scx61_check_preempt_curr),
	SCX_KP("task_tick_idle", scx61_task_tick),
	SCX_KP("select_task_rq_idle", scx61_select_task_rq),
	SCX_KP("update_curr_idle", scx61_update_curr),
};

static int __init scx_port_init(void)
{
	struct kallrecon_hint hint = { .timeout_ms = 15000 };
	const struct sched_class *idle, *fair;
	unsigned int i;
	int ret;

	if (!ds_gki_target_supported()) {
		pr_err("requires matching " DS_GKI_ANDROID "-" DS_GKI_VERSION " with gki=1 or the build VM\n");
		return -EOPNOTSUPP;
	}
	ret = kallrecon_supply(&hint);
	if (ret)
		return ret;
	find_kallsyms_base();
	if (!kallrecon_ready())
		return -ENODATA;
	/* The whole design rests on idle being the slot right after fair. */
	idle = (void *)kallsyms_name_to_addr("idle_sched_class");
	fair = (void *)kallsyms_name_to_addr("fair_sched_class");
	if (!idle || !fair || (void *)idle - (void *)fair > 512)
		return -EOPNOTSUPP;

	/* Samsung's EMS must be kept from running our tasks itself, see
	 * scx61_ems_forget(). Without its BTF the node's place is not known
	 * for sure, and guessing it would have us write into EMS's data.
	 */
	if (kallsyms_name_to_addr("tex_replace_next_task_fair")) {
		int node = scx61_module_member_offset("ems", "ems_task_struct", "qjump_node");
		int nr_tex = scx61_module_member_offset("ems", "_rq_avd1", "nr_tex");

		if (node < 0 || nr_tex < 0) {
			pr_err("Samsung EMS without BTF: cannot coexist with it\n");
			return -EOPNOTSUPP;
		}
		pr_info("Samsung EMS: queue jump node at +%d, count at +%d\n", node, nr_tex);
		scx61_set_ems_qjump(offsetof(struct task_struct, android_vendor_data1) + node, nr_tex);
	}

	/* Types first: upstream registers kfuncs by BTF id. Nothing of the
	 * class is entered before a scheduler is loaded, so the idle slot is
	 * taken last.
	 */
	ret = scx61_btf_init();
	if (ret)
		return ret;
	__module_get(THIS_MODULE);
	ret = scx61_glue_init();
	if (ret) {
		pr_err("sched_ext core: %d\n", ret);
		return ret;
	}
	ret = scx61_struct_ops_init();
	if (ret)
		pr_err("struct_ops: %d, no scheduler can be loaded\n", ret);
	for (i = 0; i < ARRAY_SIZE(kps); i++) {
		ret = register_kprobe(&kps[i].kp);
		if (ret) {
			pr_err("kprobe %s: %d\n", kps[i].kp.symbol_name, ret);
			return 0;
		}
	}
	pr_info("sched_ext (6.12) is ready\n");
	return 0;
}
module_init(scx_port_init);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("sched_ext for android14-6.1");
