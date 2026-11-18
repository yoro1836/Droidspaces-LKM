// SPDX-License-Identifier: GPL-2.0-only
/*
 * sched_ext for android14-6.1: upstream's kernel/sched/ext.c as a module.
 *
 * ext-port.c is upstream's code with its 6.1 glue, btf.c makes the
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
#include "hooks.h"

struct rq;
struct task_struct *scx61_pick_next_task(struct rq *rq);
void scx61_put_prev_task(struct rq *rq, struct task_struct *p);
void scx61_set_next_task(struct rq *rq, struct task_struct *p, bool first);
void scx61_check_preempt_curr(struct rq *rq, struct task_struct *p, int flags);
void scx61_task_tick(struct rq *rq, struct task_struct *curr, int queued);
int scx61_select_task_rq(struct task_struct *p, int prev_cpu, int wake_flags);
void scx61_update_curr(struct rq *rq);
struct hrtimer;
int scx61_bpf_timer_cb(struct hrtimer *hrtimer);
u64 scx61_bpf_loop(u64 nr_loops, u64 callback_fn, u64 callback_ctx, u64 flags, u64 r5);

/* The idle class's methods, entered by moving the PC from a kprobe: the core
 * calls them through the idle slot that the class sits in. Last in init,
 * since nothing of the class runs before a scheduler is loaded anyway.
 */
static struct scx61_hook idle_hooks[] = {
	SCX61_REDIRECT_HOOK("pick_next_task_idle", scx61_pick_next_task, SCX61_RQ_LOCKED, true,
			    "the class's pick"),
	SCX61_REDIRECT_HOOK("put_prev_task_idle", scx61_put_prev_task, SCX61_RQ_LOCKED, true,
			    "the class's put_prev, deferred to our pick"),
	/* The first instruction is a static branch site, which kprobes refuse. */
	{ .name = "set_next_task_idle", .kind = SCX61_REDIRECT, .ctx = SCX61_RQ_LOCKED, .hot = true,
	  .why = "the class's set_next", .to = (unsigned long)scx61_set_next_task, .offset = 4 },
	SCX61_REDIRECT_HOOK("check_preempt_curr_idle", scx61_check_preempt_curr, SCX61_RQ_LOCKED, true,
			    "a wakeup of ours against a running task of ours"),
	SCX61_REDIRECT_HOOK("task_tick_idle", scx61_task_tick, SCX61_RQ_LOCKED, true,
			    "the class's tick"),
	SCX61_REDIRECT_HOOK("select_task_rq_idle", scx61_select_task_rq, SCX61_PI_LOCKED, true,
			    "ops.select_cpu() on wakeup"),
	SCX61_REDIRECT_HOOK("update_curr_idle", scx61_update_curr, SCX61_RQ_LOCKED, true,
			    "runtime accounting of the running task"),
	/* see bpf-fixes.c */
	SCX61_REDIRECT_HOOK("bpf_timer_cb", scx61_bpf_timer_cb, SCX61_BPF, false,
			    "BPF timers call their callback without a kCFI type word"),
	SCX61_REDIRECT_HOOK("bpf_loop", scx61_bpf_loop, SCX61_BPF, false,
			    "bpf_loop() calls its callback without a kCFI type word"),
};

static int __init scx_port_init(void)
{
	struct kallrecon_hint hint = { .timeout_ms = 15000 };
	const struct sched_class *idle, *fair;
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
	 * scx61_ems_forget(). It is known by its module BTF, which also says
	 * where its list node is: guessing that would have us write into its
	 * data. Anything else that hooks fair's pick is not known at all.
	 */
	{
		int node = scx61_module_member_offset("ems", "ems_task_struct", "qjump_node");
		int nr_tex = scx61_module_member_offset("ems", "_rq_avd1", "nr_tex");

		if (node >= 0 && nr_tex >= 0) {
			pr_info("Samsung EMS: queue jump node at +%d, count at +%d\n", node, nr_tex);
			scx61_set_ems_qjump(offsetof(struct task_struct, android_vendor_data1) + node,
					    nr_tex);
		} else if (scx61_fair_pick_is_hooked()) {
			/* EMS was once looked for by a function name, which its
			 * build on the device did not have: the device went down.
			 */
			pr_err("a module replaces fair's pick and is not an EMS with BTF (%d, %d): "
			       "cannot coexist with it\n", node, nr_tex);
			return -EOPNOTSUPP;
		} else {
			pr_info("no Samsung EMS\n");
		}
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
	scx61_set_storage_busy((void *)kallsyms_name_to_addr("bpf_task_storage_busy"));
	if (!kallsyms_name_to_addr("bpf_task_storage_busy"))
		pr_warn("no bpf_task_storage_busy, task storage lookups can fail under load\n");
	scx61_set_hrtimer_running((void *)kallsyms_name_to_addr("hrtimer_running"));
	if (!kallsyms_name_to_addr("hrtimer_running"))
		return -ENOENT;
	ret = scx61_cpumask_init() ?: scx61_task_kfuncs_init();
	if (ret)
		pr_warn("cpumask and task kfuncs: %d, schedulers that use them will not load\n", ret);
	ret = scx61_kptr_init();
	if (ret)
		pr_warn("kptr rules: %d, schedulers that keep cpumasks per task will not load\n", ret);
	ret = scx61_struct_ops_init();
	if (ret)
		pr_err("struct_ops: %d, no scheduler can be loaded\n", ret);
	/* A failure here leaves the module loaded and the class not entered:
	 * it can no longer be unloaded, see scx61_glue_init().
	 */
	if (scx61_hooks_register(idle_hooks, ARRAY_SIZE(idle_hooks)))
		return 0;
	pr_info("sched_ext (6.12) is ready\n");
	return 0;
}
module_init(scx_port_init);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("sched_ext for android14-6.1");
