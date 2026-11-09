// SPDX-License-Identifier: GPL-2.0-only
/* Experimental entry replacements for the validated target kernel. */
#define pr_fmt(fmt) "droidspaces_ns: " fmt
#include <linux/module.h>
#include <linux/stop_machine.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/compat.h>
#include <linux/pid_namespace.h>
#include <linux/proc_ns.h>
#include <linux/fs_context.h>
#include <asm/patching.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/sched/task.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include "fs/fuse/fuse_i.h"
#include "core.h"
#include "port.h"
#include "ipc-backend.h"

extern const struct file_operations ds_proc_ns_dir_operations;
extern const struct inode_operations ds_proc_ns_dir_inode_operations;
extern long __arm64_sys_ds_setns(const struct pt_regs *regs);
extern void ds_delayed_put_pid(struct rcu_head *rcu);
extern int ds_proc_init_fs_context(struct fs_context *fc);
extern void ds_proc_kill_sb(struct super_block *sb);
extern pid_t ds_kernel_clone(struct kernel_clone_args *args);
extern int ds_ksys_unshare(unsigned long flags);

extern long (*ds_native_reboot)(const struct pt_regs *);
extern void ds_fuse_conn_init(struct fuse_conn *, struct fuse_mount *,
	struct user_namespace *, const struct fuse_iqueue_ops *, void *);
extern void ds_fuse_delayed_release(struct rcu_head *);
extern void *ds_cgroup_pidlist_start(struct seq_file *, loff_t *);
extern int ds_bpf_init_seq_pidns(void *, struct bpf_iter_aux_info *);
extern void ds_bpf_fini_seq_pidns(void *);
extern struct perf_event *ds_perf_event_alloc(struct perf_event_attr *, int,
	struct task_struct *, struct perf_event *, struct perf_event *,
	perf_overflow_handler_t, void *, int);
extern void ds_perf_free_event_rcu(struct rcu_head *);
extern u32 ds_perf_alloc_original[], ds_perf_free_original[];

struct ds_pointer_hook {
	unsigned long *slot;
	unsigned long saved, replacement;
};
static struct ds_pointer_hook bpf_hooks[6];

static bool matching_cfi(unsigned long native, unsigned long replacement)
{
	u32 host_type, module_type;

	if (!IS_ENABLED(CONFIG_CFI_CLANG))
		return true;
	return !safe_read(&host_type, (void *)(native - sizeof(u32)), sizeof(u32)) &&
		!safe_read(&module_type, (void *)(replacement - sizeof(u32)), sizeof(u32)) &&
		host_type == module_type;
}

static int write_pointer(unsigned long *slot, unsigned long value)
{
	u32 *words = (u32 *)slot;
	int ret = aarch64_insn_patch_text_nosync(words, lower_32_bits(value));
	return ret ? ret : aarch64_insn_patch_text_nosync(words + 1, upper_32_bits(value));
}

static int prepare_bpf_hooks(void)
{
	static const char *const names[] = { "task_seq_info", "task_file_seq_info", "task_vma_seq_info" };
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		struct bpf_iter_seq_info *info = (void *)kallsyms_name_to_addr(names[i]);
		struct ds_pointer_hook *init = &bpf_hooks[i * 2], *fini = init + 1;
		if (!info)
			return -ENOENT;
		init->slot = (void *)&info->init_seq_private;
		fini->slot = (void *)&info->fini_seq_private;
		if (safe_read(&init->saved, init->slot, sizeof(init->saved)) ||
		    safe_read(&fini->saved, fini->slot, sizeof(fini->saved)) ||
		    init->saved != kallsyms_name_to_addr("init_seq_pidns") ||
		    fini->saved != kallsyms_name_to_addr("fini_seq_pidns"))
			return -EINVAL;
		init->replacement = (unsigned long)ds_bpf_init_seq_pidns;
		fini->replacement = (unsigned long)ds_bpf_fini_seq_pidns;
		if (!matching_cfi(init->saved, init->replacement) ||
		    !matching_cfi(fini->saved, fini->replacement))
			return -EPROTOTYPE;
	}
	return 0;
}

#define DECLARE_IPC_SYSCALL(name) extern long __arm64_sys_ds_##name(const struct pt_regs *)
DECLARE_IPC_SYSCALL(msgget);
DECLARE_IPC_SYSCALL(msgctl);
DECLARE_IPC_SYSCALL(msgsnd);
DECLARE_IPC_SYSCALL(msgrcv);
DECLARE_IPC_SYSCALL(semget);
DECLARE_IPC_SYSCALL(semctl);
DECLARE_IPC_SYSCALL(semop);
DECLARE_IPC_SYSCALL(semtimedop);
DECLARE_IPC_SYSCALL(shmget);
DECLARE_IPC_SYSCALL(shmctl);
DECLARE_IPC_SYSCALL(shmat);
DECLARE_IPC_SYSCALL(shmdt);
DECLARE_IPC_SYSCALL(reboot);
#ifdef DS_USERNS_LIVE
#include "../userns61/userns61.h"
/* Native identity syscalls return raw kuids: the kernel lacks USER_NS. */
DECLARE_IPC_SYSCALL(getuid);
DECLARE_IPC_SYSCALL(geteuid);
DECLARE_IPC_SYSCALL(getgid);
DECLARE_IPC_SYSCALL(getegid);
#define ID_SYSCALL(name) { "__arm64_sys_" #name, __NR_##name, (unsigned long)__arm64_sys_ds_##name, 0 }
#endif

/*
 * Built without PID_NS/USER_NS, the kernel leaves init_pid_ns.ns.ops and
 * init_user_ns.ns.ops NULL. Once /proc/<pid>/ns/{pid,user} exist, nsfs
 * inodes point at these and nsfs_evict() calls ns->ops->put(), so both must
 * be set whenever the namespace files are reachable.
 */
static void set_init_ns_ops(bool live)
{
	WRITE_ONCE(init_pid_ns.ns.ops, live ? &pidns_operations : NULL);
#ifdef DS_USERNS_LIVE
	WRITE_ONCE(init_user_ns.ns.ops, live ? &userns_operations : NULL);
#endif
}


struct ds_syscall_hook {
	const char *name;
	unsigned int nr;
	unsigned long replacement, saved;
};
#define GUARDED_SYSCALL(name) \
static long ds_guard_##name(const struct pt_regs *regs) { \
	int ret = ds_ipc_ensure(ds_current_ipc_ns()); \
	return ret ? ret : __arm64_sys_ds_##name(regs); \
}
GUARDED_SYSCALL(msgget) GUARDED_SYSCALL(msgctl)
GUARDED_SYSCALL(msgsnd) GUARDED_SYSCALL(msgrcv)
GUARDED_SYSCALL(semget) GUARDED_SYSCALL(semctl)
GUARDED_SYSCALL(semop) GUARDED_SYSCALL(semtimedop)
GUARDED_SYSCALL(shmget) GUARDED_SYSCALL(shmctl)
GUARDED_SYSCALL(shmat) GUARDED_SYSCALL(shmdt)
#define IPC_SYSCALL(name) { "__arm64_sys_" #name, __NR_##name, (unsigned long)ds_guard_##name, 0 }
static struct ds_syscall_hook ipc_syscalls[] = {
	IPC_SYSCALL(msgget), IPC_SYSCALL(msgctl), IPC_SYSCALL(msgsnd), IPC_SYSCALL(msgrcv),
	IPC_SYSCALL(semget), IPC_SYSCALL(semctl), IPC_SYSCALL(semop), IPC_SYSCALL(semtimedop),
	IPC_SYSCALL(shmget), IPC_SYSCALL(shmctl), IPC_SYSCALL(shmat), IPC_SYSCALL(shmdt),
	{ "__arm64_sys_reboot", __NR_reboot, (unsigned long)__arm64_sys_ds_reboot, 0 },
#ifdef DS_USERNS_LIVE
	ID_SYSCALL(getuid), ID_SYSCALL(geteuid), ID_SYSCALL(getgid), ID_SYSCALL(getegid),
#endif
};
static unsigned long *syscall_table;

static int write_syscall(struct ds_syscall_hook *hook, bool restore)
{
	unsigned long value = restore ? hook->saved : hook->replacement;
	u32 *slot = (u32 *)&syscall_table[hook->nr];
	int ret = aarch64_insn_patch_text_nosync(slot, lower_32_bits(value));
	return ret ? ret : aarch64_insn_patch_text_nosync(slot + 1, upper_32_bits(value));
}

struct ds_hook {
	const char *name;
	unsigned long replacement;
	unsigned long address;
	u32 saved[4];
	u32 patch[4];
	u32 *original;
};

#define HOOK(name, target) { name, (unsigned long)(target), 0, { 0 }, { 0 }, NULL }
#define HOOK_ORIGINAL(name, target, original) { name, (unsigned long)(target), 0, { 0 }, { 0 }, original }
extern void ds_ipcns_put(struct ns_common *);
extern int ds_ipcns_install(struct nsset *, struct ns_common *);
static struct ds_hook hooks[] = {
	HOOK("copy_ipcs", ds_copy_ipcs),
	HOOK("put_ipc_ns", ds_put_ipc_ns),
	HOOK("ipcns_put", ds_ipcns_put),
	HOOK("ipcns_install", ds_ipcns_install),
	HOOK_ORIGINAL("perf_event_alloc", ds_perf_event_alloc, ds_perf_alloc_original),
	HOOK_ORIGINAL("free_event_rcu", ds_perf_free_event_rcu, ds_perf_free_original),
	HOOK("fuse_conn_init", ds_fuse_conn_init),
	HOOK("delayed_release", ds_fuse_delayed_release),
	HOOK("cgroup_pidlist_start", ds_cgroup_pidlist_start),
	HOOK("kernel_clone", ds_kernel_clone),
	HOOK("ksys_unshare", ds_ksys_unshare),
	HOOK("do_exit", ds_do_exit),
	HOOK("put_pid", ds_put_pid),
	HOOK("delayed_put_pid", ds_delayed_put_pid),
	HOOK("alloc_pid", ds_alloc_pid),
	HOOK("free_nsproxy", ds_free_nsproxy),
	HOOK("copy_namespaces", ds_copy_namespaces),
	HOOK("unshare_nsproxy_namespaces", ds_unshare_nsproxy_namespaces),
	HOOK("__arm64_sys_setns", __arm64_sys_ds_setns),
	HOOK("proc_init_fs_context", ds_proc_init_fs_context),
	HOOK("proc_kill_sb", ds_proc_kill_sb),
#ifdef DS_USERNS_LIVE
	/* Add uid_map, gid_map, projid_map and setgroups to /proc/<pid>[/task/<tid>]. */
	HOOK("proc_tgid_base_lookup", ds_userns_tgid_lookup),
	HOOK("proc_tid_base_lookup", ds_userns_tid_lookup),
	HOOK("proc_tgid_base_readdir", ds_userns_tgid_readdir),
	HOOK("proc_tid_base_readdir", ds_userns_tid_readdir),
#endif
};

static struct ds_hook proc_hooks[2];

/*
 * kprobe mode. Samsung EL2 (RKP/uH) rejects writes to the syscall table and
 * other protected kernel memory, so no entry, table slot or ops pointer is
 * written. Each target gets a kprobe whose pre-handler moves the PC to the
 * replacement; kprobes arm through the kernel's own patching path, which
 * this firmware permits. Calls back into a native function go through the
 * ds_kp_* stubs in perf-original.S, which set DS_KP_MAGIC in x16.
 */
bool ds_kprobe_hooks;
module_param_named(kprobe_hooks, ds_kprobe_hooks, bool, 0400);
MODULE_PARM_DESC(kprobe_hooks, "Hook through kprobes without writing kernel memory (auto on Samsung EL2)");

#define DS_KP_MAGIC 0x44534b504f524947UL
unsigned long ds_kp_perf_alloc_target, ds_kp_perf_free_target, ds_kp_reboot_target;

struct ds_kprobe {
	struct kprobe kp;
	const char *name;
	unsigned long replacement;
	bool syscall;
};
static struct ds_kprobe ds_kps[ARRAY_SIZE(hooks) + ARRAY_SIZE(proc_hooks) + 2 + ARRAY_SIZE(ipc_syscalls)];
static unsigned int ds_kp_count;
static bool ds_kp_live;

static int ds_kp_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct ds_kprobe *k = container_of(p, struct ds_kprobe, kp);
	unsigned long target = k->replacement;

	if (!READ_ONCE(ds_kp_live) || regs->regs[16] == DS_KP_MAGIC)
		return 0;
	if (k->syscall) {
		/* Native wrappers take the user pt_regs; unimplemented IPC
		 * syscalls may share one sys_ni_syscall body, so dispatch on
		 * the syscall number. Compat numbers differ: never redirect. */
		const struct pt_regs *uregs = (const struct pt_regs *)regs->regs[0];
		unsigned int i;

		if (is_compat_task())
			return 0;
		target = 0;
		for (i = 0; i < ARRAY_SIZE(ipc_syscalls); i++) {
			if (uregs->syscallno == ipc_syscalls[i].nr) {
				target = ipc_syscalls[i].replacement;
				break;
			}
		}
		if (!target)
			return 0;
	}
	instruction_pointer_set(regs, target);
	return 1;
}

static int ds_kp_add(const char *name, unsigned long address,
		     unsigned long replacement, bool syscall)
{
	struct ds_kprobe *k;
	unsigned int i;
	int ret;

	for (i = 0; i < ds_kp_count; i++) {
		if ((unsigned long)ds_kps[i].kp.addr != address)
			continue;
		if (syscall && ds_kps[i].syscall)
			return 0;
		pr_err("kprobe target %s shares an entry with %s\n", name, ds_kps[i].name);
		return -EBUSY;
	}
	if (ds_kp_count >= ARRAY_SIZE(ds_kps))
		return -ENOSPC;
	k = &ds_kps[ds_kp_count];
	memset(k, 0, sizeof(*k));
	k->kp.addr = (kprobe_opcode_t *)address;
	k->kp.pre_handler = ds_kp_pre;
	k->name = name;
	k->replacement = replacement;
	k->syscall = syscall;
	ret = register_kprobe(&k->kp);
	if (ret) {
		pr_err("cannot register kprobe on %s: %d\n", name, ret);
		return ret;
	}
	ds_kp_count++;
	return 0;
}

static void ds_kp_remove_all(void)
{
	while (ds_kp_count)
		unregister_kprobe(&ds_kps[--ds_kp_count].kp);
}

static bool samsung_el2(void)
{
	/* exynos_report_el2_crash_info lives in the exynos_el2 vendor module,
	 * which kallsyms_name_to_addr() deliberately ignores. */
	if (kr_direct && (kallrecon_klp("exynos_report_el2_crash_info") ||
			  kallrecon_klp("uh_call")))
		return true;
	return kallsyms_name_to_addr("uh_call");
}

static bool movable_prologue(u32 op)
{
	/* NOP/PACIASP; stack allocation/frame pointer; stack stores, no PC operands. */
	return op == 0xd503201f || op == 0xd503233f ||
		(op & 0xffc003ff) == 0xd10003ff ||
		(op & 0xffc003ff) == 0x910003fd ||
		(op & 0xffc003e0) == 0xf90003e0 || /* STR xN,[sp,#imm] */
		(op & 0xff8003e0) == 0xa90003e0 ||
		(op & 0xff8003e0) == 0xa98003e0;
}

static int prepare_hook(struct ds_hook *hook)
{
	char symbol[KSYM_SYMBOL_LEN];
	char *start, *end;
	unsigned long offset, size;

	hook->address = kallsyms_name_to_addr(hook->name);
	if (!hook->address || (hook->address & 3) ||
	    safe_read(hook->saved, (void *)hook->address, sizeof(hook->saved)))
		return -ENOENT;
	/* Direct entry branches preserve the host prefix. Local direct-call-only
	 * functions can lack a KCFI word; compare hashes only for pointer slots.
	 */
	sprint_symbol(symbol, hook->address);
	start = strchr(symbol, '+');
	if (!start)
		return -EINVAL;
	offset = simple_strtoul(start + 1, &end, 0);
	if (end == start + 1 || *end != '/')
		return -EINVAL;
	start = end + 1;
	size = simple_strtoul(start, &end, 0);
	if (end == start || offset || size < sizeof(hook->saved))
		return -EINVAL;
	if (hook->original && !ds_kprobe_hooks) {
		unsigned int i;
		for (i = 0; i < ARRAY_SIZE(hook->saved); i++) {
			if (!movable_prologue(hook->saved[i])) {
				pr_err("unsupported original prologue %s word %u: %08x\n",
				       hook->name, i, hook->saved[i]);
				return -EOPNOTSUPP;
			}
		}
	}
	/* ldr x16, .+8; br x16; .quad destination. CFI type prefixes stay intact. */
	hook->patch[0] = 0x58000050;
	hook->patch[1] = 0xd61f0200;
	hook->patch[2] = lower_32_bits(hook->replacement);
	hook->patch[3] = upper_32_bits(hook->replacement);
	return 0;
}

static int write_hook(struct ds_hook *hook, bool restore)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(hook->saved); i++) {
		ret = aarch64_insn_patch_text_nosync((void *)(hook->address + i * 4),
					 restore ? hook->saved[i] : hook->patch[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static int install_stopped(void *unused)
{
	unsigned int i;
	int ret;
	for (i = 0; i < ARRAY_SIZE(hooks); i++) {
		struct ds_hook *h = &hooks[i];
		u32 code[8];
		unsigned int j;
		if (!h->original)
			continue;
		memcpy(code, h->saved, sizeof(h->saved));
		code[4] = 0x58000050;
		code[5] = 0xd61f0200;
		code[6] = lower_32_bits(h->address + sizeof(h->saved));
		code[7] = upper_32_bits(h->address + sizeof(h->saved));
		for (j = 0; j < ARRAY_SIZE(code); j++) {
			ret = aarch64_insn_patch_text_nosync(&h->original[j], code[j]);
			if (ret)
				goto rollback;
		}
	}

	for (i = 0; i < ARRAY_SIZE(hooks); i++) {
		ret = write_hook(&hooks[i], false);
		if (ret)
			goto rollback;
	}
	for (i = 0; i < ARRAY_SIZE(proc_hooks); i++) {
		ret = write_hook(&proc_hooks[i], false);
		if (ret)
			goto rollback;
	}
	set_init_ns_ops(true);
	for (i = 0; i < ARRAY_SIZE(ipc_syscalls); i++) {
		ret = write_syscall(&ipc_syscalls[i], false);
		if (ret) {
			set_init_ns_ops(false);
			goto rollback;
		}
	}
	WRITE_ONCE(ds_ipc_active, true);
	for (i = 0; i < ARRAY_SIZE(bpf_hooks); i++) {
		ret = write_pointer(bpf_hooks[i].slot, bpf_hooks[i].replacement);
		if (ret) {
			WRITE_ONCE(ds_ipc_active, false);
			set_init_ns_ops(false);
			goto rollback;
		}
	}
	return 0;

rollback:
	for (i = 0; i < ARRAY_SIZE(bpf_hooks); i++)
		if (write_pointer(bpf_hooks[i].slot, bpf_hooks[i].saved))
			panic("droidspaces_ns: BPF rollback failed");
	for (i = 0; i < ARRAY_SIZE(ipc_syscalls); i++)
		if (write_syscall(&ipc_syscalls[i], true))
			panic("droidspaces_ns: syscall rollback failed");
	/* Do not resume CPUs with an incomplete set of lifecycle replacements. */
	for (i = 0; i < ARRAY_SIZE(hooks); i++)
		if (write_hook(&hooks[i], true))
			panic("droidspaces_ns: hook rollback failed");
	for (i = 0; i < ARRAY_SIZE(proc_hooks); i++)
		if (write_hook(&proc_hooks[i], true))
			panic("droidspaces_ns: proc hook rollback failed");
	return ret;
}

int ds_hooks_prepare(void)
{
	unsigned int i;
	int ret;

	if (IS_ENABLED(CONFIG_ARM64_BTI_KERNEL) || init_pid_ns.ns.ops
#ifdef DS_USERNS_LIVE
	    || init_user_ns.ns.ops
#endif
	   )
		return -EOPNOTSUPP;
	if (!ds_kprobe_hooks && samsung_el2()) {
		pr_info("Samsung EL2 detected; using kprobe hooks without kernel memory writes\n");
		ds_kprobe_hooks = true;
	}
	ret = prepare_bpf_hooks();
	if (ret)
		return ret;
	syscall_table = (void *)kallsyms_name_to_addr("sys_call_table");
	if (!syscall_table)
		return -ENOENT;
	for (i = 0; i < ARRAY_SIZE(ipc_syscalls); i++) {
		struct ds_syscall_hook *hook = &ipc_syscalls[i];
		if (safe_read(&hook->saved, &syscall_table[hook->nr], sizeof(hook->saved)) ||
		    hook->saved != kallsyms_name_to_addr(hook->name)) {
			pr_err("syscall %u no longer points to %s\n", hook->nr, hook->name);
			return -EOPNOTSUPP;
		}
		if (hook->nr == __NR_reboot) {
			ds_native_reboot = (void *)hook->saved;
			ds_kp_reboot_target = hook->saved;
		}
		if (!matching_cfi(hook->saved, hook->replacement)) {
			pr_err("CFI mismatch for %s\n", hook->name);
			return -EPROTOTYPE;
		}
	}
	proc_hooks[0] = (struct ds_hook)HOOK("proc_ns_dir_readdir",
					ds_proc_ns_dir_operations.iterate_shared);
	proc_hooks[1] = (struct ds_hook)HOOK("proc_ns_dir_lookup",
					ds_proc_ns_dir_inode_operations.lookup);
	for (i = 0; i < ARRAY_SIZE(hooks); i++) {
		ret = prepare_hook(&hooks[i]);
		if (ret) {
			pr_err("cannot prepare hook %s: %d\n", hooks[i].name, ret);
			return ret;
		}
	}
	for (i = 0; i < ARRAY_SIZE(proc_hooks); i++) {
		ret = prepare_hook(&proc_hooks[i]);
		if (ret)
			return ret;
	}
	ds_kp_perf_alloc_target = kallsyms_name_to_addr("perf_event_alloc");
	ds_kp_perf_free_target = kallsyms_name_to_addr("free_event_rcu");
	if (ds_kprobe_hooks && (!ds_kp_perf_alloc_target || !ds_kp_perf_free_target ||
				!ds_kp_reboot_target))
		return -ENOENT;
	pr_info("entry preflight passed (%s): %zu functions, %zu syscalls, %zu BPF callbacks; no patches written\n",
		ds_kprobe_hooks ? "kprobe" : "text patch", ARRAY_SIZE(hooks) + ARRAY_SIZE(proc_hooks), ARRAY_SIZE(ipc_syscalls), ARRAY_SIZE(bpf_hooks));
	return 0;
}

/*
 * Samsung DEFEX kills a task whose euid rises above the credentials it
 * recorded, which is every setuid exec (sudo, su) inside a container.
 * Like KernelSU-Next's KernelSU-only exemption, clear the task argument of
 * task_defex_enforce() so DEFEX skips the check, but only for the calling
 * task and only while it lives in a PID namespace this module created.
 * Android tasks in the initial PID namespace keep full DEFEX enforcement.
 */
static bool defex_bypass = true;
module_param(defex_bypass, bool, 0400);
MODULE_PARM_DESC(defex_bypass, "Skip Samsung DEFEX enforcement inside container PID namespaces (kprobe mode)");

static int ds_defex_pre(struct kprobe *p, struct pt_regs *regs)
{
	if ((struct task_struct *)regs->regs[0] == current &&
	    task_active_pid_ns(current) != &init_pid_ns)
		regs->regs[0] = 0;
	return 0;
}

static struct kprobe ds_defex_kprobe = {
	.symbol_name = "task_defex_enforce",
	.pre_handler = ds_defex_pre,
};

static void ds_defex_install(void)
{
	int ret;

	if (!defex_bypass)
		return;
	ret = register_kprobe(&ds_defex_kprobe);
	if (ret == -ENOENT || ret == -EINVAL) {
		pr_info("Samsung DEFEX not present; no container exemption needed\n");
		return;
	}
	if (ret) {
		/* Containers still work; only setuid escalation inside them is killed. */
		pr_warn("cannot hook task_defex_enforce: %d; setuid inside containers stays blocked\n", ret);
		return;
	}
	pr_info("Samsung DEFEX: enforcement skipped for tasks in container PID namespaces\n");
}

static int kp_go_live(void *unused)
{
	/* Every probe is armed but passive; switch all of them at once. */
	set_init_ns_ops(true);
	WRITE_ONCE(ds_ipc_active, true);
	WRITE_ONCE(ds_kp_live, true);
	return 0;
}

static int install_kprobes(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(hooks); i++) {
		ret = ds_kp_add(hooks[i].name, hooks[i].address, hooks[i].replacement, false);
		if (ret)
			goto fail;
	}
	for (i = 0; i < ARRAY_SIZE(proc_hooks); i++) {
		ret = ds_kp_add(proc_hooks[i].name, proc_hooks[i].address,
				proc_hooks[i].replacement, false);
		if (ret)
			goto fail;
	}
	for (i = 0; i < ARRAY_SIZE(ipc_syscalls); i++) {
		ret = ds_kp_add(ipc_syscalls[i].name, ipc_syscalls[i].saved, 0, true);
		if (ret)
			goto fail;
	}
	/* The three task iterators share these two callbacks. */
	ret = ds_kp_add("init_seq_pidns", bpf_hooks[0].saved, bpf_hooks[0].replacement, false);
	if (ret)
		goto fail;
	ret = ds_kp_add("fini_seq_pidns", bpf_hooks[1].saved, bpf_hooks[1].replacement, false);
	if (ret)
		goto fail;
	ret = stop_machine(kp_go_live, NULL, NULL);
	if (ret)
		goto fail;
	ds_defex_install();
	return 0;
fail:
	ds_kp_remove_all();
	return ret;
}

int ds_hooks_install(void)
{
	int ret = ds_hooks_prepare();

	if (ret)
		return ret;
	if (ds_kprobe_hooks) {
		__module_get(THIS_MODULE);
		ret = install_kprobes();
		if (ret)
			module_put(THIS_MODULE);
		return ret;
	}
	/* Objects in procfs can retain operation pointers after all tasks exit. */
	__module_get(THIS_MODULE);
	ret = stop_machine(install_stopped, NULL, NULL);
	if (ret)
		module_put(THIS_MODULE);
	return ret;
}
