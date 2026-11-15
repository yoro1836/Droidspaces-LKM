// SPDX-License-Identifier: GPL-2.0-only
/*
 * Lets a BPF program be the scheduler, on a kernel whose struct_ops support
 * knows two built-in types and looks every type up in vmlinux BTF only.
 *
 * Two things make the stock code accept ours without touching kernel text.
 * Module BTF ids continue where vmlinux's end, so appending this module's
 * types and strings to the vmlinux BTF object leaves every id as compiled,
 * and that object lives on the heap. And the table of struct_ops types
 * holds pointers to writable descriptors: the one for bpf_dummy_ops, which
 * only BPF_PROG_TEST_RUN selftests use, is refilled to describe
 * sched_ext_ops.
 *
 * Userspace cannot see the appended types in /sys/kernel/btf/vmlinux, which
 * is the raw image. The merged BTF is offered as the "btf" file of this
 * module, to be bind-mounted over that path by the loader.
 *
 * A module with BTF that loads after this one would get ids that start past
 * our types and fail validation. Load this last.
 */
#define pr_fmt(fmt) "droidspaces_scx: " fmt
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/stop_machine.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include "core.h"
#include "scx.h"

/* kernel/bpf/btf.c keeps these private. android14-6.1 layout. */
struct ds_btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types;
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct rcu_head rcu;
	void *kfunc_set_tab;
	void *dtor_kfunc_tab;
	struct ds_btf *base_btf;
	u32 start_id;
	u32 start_str_off;
	char name[MODULE_NAME_LEN];
	bool kernel_btf;
};

struct ds_btf_module {
	struct list_head list;
	struct module *module;
	struct ds_btf *btf;
};

/* kernel/bpf/bpf_struct_ops.c keeps the value header private too. */
enum ds_struct_ops_state { DS_STRUCT_OPS_INIT, DS_STRUCT_OPS_INUSE, DS_STRUCT_OPS_TOBEFREE };
struct bpf_struct_ops_sched_ext_ops {
	refcount_t refcnt;
	enum ds_struct_ops_state state;
	struct sched_ext_ops data ____cacheline_aligned_in_smp;
};

/* Never used: its member puts the name "scx" into this module's BTF strings,
 * for the task_struct member the merged BTF gains below.
 */
struct scx_btf_anchor {
	struct sched_ext_entity scx;
};

static struct sched_ext_ops __rcu *scx_ops;
/* Set by a kfunc the scheduler misused: it is no longer asked anything, the
 * class runs on its defaults, and exit() reports why once it is unloaded.
 */
static bool scx_errored;
static char scx_error_msg[96];

void scx_ops_error(const char *msg)
{
	if (cmpxchg(&scx_errored, false, true))
		return;
	strscpy(scx_error_msg, msg, sizeof(scx_error_msg));
	pr_err("BPF scheduler error: %s\n", scx_error_msg);
}

static struct sched_ext_ops *ops_get(void)
{
	return READ_ONCE(scx_errored) ? NULL : rcu_dereference(scx_ops);
}
static unsigned long nr_ops_calls;
module_param(nr_ops_calls, ulong, 0400);

/* A BPF trampoline carries no kCFI type word, so every call into the
 * scheduler is made from a function that skips the check.
 */
__nocfi s32 scx_ops_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct sched_ext_ops *ops;
	s32 cpu = -1;

	rcu_read_lock();
	ops = ops_get();
	if (ops && ops->select_cpu) {
		cpu = ops->select_cpu(p, prev_cpu, wake_flags);
		nr_ops_calls++;
		if (cpu < 0 || cpu >= nr_cpu_ids || !cpu_active(cpu) ||
		    !cpumask_test_cpu(cpu, p->cpus_ptr))
			cpu = -1;
	}
	rcu_read_unlock();
	return cpu;
}

__nocfi bool scx_ops_enqueue(struct task_struct *p, u64 enq_flags)
{
	struct sched_ext_ops *ops;
	bool has;

	rcu_read_lock();
	ops = ops_get();
	has = ops && ops->enqueue;
	if (has)
		ops->enqueue(p, enq_flags);
	rcu_read_unlock();
	return has;
}

__nocfi bool scx_ops_dispatch(s32 cpu)
{
	struct sched_ext_ops *ops;
	bool has;

	rcu_read_lock();
	ops = ops_get();
	has = ops && ops->dispatch;
	if (has)
		ops->dispatch(cpu, NULL);
	rcu_read_unlock();
	return has;
}

__nocfi void scx_ops_running(struct task_struct *p)
{
	struct sched_ext_ops *ops;

	rcu_read_lock();
	ops = ops_get();
	if (ops && ops->running)
		ops->running(p);
	rcu_read_unlock();
}

__nocfi void scx_ops_stopping(struct task_struct *p, bool runnable)
{
	struct sched_ext_ops *ops;

	rcu_read_lock();
	ops = ops_get();
	if (ops && ops->stopping)
		ops->stopping(p, runnable);
	rcu_read_unlock();
}

__nocfi void scx_ops_enable(struct task_struct *p)
{
	struct sched_ext_ops *ops;

	rcu_read_lock();
	ops = ops_get();
	if (ops && ops->enable)
		ops->enable(p);
	rcu_read_unlock();
}

static const struct btf_type *task_struct_type;
static int (*btf_struct_access_fn)(struct bpf_verifier_log *, const struct btf *,
				   const struct btf_type *, int, int, enum bpf_access_type,
				   u32 *, enum bpf_type_flag *);

/* Reads are the kernel's business. Of writes, a scheduler may set a task's
 * slice and vtime, as upstream allows through p->scx.
 */
static __nocfi int scx_btf_struct_access(struct bpf_verifier_log *log, const struct btf *btf,
					 const struct btf_type *t, int off, int size,
					 enum bpf_access_type atype, u32 *next_btf_id,
					 enum bpf_type_flag *flag)
{
	int base = offsetof(struct task_struct, dl.dl_runtime);

	if (atype == BPF_READ)
		return btf_struct_access_fn(log, btf, t, off, size, atype, next_btf_id, flag);
	if (t == task_struct_type && size == sizeof(u64) &&
	    (off == base + offsetof(struct sched_ext_entity, slice) ||
	     off == base + offsetof(struct sched_ext_entity, dsq_vtime)))
		return SCALAR_VALUE;
	return -EACCES;
}

static bool (*btf_ctx_access_fn)(int, int, enum bpf_access_type, const struct bpf_prog *,
				 struct bpf_insn_access_aux *);
static const struct bpf_func_proto *(*base_func_proto_fn)(enum bpf_func_id);
static const struct btf_type *(*resolve_func_ptr_fn)(const struct btf *, u32, u32 *);
static int (*distill_func_proto_fn)(struct bpf_verifier_log *, struct btf *,
				    const struct btf_type *, const char *,
				    struct btf_func_model *);

static __nocfi bool scx_is_valid_access(int off, int size, enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	if (type != BPF_READ || off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS ||
	    off % size)
		return false;
	return btf_ctx_access_fn(off, size, type, prog, info);
}

static __nocfi const struct bpf_func_proto *
scx_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return base_func_proto_fn(func_id);
}

static const struct bpf_verifier_ops scx_verifier_ops = {
	.is_valid_access = scx_is_valid_access,
	.get_func_proto = scx_get_func_proto,
	.btf_struct_access = scx_btf_struct_access,
};

static int scx_init_member(const struct btf_type *t, const struct btf_member *member,
			   void *kdata, const void *udata)
{
	const struct sched_ext_ops *uops = udata;
	struct sched_ext_ops *ops = kdata;

	u32 moff = __btf_member_bit_offset(t, member) / 8;

	/* The generic code takes the function pointers and wants every other
	 * member to be zero unless it is claimed here.
	 */
	switch (moff) {
	case offsetof(struct sched_ext_ops, name):
		if (strscpy(ops->name, uops->name, sizeof(ops->name)) <= 0)
			return -EINVAL;
		return 1;
	case offsetof(struct sched_ext_ops, dispatch_max_batch):
		ops->dispatch_max_batch = uops->dispatch_max_batch;
		return 1;
	case offsetof(struct sched_ext_ops, flags):
		ops->flags = uops->flags;
		return 1;
	case offsetof(struct sched_ext_ops, timeout_ms):
		ops->timeout_ms = uops->timeout_ms;
		return 1;
	case offsetof(struct sched_ext_ops, exit_dump_len):
		ops->exit_dump_len = uops->exit_dump_len;
		return 1;
	case offsetof(struct sched_ext_ops, hotplug_seq):
		ops->hotplug_seq = uops->hotplug_seq;
		return 1;
	}
	return 0;
}

static DEFINE_MUTEX(scx_reg_lock);

static __nocfi int scx_reg(void *kdata)
{
	struct sched_ext_ops *ops = kdata;
	int ret = 0;

	mutex_lock(&scx_reg_lock);
	if (rcu_access_pointer(scx_ops))
		ret = -EBUSY;
	else if (ops->init)
		ret = ops->init();
	if (ret) {
		/* init may have made queues before it failed */
		if (ret != -EBUSY)
			scx_ops_gone();
		mutex_unlock(&scx_reg_lock);
		return ret > 0 ? -EINVAL : ret;
	}
	WRITE_ONCE(scx_errored, false);
	rcu_assign_pointer(scx_ops, ops);
	if (!(ops->flags & SCX_OPS_SWITCH_PARTIAL))
		scx_switch_all_tasks(true);
	mutex_unlock(&scx_reg_lock);
	pr_info("BPF scheduler \"%s\" enabled\n", ops->name);
	return 0;
}

static __nocfi void scx_unreg(void *kdata)
{
	struct sched_ext_ops *ops = kdata;
	static struct scx_exit_info ei;

	mutex_lock(&scx_reg_lock);
	/* Tasks leave while the scheduler can still see them go. */
	if (!(ops->flags & SCX_OPS_SWITCH_PARTIAL))
		scx_switch_all_tasks(false);
	rcu_assign_pointer(scx_ops, NULL);
	synchronize_rcu();
	scx_ops_gone();
	if (ops->exit) {
		ei.kind = scx_errored ? SCX_EXIT_ERROR_BPF : SCX_EXIT_UNREG;
		ei.reason = scx_errored ? "scx_bpf_error" : "unregistered from user space";
		ei.msg = scx_errored ? scx_error_msg : "";
		ei.dump = "";
		ops->exit(&ei);
	}
	mutex_unlock(&scx_reg_lock);
	pr_info("BPF scheduler \"%s\" disabled\n", ops->name);
}

static struct ds_btf *vm_btf, *mod_btf;
static struct btf_type **new_types;
static char *new_strings;

static int graft_stopped(void *unused)
{
	vm_btf->types = new_types;
	vm_btf->strings = new_strings;
	vm_btf->hdr.str_len += mod_btf->hdr.str_len;
	vm_btf->nr_types += mod_btf->nr_types;
	vm_btf->types_size = vm_btf->nr_types;
	return 0;
}

static ssize_t merged_read(struct file *file, struct kobject *kobj,
			   struct bin_attribute *attr, char *buf, loff_t off, size_t len)
{
	return memory_read_from_buffer(buf, len, &off, attr->private, attr->size);
}

/* A module built from vendor headers that differ anywhere from the running
 * kernel carries its own copies of kernel structs: this module's BTF had two
 * of task_struct on a Samsung device. The verifier compares type ids, so a
 * kfunc that takes such a copy rejects the kernel's own task_struct.
 *
 * Point every pointer in the module's types at vmlinux's struct of the same
 * name instead. Only pointers and their qualifiers are retargeted, never a
 * struct embedded by value, so no layout the module was compiled with
 * changes. Returns, per module type, the vmlinux id it duplicates or 0.
 */
static u32 *adopt_vmlinux_structs(void)
{
	u32 *dup = kvcalloc(mod_btf->nr_types, sizeof(*dup), GFP_KERNEL);
	u32 i, j, n = 0;

	if (!dup)
		return NULL;
	for (i = 0; i < mod_btf->nr_types; i++) {
		const struct btf_type *m = mod_btf->types[i];
		u32 kind = BTF_INFO_KIND(m->info);
		const char *name;

		if ((kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION) || !m->name_off)
			continue;
		name = mod_btf->strings + (m->name_off - mod_btf->start_str_off);
		if (m->name_off < mod_btf->start_str_off)
			name = vm_btf->strings + m->name_off;
		for (j = 1; j < vm_btf->nr_types; j++) {
			const struct btf_type *v = vm_btf->types[j];

			if (BTF_INFO_KIND(v->info) == kind && v->name_off &&
			    !strcmp(vm_btf->strings + v->name_off, name)) {
				dup[i] = j;
				n++;
				break;
			}
		}
		cond_resched();
	}
	for (i = 0; i < mod_btf->nr_types; i++) {
		struct btf_type *m = mod_btf->types[i];
		u32 kind = BTF_INFO_KIND(m->info);

		if ((kind == BTF_KIND_PTR || kind == BTF_KIND_CONST ||
		     kind == BTF_KIND_VOLATILE || kind == BTF_KIND_RESTRICT) &&
		    m->type >= mod_btf->start_id && dup[m->type - mod_btf->start_id])
			m->type = dup[m->type - mod_btf->start_id];
	}
	if (n)
		pr_info("%u kernel structs duplicated in module BTF, pointers retargeted\n", n);
	return dup;
}

static struct bin_attribute merged_attr = {
	.attr = { .name = "btf", .mode = 0444 },
	.read = merged_read,
};

static int graft_btf(void)
{
	struct list_head *modules = (void *)kallsyms_name_to_addr("btf_modules");
	struct mutex *lock = (void *)kallsyms_name_to_addr("btf_module_mutex");
	struct ds_btf **vmp = (void *)kallsyms_name_to_addr("btf_vmlinux");
	struct ds_btf_module *m;
	u32 vt, vs, mt, ms, i, extra = 0, split = 0, entity_id = 0, scx_name_off = 0;
	struct btf_header *hdr;
	void *base_types;
	char *blob, *out;
	u32 *dup;

	if (!modules || !lock || !vmp || !*vmp)
		return -ENOENT;
	vm_btf = *vmp;
	mutex_lock(lock);
	list_for_each_entry(m, modules, list)
		if (m->module == THIS_MODULE)
			mod_btf = m->btf;
	mutex_unlock(lock);
	if (!mod_btf) {
		pr_err("this module carries no BTF the kernel accepted\n");
		return -ENODATA;
	}
	/* Refuse anything but the layout the ids were compiled for. */
	if (vm_btf->base_btf || vm_btf->start_id || !vm_btf->kernel_btf ||
	    mod_btf->base_btf != vm_btf || mod_btf->start_id != vm_btf->nr_types ||
	    mod_btf->start_str_off != vm_btf->hdr.str_len ||
	    vm_btf->resolved_ids || vm_btf->resolved_sizes) {
		pr_err("unexpected BTF layout, or a module with BTF loaded before the graft\n");
		return -EOPNOTSUPP;
	}
	dup = adopt_vmlinux_structs();
	if (!dup)
		return -ENOMEM;
	vt = vm_btf->hdr.type_len;
	vs = vm_btf->hdr.str_len;
	mt = mod_btf->hdr.type_len;
	ms = mod_btf->hdr.str_len;

	new_types = kvcalloc(vm_btf->nr_types + mod_btf->nr_types, sizeof(*new_types), GFP_KERNEL);
	new_strings = kvmalloc(vs + ms, GFP_KERNEL);
	blob = kvzalloc(sizeof(*hdr) + vt + mt + vs + ms + sizeof(struct btf_member), GFP_KERNEL);
	if (!new_types || !new_strings || !blob)
		return -ENOMEM;
	memcpy(new_types, vm_btf->types, vm_btf->nr_types * sizeof(*new_types));
	memcpy(new_types + vm_btf->nr_types, mod_btf->types,
	       mod_btf->nr_types * sizeof(*new_types));
	memcpy(new_strings, vm_btf->strings, vs);
	memcpy(new_strings + vs, mod_btf->strings, ms);

	/* Find what the task_struct member needs; without it the image is the
	 * plain merge and schedulers that touch p->scx fail to load.
	 */
	for (i = 1; i < vm_btf->nr_types; i++) {
		const struct btf_type *t = vm_btf->types[i];

		if (BTF_INFO_KIND(t->info) == BTF_KIND_STRUCT &&
		    !strcmp(vm_btf->strings + t->name_off, "task_struct")) {
			task_struct_type = t;
			break;
		}
	}
	for (i = 0; i < mod_btf->nr_types; i++) {
		const struct btf_type *t = mod_btf->types[i];

		if (BTF_INFO_KIND(t->info) == BTF_KIND_STRUCT &&
		    !strcmp(new_strings + t->name_off, "sched_ext_entity"))
			entity_id = mod_btf->start_id + i;
	}
	for (i = vs; i + 4 <= vs + ms; i++)
		if (!new_strings[i - 1] && !strcmp(new_strings + i, "scx"))
			scx_name_off = i;
	if (task_struct_type && entity_id && scx_name_off) {
		extra = sizeof(struct btf_member);
		split = (void *)(btf_type_member(task_struct_type) +
				 btf_type_vlen(task_struct_type)) -
			(vm_btf->nohdr_data + vm_btf->hdr.type_off);
	} else {
		pr_warn("p->scx will not resolve: task_struct %d entity %u name %u\n",
			!!task_struct_type, entity_id, scx_name_off);
	}

	/* The merged image, with one change to vmlinux's part: task_struct gains
	 * a member "scx" over the words of p->dl that hold our per-task state,
	 * so that p->scx.slice in a scheduler relocates to where it really is.
	 * A member more makes the type 12 bytes longer and moves no id.
	 */
	hdr = (void *)blob;
	*hdr = vm_btf->hdr;
	hdr->type_off = 0;
	hdr->type_len = vt + mt + extra;
	hdr->str_off = vt + mt + extra;
	hdr->str_len = vs + ms;
	out = blob + sizeof(*hdr);
	base_types = vm_btf->nohdr_data + vm_btf->hdr.type_off;
	if (extra) {
		struct btf_type *ts;
		struct btf_member *m;

		memcpy(out, base_types, split);
		ts = (void *)(out + ((void *)task_struct_type - base_types));
		ts->info = (ts->info & ~0xffffU) | (btf_type_vlen(task_struct_type) + 1);
		m = (void *)(out + split);
		m->name_off = scx_name_off;
		m->type = entity_id;
		m->offset = offsetof(struct task_struct, dl.dl_runtime) * 8;
		memcpy(out + split + extra, base_types + split, vt - split);
	} else {
		memcpy(out, base_types, vt);
	}
	memcpy(out + vt + extra, mod_btf->nohdr_data + mod_btf->hdr.type_off, mt);
	/* In the image a loader searches by name, the module's copies would be
	 * second candidates for every CO-RE relocation. Leave them nameless.
	 */
	for (i = 0; i < mod_btf->nr_types; i++) {
		struct btf_type *t;

		if (!dup[i])
			continue;
		t = (void *)(out + vt + extra + ((void *)mod_btf->types[i] -
			     (mod_btf->nohdr_data + mod_btf->hdr.type_off)));
		t->name_off = 0;
	}
	kvfree(dup);
	memcpy(out + vt + extra + mt, new_strings, vs + ms);
	merged_attr.private = blob;
	merged_attr.size = sizeof(*hdr) + vt + extra + mt + vs + ms;

	/* Readers take no lock on the vmlinux BTF, so swap with all CPUs held. */
	return stop_machine(graft_stopped, NULL, NULL);
}

static s32 find_struct(const char *name)
{
	u32 id;

	for (id = mod_btf->start_id; id < mod_btf->start_id + mod_btf->nr_types; id++) {
		const struct btf_type *t = btf_type_by_id((struct btf *)vm_btf, id);

		if (t && BTF_INFO_KIND(t->info) == BTF_KIND_STRUCT &&
		    !strcmp(vm_btf->strings + t->name_off, name))
			return id;
	}
	return -ENOENT;
}

static __nocfi int take_struct_ops_slot(void)
{
	struct bpf_struct_ops *st = (void *)kallsyms_name_to_addr("bpf_bpf_dummy_ops");
	s32 type_id = find_struct("sched_ext_ops");
	s32 value_id = find_struct("bpf_struct_ops_sched_ext_ops");
	const struct btf_member *member;
	const struct btf_type *t;
	u32 i;

	if (!st || strcmp(st->name, "bpf_dummy_ops"))
		return -ENOENT;
	if (type_id < 0 || value_id < 0) {
		pr_err("sched_ext_ops is missing from this module's BTF\n");
		return -ENOENT;
	}
	t = btf_type_by_id((struct btf *)vm_btf, type_id);
	if (btf_type_vlen(t) > BPF_STRUCT_OPS_MAX_NR_MEMBERS)
		return -E2BIG;
	memset(st->func_models, 0, sizeof(st->func_models));
	for (i = 0, member = btf_type_member(t); i < btf_type_vlen(t); i++, member++) {
		const char *mname = vm_btf->strings + member->name_off;
		const struct btf_type *proto =
			resolve_func_ptr_fn((struct btf *)vm_btf, member->type, NULL);

		if (proto && distill_func_proto_fn(NULL, (struct btf *)vm_btf, proto, mname,
						   &st->func_models[i])) {
			pr_err("cannot model sched_ext_ops.%s\n", mname);
			return -EINVAL;
		}
	}
	st->verifier_ops = &scx_verifier_ops;
	st->init = NULL;
	st->check_member = NULL;
	st->init_member = scx_init_member;
	st->reg = scx_reg;
	st->unreg = scx_unreg;
	st->name = "sched_ext_ops";
	st->type = t;
	st->value_type = btf_type_by_id((struct btf *)vm_btf, value_id);
	st->value_id = value_id;
	/* Lookups go by type_id, so the slot becomes ours with this store. */
	st->type_id = type_id;
	return 0;
}

/* Upstream's loader reads /sys/kernel/sched_ext/hotplug_seq before it loads a
 * scheduler and gives up without it. CPUs coming and going are not tracked
 * here, so the sequence stays 0.
 */
static ssize_t hotplug_seq_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "0\n");
}

static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n", rcu_access_pointer(scx_ops) ? "enabled" : "disabled");
}

static struct kobj_attribute hotplug_seq_attr = __ATTR_RO(hotplug_seq);
static struct kobj_attribute state_attr = __ATTR_RO(state);
static struct attribute *scx_sysfs_attrs[] = { &hotplug_seq_attr.attr, &state_attr.attr, NULL };
static const struct attribute_group scx_sysfs_group = { .attrs = scx_sysfs_attrs };

int scx_bpf_init(void)
{
	struct kobject *kobj;
	int ret;

	BTF_TYPE_EMIT(struct bpf_struct_ops_sched_ext_ops);
	BTF_TYPE_EMIT(struct scx_btf_anchor);
	BTF_TYPE_EMIT_ENUM(SCX_OPS_NAME_LEN);
	BTF_TYPE_EMIT_ENUM(SCX_DSQ_LOCAL);
	BTF_TYPE_EMIT_ENUM(SCX_ENQ_WAKEUP);
	BTF_TYPE_EMIT_ENUM(SCX_KICK_IDLE);
	BTF_TYPE_EMIT_ENUM(SCX_OPS_SWITCH_PARTIAL);
	btf_ctx_access_fn = (void *)kallsyms_name_to_addr("btf_ctx_access");
	btf_struct_access_fn = (void *)kallsyms_name_to_addr("btf_struct_access");
	base_func_proto_fn = (void *)kallsyms_name_to_addr("bpf_base_func_proto");
	resolve_func_ptr_fn = (void *)kallsyms_name_to_addr("btf_type_resolve_func_ptr");
	distill_func_proto_fn = (void *)kallsyms_name_to_addr("btf_distill_func_proto");
	if (!btf_ctx_access_fn || !btf_struct_access_fn || !base_func_proto_fn || !resolve_func_ptr_fn ||
	    !distill_func_proto_fn)
		return -ENOENT;
	ret = graft_btf();
	if (ret)
		return ret;
	ret = take_struct_ops_slot();
	if (ret)
		return ret;
	ret = scx_register_kfuncs();
	if (ret)
		return ret;
	ret = sysfs_create_bin_file(&THIS_MODULE->mkobj.kobj, &merged_attr);
	if (ret)
		return ret;
	kobj = kobject_create_and_add("sched_ext", kernel_kobj);
	if (!kobj || sysfs_create_group(kobj, &scx_sysfs_group))
		pr_warn("no /sys/kernel/sched_ext, upstream loaders will refuse to start\n");
	pr_info("struct_ops type sched_ext_ops registered, %u types grafted\n",
		mod_btf->nr_types);
	return 0;
}
