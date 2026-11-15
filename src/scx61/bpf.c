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

static struct sched_ext_ops __rcu *scx_ops;
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
	ops = rcu_dereference(scx_ops);
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
	ops = rcu_dereference(scx_ops);
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
	ops = rcu_dereference(scx_ops);
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
	ops = rcu_dereference(scx_ops);
	if (ops && ops->running)
		ops->running(p);
	rcu_read_unlock();
}

__nocfi void scx_ops_stopping(struct task_struct *p, bool runnable)
{
	struct sched_ext_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(scx_ops);
	if (ops && ops->stopping)
		ops->stopping(p, runnable);
	rcu_read_unlock();
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
};

static int scx_init_member(const struct btf_type *t, const struct btf_member *member,
			   void *kdata, const void *udata)
{
	const struct sched_ext_ops *uops = udata;
	struct sched_ext_ops *ops = kdata;

	if (__btf_member_bit_offset(t, member) / 8 == offsetof(struct sched_ext_ops, name)) {
		if (strscpy(ops->name, uops->name, sizeof(ops->name)) <= 0)
			return -EINVAL;
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
	rcu_assign_pointer(scx_ops, ops);
	mutex_unlock(&scx_reg_lock);
	pr_info("BPF scheduler \"%s\" enabled\n", ops->name);
	return 0;
}

static void scx_unreg(void *kdata)
{
	struct sched_ext_ops *ops = kdata;

	mutex_lock(&scx_reg_lock);
	rcu_assign_pointer(scx_ops, NULL);
	synchronize_rcu();
	scx_ops_gone();
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
	struct btf_header *hdr;
	u32 vt, vs, mt, ms;
	char *blob;

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
	vt = vm_btf->hdr.type_len;
	vs = vm_btf->hdr.str_len;
	mt = mod_btf->hdr.type_len;
	ms = mod_btf->hdr.str_len;

	new_types = kvcalloc(vm_btf->nr_types + mod_btf->nr_types, sizeof(*new_types), GFP_KERNEL);
	new_strings = kvmalloc(vs + ms, GFP_KERNEL);
	blob = kvzalloc(sizeof(*hdr) + vt + mt + vs + ms, GFP_KERNEL);
	if (!new_types || !new_strings || !blob)
		return -ENOMEM;
	memcpy(new_types, vm_btf->types, vm_btf->nr_types * sizeof(*new_types));
	memcpy(new_types + vm_btf->nr_types, mod_btf->types,
	       mod_btf->nr_types * sizeof(*new_types));
	memcpy(new_strings, vm_btf->strings, vs);
	memcpy(new_strings + vs, mod_btf->strings, ms);

	hdr = (void *)blob;
	*hdr = vm_btf->hdr;
	hdr->type_off = 0;
	hdr->type_len = vt + mt;
	hdr->str_off = vt + mt;
	hdr->str_len = vs + ms;
	memcpy(blob + sizeof(*hdr), vm_btf->nohdr_data + vm_btf->hdr.type_off, vt);
	memcpy(blob + sizeof(*hdr) + vt, mod_btf->nohdr_data + mod_btf->hdr.type_off, mt);
	memcpy(blob + sizeof(*hdr) + vt + mt, new_strings, vs + ms);
	merged_attr.private = blob;
	merged_attr.size = sizeof(*hdr) + vt + mt + vs + ms;

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

int scx_bpf_init(void)
{
	int ret;

	BTF_TYPE_EMIT(struct bpf_struct_ops_sched_ext_ops);
	btf_ctx_access_fn = (void *)kallsyms_name_to_addr("btf_ctx_access");
	base_func_proto_fn = (void *)kallsyms_name_to_addr("bpf_base_func_proto");
	resolve_func_ptr_fn = (void *)kallsyms_name_to_addr("btf_type_resolve_func_ptr");
	distill_func_proto_fn = (void *)kallsyms_name_to_addr("btf_distill_func_proto");
	if (!btf_ctx_access_fn || !base_func_proto_fn || !resolve_func_ptr_fn ||
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
	pr_info("struct_ops type sched_ext_ops registered, %u types grafted\n",
		mod_btf->nr_types);
	return 0;
}
