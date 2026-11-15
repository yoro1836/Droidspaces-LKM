// SPDX-License-Identifier: GPL-2.0-only
/*
 * Makes the stock struct_ops code of android14-6.1 accept sched_ext_ops, for
 * the port of upstream's ext.c (ext-port.c).
 *
 * That code knows two built-in types and looks every type up in vmlinux BTF
 * only. Module BTF ids continue where vmlinux's end, so appending this
 * module's types and strings to the vmlinux BTF object leaves every id as
 * compiled, and that object lives on the heap. And the table of struct_ops
 * types holds pointers to writable descriptors: the one for bpf_dummy_ops,
 * which only BPF_PROG_TEST_RUN selftests use, is refilled to describe
 * sched_ext_ops with upstream's callbacks.
 *
 * Userspace cannot see the appended types in /sys/kernel/btf/vmlinux, which
 * is the raw image. The merged BTF is offered as the "btf" file of this
 * module, to be bound over that path by the loader (contrib/scx61/scx-run).
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
#include "port.h"

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

static const struct btf_type *task_struct_type;
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
	 * a member "scx" over the vendor data words that hold the entity,
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
		m->offset = scx61_ent_offset() * 8;
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
	const struct btf_type *(*resolve_func_ptr)(const struct btf *, u32, u32 *) =
		(void *)kallsyms_name_to_addr("btf_type_resolve_func_ptr");
	int (*distill)(struct bpf_verifier_log *, struct btf *, const struct btf_type *,
		       const char *, struct btf_func_model *) =
		(void *)kallsyms_name_to_addr("btf_distill_func_proto");
	const struct btf_member *member;
	const struct btf_type *t;
	u32 i;
	int ret;

	if (!st || strcmp(st->name, "bpf_dummy_ops") || !resolve_func_ptr || !distill)
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
		const struct btf_type *proto = resolve_func_ptr((struct btf *)vm_btf, member->type, NULL);

		if (proto && distill(NULL, (struct btf *)vm_btf, proto, mname, &st->func_models[i])) {
			pr_err("cannot model sched_ext_ops.%s\n", mname);
			return -EINVAL;
		}
	}
	ret = scx61_st_init((struct btf *)vm_btf);
	if (ret)
		return ret;
	st->verifier_ops = scx61_st_verifier_ops();
	st->init = NULL;
	st->check_member = scx61_st_check_member;
	st->init_member = scx61_st_init_member;
	st->reg = scx61_st_reg;
	st->unreg = scx61_st_unreg;
	st->name = "sched_ext_ops";
	st->type = t;
	st->value_type = btf_type_by_id((struct btf *)vm_btf, value_id);
	st->value_id = value_id;
	/* Lookups go by type_id, so the slot becomes ours with this store. */
	st->type_id = type_id;
	return 0;
}

int scx61_btf_init(void)
{
	int ret;

	ret = graft_btf();
	if (ret)
		return ret;
	ret = sysfs_create_bin_file(&THIS_MODULE->mkobj.kobj, &merged_attr);
	if (ret)
		return ret;
	pr_info("%u types grafted onto the vmlinux BTF\n", mod_btf->nr_types);
	return 0;
}

int scx61_struct_ops_init(void)
{
	int ret = take_struct_ops_slot();

	if (!ret)
		pr_info("struct_ops type sched_ext_ops registered\n");
	return ret;
}
