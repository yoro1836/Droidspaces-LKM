// SPDX-License-Identifier: GPL-2.0
/*
 * The kptr rules of v6.4 for the BPF core of android14-6.1.
 *
 * Schedulers keep a cpumask per task as a kptr in a task storage map, read
 * it inside an RCU section and hand it to cpumask kfuncs. On 6.1 a kptr may
 * only live in a hash or array map, and one read from a map is marked
 * untrusted, which no kfunc accepts. Both rules sit in functions of the
 * kernel that a kprobe can reach, and nothing here writes kernel memory:
 *
 * - map_check_btf() is replaced by a copy that also lets task storage maps
 *   have kptrs, and that finds the kptrs of a value as v6.4 does: 6.1 gives
 *   up on the whole value, silently, when it holds a struct or a pointer
 *   that is not laid out or tagged the way its kptr search expects.
 * - A task storage element is freed without a look at its kptrs, since none
 *   could be there: they are released when the element is unlinked.
 * - The verifier is left to run, and the register it marked for a load of a
 *   referenced kptr loses the untrusted mark afterwards, which
 *   is what v6.4 gives one inside an RCU section. BPF programs of the kinds
 *   that call our kfuncs always run inside one, and the cpumasks are freed
 *   through call_rcu, so the object is there for as long as the program
 *   can hold the pointer. The verifier no longer checks that, though.
 */
#define pr_fmt(fmt) "droidspaces_scx: " fmt
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf_local_storage.h>
#include <linux/btf.h>
#include <linux/kprobes.h>
#include "core.h"
#include "port.h"

static s32 (*find_btf_id_fn)(const char *name, u32 kind, struct btf **btf_p);
static s32 (*find_dtor_kfunc_fn)(struct btf *btf, u32 btf_id);
static struct module *(*try_get_module_fn)(const struct btf *btf);
/* the kernel's own, which knows module symbols: a destructor is in one */
static unsigned long (*lookup_name_fn)(const char *name);

/* btf.c keeps these two to itself. */
static bool kind_is_struct(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_STRUCT;
}

static bool kind_is_datasec(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_DATASEC;
}

struct kptr_field {
	u32 type_id;
	u32 off;
	enum bpf_kptr_type type;
};

/* Is @t, a member of a map value at byte @off, a kptr? Anything else in the
 * value is none of our business, which is where 6.1's search differs: it
 * fails on a pointer with a tag it does not know and on a struct that is
 * not 8-byte aligned.
 */
static int kptr_field(const struct btf *btf, const struct btf_type *t, u32 off,
		      struct kptr_field *field)
{
	const struct btf_type *tag;
	const char *name;
	u32 res_id;

	if (!btf_type_is_ptr(t))
		return 0;
	tag = btf_type_by_id(btf, t->type);
	if (!btf_type_is_type_tag(tag) || btf_type_is_type_tag(btf_type_by_id(btf, tag->type)))
		return 0;
	name = btf_name_by_offset(btf, tag->name_off);
	if (!strcmp(name, "kptr_ref"))
		field->type = BPF_KPTR_REF;
	else if (!strcmp(name, "kptr"))
		field->type = BPF_KPTR_UNREF;
	else
		return 0;
	if (off % 8 || !kind_is_struct(btf_type_skip_modifiers(btf, tag->type, &res_id)))
		return -EINVAL;
	field->type_id = res_id;
	field->off = off;
	return 1;
}

static int find_kptrs(const struct btf *btf, const struct btf_type *t,
		      struct kptr_field *fields, int max)
{
	const struct btf_var_secinfo *vsi;
	const struct btf_member *member;
	int i, ret, nr = 0;

	if (kind_is_struct(t)) {
		for_each_member(i, t, member) {
			if (__btf_member_bit_offset(t, member) % 8)
				continue;
			ret = kptr_field(btf, btf_type_by_id(btf, member->type),
					 __btf_member_bit_offset(t, member) / 8,
					 nr < max ? &fields[nr] : &fields[max - 1]);
			if (ret < 0)
				return ret;
			if (ret && ++nr > max)
				return -E2BIG;
		}
	} else if (kind_is_datasec(t)) {
		for_each_vsi(i, t, vsi) {
			const struct btf_type *var = btf_type_by_id(btf, vsi->type);

			ret = kptr_field(btf, btf_type_by_id(btf, var->type), vsi->offset,
					 nr < max ? &fields[nr] : &fields[max - 1]);
			if (ret < 0)
				return ret;
			if (ret && ++nr > max)
				return -E2BIG;
		}
	}
	return nr;
}

/* btf_parse_kptrs() of kernel/bpf/btf.c, on top of find_kptrs() */
static __nocfi struct bpf_map_value_off *scx61_parse_kptrs(const struct btf *btf,
							   const struct btf_type *t)
{
	struct kptr_field info_arr[BPF_MAP_VALUE_OFF_MAX];
	struct bpf_map_value_off *tab;
	struct btf *kernel_btf = NULL;
	struct module *mod = NULL;
	int ret, i, nr_off;

	ret = find_kptrs(btf, t, info_arr, ARRAY_SIZE(info_arr));
	if (ret < 0)
		return ERR_PTR(ret);
	if (!ret)
		return NULL;

	nr_off = ret;
	tab = kzalloc(offsetof(struct bpf_map_value_off, off[nr_off]), GFP_KERNEL | __GFP_NOWARN);
	if (!tab)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < nr_off; i++) {
		const struct btf_type *t;
		s32 id;

		/* Find type in map BTF, and use it to look up the matching type
		 * in vmlinux or module BTFs, by name and kind.
		 */
		t = btf_type_by_id(btf, info_arr[i].type_id);
		id = find_btf_id_fn(btf_name_by_offset(btf, t->name_off), BTF_INFO_KIND(t->info),
				    &kernel_btf);
		if (id < 0) {
			ret = id;
			goto end;
		}

		/* Find and stash the function pointer for the destruction function that
		 * needs to be eventually invoked from the map free path.
		 */
		mod = NULL;
		if (info_arr[i].type == BPF_KPTR_REF) {
			const struct btf_type *dtor_func;
			unsigned long addr;
			s32 dtor_btf_id;

			dtor_btf_id = find_dtor_kfunc_fn(kernel_btf, id);
			if (dtor_btf_id < 0) {
				ret = dtor_btf_id;
				goto end_btf;
			}

			dtor_func = btf_type_by_id(kernel_btf, dtor_btf_id);
			if (!dtor_func) {
				ret = -ENOENT;
				goto end_btf;
			}

			if (btf_is_module(kernel_btf)) {
				mod = try_get_module_fn(kernel_btf);
				if (!mod) {
					ret = -ENXIO;
					goto end_btf;
				}
			}

			addr = lookup_name_fn(btf_name_by_offset(kernel_btf, dtor_func->name_off));
			if (!addr) {
				ret = -EINVAL;
				goto end_mod;
			}
			tab->off[i].kptr.dtor = (void *)addr;
		}

		tab->off[i].offset = info_arr[i].off;
		tab->off[i].type = info_arr[i].type;
		tab->off[i].kptr.btf_id = id;
		tab->off[i].kptr.btf = kernel_btf;
		tab->off[i].kptr.module = mod;
	}
	tab->nr_off = nr_off;
	return tab;
end_mod:
	module_put(mod);
end_btf:
	btf_put(kernel_btf);
end:
	while (i--) {
		btf_put(tab->off[i].kptr.btf);
		if (tab->off[i].kptr.module)
			module_put(tab->off[i].kptr.module);
	}
	kfree(tab);
	return ERR_PTR(ret);
}

/* map_check_btf() of kernel/bpf/syscall.c, with BPF_MAP_TYPE_TASK_STORAGE
 * added to the maps that may hold kptrs.
 */
static int scx61_map_check_btf(struct bpf_map *map, const struct btf *btf,
			       u32 btf_key_id, u32 btf_value_id)
{
	const struct btf_type *key_type, *value_type;
	u32 key_size, value_size;
	int ret = 0;

	/* Some maps allow key to be unspecified. */
	if (btf_key_id) {
		key_type = btf_type_id_size(btf, &btf_key_id, &key_size);
		if (!key_type || key_size != map->key_size)
			return -EINVAL;
	} else {
		key_type = btf_type_by_id(btf, 0);
		if (!map->ops->map_check_btf)
			return -EINVAL;
	}

	value_type = btf_type_id_size(btf, &btf_value_id, &value_size);
	if (!value_type || value_size != map->value_size)
		return -EINVAL;

	map->spin_lock_off = btf_find_spin_lock(btf, value_type);

	if (map_value_has_spin_lock(map)) {
		if (map->map_flags & BPF_F_RDONLY_PROG)
			return -EACCES;
		if (map->map_type != BPF_MAP_TYPE_HASH &&
		    map->map_type != BPF_MAP_TYPE_ARRAY &&
		    map->map_type != BPF_MAP_TYPE_CGROUP_STORAGE &&
		    map->map_type != BPF_MAP_TYPE_SK_STORAGE &&
		    map->map_type != BPF_MAP_TYPE_INODE_STORAGE &&
		    map->map_type != BPF_MAP_TYPE_TASK_STORAGE)
			return -ENOTSUPP;
		if (map->spin_lock_off + sizeof(struct bpf_spin_lock) >
		    map->value_size) {
			WARN_ONCE(1,
				  "verifier bug spin_lock_off %d value_size %d\n",
				  map->spin_lock_off, map->value_size);
			return -EFAULT;
		}
	}

	map->timer_off = btf_find_timer(btf, value_type);
	if (map_value_has_timer(map)) {
		if (map->map_flags & BPF_F_RDONLY_PROG)
			return -EACCES;
		if (map->map_type != BPF_MAP_TYPE_HASH &&
		    map->map_type != BPF_MAP_TYPE_LRU_HASH &&
		    map->map_type != BPF_MAP_TYPE_ARRAY)
			return -EOPNOTSUPP;
	}

	map->kptr_off_tab = scx61_parse_kptrs(btf, value_type);
	if (IS_ERR(map->kptr_off_tab))
		pr_warn("map %s: kptrs not usable: %ld\n", map->name, PTR_ERR(map->kptr_off_tab));
	if (map_value_has_kptrs(map)) {
		if (!bpf_capable()) {
			ret = -EPERM;
			goto free_map_tab;
		}
		if (map->map_flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG)) {
			ret = -EACCES;
			goto free_map_tab;
		}
		if (map->map_type != BPF_MAP_TYPE_HASH &&
		    map->map_type != BPF_MAP_TYPE_LRU_HASH &&
		    map->map_type != BPF_MAP_TYPE_ARRAY &&
		    map->map_type != BPF_MAP_TYPE_PERCPU_ARRAY &&
		    map->map_type != BPF_MAP_TYPE_TASK_STORAGE) {
			ret = -EOPNOTSUPP;
			goto free_map_tab;
		}
	}

	if (map->ops->map_check_btf) {
		ret = map->ops->map_check_btf(map, btf, key_type, value_type);
		if (ret < 0)
			goto free_map_tab;
	}

	return ret;
free_map_tab:
	bpf_map_free_kptr_off_tab(map);
	return ret;
}

static int redirect_pre(struct kprobe *kp, struct pt_regs *regs)
{
	instruction_pointer_set(regs, (unsigned long)scx61_map_check_btf);
	return 1;
}

static struct kprobe map_check_btf_kp = {
	.symbol_name = "map_check_btf",
	.pre_handler = redirect_pre,
};

/* bpf_selem_unlink_storage_nolock(local_storage, selem, uncharge_mem,
 * use_trace_rcu): every element of a local storage map leaves through it.
 */
static int selem_unlink_pre(struct kprobe *kp, struct pt_regs *regs)
{
	struct bpf_local_storage_elem *selem = (void *)regs->regs[1];
	struct bpf_local_storage_map *smap;

	smap = rcu_dereference_check(SDATA(selem)->smap, true);
	if (smap && map_value_has_kptrs(&smap->map))
		bpf_map_free_kptrs(&smap->map, SDATA(selem)->data);
	return 0;
}

static struct kprobe selem_unlink_kp = {
	.symbol_name = "bpf_selem_unlink_storage_nolock",
	.pre_handler = selem_unlink_pre,
};

/* bpf_task_storage_get() gives up with NULL when a task storage operation is
 * already under way on this CPU, as when a wakeup from an interrupt lands in
 * a task's exit. From v6.2 only tracing programs get that, and schedulers
 * count on a lookup not failing: scx_bpfland returned the error from
 * select_cpu() on a Galaxy S24 and was thrown out. In that case the lookup
 * is done without touching the cache, which the core does itself without its
 * guard; creating storage still fails, as only init_task() does that.
 */
static int __percpu *task_storage_busy;
static struct bpf_local_storage_data *(*storage_lookup_fn)(struct bpf_local_storage *,
							   struct bpf_local_storage_map *, bool);

static __nocfi u64 scx61_task_storage_get_busy(struct bpf_map *map, struct task_struct *task,
					       void *value, u64 flags, gfp_t gfp)
{
	struct bpf_local_storage *storage;
	struct bpf_local_storage_data *sdata;

	if (!task || (flags & ~BPF_LOCAL_STORAGE_GET_F_CREATE))
		return 0;
	storage = rcu_dereference_check(task->bpf_storage, bpf_rcu_lock_held());
	if (!storage)
		return 0;
	sdata = storage_lookup_fn(storage, (struct bpf_local_storage_map *)map, false);
	return sdata ? (u64)sdata->data : 0;
}

static int task_storage_get_pre(struct kprobe *kp, struct pt_regs *regs)
{
	if (!this_cpu_read(*task_storage_busy))
		return 0;
	instruction_pointer_set(regs, (unsigned long)scx61_task_storage_get_busy);
	return 1;
}

static struct kprobe task_storage_get_kp = {
	.symbol_name = "bpf_task_storage_get",
	.pre_handler = task_storage_get_pre,
};

/* The verifier gives up after a million instructions walked. A v6.4 one
 * walks a bpf_for() once, as an iterator; this one walks every round, so a
 * scheduler that is small upstream runs out here (scx_lavd's dispatch does).
 * The limit only bounds how long verification takes, every path is still
 * checked, so a scheduler gets a larger one: the count is wound back as it
 * nears the limit, up to SCX61_INSN_BUDGET in all. It is seen from the
 * probe already on check_mem_access(), at every load and store, and from
 * states_equal(), which the compiler mostly inlined. A new probe on
 * push_stack() went with struct_ops trampolines that could not be executed
 * on a Galaxy S24, as one on bpf_task_storage_get() had, so none is added.
 */
#define SCX61_INSN_BUDGET (16U << 20)
#define SCX61_INSN_STEP (1U << 19)
static struct { struct bpf_verifier_env *env; u32 given; } insn_budget[4];
static unsigned int insn_budget_next;
static DEFINE_SPINLOCK(insn_budget_lock);

static void extend_insn_budget(struct bpf_verifier_env *env)
{
	unsigned int i;

	if (env->prog->type != BPF_PROG_TYPE_STRUCT_OPS || env->insn_processed < 3 * SCX61_INSN_STEP / 2)
		return;
	spin_lock(&insn_budget_lock);
	for (i = 0; i < ARRAY_SIZE(insn_budget); i++)
		if (insn_budget[i].env == env)
			break;
	/* A program verified at the address of an earlier one reaches this
	 * with an entry that has given some already: at worst it gets less.
	 */
	if (i == ARRAY_SIZE(insn_budget)) {
		i = insn_budget_next++ % ARRAY_SIZE(insn_budget);
		insn_budget[i].env = env;
		insn_budget[i].given = 0;
	}
	if (insn_budget[i].given < SCX61_INSN_BUDGET) {
		insn_budget[i].given += SCX61_INSN_STEP;
		env->insn_processed -= SCX61_INSN_STEP;
		env->prev_insn_processed -= min(env->prev_insn_processed, SCX61_INSN_STEP);
	}
	spin_unlock(&insn_budget_lock);
}

static int insn_budget_pre(struct kprobe *kp, struct pt_regs *regs)
{
	extend_insn_budget((void *)regs->regs[0]);
	return 0;
}

static struct kprobe states_equal_kp = {
	.symbol_name = "states_equal",
	.pre_handler = insn_budget_pre,
};


/* The rule itself is in check_map_kptr_access(), which the compiler folded
 * into its caller, so the probe is on that: check_mem_access(env, insn_idx,
 * regno, off, bpf_size, t, value_regno, strict_alignment_once). On the way
 * in it is noted whether this is a read of a referenced kptr out of a map
 * value, on the way out the register that received it is unmarked.
 */
struct kptr_access_args {
	struct bpf_verifier_env *env;
	int value_regno;
};

static int kptr_access_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kptr_access_args *a = (void *)ri->data;
	struct bpf_verifier_env *env = (void *)regs->regs[0];
	u32 regno = regs->regs[2];
	int off = regs->regs[3];
	enum bpf_access_type t = regs->regs[5];
	int value_regno = regs->regs[6];
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_map_value_off_desc *desc;
	struct bpf_reg_state *reg;

	a->env = NULL;
	extend_insn_budget(env);
	if (t != BPF_READ || value_regno < 0 || value_regno >= MAX_BPF_REG || regno >= MAX_BPF_REG)
		return 0;
	reg = &state->frame[state->curframe]->regs[regno];
	if (reg->type != PTR_TO_MAP_VALUE || !tnum_is_const(reg->var_off) ||
	    !map_value_has_kptrs(reg->map_ptr))
		return 0;
	desc = bpf_map_kptr_off_contains(reg->map_ptr, off + reg->off + reg->var_off.value);
	if (!desc || desc->type != BPF_KPTR_REF)
		return 0;
	a->env = env;
	a->value_regno = value_regno;
	return 0;
}

static int kptr_access_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kptr_access_args *a = (void *)ri->data;
	struct bpf_verifier_state *state;
	struct bpf_reg_state *reg;

	if (!a->env || regs_return_value(regs))
		return 0;
	state = a->env->cur_state;
	reg = &state->frame[state->curframe]->regs[a->value_regno];
	if (base_type(reg->type) == PTR_TO_BTF_ID)
		reg->type &= ~PTR_UNTRUSTED;
	return 0;
}

static struct kretprobe kptr_access_krp = {
	.kp.symbol_name = "check_mem_access",
	.entry_handler = kptr_access_entry,
	.handler = kptr_access_ret,
	.data_size = sizeof(struct kptr_access_args),
	.maxactive = 16,
};

/* check_map_func_compatibility(env, map, func_id) lists, per map type, the
 * helpers that may be handed such a map, and a task storage map is not on
 * bpf_kptr_xchg()'s. That refusal is turned into a pass on the way out.
 */
struct map_func_args {
	struct bpf_map *map;
	int func_id;
};

static int map_func_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct map_func_args *a = (void *)ri->data;

	a->map = (void *)regs->regs[1];
	a->func_id = regs->regs[2];
	return 0;
}

static int map_func_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct map_func_args *a = (void *)ri->data;

	if (regs_return_value(regs) && a->map && a->func_id == BPF_FUNC_kptr_xchg &&
	    a->map->map_type == BPF_MAP_TYPE_TASK_STORAGE)
		regs_set_return_value(regs, 0);
	return 0;
}

static struct kretprobe map_func_krp = {
	.kp.symbol_name = "check_map_func_compatibility",
	.entry_handler = map_func_entry,
	.handler = map_func_ret,
	.data_size = sizeof(struct map_func_args),
	.maxactive = 16,
};

int __init scx61_kptr_init(void)
{
	int ret;

	find_btf_id_fn = (void *)kallsyms_name_to_addr("bpf_find_btf_id");
	find_dtor_kfunc_fn = (void *)kallsyms_name_to_addr("btf_find_dtor_kfunc");
	try_get_module_fn = (void *)kallsyms_name_to_addr("btf_try_get_module");
	lookup_name_fn = (void *)kallsyms_name_to_addr("kallsyms_lookup_name");
	if (!find_btf_id_fn || !find_dtor_kfunc_fn || !try_get_module_fn || !lookup_name_fn)
		return -ENOENT;

	task_storage_busy = (void *)kallsyms_name_to_addr("bpf_task_storage_busy");
	storage_lookup_fn = (void *)kallsyms_name_to_addr("bpf_local_storage_lookup");
	/* Off: device crashes on non-executable trampolines began with the
	 * module that added this probe, and this is the check.
	 */
	if (true || !task_storage_busy || !storage_lookup_fn || register_kprobe(&task_storage_get_kp))
		pr_warn("droidspaces_scx: task storage lookups can fail under load\n");
	/* Small schedulers verify without it. */
	if (register_kprobe(&states_equal_kp))
		pr_warn("droidspaces_scx: no larger verifier budget, large schedulers will not load\n");
	ret = register_kprobe(&map_check_btf_kp);
	if (ret)
		return ret;
	ret = register_kprobe(&selem_unlink_kp);
	if (ret)
		return ret;
	ret = register_kretprobe(&kptr_access_krp);
	if (ret)
		return ret;
	return register_kretprobe(&map_func_krp);
}
