// SPDX-License-Identifier: GPL-2.0
/* Upstream's kernel/bpf/cpumask.c, compiled for android14-6.1, where these
 * kfuncs do not exist yet (v6.3). The code is in cpumask-gen.c, generated
 * from upstream/cpumask.c.
 */
#define pr_fmt(fmt) "droidspaces_scx: " fmt
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/cpumask.h>
#include "compat-bpf.h"
#include "port.h"

/* 6.12 frees through bpf_mem_alloc's RCU variant, which 6.1's allocator does
 * not have. A mask is rare enough for kmalloc and call_rcu, with the RCU
 * head in front of it.
 */
struct scx61_rcu_obj {
	struct rcu_head rcu;
	char obj[];
};

static void *scx61_rcu_alloc(size_t size)
{
	struct scx61_rcu_obj *o = kmalloc(sizeof(*o) + size, GFP_ATOMIC);

	return o ? o->obj : NULL;
}

static void scx61_rcu_free_cb(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct scx61_rcu_obj, rcu));
}

static void scx61_rcu_free(void *obj)
{
	call_rcu(&container_of(obj, struct scx61_rcu_obj, obj)->rcu, scx61_rcu_free_cb);
}

#define bpf_mem_alloc_init(ma, size, percpu)	0
#define bpf_mem_cache_alloc(ma)			scx61_rcu_alloc(sizeof(struct bpf_cpumask))
#define bpf_mem_cache_free_rcu(ma, obj)		scx61_rcu_free(obj)

#include "cpumask-gen.c"

int __init scx61_cpumask_init(void)
{
	return cpumask_kfunc_init();
}
