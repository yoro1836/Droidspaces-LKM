// SPDX-License-Identifier: GPL-2.0
/* android14-6.1 is built with kCFI, and its BPF JIT puts no type word in
 * front of a program (v6.8 does). Kernel code that calls a BPF callback
 * through a function pointer therefore fails the check and the kernel
 * panics: the first bpf_timer that fired under a scheduler took the test VM
 * down, in bpf_timer_cb().
 *
 * The two such callers a scheduler is likely to reach are replaced by the
 * copies below, which make the same call without the check. main.c puts a
 * kprobe on each that moves the PC here. The map iteration helpers
 * (bpf_for_each_map_elem) and bpf_find_vma call callbacks the same way and
 * are not covered.
 */
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/hrtimer.h>
#include <linux/percpu.h>
#include "port.h"

/* kernel/bpf/helpers.c keeps this private. android14-6.1 layout. */
struct ds_bpf_hrtimer {
	struct hrtimer timer;
	struct bpf_map *map;
	struct bpf_prog *prog;
	void __rcu *callback_fn;
	void *value;
	struct rcu_head rcu;
};

/* helpers.c's per-CPU note of the timer whose callback is running, which
 * bpf_timer_cancel() reads to avoid waiting for itself.
 */
static struct ds_bpf_hrtimer * __percpu *hrtimer_running;

void scx61_set_hrtimer_running(void *addr)
{
	hrtimer_running = addr;
}

/* bpf_timer_cb() of kernel/bpf/helpers.c */
__nocfi enum hrtimer_restart scx61_bpf_timer_cb(struct hrtimer *hrtimer)
{
	struct ds_bpf_hrtimer *t = container_of(hrtimer, struct ds_bpf_hrtimer, timer);
	struct bpf_map *map = t->map;
	void *value = t->value;
	bpf_callback_t callback_fn;
	void *key;
	u32 idx;

	callback_fn = rcu_dereference_check(t->callback_fn, rcu_read_lock_bh_held());
	if (!callback_fn)
		goto out;

	this_cpu_write(*hrtimer_running, t);
	if (map->map_type == BPF_MAP_TYPE_ARRAY) {
		struct bpf_array *array = container_of(map, struct bpf_array, map);

		/* compute the key */
		idx = ((char *)value - array->value) / array->elem_size;
		key = &idx;
	} else { /* hash or lru */
		key = value - round_up(map->key_size, 8);
	}

	callback_fn((u64)(long)map, (u64)(long)key, (u64)(long)value, 0, 0);
	/* The verifier checked that return value is zero. */

	this_cpu_write(*hrtimer_running, NULL);
out:
	return HRTIMER_NORESTART;
}

/* bpf_loop() of kernel/bpf/bpf_iter.c, as the helper's five-register entry */
__nocfi u64 scx61_bpf_loop(u64 nr_loops, u64 callback_fn, u64 callback_ctx, u64 flags, u64 r5)
{
	bpf_callback_t callback = (bpf_callback_t)callback_fn;
	u64 ret;
	u32 i;

	if (flags)
		return -EINVAL;
	if ((u32)nr_loops > BPF_MAX_LOOPS)
		return -E2BIG;

	for (i = 0; i < (u32)nr_loops; i++) {
		ret = callback((u64)i, callback_ctx, 0, 0, 0);
		/* return value: 0 - continue, 1 - stop and return */
		if (ret)
			return i + 1;
	}

	return i;
}
