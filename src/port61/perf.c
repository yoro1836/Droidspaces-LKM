// SPDX-License-Identifier: GPL-2.0-only
/* Add namespace ownership while retaining the target kernel's perf implementation. */
#include <linux/perf_event.h>
#include <linux/pid_namespace.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

extern struct perf_event *ds_perf_alloc_original(struct perf_event_attr *, int,
	struct task_struct *, struct perf_event *, struct perf_event *,
	perf_overflow_handler_t, void *, int);
extern void ds_perf_free_original(struct rcu_head *);
/* kprobe mode: direct calls (no kCFI check) into the native function */
extern bool ds_kprobe_hooks;
extern struct perf_event *ds_kp_perf_alloc(struct perf_event_attr *, int,
	struct task_struct *, struct perf_event *, struct perf_event *,
	perf_overflow_handler_t, void *, int);
extern void ds_kp_perf_free(struct rcu_head *);

struct ds_perf_ref {
	struct hlist_node link;
	struct perf_event *event;
	struct pid_namespace *ns;
};
static DEFINE_HASHTABLE(perf_refs, 8);
static DEFINE_SPINLOCK(perf_refs_lock);

struct perf_event *ds_perf_event_alloc(struct perf_event_attr *attr, int cpu,
	struct task_struct *task, struct perf_event *leader, struct perf_event *parent,
	perf_overflow_handler_t handler, void *context, int cgroup_fd)
{
	struct pid_namespace *ns = task_active_pid_ns(current);
	struct ds_perf_ref *ref = NULL;
	struct perf_event *event;
	unsigned long flags;

	if (ns != &init_pid_ns) {
		ref = kmalloc(sizeof(*ref), GFP_KERNEL);
		if (!ref)
			return ERR_PTR(-ENOMEM);
	}
	if (ds_kprobe_hooks)
		event = ds_kp_perf_alloc(attr, cpu, task, leader, parent, handler,
					 context, cgroup_fd);
	else
		event = ds_perf_alloc_original(attr, cpu, task, leader, parent,
					       handler, context, cgroup_fd);
	if (IS_ERR(event)) {
		/* Native allocation failures never enter the ownership table. */
		kfree(ref);
		return event;
	}
	if (ref) {
		ref->event = event;
		ref->ns = get_pid_ns(event->ns);
		spin_lock_irqsave(&perf_refs_lock, flags);
		hash_add(perf_refs, &ref->link, (unsigned long)event);
		spin_unlock_irqrestore(&perf_refs_lock, flags);
	}
	return event;
}

void ds_perf_free_event_rcu(struct rcu_head *head)
{
	struct perf_event *event = container_of(head, struct perf_event, rcu_head);
	struct ds_perf_ref *ref, *owned = NULL;
	unsigned long flags;

	spin_lock_irqsave(&perf_refs_lock, flags);
	hash_for_each_possible(perf_refs, ref, link, (unsigned long)event) {
		if (ref->event == event) {
			hash_del(&ref->link);
			owned = ref;
			break;
		}
	}
	spin_unlock_irqrestore(&perf_refs_lock, flags);
	if (ds_kprobe_hooks)
		ds_kp_perf_free(head);
	else
		ds_perf_free_original(head);
	if (owned) {
		put_pid_ns(owned->ns);
		kfree(owned);
	}
}
