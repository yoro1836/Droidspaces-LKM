// SPDX-License-Identifier: GPL-2.0-only
/* The logic of upstream's scx_simple, both of its modes: a waking task that
 * finds an idle CPU runs there at once, everything else waits in one shared
 * queue that every CPU takes from, ordered by weighted vtime or, with
 * fifo_sched set, by arrival. Only the declarations differ from upstream,
 * which takes them from vmlinux.h and scx/common.bpf.h.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;

struct sched_ext_entity {
	u64 slice;
	u64 dsq_vtime;
	u32 weight;
} __attribute__((preserve_access_index));

struct task_struct {
	struct sched_ext_entity scx;
} __attribute__((preserve_access_index));

enum scx_exit_kind {
	SCX_EXIT_NONE,
};

struct scx_exit_info {
	enum scx_exit_kind kind;
} __attribute__((preserve_access_index));

struct sched_ext_ops {
	s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
	void (*enqueue)(struct task_struct *p, u64 enq_flags);
	void (*dispatch)(s32 cpu, struct task_struct *prev);
	void (*running)(struct task_struct *p);
	void (*stopping)(struct task_struct *p, _Bool runnable);
	void (*enable)(struct task_struct *p);
	s32 (*init)(void);
	void (*exit)(struct scx_exit_info *info);
	u32 timeout_ms;
	char name[128];
};

#define SCX_DSQ_LOCAL	((1ULL << 63) | 2)
#define SCX_SLICE_DFL	20000000ULL
#define SHARED_DSQ	0

extern void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern void scx_bpf_dispatch_vtime(struct task_struct *p, u64 dsq_id, u64 slice, u64 vtime,
				   u64 enq_flags) __ksym;
extern _Bool scx_bpf_consume(u64 dsq_id) __ksym;
extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
				  _Bool *is_idle) __ksym;

const volatile _Bool fifo_sched;

/* read by tests/vm/scx-load.c in this order */
unsigned long nr_local, nr_queued, nr_dispatch, nr_consumed, nr_running, nr_stopping;
unsigned long exit_kind;
static u64 vtime_now;

static inline _Bool vtime_before(u64 a, u64 b)
{
	return (long long)(a - b) < 0;
}

SEC("struct_ops/select_cpu")
s32 BPF_PROG(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	_Bool is_idle = 0;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		__sync_fetch_and_add(&nr_local, 1);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}
	return cpu;
}

SEC("struct_ops/enqueue")
void BPF_PROG(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	__sync_fetch_and_add(&nr_queued, 1);
	if (fifo_sched) {
		scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/* Limit the budget an idling task can build up to one slice. */
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;
		scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
	}
}

SEC("struct_ops/dispatch")
void BPF_PROG(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	__sync_fetch_and_add(&nr_dispatch, 1);
	if (scx_bpf_consume(SHARED_DSQ))
		__sync_fetch_and_add(&nr_consumed, 1);
}

SEC("struct_ops/running")
void BPF_PROG(simple_running, struct task_struct *p)
{
	__sync_fetch_and_add(&nr_running, 1);
	if (fifo_sched)
		return;
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

SEC("struct_ops/stopping")
void BPF_PROG(simple_stopping, struct task_struct *p, _Bool runnable)
{
	__sync_fetch_and_add(&nr_stopping, 1);
	if (fifo_sched)
		return;
	/* Charge the part of the slice that was used, scaled by weight. */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

SEC("struct_ops/enable")
void BPF_PROG(simple_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

SEC("struct_ops/init")
s32 BPF_PROG(simple_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

SEC("struct_ops/exit")
void BPF_PROG(simple_exit, struct scx_exit_info *ei)
{
	exit_kind = ei->kind;
}

SEC(".struct_ops")
struct sched_ext_ops simple_ops = {
	.select_cpu = (void *)simple_select_cpu,
	.enqueue = (void *)simple_enqueue,
	.dispatch = (void *)simple_dispatch,
	.running = (void *)simple_running,
	.stopping = (void *)simple_stopping,
	.enable = (void *)simple_enable,
	.init = (void *)simple_init,
	.exit = (void *)simple_exit,
	.timeout_ms = 5000,
	.name = "simple",
};

char _license[] SEC("license") = "GPL";
