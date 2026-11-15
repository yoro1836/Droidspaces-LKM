// SPDX-License-Identifier: GPL-2.0-only
/* A global FIFO scheduler, the shape of upstream's scx_simple in FIFO mode:
 * a waking task that finds an idle CPU runs there at once, everything else
 * waits in one shared queue that every CPU takes from.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* A full scheduler takes this from vmlinux.h. libbpf will not match a kfunc
 * whose argument is only forward declared here.
 */
struct task_struct {
	int pid;
} __attribute__((preserve_access_index));

struct sched_ext_ops {
	int (*select_cpu)(struct task_struct *p, int prev_cpu, unsigned long long wake_flags);
	void (*enqueue)(struct task_struct *p, unsigned long long enq_flags);
	void (*dispatch)(int cpu, struct task_struct *prev);
	void (*running)(struct task_struct *p);
	void (*stopping)(struct task_struct *p, _Bool runnable);
	int (*init)(void);
	char name[128];
};

#define SCX_DSQ_LOCAL	((1ULL << 63) | 2)
#define SCX_SLICE_DFL	20000000ULL
#define SHARED_DSQ	0

extern void scx_bpf_dispatch(struct task_struct *p, __u64 dsq_id, __u64 slice,
			     __u64 enq_flags) __ksym;
extern _Bool scx_bpf_consume(__u64 dsq_id) __ksym;
extern int scx_bpf_create_dsq(__u64 dsq_id, int node) __ksym;
extern int scx_bpf_select_cpu_dfl(struct task_struct *p, int prev_cpu, __u64 wake_flags,
				  _Bool *is_idle) __ksym;

/* read by tests/vm/scx-load.c in this order */
unsigned long nr_local, nr_queued, nr_dispatch, nr_consumed, nr_running, nr_stopping;

SEC("struct_ops/select_cpu")
int BPF_PROG(fifo_select_cpu, struct task_struct *p, int prev_cpu, unsigned long long wake_flags)
{
	_Bool is_idle = 0;
	int cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		__sync_fetch_and_add(&nr_local, 1);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}
	return cpu;
}

SEC("struct_ops/enqueue")
int BPF_PROG(fifo_enqueue, struct task_struct *p, unsigned long long enq_flags)
{
	__sync_fetch_and_add(&nr_queued, 1);
	scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	return 0;
}

SEC("struct_ops/dispatch")
int BPF_PROG(fifo_dispatch, int cpu, struct task_struct *prev)
{
	__sync_fetch_and_add(&nr_dispatch, 1);
	if (scx_bpf_consume(SHARED_DSQ))
		__sync_fetch_and_add(&nr_consumed, 1);
	return 0;
}

SEC("struct_ops/running")
int BPF_PROG(fifo_running, struct task_struct *p)
{
	__sync_fetch_and_add(&nr_running, 1);
	return 0;
}

SEC("struct_ops/stopping")
int BPF_PROG(fifo_stopping, struct task_struct *p, _Bool runnable)
{
	__sync_fetch_and_add(&nr_stopping, 1);
	return 0;
}

SEC("struct_ops/init")
int BPF_PROG(fifo_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

SEC(".struct_ops")
struct sched_ext_ops fifo_ops = {
	.select_cpu = (void *)fifo_select_cpu,
	.enqueue = (void *)fifo_enqueue,
	.dispatch = (void *)fifo_dispatch,
	.running = (void *)fifo_running,
	.stopping = (void *)fifo_stopping,
	.init = (void *)fifo_init,
	.name = "fifo",
};

char _license[] SEC("license") = "GPL";
