// SPDX-License-Identifier: GPL-2.0-only
/* The smallest BPF scheduler: every task of the class goes to CPU 0. The test
 * watches where its tasks run and how often the kernel asked.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct task_struct;

struct sched_ext_ops {
	int (*select_cpu)(struct task_struct *p, int prev_cpu, unsigned long long wake_flags);
	char name[128];
};

extern unsigned int scx_bpf_nr_cpu_ids(void) __ksym;

unsigned long nr_calls;
unsigned int nr_cpus;

SEC("struct_ops/select_cpu")
int BPF_PROG(pin_select_cpu, struct task_struct *p, int prev_cpu, unsigned long long wake_flags)
{
	nr_cpus = scx_bpf_nr_cpu_ids();
	__sync_fetch_and_add(&nr_calls, 1);
	return 0;
}

SEC(".struct_ops")
struct sched_ext_ops pin_ops = {
	.select_cpu = (void *)pin_select_cpu,
	.name = "pin_to_cpu0",
};

char _license[] SEC("license") = "GPL";
