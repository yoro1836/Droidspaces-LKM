// SPDX-License-Identifier: GPL-2.0-only
/*
 * The "scx" cpufreq governor: 6.1's schedutil as 6.12 runs it under
 * sched_ext. Included from ext-port.c after ext-glue.c, for scx_enabled()
 * and the per-rq cpuperf_target.
 *
 * 6.12's sugov_get_util() takes the BPF scheduler's cpuperf target as the
 * CPU's fair utilization while every task is ours, and the core adds rt, dl
 * and irq on top. 6.1's schedutil cannot: it reads cfs util, which is empty
 * while our tasks run, so the frequency would sit at the bottom. Before this
 * governor the target was carried by FREQ_QOS_MIN floors (scx61_perf_workfn),
 * which stay as they are for policies run by any other governor.
 *
 * What differs from schedutil:
 * - Updates come from three places: the hooks of fair, rt and dl, which
 *   cpufreq_update_util() calls as for schedutil; scx_bpf_cpuperf_set(); and
 *   the tick of a task of ours. The rate limit counts in sched_clock(),
 *   since the last two do not have an rq clock to hand.
 * - No iowait boost: our tasks do not pass SCHED_CPUFREQ_IOWAIT.
 * - An idle CPU counts no cpuperf target. A scheduler sets the target when a
 *   task starts running and leaves it when the CPU goes idle, and 6.12 keeps
 *   counting that stale value for the whole policy. On a phone that holds a
 *   cluster at the last busy frequency while it sleeps.
 * With sched_ext off it is schedutil without iowait boost.
 */

struct scxg_policy {
	struct cpufreq_policy *policy;
	raw_spinlock_t update_lock;
	u64 last_update;
	s64 delay_ns;
	unsigned int next_freq;
	unsigned int cached_raw_freq;
	bool limits_changed;
	bool need_freq_update;
	/* the slow path, for a policy that cannot switch from the hook */
	struct irq_work irq_work;
	struct kthread_work work;
	struct kthread_worker *worker;
	struct mutex work_lock;
	bool work_in_progress;
};

struct scxg_cpu {
	struct update_util_data update_util;
	struct scxg_policy *sg;
	unsigned int cpu;
};

static DEFINE_PER_CPU(struct scxg_cpu, scxg_cpu);
/* set while the governor runs this CPU's policy, read by scx61_gov_update() */
static DEFINE_PER_CPU(struct scxg_cpu *, scxg_active);

static unsigned int scxg_rate_limit_us;
module_param_named(gov_rate_limit_us, scxg_rate_limit_us, uint, 0644);
MODULE_PARM_DESC(gov_rate_limit_us, "scx governor: minimum time between frequency changes, 0 for the driver's transition delay");

static unsigned long scxg_util(unsigned int cpu, unsigned long *max)
{
	unsigned long util;

	*max = arch_scale_cpu_capacity(cpu);
	if (scx_enabled())
		util = idle_cpu(cpu) ? 0 : scx_rq(cpu_rq(cpu))->cpuperf_target;
	else
		util = cpu_util_cfs(cpu);
	return effective_cpu_util(cpu, util, FREQUENCY_UTIL, NULL);
}

static unsigned int scxg_next_freq(struct scxg_policy *sg)
{
	struct cpufreq_policy *policy = sg->policy;
	unsigned long util = 0, max = 1, freq;
	unsigned int j;

	for_each_cpu(j, policy->cpus) {
		unsigned long j_max, j_util = scxg_util(j, &j_max);

		if (j_util * max > j_max * util) {
			util = j_util;
			max = j_max;
		}
	}
	freq = arch_scale_freq_invariant() ? policy->cpuinfo.max_freq : policy->cur;
	freq = map_util_freq(map_util_perf(util), freq, max);
	if (freq == sg->cached_raw_freq && !sg->need_freq_update)
		return sg->next_freq;
	sg->cached_raw_freq = freq;
	return cpufreq_driver_resolve_freq(policy, freq);
}

static void scxg_update(struct scxg_cpu *sg_cpu)
{
	struct scxg_policy *sg = sg_cpu->sg;
	unsigned long flags;
	unsigned int next;
	u64 now;

	if (!cpufreq_this_cpu_can_update(sg->policy))
		return;
	raw_spin_lock_irqsave(&sg->update_lock, flags);
	now = sched_clock();
	if (unlikely(sg->limits_changed)) {
		sg->limits_changed = false;
		sg->need_freq_update = true;
	} else if ((s64)(now - sg->last_update) < sg->delay_ns) {
		goto unlock;
	}
	next = scxg_next_freq(sg);
	if (sg->need_freq_update) {
		sg->need_freq_update = false;
		if (sg->next_freq == next && !cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS))
			goto unlock;
	} else if (sg->next_freq == next) {
		goto unlock;
	}
	sg->next_freq = next;
	sg->last_update = now;
	if (sg->policy->fast_switch_enabled) {
		cpufreq_driver_fast_switch(sg->policy, next);
	} else if (!sg->work_in_progress) {
		sg->work_in_progress = true;
		irq_work_queue(&sg->irq_work);
	}
unlock:
	raw_spin_unlock_irqrestore(&sg->update_lock, flags);
}

static void scxg_hook(struct update_util_data *data, u64 time, unsigned int flags)
{
	scxg_update(container_of(data, struct scxg_cpu, update_util));
}

/* From scx_bpf_cpuperf_set() and our tick. Returns false when this CPU's
 * policy is not ours, for the caller to fall back to the floors.
 */
static bool scx61_gov_update(void)
{
	struct scxg_cpu *sg_cpu;
	bool ours;

	/* Also called from process context, and the CPU must not change
	 * under it. synchronize_rcu() in scxg_stop() waits for this too.
	 */
	preempt_disable();
	sg_cpu = READ_ONCE(*this_cpu_ptr(&scxg_active));
	ours = sg_cpu;
	if (sg_cpu)
		scxg_update(sg_cpu);
	preempt_enable();
	return ours;
}

static void scxg_work(struct kthread_work *work)
{
	struct scxg_policy *sg = container_of(work, struct scxg_policy, work);
	unsigned long flags;
	unsigned int freq;

	raw_spin_lock_irqsave(&sg->update_lock, flags);
	freq = sg->next_freq;
	sg->work_in_progress = false;
	raw_spin_unlock_irqrestore(&sg->update_lock, flags);

	mutex_lock(&sg->work_lock);
	__cpufreq_driver_target(sg->policy, freq, CPUFREQ_RELATION_L);
	mutex_unlock(&sg->work_lock);
}

static void scxg_irq_work(struct irq_work *irq_work)
{
	struct scxg_policy *sg = container_of(irq_work, struct scxg_policy, irq_work);

	kthread_queue_work(sg->worker, &sg->work);
}

static int scxg_init(struct cpufreq_policy *policy)
{
	struct scxg_policy *sg;

	if (policy->governor_data)
		return -EBUSY;
	sg = kzalloc(sizeof(*sg), GFP_KERNEL);
	if (!sg)
		return -ENOMEM;
	sg->policy = policy;
	raw_spin_lock_init(&sg->update_lock);
	cpufreq_enable_fast_switch(policy);
	if (!policy->fast_switch_enabled) {
		sg->worker = kthread_create_worker(0, "scxgov:%d", cpumask_first(policy->related_cpus));
		if (IS_ERR(sg->worker)) {
			int ret = PTR_ERR(sg->worker);

			kfree(sg);
			return ret;
		}
		/* as schedutil's thread: frequency changes must not wait behind
		 * the work they are for. FIFO rather than its SCHED_DEADLINE
		 * with SCHED_FLAG_SUGOV, which is for the core's own thread.
		 */
		sched_set_fifo(sg->worker->task);
		kthread_bind_mask(sg->worker->task, policy->related_cpus);
		kthread_init_work(&sg->work, scxg_work);
		init_irq_work(&sg->irq_work, scxg_irq_work);
		mutex_init(&sg->work_lock);
	}
	policy->governor_data = sg;
	return 0;
}

static void scxg_exit(struct cpufreq_policy *policy)
{
	struct scxg_policy *sg = policy->governor_data;

	policy->governor_data = NULL;
	if (sg->worker)
		kthread_destroy_worker(sg->worker);
	cpufreq_disable_fast_switch(policy);
	kfree(sg);
}

static int scxg_start(struct cpufreq_policy *policy)
{
	struct scxg_policy *sg = policy->governor_data;
	unsigned int cpu, us = scxg_rate_limit_us ?: cpufreq_policy_transition_delay_us(policy);

	sg->delay_ns = (s64)us * NSEC_PER_USEC;
	sg->last_update = 0;
	sg->next_freq = 0;
	sg->cached_raw_freq = 0;
	sg->limits_changed = false;
	sg->work_in_progress = false;
	sg->need_freq_update = cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS);
	for_each_cpu(cpu, policy->cpus) {
		struct scxg_cpu *sg_cpu = &per_cpu(scxg_cpu, cpu);

		memset(sg_cpu, 0, sizeof(*sg_cpu));
		sg_cpu->cpu = cpu;
		sg_cpu->sg = sg;
		cpufreq_add_update_util_hook(cpu, &sg_cpu->update_util, scxg_hook);
		WRITE_ONCE(per_cpu(scxg_active, cpu), sg_cpu);
	}
	/* a floor set before the switch would hold the policy up */
	scx61_cpuperf_kick();
	return 0;
}

static void scxg_stop(struct cpufreq_policy *policy)
{
	struct scxg_policy *sg = policy->governor_data;
	unsigned int cpu;

	for_each_cpu(cpu, policy->cpus) {
		WRITE_ONCE(per_cpu(scxg_active, cpu), NULL);
		cpufreq_remove_update_util_hook(cpu);
	}
	synchronize_rcu();
	if (sg->worker) {
		irq_work_sync(&sg->irq_work);
		kthread_cancel_work_sync(&sg->work);
	}
	scx61_cpuperf_kick();
}

static void scxg_limits(struct cpufreq_policy *policy)
{
	struct scxg_policy *sg = policy->governor_data;

	if (sg->worker) {
		mutex_lock(&sg->work_lock);
		cpufreq_policy_apply_limits(policy);
		mutex_unlock(&sg->work_lock);
	}
	sg->limits_changed = true;
}

static struct cpufreq_governor scx61_gov = {
	.name = "scx",
	.owner = THIS_MODULE,
	.flags = CPUFREQ_GOV_DYNAMIC_SWITCHING,
	.init = scxg_init,
	.exit = scxg_exit,
	.start = scxg_start,
	.stop = scxg_stop,
	.limits = scxg_limits,
};

static bool scx61_policy_is_ours(struct cpufreq_policy *policy)
{
	return policy->governor == &scx61_gov;
}

static int scx61_gov_init(void)
{
	return cpufreq_register_governor(&scx61_gov);
}
