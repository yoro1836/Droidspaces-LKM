/* SPDX-License-Identifier: GPL-2.0-only */
/* Force-included ahead of a scheduler's own headers when it is built for
 * android14-6.1 (build-upstream.sh), so that the scheduler source stays as
 * upstream has it.
 *
 * bpf_for() and bpf_repeat() are open-coded iterators, which the verifier
 * learned in v6.4. This one does know bounded loops, which is what they
 * become: libbpf's bpf_helpers.h leaves a definition alone that is already
 * there. The bound has to be something the verifier can see, such as a
 * constant or a value from read-only data, which is what schedulers loop to.
 */
#ifndef __SCX61_COMPAT_BPF_H
#define __SCX61_COMPAT_BPF_H

/* A loop to a bound the verifier cannot see, such as the weight of a cpumask,
 * never ends for it, and one to a large constant with branches in its body
 * overruns its limit of 8192 pending branches. So a bpf_for() runs for
 * SCX61_FOR_MAX rounds at most. Schedulers loop over CPUs, of which a phone
 * has far fewer; build with -DSCX61_FOR_MAX=N for a machine with more.
 */
#ifndef SCX61_FOR_MAX
#define SCX61_FOR_MAX 64
#endif
#define bpf_for(i, start, end) \
	for ((i) = (start); (i) < (end) && (i) < (start) + SCX61_FOR_MAX; (i)++)

/* bpf_for_each() over a typed iterator, such as the tasks of a DSQ. The
 * iterator kfuncs are there (upstream's ext.c brings its own), but to this
 * verifier they are three calls and a loop without a bound, so the rounds
 * are counted. The iterator starts zeroed because a kfunc may not be handed
 * uninitialised stack here.
 */
#ifndef SCX61_FOR_EACH_MAX
#define SCX61_FOR_EACH_MAX 32
#endif
#define bpf_for_each(type, cur, args...)						\
	for (int ___n = 0, ___once = 1; ___once; ___once = 0)				\
	for (struct bpf_iter_##type ___it						\
		     __attribute__((aligned(8), cleanup(bpf_iter_##type##_destroy))) = {},	\
	     *___p __attribute__((unused)) =						\
		     (bpf_iter_##type##_new(&___it, ##args),				\
		      /* as in libbpf: makes clang emit BTF for the destructor */	\
		      (void)bpf_iter_##type##_destroy, (void *)0);			\
	     ___n++ < SCX61_FOR_EACH_MAX && ((cur) = bpf_iter_##type##_next(&___it));)

/* bpf_repeat(BPF_MAX_LOOPS) is how a scheduler says "until I break", eight
 * million times at most. An iterator costs the v6.4 verifier nothing per
 * round, but this verifier walks a bounded loop round by round and gives up
 * after a million instructions. So the count is capped here; a scheduler
 * that pops a queue in such a loop pops that many per call at most.
 */
#define SCX61_REPEAT_MAX 256
#define bpf_repeat(N) \
	for (int ___i = 0; ___i < (N) && ___i < SCX61_REPEAT_MAX; ___i++)

#endif
