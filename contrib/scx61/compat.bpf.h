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

#define bpf_for(i, start, end) for ((i) = (start); (i) < (end); (i)++)

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
