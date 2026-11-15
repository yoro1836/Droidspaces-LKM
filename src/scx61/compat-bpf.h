/* SPDX-License-Identifier: GPL-2.0-only */
/* How 6.12 declares kfuncs, for a verifier that is 6.1's. */
#ifndef DS_SCX61_COMPAT_BPF_H
#define DS_SCX61_COMPAT_BPF_H
#include <linux/btf.h>
#include <linux/btf_ids.h>

#define __bpf_kfunc			__used noinline
#define __bpf_kfunc_start_defs()						\
	__diag_push();								\
	__diag_ignore_all("-Wmissing-prototypes", "kfuncs are called from BPF only")
#define __bpf_kfunc_end_defs()		__diag_pop()
#define BTF_KFUNCS_START(name)		BTF_SET8_START(name)
#define BTF_KFUNCS_END(name)		BTF_SET8_END(name)
/* x86 IBT sealing, which 6.12 exempts destructors from */
#define CFI_NOSEAL(func)
/* Flags this verifier does not know. A kfunc that takes a task gets it from
 * the callback's arguments, which 6.1 does not count as trusted, so that
 * requirement goes too.
 */
#define KF_RCU			0
#define KF_ITER_NEW		0
#define KF_ITER_NEXT		0
#define KF_ITER_DESTROY		0
#define KF_RCU_PROTECTED		0
/* See the kmalloc_node() change in scripts/gen-scx61.py. */
#undef KF_SLEEPABLE
#define KF_SLEEPABLE		0
#undef KF_TRUSTED_ARGS
#define KF_TRUSTED_ARGS		0
#define PTR_TRUSTED		0

#endif
