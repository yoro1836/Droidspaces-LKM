/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Every hook the module puts on the kernel, as tables.
 *
 * The port lives on hooks: vendor hooks where Android has one, kprobes
 * where it does not. Written out one call at a time they were spread over
 * three files, and finding the ones that decide something without the rq
 * lock (a Galaxy S24 went down in do_sched_yield() from one of those) meant
 * reading all of them. Each entry says where it sits, how it is entered, in
 * what lock context the kernel calls it, whether it is on a hot path, and
 * why it is there.
 */
#ifndef DS_SCX61_HOOKS_H
#define DS_SCX61_HOOKS_H
#include <linux/kprobes.h>

enum scx61_hook_kind {
	SCX61_VENDOR,	/* register_trace_android_{vh,rvh}_*: cannot be unregistered */
	SCX61_REDIRECT,	/* kprobe that moves the PC to .to: replaces the function */
	SCX61_KPROBE,	/* kprobe with its own pre_handler: runs before it */
	SCX61_KRETPROBE,
};

/* The lock the kernel holds when it enters the hook. */
enum scx61_hook_ctx {
	SCX61_RQ_LOCKED,
	SCX61_PI_LOCKED,	/* p->pi_lock, not the rq lock */
	SCX61_UNLOCKED,		/* anything decided here can change before use */
	SCX61_BPF,		/* BPF load or run time, outside the scheduler */
};

struct scx61_hook {
	const char *name;
	enum scx61_hook_kind kind;
	enum scx61_hook_ctx ctx;
	bool hot;		/* taken on every context switch, tick or wakeup */
	bool optional;		/* a failure is logged and the rest goes on */
	const char *why;
	union {
		int (*reg)(void);		/* SCX61_VENDOR */
		struct kprobe *kp;		/* SCX61_KPROBE */
		struct kretprobe *krp;		/* SCX61_KRETPROBE */
		struct {			/* SCX61_REDIRECT */
			unsigned long to;
			unsigned int offset;
		};
	};
	struct kprobe redirect_kp;	/* SCX61_REDIRECT: filled at registration */
};

/* A vendor hook needs a registration function of its own type, so each one
 * gets a small one: SCX61_VENDOR_REG(android_rvh_x, fn) before the table,
 * then SCX61_VENDOR_HOOK(android_rvh_x, ...) in it.
 */
#define SCX61_VENDOR_REG(hook, fn) \
	static int scx61_reg_##hook(void) { return register_trace_##hook(fn, NULL); }
#define SCX61_VENDOR_HOOK(hook, c, h, w) \
	{ .name = #hook, .kind = SCX61_VENDOR, .ctx = c, .hot = h, .why = w, .reg = scx61_reg_##hook }
#define SCX61_REDIRECT_HOOK(sym, fn, c, h, w) \
	{ .name = sym, .kind = SCX61_REDIRECT, .ctx = c, .hot = h, .why = w, .to = (unsigned long)(fn) }

/* Registers the table in order. Stops at the first failure of an entry that
 * is not optional and returns its error; what was registered before stays.
 */
int scx61_hooks_register(struct scx61_hook *hooks, unsigned int n);

#endif
