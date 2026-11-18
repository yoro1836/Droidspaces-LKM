// SPDX-License-Identifier: GPL-2.0-only
/* Registration of the hook tables in hooks.h. */
#define pr_fmt(fmt) "droidspaces_scx: " fmt
#include <linux/module.h>
#include <linux/kprobes.h>
#include "hooks.h"

static const char *const kind_name[] = {
	[SCX61_VENDOR] = "vendor hook",
	[SCX61_REDIRECT] = "kprobe",
	[SCX61_KPROBE] = "kprobe",
	[SCX61_KRETPROBE] = "kretprobe",
};

static int redirect_pre(struct kprobe *kp, struct pt_regs *regs)
{
	instruction_pointer_set(regs, container_of(kp, struct scx61_hook, redirect_kp)->to);
	return 1;
}

int scx61_hooks_register(struct scx61_hook *hooks, unsigned int n)
{
	unsigned int i;
	int ret;

	for (i = 0; i < n; i++) {
		struct scx61_hook *h = &hooks[i];

		switch (h->kind) {
		case SCX61_VENDOR:
			ret = h->reg();
			break;
		case SCX61_REDIRECT:
			h->redirect_kp.symbol_name = h->name;
			h->redirect_kp.offset = h->offset;
			h->redirect_kp.pre_handler = redirect_pre;
			ret = register_kprobe(&h->redirect_kp);
			break;
		case SCX61_KPROBE:
			ret = register_kprobe(h->kp);
			break;
		case SCX61_KRETPROBE:
			ret = register_kretprobe(h->krp);
			break;
		default:
			ret = -EINVAL;
		}
		if (!ret)
			continue;
		if (h->optional) {
			pr_warn("%s %s: %d, without it: %s\n", kind_name[h->kind], h->name, ret, h->why);
			continue;
		}
		pr_err("%s %s: %d (%s)\n", kind_name[h->kind], h->name, ret, h->why);
		return ret;
	}
	return 0;
}
