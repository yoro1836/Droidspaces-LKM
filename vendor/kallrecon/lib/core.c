// SPDX-License-Identifier: GPL-2.0-only
/*
 * core.c
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include "core.h"
#include "ks_dbg.h"
#include "access.h"
#include "discover.h"
#include "fastboot.h"
#include "hint.h"

unsigned long sprint_addr;
unsigned long kernel_base;
unsigned long klbase_addr;
unsigned long klbase_val;
unsigned long kloffs_addr;
unsigned long klindex_addr;
unsigned long klseqs_addr;
int klseqs_stride = 3;
unsigned int  klnum_val;
unsigned long klmarks_addr;
unsigned long kltable_addr;
unsigned long klnames_addr;
unsigned long klnum_addr;

enum layout_v kl_layout = LAYOUT_V2;
int is_v1_layout;

unsigned long (*kallrecon_klp)(const char *name);
#ifdef KALLRECON_MODULE_LOOKUP
unsigned long (*kallrecon_module_klp)(const char *name); /* experimental, may be unstable */
#endif

static DEFINE_MUTEX(ks_lock);
static int ks_done;
int kr_direct;

/*
 * Ask kprobes for kallsyms_lookup_name. The probe is registered disabled,
 * so no breakpoint is written, and nothing in kernel memory is scanned.
 * Scanning must be avoided where an EL2 hypervisor (Samsung Exynos)
 * forbids reads of some kernel image pages: that stage-2 fault is not a
 * recoverable EL1 fault, so copy_from_kernel_nofault() cannot catch it
 * and the device resets.
 */
static unsigned long kr_kprobe_klp(void)
{
#ifdef CONFIG_KPROBES
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
		.flags = KPROBE_FLAG_DISABLED,
	};
	unsigned long addr = 0;

	if (!register_kprobe(&kp)) {
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
	}
	return addr;
#else
	return 0;
#endif
}

static int find_kallsyms_base_once(void)
{
	unsigned long klp = kr_kprobe_klp();

	if (klp) {
		kallrecon_klp = (unsigned long (*)(const char *))klp;
		kr_direct = 1;
		ks_dbg("[kallrecon] kallsyms_lookup_name via kprobe: 0x%lx\n", klp);
		return 1;
	}

	if (!kr_discover_layout())
		return 0;

	if (kloffs_addr && klnames_addr && klnum_val) {
		unsigned long addr = 0;

#ifdef KALLRECON_FAST_BOOT
		/* only linear (no seqs) kernels need the walk, the seqs
		 * lookup is a fast binary search, KALLRECON_FAST_BOOT_ALL
		 * skips the seqs check */
		if (KALLRECON_FAST_BOOT_ALL || !klseqs_addr) {
			addr = fast_find_klp();
			ks_dbg("[kallrecon] fast boot: %s\n",
				addr ? "hit" : "miss");
		}
#endif
		if (!addr)
			addr = kallsyms_name_to_addr("kallsyms_lookup_name");
		if (addr)
			kallrecon_klp = (unsigned long (*)(const char *))addr;

#ifdef KALLRECON_MODULE_LOOKUP
		unsigned long maddr =
			kallsyms_name_to_addr("module_kallsyms_lookup_name");

		if (maddr)
			kallrecon_module_klp =
				(unsigned long (*)(const char *))maddr;
#endif
	} else {
		kr_fail_set(KALLRECON_NO_LAYOUT);
	}
	return 1;
}

int kallrecon_ready(void)
{
	return kallrecon_fail_reason() == KALLRECON_OK && (kr_direct || klnum_val);
}

void find_kallsyms_base(void)
{
	mutex_lock(&ks_lock);
	if (!ks_done) {
		kr_discover_reset();
		kr_direct = 0;
		if (find_kallsyms_base_once())
			ks_done = 1;
	}
	mutex_unlock(&ks_lock);
}
