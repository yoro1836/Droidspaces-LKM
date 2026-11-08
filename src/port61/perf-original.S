/* SPDX-License-Identifier: GPL-2.0-only */
/* Populated before hooks become reachable; only checked position-independent prologues. */
.text
.balign 16
.global ds_perf_alloc_original
.type ds_perf_alloc_original, %function
ds_perf_alloc_original:
.rept 8
brk #0
.endr
.size ds_perf_alloc_original, .-ds_perf_alloc_original
.balign 16
.global ds_perf_free_original
.type ds_perf_free_original, %function
ds_perf_free_original:
.rept 8
brk #0
.endr
.size ds_perf_free_original, .-ds_perf_free_original

/*
 * kprobe mode (no kernel text writes): call the native function itself.
 * x16 carries DS_KP_MAGIC so the entry kprobe lets this call through.
 * x16/x17 are intra-procedure scratch registers, never arguments.
 */
.macro ds_kp_call name, target
.balign 16
.global \name
.type \name, %function
\name:
	adrp	x17, \target
	ldr	x17, [x17, :lo12:\target]
	movz	x16, #0x4947
	movk	x16, #0x4f52, lsl #16
	movk	x16, #0x4b50, lsl #32
	movk	x16, #0x4453, lsl #48
	br	x17
.size \name, .-\name
.endm

ds_kp_call ds_kp_perf_alloc, ds_kp_perf_alloc_target
ds_kp_call ds_kp_perf_free, ds_kp_perf_free_target
ds_kp_call ds_kp_reboot, ds_kp_reboot_target
