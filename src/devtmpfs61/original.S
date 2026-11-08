/* SPDX-License-Identifier: GPL-2.0-only */
/* Populated before hooks become reachable; only checked position-independent prologues. */
.text
.balign 16
.global ds_device_add_original
.type ds_device_add_original, %function
ds_device_add_original:
.rept 8
brk #0
.endr
.size ds_device_add_original, .-ds_device_add_original
.balign 16
.global ds_device_del_original
.type ds_device_del_original, %function
ds_device_del_original:
.rept 8
brk #0
.endr
.size ds_device_del_original, .-ds_device_del_original

/* kprobe mode: x16 = DS_KP_MAGIC marks a native call for the entry kprobe. */
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

ds_kp_call ds_kp_device_add, ds_kp_device_add_target
ds_kp_call ds_kp_device_del, ds_kp_device_del_target
