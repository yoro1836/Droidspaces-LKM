/* SPDX-License-Identifier: GPL-2.0-only */
/* Between the three files of the port: ext-port.c (upstream's ext.c and its
 * 6.1 glue), port-btf.c (BTF graft and the struct_ops slot) and port-main.c
 * (module init).
 */
#ifndef DS_SCX61_PORT_H
#define DS_SCX61_PORT_H
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/btf.h>

/* ext-port.c */
int scx61_glue_init(void);
size_t scx61_ent_offset(void);
const struct bpf_verifier_ops *scx61_st_verifier_ops(void);
int scx61_st_init(struct btf *btf);
int scx61_st_check_member(const struct btf_type *t, const struct btf_member *member);
int scx61_st_init_member(const struct btf_type *t, const struct btf_member *member,
			 void *kdata, const void *udata);
int scx61_st_reg(void *kdata);
void scx61_st_unreg(void *kdata);

/* port-btf.c */
int scx61_btf_init(void);
int scx61_struct_ops_init(void);
#endif
