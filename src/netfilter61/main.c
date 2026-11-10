// SPDX-License-Identifier: GPL-2.0-only
/*
 * nftables for an android14-6.1 kernel built without CONFIG_NF_TABLES.
 * The upstream/ sources are the vendor's, adapted mechanically by
 * scripts/gen-netfilter61.py; per-net nftables state lives in net_generic
 * storage so the native struct net is not changed. Units register in the
 * order of units.h and are torn down in reverse.
 */
#define pr_fmt(fmt) "droidspaces_netfilter: " fmt
#include <linux/module.h>
#include <linux/string.h>
#include <linux/utsname.h>
#include <net/net_namespace.h>
#include <net/netns/nftables.h>

unsigned int ds_nft_state_id;
static struct pernet_operations ds_nft_state_ops = {
    .id = &ds_nft_state_id,
    .size = sizeof(struct netns_nftables),
};
#define DS_NF_UNIT(name) \
    extern int ds_nf_init_##name(void); \
    extern void ds_nf_exit_##name(void);
#include "units.h"
#undef DS_NF_UNIT
struct ds_nf_unit { const char *name; int (*init)(void); void (*exit)(void); };
static struct ds_nf_unit units[] = {
#define DS_NF_UNIT(name) { #name, ds_nf_init_##name, ds_nf_exit_##name },
#include "units.h"
#undef DS_NF_UNIT
};
static int __init ds_netfilter_init(void)
{
    const char *release = utsname()->release;
    unsigned int i;
    int err;

    /* Built from android14-6.1 sources; structure layouts are that KMI's. */
    if (strncmp(release, "6.1.", 4) || !strstr(release, "-android14-"))
        return -EOPNOTSUPP;
    err = register_pernet_subsys(&ds_nft_state_ops);
    if (err)
        return err;
    for (i = 0; i < ARRAY_SIZE(units); i++) {
        err = units[i].init();
        if (err) {
            pr_err("%s registration failed: %d\n", units[i].name, err);
            while (i)
                units[--i].exit();
            unregister_pernet_subsys(&ds_nft_state_ops);
            return err;
        }
    }
    pr_info("nftables registered (%zu units); private per-net state\n", ARRAY_SIZE(units));
    return 0;
}
static void __exit ds_netfilter_exit(void)
{
    unsigned int i = ARRAY_SIZE(units);
    while (i)
        units[--i].exit();
    unregister_pernet_subsys(&ds_nft_state_ops);
}
module_init(ds_netfilter_init);
module_exit(ds_netfilter_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shikochin");
MODULE_DESCRIPTION("Droidspaces nftables for android14-6.1 kernels without CONFIG_NF_TABLES");
