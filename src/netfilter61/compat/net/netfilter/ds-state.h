/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DS_NFT_STATE_H
#define DS_NFT_STATE_H
#include <net/netns/generic.h>
#include <net/netns/nftables.h>
/* Never add CONFIG_NF_TABLES to compilation: the native net lacks net->nft. */
extern unsigned int ds_nft_state_id;
static inline struct netns_nftables *ds_nft_state(const struct net *net)
{
    return net_generic(net, ds_nft_state_id);
}
#endif
