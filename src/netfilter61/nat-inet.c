// SPDX-License-Identifier: GPL-2.0
/* INET NAT registration from the android14-6.1 vendor net/netfilter/nf_nat_proto.c.
 * The native kernel omits the INET wrapper. Reuse its protocol hooks and
 * registration machinery; private arrays avoid ambiguous native data names.
 */
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/netfilter/nf_nat.h>
extern unsigned int nf_nat_ipv4_pre_routing(void *, struct sk_buff *, const struct nf_hook_state *);
extern unsigned int nf_nat_ipv4_out(void *, struct sk_buff *, const struct nf_hook_state *);
extern unsigned int nf_nat_ipv4_local_fn(void *, struct sk_buff *, const struct nf_hook_state *);
extern unsigned int nf_nat_ipv4_local_in(void *, struct sk_buff *, const struct nf_hook_state *);
extern unsigned int nf_nat_ipv6_in(void *, struct sk_buff *, const struct nf_hook_state *);
extern unsigned int nf_nat_ipv6_out(void *, struct sk_buff *, const struct nf_hook_state *);
extern unsigned int nf_nat_ipv6_local_fn(void *, struct sk_buff *, const struct nf_hook_state *);
extern unsigned int nf_nat_ipv6_fn(void *, struct sk_buff *, const struct nf_hook_state *);

static const struct nf_hook_ops nf_nat_ipv4_ops[] = {
	/* Before packet filtering, change destination */
	{
		.hook		= nf_nat_ipv4_pre_routing,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_NAT_DST,
	},
	/* After packet filtering, change source */
	{
		.hook		= nf_nat_ipv4_out,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_NAT_SRC,
	},
	/* Before packet filtering, change destination */
	{
		.hook		= nf_nat_ipv4_local_fn,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_NAT_DST,
	},
	/* After packet filtering, change source */
	{
		.hook		= nf_nat_ipv4_local_in,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_NAT_SRC,
	},
};
static const struct nf_hook_ops nf_nat_ipv6_ops[] = {
	/* Before packet filtering, change destination */
	{
		.hook		= nf_nat_ipv6_in,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP6_PRI_NAT_DST,
	},
	/* After packet filtering, change source */
	{
		.hook		= nf_nat_ipv6_out,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP6_PRI_NAT_SRC,
	},
	/* Before packet filtering, change destination */
	{
		.hook		= nf_nat_ipv6_local_fn,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP6_PRI_NAT_DST,
	},
	/* After packet filtering, change source */
	{
		.hook		= nf_nat_ipv6_fn,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP6_PRI_NAT_SRC,
	},
};
int ds_nf_nat_inet_register_fn(struct net *net, const struct nf_hook_ops *ops)
{
	int ret;

	if (WARN_ON_ONCE(ops->pf != NFPROTO_INET))
		return -EINVAL;

	ret = nf_nat_register_fn(net, NFPROTO_IPV6, ops, nf_nat_ipv6_ops,
				 ARRAY_SIZE(nf_nat_ipv6_ops));
	if (ret)
		return ret;

	ret = nf_nat_register_fn(net, NFPROTO_IPV4, ops, nf_nat_ipv4_ops,
				 ARRAY_SIZE(nf_nat_ipv4_ops));
	if (ret)
		nf_nat_unregister_fn(net, NFPROTO_IPV6, ops,
					ARRAY_SIZE(nf_nat_ipv6_ops));
	return ret;
}

void ds_nf_nat_inet_unregister_fn(struct net *net, const struct nf_hook_ops *ops)
{
	nf_nat_unregister_fn(net, NFPROTO_IPV4, ops, ARRAY_SIZE(nf_nat_ipv4_ops));
	nf_nat_unregister_fn(net, NFPROTO_IPV6, ops, ARRAY_SIZE(nf_nat_ipv6_ops));
}
