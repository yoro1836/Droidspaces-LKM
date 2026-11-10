// SPDX-License-Identifier: GPL-2.0
/*
 * nsfs ioctls and the ping group range sysctl from the Samsung S5E9945
 * vendor kernel (6.1), fs/nsfs.c and net/ipv4/sysctl_net_ipv4.c, compiled
 * with CONFIG_USER_NS. The native functions are redirected here
 * (port61/hooks.c).
 *
 * ns_ioctl(): natively ns_get_owner() is a stub returning -EPERM and
 * NS_GET_OWNER_UID converts with identity. Here NS_GET_USERNS uses this
 * module's ns_get_owner() (user_namespace.c), which follows each
 * namespace's ->owner() and admits only owners at or below the caller's
 * namespace; the reference it takes is dropped by userns_operations.put
 * when the nsfs inode is evicted.
 *
 * ipv4_ping_group_range(): natively the range is converted with
 * init_user_ns, so "0 0" written from a child namespace meant host gid 0.
 * Here it is read and written through the caller's namespace, as upstream;
 * the stored kgids and the native ping_init_sock() check are unchanged.
 */
#include <linux/fs.h>
#include <linux/nsfs.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/seqlock.h>
#include <linux/sysctl.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>
#include <net/ping.h>
#include "userns61.h"

long ds_ns_ioctl(struct file *filp, unsigned int ioctl,
			unsigned long arg)
{
	struct user_namespace *user_ns;
	struct ns_common *ns = get_proc_ns(file_inode(filp));
	uid_t __user *argp;
	uid_t uid;

	switch (ioctl) {
	case NS_GET_USERNS:
		return open_related_ns(ns, ns_get_owner);
	case NS_GET_PARENT:
		if (!ns->ops->get_parent)
			return -EINVAL;
		return open_related_ns(ns, ns->ops->get_parent);
	case NS_GET_NSTYPE:
		return ns->ops->type;
	case NS_GET_OWNER_UID:
		if (ns->ops->type != CLONE_NEWUSER)
			return -EINVAL;
		user_ns = container_of(ns, struct user_namespace, ns);
		argp = (uid_t __user *) arg;
		uid = from_kuid_munged(current_user_ns(), user_ns->owner);
		return put_user(uid, argp);
	default:
		return -ENOTTY;
	}
}

static unsigned long ip_ping_group_range_min[] = { 0, 0 };
static unsigned long ip_ping_group_range_max[] = { GID_T_MAX, GID_T_MAX };

static void inet_get_ping_group_range_table(struct ctl_table *table, kgid_t *low, kgid_t *high)
{
	kgid_t *data = table->data;
	struct net *net =
		container_of(table->data, struct net, ipv4.ping_group_range.range);
	unsigned int seq;
	do {
		seq = read_seqbegin(&net->ipv4.ping_group_range.lock);

		*low = data[0];
		*high = data[1];
	} while (read_seqretry(&net->ipv4.ping_group_range.lock, seq));
}

/* Update system visible IP port range */
static void set_ping_group_range(struct ctl_table *table, kgid_t low, kgid_t high)
{
	kgid_t *data = table->data;
	struct net *net =
		container_of(table->data, struct net, ipv4.ping_group_range.range);
	write_seqlock(&net->ipv4.ping_group_range.lock);
	data[0] = low;
	data[1] = high;
	write_sequnlock(&net->ipv4.ping_group_range.lock);
}

/* Validate changes from /proc interface. */
int ds_ipv4_ping_group_range(struct ctl_table *table, int write,
				 void *buffer, size_t *lenp, loff_t *ppos)
{
	struct user_namespace *user_ns = current_user_ns();
	int ret;
	unsigned long urange[2];
	kgid_t low, high;
	struct ctl_table tmp = {
		.data = &urange,
		.maxlen = sizeof(urange),
		.mode = table->mode,
		.extra1 = &ip_ping_group_range_min,
		.extra2 = &ip_ping_group_range_max,
	};

	inet_get_ping_group_range_table(table, &low, &high);
	urange[0] = from_kgid_munged(user_ns, low);
	urange[1] = from_kgid_munged(user_ns, high);
	ret = proc_doulongvec_minmax(&tmp, write, buffer, lenp, ppos);

	if (write && ret == 0) {
		low = make_kgid(user_ns, urange[0]);
		high = make_kgid(user_ns, urange[1]);
		if (!gid_valid(low) || !gid_valid(high))
			return -EINVAL;
		if (urange[1] < urange[0] || gid_lt(high, low)) {
			low = make_kgid(&init_user_ns, 1);
			high = make_kgid(&init_user_ns, 0);
		}
		set_ping_group_range(table, low, high);
	}

	return ret;
}
