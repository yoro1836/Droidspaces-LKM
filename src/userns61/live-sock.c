// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Socket peer identities as seen from the caller's user namespace, from the
 * Samsung S5E9945 vendor kernel (6.1) net/core/sock.c and net/core/scm.c.
 * Natively current_user_ns() is init_user_ns and from_kuid()/make_kuid()
 * are identity, so a task in a child namespace read host ids from
 * SO_PEERCRED, SO_PEERGROUPS and SCM_CREDENTIALS, and the ids it sent in
 * SCM_CREDENTIALS were taken as host ids.
 *
 * SO_PEERCRED / SO_PEERGROUPS: sk_getsockopt() is redirected to
 * ds_sk_getsockopt() for these two options when the caller is in a child
 * namespace (ds_sk_getsockopt_filter); the cases, cred_to_ucred() and
 * groups_to_user() are the vendor's, compiled with CONFIG_USER_NS.
 *
 * SCM_CREDENTIALS: scm_recv() and scm_check_creds() are inlined into their
 * callers, so two plain kprobes adjust the data those inlined conversions
 * use, giving the upstream results without copying the af_unix and netlink
 * receive paths:
 *  - put_cmsg(msg, SOL_SOCKET, SCM_CREDENTIALS, len, data): data is the
 *    ucred scm_recv() just built on its stack with identity conversion,
 *    i.e. the raw kuid/kgid values; map them into the receiver's namespace
 *    (from_k[ug]id_munged) before they are copied out.
 *  - __scm_send(sock, msg, scm): the control buffer is the kernel copy made
 *    by sendmsg; rewrite a sender's ucred ids to the kuid/kgid values they
 *    name in its namespace (make_k[ug]id), which is what the native identity
 *    make_kuid() then yields. An unmapped id becomes -1 and the native
 *    uid_valid() check fails with EINVAL, as upstream.
 * Both only act for a caller in a child namespace.
 */
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockptr.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <net/scm.h>
#include <net/sock.h>
#include "userns61.h"

static const struct cred *sk_get_peer_cred(struct sock *sk)
{
	const struct cred *cred;

	spin_lock(&sk->sk_peer_lock);
	cred = get_cred(sk->sk_peer_cred);
	spin_unlock(&sk->sk_peer_lock);

	return cred;
}

static void cred_to_ucred(struct pid *pid, const struct cred *cred,
			  struct ucred *ucred)
{
	ucred->pid = pid_vnr(pid);
	ucred->uid = ucred->gid = -1;
	if (cred) {
		struct user_namespace *current_ns = current_user_ns();

		ucred->uid = from_kuid_munged(current_ns, cred->euid);
		ucred->gid = from_kgid_munged(current_ns, cred->egid);
	}
}

static int groups_to_user(sockptr_t dst, const struct group_info *src)
{
	struct user_namespace *user_ns = current_user_ns();
	int i;

	for (i = 0; i < src->ngroups; i++) {
		gid_t gid = from_kgid_munged(user_ns, src->gid[i]);

		if (copy_to_sockptr_offset(dst, i * sizeof(gid), &gid, sizeof(gid)))
			return -EFAULT;
	}

	return 0;
}

/* sk_getsockopt(), SO_PEERCRED and SO_PEERGROUPS only (see the filter). */
int ds_sk_getsockopt(struct sock *sk, int level, int optname,
		     sockptr_t optval, sockptr_t optlen)
{
	int len;

	if (copy_from_sockptr(&len, optlen, sizeof(int)))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case SO_PEERCRED:
	{
		struct ucred peercred;
		if (len > sizeof(peercred))
			len = sizeof(peercred);

		spin_lock(&sk->sk_peer_lock);
		cred_to_ucred(sk->sk_peer_pid, sk->sk_peer_cred, &peercred);
		spin_unlock(&sk->sk_peer_lock);

		if (copy_to_sockptr(optval, &peercred, len))
			return -EFAULT;
		goto lenout;
	}

	case SO_PEERGROUPS:
	{
		const struct cred *cred;
		int ret, n;

		cred = sk_get_peer_cred(sk);
		if (!cred)
			return -ENODATA;

		n = cred->group_info->ngroups;
		if (len < n * sizeof(gid_t)) {
			len = n * sizeof(gid_t);
			put_cred(cred);
			return copy_to_sockptr(optlen, &len, sizeof(int)) ? -EFAULT : -ERANGE;
		}
		len = n * sizeof(gid_t);

		ret = groups_to_user(optval, cred->group_info);
		put_cred(cred);
		if (ret)
			return ret;
		goto lenout;
	}

	default:
		return -ENOPROTOOPT;
	}

lenout:
	if (copy_to_sockptr(optlen, &len, sizeof(int)))
		return -EFAULT;
	return 0;
}

/* Redirect only these options, and only for a caller in a child namespace. */
bool ds_sk_getsockopt_filter(struct pt_regs *regs)
{
	int optname = (int)regs->regs[2];

	return (optname == SO_PEERCRED || optname == SO_PEERGROUPS) &&
	       current_user_ns() != &init_user_ns;
}

static int put_cmsg_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct user_namespace *ns;
	struct ucred *u = (struct ucred *)regs->regs[4];

	if ((int)regs->regs[1] != SOL_SOCKET || (int)regs->regs[2] != SCM_CREDENTIALS ||
	    (int)regs->regs[3] != sizeof(*u) || !u)
		return 0;
	ns = current_user_ns();
	if (ns == &init_user_ns)
		return 0;
	u->uid = from_kuid_munged(ns, KUIDT_INIT(u->uid));
	u->gid = from_kgid_munged(ns, KGIDT_INIT(u->gid));
	return 0;
}

static int scm_send_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct msghdr *msg = (struct msghdr *)regs->regs[1];
	struct user_namespace *ns = current_user_ns();
	struct cmsghdr *cmsg;

	if (ns == &init_user_ns || !msg || msg->msg_control_is_user)
		return 0;
	for_each_cmsghdr(cmsg, msg) {
		struct ucred *u;

		if (!CMSG_OK(msg, cmsg))
			break;
		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_CREDENTIALS ||
		    cmsg->cmsg_len != CMSG_LEN(sizeof(*u)))
			continue;
		u = CMSG_DATA(cmsg);
		u->uid = __kuid_val(make_kuid(ns, u->uid));
		u->gid = __kgid_val(make_kgid(ns, u->gid));
	}
	return 0;
}

static struct kprobe put_cmsg_probe = {
	.symbol_name = "put_cmsg",
	.pre_handler = put_cmsg_pre,
};

static struct kprobe scm_send_probe = {
	.symbol_name = "__scm_send",
	.pre_handler = scm_send_pre,
};

/*
 * Both or neither: with only the receive side mapped, ids a child sends
 * would still be taken as host ids, as before this file.
 */
int ds_sock_creds_register(void)
{
	int ret = register_kprobe(&scm_send_probe);

	if (ret)
		return ret;
	ret = register_kprobe(&put_cmsg_probe);
	if (ret)
		unregister_kprobe(&scm_send_probe);
	return ret;
}
