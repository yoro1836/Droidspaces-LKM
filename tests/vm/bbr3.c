// SPDX-License-Identifier: GPL-2.0-only
/*
 * Exercise the "bbr3" congestion control over loopback: select it per socket,
 * push data for a few seconds, and read its state back through TCP_CC_INFO.
 * With a delay/loss argument a netem qdisc is put on lo first, so the loss
 * and probing paths run too.
 *
 * usage: bbr3 <label> <seconds> [delay_ms loss_permille]
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PORT 5201

static void die(const char *what)
{
	fprintf(stderr, "bbr3: %s: %s\n", what, strerror(errno));
	exit(1);
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* RTM_NEWQDISC/RTM_DELQDISC for "netem" as the root qdisc of lo. */
static void netem(int add, unsigned int delay_ms, unsigned int loss_permille)
{
	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[256];
	} req;
	struct {
		struct nlmsghdr n;
		struct nlmsgerr e;
	} ack;
	struct rtattr *kind, *opts, *lat;
	struct tc_netem_qopt qopt;
	int64_t latency_ns = (int64_t)delay_ms * 1000000;
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (fd < 0)
		die("netlink socket");
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.t));
	req.n.nlmsg_type = add ? RTM_NEWQDISC : RTM_DELQDISC;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
	req.t.tcm_family = AF_UNSPEC;
	req.t.tcm_ifindex = if_nametoindex("lo");
	req.t.tcm_handle = 0x00010000;
	req.t.tcm_parent = TC_H_ROOT;

	kind = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
	kind->rta_type = TCA_KIND;
	kind->rta_len = RTA_LENGTH(sizeof("netem"));
	memcpy(RTA_DATA(kind), "netem", sizeof("netem"));
	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(kind->rta_len);

	if (add) {
		memset(&qopt, 0, sizeof(qopt));
		qopt.limit = 10000;
		qopt.loss = (uint32_t)((uint64_t)loss_permille * 0xffffffffULL / 1000);
		opts = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
		opts->rta_type = TCA_OPTIONS;
		memcpy(RTA_DATA(opts), &qopt, sizeof(qopt));
		lat = (struct rtattr *)((char *)RTA_DATA(opts) + RTA_ALIGN(sizeof(qopt)));
		lat->rta_type = TCA_NETEM_LATENCY64;
		lat->rta_len = RTA_LENGTH(sizeof(latency_ns));
		memcpy(RTA_DATA(lat), &latency_ns, sizeof(latency_ns));
		opts->rta_len = RTA_LENGTH(RTA_ALIGN(sizeof(qopt)) + RTA_ALIGN(lat->rta_len));
		req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(opts->rta_len);
	}
	if (send(fd, &req, req.n.nlmsg_len, 0) < 0)
		die("netlink send");
	if (recv(fd, &ack, sizeof(ack), 0) < 0)
		die("netlink recv");
	if (ack.n.nlmsg_type == NLMSG_ERROR && ack.e.error) {
		errno = -ack.e.error;
		die(add ? "add netem" : "delete netem");
	}
	close(fd);
}

static void *sink(void *arg)
{
	int lfd = *(int *)arg, fd;
	static char buf[1 << 16];

	fd = accept(lfd, NULL, NULL);
	if (fd < 0)
		die("accept");
	while (read(fd, buf, sizeof(buf)) > 0)
		;
	close(fd);
	return NULL;
}

int main(int argc, char **argv)
{
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT) };
	static char chunk[1 << 16];
	unsigned int delay_ms = 0, loss = 0, gains[16], ngains = 0, i;
	uint64_t max_bw = 0, last_acked = 0, tail_acked = 0;
	uint32_t min_rtt = 0;
	struct tcp_info ti;
	union tcp_cc_info cc;
	char name[16] = "";
	socklen_t len;
	pthread_t thread;
	double start, seconds, next;
	int lfd, fd, one = 1, ok = 1;

	if (argc != 3 && argc != 5) {
		fprintf(stderr, "usage: bbr3 label seconds [delay_ms loss_permille]\n");
		return 2;
	}
	seconds = atof(argv[2]);
	if (argc == 5) {
		delay_ms = atoi(argv[3]);
		loss = atoi(argv[4]);
		netem(1, delay_ms, loss);
	}
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (lfd < 0 || bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) || listen(lfd, 1))
		die("listen");
	if (pthread_create(&thread, NULL, sink, &lfd))
		die("thread");

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		die("socket");
	if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "bbr3", 4))
		die("select bbr3");
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
		die("connect");
	len = sizeof(name);
	if (getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name, &len))
		die("read back congestion control");
	fcntl(fd, F_SETFL, O_NONBLOCK);

	start = now();
	next = start + 0.1;
	while (now() - start < seconds) {
		struct pollfd pfd = { .fd = fd, .events = POLLOUT };

		if (poll(&pfd, 1, 50) > 0 && write(fd, chunk, sizeof(chunk)) < 0 &&
		    errno != EAGAIN)
			die("write");
		if (now() < next)
			continue;
		next += 0.1;
		len = sizeof(cc);
		memset(&cc, 0, sizeof(cc));
		if (getsockopt(fd, IPPROTO_TCP, TCP_CC_INFO, &cc, &len) || len < sizeof(cc.bbr))
			continue;
		uint64_t bw = ((uint64_t)cc.bbr.bbr_bw_hi << 32) | cc.bbr.bbr_bw_lo;

		if (bw > max_bw)
			max_bw = bw;
		min_rtt = cc.bbr.bbr_min_rtt;
		for (i = 0; i < ngains && gains[i] != cc.bbr.bbr_pacing_gain; i++)
			;
		if (i == ngains && ngains < 16)
			gains[ngains++] = cc.bbr.bbr_pacing_gain;
		len = sizeof(ti);
		if (!getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len)) {
			if (now() - start < seconds - 1.0)
				last_acked = ti.tcpi_bytes_acked;
			tail_acked = ti.tcpi_bytes_acked;
		}
	}
	len = sizeof(ti);
	memset(&ti, 0, sizeof(ti));
	getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len);
	close(fd);
	pthread_join(thread, NULL);
	close(lfd);
	if (argc == 5)
		netem(0, 0, 0);

	printf("BBR3 %s: cc=%s acked=%llu KB max_bw=%llu B/s min_rtt=%u us retrans=%u gains=",
	       argv[1], name, (unsigned long long)ti.tcpi_bytes_acked / 1024,
	       (unsigned long long)max_bw, min_rtt, ti.tcpi_total_retrans);
	for (i = 0; i < ngains; i++)
		printf("%s%u", i ? "," : "", gains[i]);
	printf("\n");

	if (strcmp(name, "bbr3")) { printf("BBR3 %s: FAIL congestion control is %s\n", argv[1], name); ok = 0; }
	if (!max_bw) { printf("BBR3 %s: FAIL no bandwidth estimate\n", argv[1]); ok = 0; }
	if (!min_rtt || min_rtt == ~0U) { printf("BBR3 %s: FAIL no min_rtt\n", argv[1]); ok = 0; }
	/* Leaving STARTUP needs a bandwidth plateau, which an unshaped loopback
	 * limited by the sender's CPU never shows; only expect it on a shaped path.
	 */
	if (delay_ms && seconds >= 8 && ngains < 2) { printf("BBR3 %s: FAIL pacing gain never changed\n", argv[1]); ok = 0; }
	if (tail_acked <= last_acked) { printf("BBR3 %s: FAIL transfer stalled\n", argv[1]); ok = 0; }
	if (loss && !ti.tcpi_total_retrans) { printf("BBR3 %s: FAIL no retransmits under loss\n", argv[1]); ok = 0; }
	if (delay_ms && min_rtt < delay_ms * 1000) { printf("BBR3 %s: FAIL min_rtt below the path delay\n", argv[1]); ok = 0; }
	printf("BBR3 %s: %s\n", argv[1], ok ? "PASS" : "FAIL");
	return !ok;
}
