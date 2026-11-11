/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0) */
/*
 * TCP stack features of android14-6.1 for bbr_compat.h.
 *
 * Upstream generates this file by test-compiling one probe per macro
 * (gen_kconfig.py + kapi_checklist). Here each macro was decided by reading
 * the Samsung S5E9945 vendor tree (6.1.138), whose TCP headers match the
 * android14-6.1 common kernel: include/net/tcp.h, include/linux/tcp.h,
 * include/linux/random.h, include/linux/prandom.h,
 * include/net/inet_connection_sock.h, include/uapi/linux/inet_diag.h.
 *
 * Everything that only exists in Google's BBRv3 tree is left undefined:
 * the 4-argument cong_control, tso_segs, skb_marked_lost, TCP_ECN_LOW,
 * TCP_ECN_ECT_PERMANENT, TCP_CONG_WANTS_CE_EVENTS, CA_EVENT_TLP_RECOVERY,
 * rate_sample.lost/tx_in_flight/is_acking_tlp_retrans_seq/is_ece,
 * tcp_sock.fast_ack_mode/tlp_orig_data_app_limited, tcp_skb_cb tx.in_flight
 * and tx.lost, PLB (mainline 6.2+) and the extended tcp_bbr_info.
 */
#pragma once

#define HAVE_TCP_ECN_OK 1
#define HAVE_TCP_CONG_NEEDS_ECN 1
#define HAVE_CA_EVENT_ECN_IS_CE 1

#define HAVE_RATE_SAMPLE_LOSSES 1
#define HAVE_RATE_SAMPLE_PRIOR_IN_FLIGHT 1
#define HAVE_RATE_SAMPLE_DELIVERED_CE 1

#define HAVE_TCP_SOCK_DELIVERED_CE 1
#define HAVE_TCP_SOCK_IS_SACK_RENEG 1
#define HAVE_TCP_SOCK_LOST 1
#define HAVE_TCP_SOCK_LOST_OUT 1
#define HAVE_TCP_SOCK_PRIOR_CWND 1
#define HAVE_TCP_SOCK_TCP_CLOCK_CACHE 1
#define HAVE_TCP_SOCK_ECN_FLAGS 1
#define HAVE_TCP_SOCK_SND_CWND 1

#define HAVE_SKB_CB_TX_DELIVERED_MSTAMP 1
#define HAVE_SKB_CB_TX_IS_APP_LIMITED 1

#define HAVE_TCP_SND_CWND 1
#define HAVE_TCP_SND_CWND_SET 1
#define HAVE_TCP_STAMP_US_DELTA 1
#define HAVE_TCP_MIN_RTT 1
#define HAVE___TCP_SEND_ACK 1

#define HAVE_GET_RANDOM_U32_BELOW 1
#define HAVE_PRANDOM_U32_MAX 1

#define HAVE_ICSK_CA_PRIV 1
