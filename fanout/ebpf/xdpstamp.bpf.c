// SPDX-License-Identifier: GPL-2.0
/*
 * Measurement only: stamps shreds with their arrival time at the NIC driver.
 *
 * For UDP packets to the watched ports, writes 16 bytes of XDP metadata in
 * front of the packet: "xdpstmp1" + bpf_ktime_get_ns() (CLOCK_MONOTONIC).
 * Every packet passes on unchanged (XDP_PASS); the packet data itself is not
 * touched. kfan.bpf.c (built with STAMP_PORT) reads the time and puts it in
 * the copies for the measurement receivers, so their latency includes any
 * queueing between the driver and the fan-out.
 *
 * Watched ports are fixed at build time: -DPORT_A=... [-DPORT_B ... -DPORT_D].
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef PORT_A
#error "build with -DPORT_A=<port> (and optionally PORT_B, PORT_C, PORT_D)"
#endif
#ifndef PORT_B
#define PORT_B 0
#endif
#ifndef PORT_C
#define PORT_C 0
#endif
#ifndef PORT_D
#define PORT_D 0
#endif

#define META_MAGIC 0x31706d7473706478ULL /* "xdpstmp1" */

static __always_inline int watched(__u16 port)
{
	return port == PORT_A || (PORT_B && port == PORT_B) ||
	       (PORT_C && port == PORT_C) || (PORT_D && port == PORT_D);
}

SEC("xdp")
int xdpstamp(struct xdp_md *ctx)
{
	__u64 now = bpf_ktime_get_ns();
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	__u16 proto;
	__u64 off, *meta;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	proto = eth->h_proto;
	off = sizeof(*eth);
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		if (data + off + 4 > data_end)
			return XDP_PASS;
		proto = *(__u16 *)(data + off + 2);
		off += 4;
	}
	if (proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	ip = data + off;
	if ((void *)(ip + 1) > data_end || ip->ihl != 5 || ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end || !watched(bpf_ntohs(udp->dest)))
		return XDP_PASS;

	if (bpf_xdp_adjust_meta(ctx, -16))
		return XDP_PASS;
	data = (void *)(long)ctx->data;
	meta = (void *)(long)ctx->data_meta;
	if ((void *)(meta + 2) > data)
		return XDP_PASS;
	meta[0] = META_MAGIC;
	meta[1] = now;
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
