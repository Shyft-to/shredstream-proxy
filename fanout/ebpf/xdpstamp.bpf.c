// SPDX-License-Identifier: GPL-2.0
/*
 * Front end of the kernel fan-out, at the NIC driver (XDP).
 *
 * For UDP packets to the watched ports:
 *  - stamps the arrival time into XDP metadata in front of the packet
 *    (16 bytes: magic + bpf_ktime_get_ns(), CLOCK_MONOTONIC), which kfan.bpf.c
 *    uses for its latency histograms and measurement copies;
 *  - with -DDEDUP=1, also drops later copies of a shred (same key as
 *    kfan.bpf.c: the first 88 payload bytes) before the kernel builds a packet
 *    buffer for them, and marks first copies "xdpstmp2" so kfan skips its own
 *    check. One program and one duplicate table serve all ports (xdpstamp.sh
 *    loads it once and attaches it to each), so copies arriving on different
 *    ports are caught too.
 * Everything else passes unchanged. Without the mark ("xdpstmp1", or no
 * metadata at all) kfan deduplicates by itself, so it works with or without
 * this program.
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
#ifndef DEDUP
#define DEDUP 0
#endif

#define META_MAGIC 0x31706d7473706478ULL       /* "xdpstmp1": stamped */
#define META_MAGIC_DEDUP 0x32706d7473706478ULL /* "xdpstmp2": stamped, first copy (checked here) */
#define KEY_BYTES 88                           /* must match kfan.bpf.c */
#define SEEN_ENTRIES 1048576
#define EEXIST 17

struct shred_key {
	__u8 b[KEY_BYTES];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, DEDUP ? SEEN_ENTRIES : 1);
	__type(key, struct shred_key);
	__type(value, __u8);
} xdps_seen SEC(".maps");

enum {
	XS_STAMPED,   /* watched packets stamped */
	XS_FIRST,     /* DEDUP: first copies */
	XS_DUPLICATE, /* DEDUP: later copies, dropped */
	XS_SHORT,     /* DEDUP: too short for the key, left to kfan */
	XS_ERROR,     /* DEDUP: table error, left to kfan */
	XS_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XS_MAX);
	__type(key, __u32);
	__type(value, __u64);
} xdps_stats SEC(".maps");

static __always_inline void count(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&xdps_stats, &i);

	if (v)
		(*v)++;
}

static __always_inline int watched(__u16 port)
{
	return port == PORT_A || (PORT_B && port == PORT_B) ||
	       (PORT_C && port == PORT_C) || (PORT_D && port == PORT_D);
}

SEC("xdp")
int xdpstamp(struct xdp_md *ctx)
{
	__u64 now = bpf_ktime_get_ns(), magic = META_MAGIC, *meta;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	__u16 proto;
	__u64 off;

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
	if (ip->frag_off & bpf_htons(0x3fff))
		return XDP_PASS;
	udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end || !watched(bpf_ntohs(udp->dest)))
		return XDP_PASS;

	if (DEDUP) {
		struct shred_key key;
		__u8 one = 1;
		long ret;

		if ((void *)(udp + 1) + KEY_BYTES > data_end) {
			count(XS_SHORT);
		} else {
			__builtin_memcpy(&key, (void *)(udp + 1), KEY_BYTES);
			ret = bpf_map_update_elem(&xdps_seen, &key, &one, BPF_NOEXIST);
			if (ret == -EEXIST) {
				count(XS_DUPLICATE);
				return XDP_DROP;
			}
			if (ret) {
				count(XS_ERROR);
			} else {
				count(XS_FIRST);
				magic = META_MAGIC_DEDUP;
			}
		}
	}

	if (bpf_xdp_adjust_meta(ctx, -16))
		return XDP_PASS;
	data = (void *)(long)ctx->data;
	meta = (void *)(long)ctx->data_meta;
	if ((void *)(meta + 2) > data)
		return XDP_PASS;
	meta[0] = magic;
	meta[1] = now;
	count(XS_STAMPED);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
