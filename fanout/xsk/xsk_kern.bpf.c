// SPDX-License-Identifier: GPL-2.0
/*
 * XDP side of the AF_XDP shred fan-out (xskfwd.c).
 *
 * On every packet of a NIC port: UDP to a watched port (shreds) is
 * deduplicated against the shred table shared by all ports; the first copy is
 * stamped with its arrival time (XDP metadata) and handed to the forwarder's
 * AF_XDP socket for this port and queue; later copies are dropped. Everything
 * else passes up the normal stack untouched. If the forwarder has no socket
 * for this port/queue (not running), the first copy also passes up the stack,
 * where the regular forwarders take over.
 *
 * Watched ports are fixed at build time: -DPORT_A=... [-DPORT_B ... -DPORT_D].
 * Maps are pinned by name (xdp-loader -p <dir>) so both ports share them and
 * the forwarder can find them.
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

#define KEY_BYTES 88
#define SEEN_ENTRIES 1048576
#define EEXIST 17
#define QUEUES_PER_SLOT 64
/* Written before the packet as XDP metadata; xskfwd checks the magic. */
#define META_MAGIC 0x78736b6d65746131ULL /* "xskmeta1" */

struct shred_key {
	__u8 b[KEY_BYTES];
};

struct meta {
	__u64 magic;
	__u64 rx_ns; /* bpf_ktime_get_ns() = CLOCK_MONOTONIC */
};

/* Forwarder sockets, key = slot * QUEUES_PER_SLOT + rx queue. */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 8 * QUEUES_PER_SLOT);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xsk_socks SEC(".maps");

/* ifindex -> slot (1..8), set by the forwarder for each port it serves. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xsk_slots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SEEN_ENTRIES);
	__type(key, struct shred_key);
	__type(value, __u16);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xsk_seen SEC(".maps");

enum {
	STAT_FIRST,      /* first copies */
	STAT_DUPLICATE,  /* later copies, dropped */
	STAT_TO_SOCKET,  /* handed to the forwarder */
	STAT_TO_STACK,   /* first copies passed up the stack (no forwarder socket) */
	STAT_SHORT,      /* watched port, too short: passed */
	STAT_ERROR,      /* dedup map error: passed */
	STAT_NO_META,    /* could not add the arrival-time metadata */
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xsk_stats SEC(".maps");

static __always_inline void count(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&xsk_stats, &i);

	if (v)
		(*v)++;
}

static __always_inline int watched(__u16 port)
{
	return port == PORT_A || (PORT_B && port == PORT_B) ||
	       (PORT_C && port == PORT_C) || (PORT_D && port == PORT_D);
}

SEC("xdp")
int xskfwd_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	struct shred_key key;
	struct meta *m;
	__u32 ifindex = ctx->ingress_ifindex, *slot, sock_key;
	__u16 proto, port;
	__u64 off;
	long ret;

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
	if ((void *)(ip + 1) > data_end || ip->ihl != 5)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP || (ip->frag_off & bpf_htons(0x3fff)))
		return XDP_PASS;
	udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	port = bpf_ntohs(udp->dest);
	if (!watched(port))
		return XDP_PASS;
	if ((void *)(udp + 1) + KEY_BYTES > data_end) {
		count(STAT_SHORT);
		return XDP_PASS;
	}
	__builtin_memcpy(&key, (void *)(udp + 1), KEY_BYTES);

	ret = bpf_map_update_elem(&xsk_seen, &key, &port, BPF_NOEXIST);
	if (ret == -EEXIST) {
		count(STAT_DUPLICATE);
		return XDP_DROP;
	}
	if (ret) {
		count(STAT_ERROR);
		return XDP_PASS;
	}
	count(STAT_FIRST);

	slot = bpf_map_lookup_elem(&xsk_slots, &ifindex);
	if (!slot) {
		count(STAT_TO_STACK);
		return XDP_PASS;
	}
	sock_key = *slot * QUEUES_PER_SLOT + ctx->rx_queue_index;

	/* Arrival time for the forwarder's own latency measurement. */
	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta)) == 0) {
		data = (void *)(long)ctx->data;
		m = (void *)(long)ctx->data_meta;
		if ((void *)(m + 1) <= data) {
			m->magic = META_MAGIC;
			m->rx_ns = bpf_ktime_get_ns();
		}
	} else {
		count(STAT_NO_META);
	}

	/* No socket at this key (forwarder stopped): pass up the stack. */
	ret = bpf_redirect_map(&xsk_socks, sock_key, XDP_PASS);
	if (ret == XDP_REDIRECT)
		count(STAT_TO_SOCKET);
	else
		count(STAT_TO_STACK);
	return ret;
}

char LICENSE[] SEC("license") = "GPL";
