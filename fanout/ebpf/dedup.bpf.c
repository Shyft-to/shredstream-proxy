// SPDX-License-Identifier: GPL-2.0
/*
 * Cross-source shred dedup on tc ingress.
 *
 * Several sources send the same shreds to different UDP ports on this box,
 * each port served by its own forwarder. This filter lets only the first
 * copy of each shred through (on whichever watched port it arrived) and drops
 * the rest, so each shred is forwarded once instead of once per source.
 *
 * Everything that is not IPv4/UDP to a watched port passes untouched.
 * Watched ports are fixed at build time: -DPORT_A=... [-DPORT_B ... -DPORT_D].
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
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

/* Identity of a shred: signature (64), variant, slot, index, version,
 * fec_set_index (83 bytes), plus the next 5 header bytes. Identical in every
 * source's copy, distinct between shreds. */
#define KEY_BYTES 88
/* Recently seen shreds: ~2 min at ~8-9k first copies/s. Long enough to
 * also catch sources that re-send shreds tens of seconds late (5544 does),
 * so those are not fanned out a second time. ~150 MB of kernel memory. */
#define SEEN_ENTRIES 1048576
#define EEXIST 17

struct shred_key {
	__u8 b[KEY_BYTES];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SEEN_ENTRIES);
	__type(key, struct shred_key);
	__type(value, __u16); /* port that delivered the shred first */
} dedup_seen SEC(".maps");

enum {
	STAT_FIRST,     /* first copy, passed */
	STAT_DUPLICATE, /* later copy, dropped */
	STAT_SHORT,     /* watched port, but too short to be a shred: passed */
	STAT_ERROR,     /* map update failed for another reason: passed */
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} dedup_stats SEC(".maps");

static __always_inline void count(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&dedup_stats, &i);

	if (v)
		(*v)++;
}

static __always_inline int watched(__u16 port)
{
	return port == PORT_A || (PORT_B && port == PORT_B) ||
	       (PORT_C && port == PORT_C) || (PORT_D && port == PORT_D);
}

SEC("tc")
int dedup(struct __sk_buff *skb)
{
	struct iphdr ip;
	struct udphdr udp;
	struct shred_key key;
	__u8 first_byte;
	__u32 ihl, l4;
	__u16 port;
	long ret;

	/* VLAN tags are stripped into metadata by the NIC, so this is the inner
	 * protocol; packets carrying an in-band tag simply pass. */
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &first_byte, 1))
		return TC_ACT_OK;
	ihl = (first_byte & 0x0f) * 4;
	if (ihl < sizeof(ip) || ihl > 60)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)))
		return TC_ACT_OK;
	/* Only unfragmented UDP. */
	if (ip.protocol != IPPROTO_UDP || (ip.frag_off & bpf_htons(0x3fff)))
		return TC_ACT_OK;
	l4 = ETH_HLEN + ihl;
	if (bpf_skb_load_bytes(skb, l4, &udp, sizeof(udp)))
		return TC_ACT_OK;
	port = bpf_ntohs(udp.dest);
	if (!watched(port))
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, l4 + sizeof(udp), &key, sizeof(key))) {
		count(STAT_SHORT);
		return TC_ACT_OK;
	}

	/* Atomic insert: exactly one copy wins, even when copies from different
	 * sources are processed on different CPUs at the same time. */
	ret = bpf_map_update_elem(&dedup_seen, &key, &port, BPF_NOEXIST);
	if (ret == 0) {
		count(STAT_FIRST);
		return TC_ACT_OK;
	}
	if (ret == -EEXIST) {
		count(STAT_DUPLICATE);
		return TC_ACT_SHOT;
	}
	/* Never drop because of an internal error. */
	count(STAT_ERROR);
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
