// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel shred fan-out on tc ingress.
 *
 * For UDP packets to the watched ports: drop later copies of a shred (same
 * dedup as dedup.bpf.c), and clone the first copy straight to every
 * destination in kfan_dests, rewriting Ethernet, IP and UDP headers for each.
 * The original is then dropped, so the userspace forwarders receive nothing.
 *
 * Fail-open: with an empty destination table, or on an internal error, the
 * original passes up the stack untouched and the forwarders handle it.
 * Watched ports are fixed at build time: -DPORT_A=... [-DPORT_B ... -DPORT_D].
 * Optional -DDROP_A=... [-DDROP_B=...]: UDP to these ports is dropped before
 * anything else (e.g. to switch a source off without stopping its forwarder).
 */
#include <stddef.h>
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
#ifndef DROP_A
#define DROP_A 0
#endif
#ifndef DROP_B
#define DROP_B 0
#endif

#define KEY_BYTES 88
#define SEEN_ENTRIES 262144
#define MAX_DESTS 32
#define EEXIST 17

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

struct shred_key {
	__u8 b[KEY_BYTES];
};

/* One destination, as written by kfan.sh (28 bytes, no implicit padding). */
struct dest {
	__u32 ifindex; /* outgoing device; 0 ends the list */
	__u8 dmac[6];
	__u8 smac[6];
	__be32 saddr;
	__be32 daddr;
	__be16 dport;
	__u16 vlan; /* 802.1Q tag the NIC should add (sending straight to a port); 0 = none */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, SEEN_ENTRIES);
	__type(key, struct shred_key);
	__type(value, __u16);
} kfan_seen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_DESTS);
	__type(key, __u32);
	__type(value, struct dest);
} kfan_dests SEC(".maps");

enum {
	STAT_FIRST,      /* first copy of a shred */
	STAT_DUPLICATE,  /* later copy, dropped */
	STAT_SHORT,      /* watched port, too short to be a shred: passed */
	STAT_ERROR,      /* dedup map error: passed to the forwarders */
	STAT_NO_DESTS,   /* destination table empty: passed to the forwarders */
	STAT_CLONED,     /* copies sent */
	STAT_CLONE_FAIL, /* copies the kernel refused */
	STAT_IGNORED,    /* UDP to a DROP_ port, dropped */
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} kfan_stats SEC(".maps");

static __always_inline void count(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&kfan_stats, &i);

	if (v)
		(*v)++;
}

static __always_inline int watched(__u16 port)
{
	return port == PORT_A || (PORT_B && port == PORT_B) ||
	       (PORT_C && port == PORT_C) || (PORT_D && port == PORT_D);
}

SEC("tc")
int kfan(struct __sk_buff *skb)
{
	struct iphdr ip;
	struct udphdr udp;
	struct shred_key key;
	struct dest *d;
	__u8 first_byte;
	__u32 ihl, l4, i, zero = 0;
	__be32 cur_saddr, cur_daddr;
	__be16 sport;
	__u16 cur_vlan;
	__u16 port, no_csum = 0;
	long ret;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &first_byte, 1))
		return TC_ACT_OK;
	ihl = (first_byte & 0x0f) * 4;
	if (ihl < sizeof(ip) || ihl > 60)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)))
		return TC_ACT_OK;
	if (ip.protocol != IPPROTO_UDP || (ip.frag_off & bpf_htons(0x3fff)))
		return TC_ACT_OK;
	l4 = ETH_HLEN + ihl;
	if (bpf_skb_load_bytes(skb, l4, &udp, sizeof(udp)))
		return TC_ACT_OK;
	port = bpf_ntohs(udp.dest);
	if ((DROP_A && port == DROP_A) || (DROP_B && port == DROP_B)) {
		count(STAT_IGNORED);
		return TC_ACT_SHOT;
	}
	if (!watched(port))
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, l4 + sizeof(udp), &key, sizeof(key))) {
		count(STAT_SHORT);
		return TC_ACT_OK;
	}

	ret = bpf_map_update_elem(&kfan_seen, &key, &port, BPF_NOEXIST);
	if (ret == -EEXIST) {
		count(STAT_DUPLICATE);
		return TC_ACT_SHOT;
	}
	if (ret) {
		count(STAT_ERROR);
		return TC_ACT_OK;
	}
	count(STAT_FIRST);

	d = bpf_map_lookup_elem(&kfan_dests, &zero);
	if (!d || !d->ifindex) {
		count(STAT_NO_DESTS);
		return TC_ACT_OK;
	}

	/* Same for every copy: sent from the port the shred arrived on, and
	 * without a UDP checksum (0 = none, valid for IPv4). */
	sport = udp.dest;
	bpf_skb_store_bytes(skb, l4 + offsetof(struct udphdr, source), &sport, sizeof(sport), 0);
	bpf_skb_store_bytes(skb, l4 + offsetof(struct udphdr, check), &no_csum, sizeof(no_csum), 0);
	cur_saddr = ip.saddr;
	cur_daddr = ip.daddr;
	cur_vlan = skb->vlan_present ? skb->vlan_tci : 0;

	for (i = 0; i < MAX_DESTS; i++) {
		__u32 k = i;

		d = bpf_map_lookup_elem(&kfan_dests, &k);
		if (!d || !d->ifindex)
			break;
		bpf_skb_store_bytes(skb, 0, d->dmac, 6, 0);
		bpf_skb_store_bytes(skb, 6, d->smac, 6, 0);
		if (d->saddr != cur_saddr) {
			bpf_l3_csum_replace(skb, IP_CSUM_OFF, cur_saddr, d->saddr, sizeof(__u32));
			bpf_skb_store_bytes(skb, IP_SRC_OFF, &d->saddr, sizeof(__u32), 0);
			cur_saddr = d->saddr;
		}
		if (d->daddr != cur_daddr) {
			bpf_l3_csum_replace(skb, IP_CSUM_OFF, cur_daddr, d->daddr, sizeof(__u32));
			bpf_skb_store_bytes(skb, IP_DST_OFF, &d->daddr, sizeof(__u32), 0);
			cur_daddr = d->daddr;
		}
		bpf_skb_store_bytes(skb, l4 + offsetof(struct udphdr, dest), &d->dport, sizeof(d->dport), 0);
		/* The tag lives in packet metadata; the NIC inserts it on send. */
		if (d->vlan != cur_vlan) {
			if (cur_vlan)
				bpf_skb_vlan_pop(skb);
			if (d->vlan)
				bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), d->vlan);
			cur_vlan = d->vlan;
		}
		if (bpf_clone_redirect(skb, d->ifindex, 0))
			count(STAT_CLONE_FAIL);
		else
			count(STAT_CLONED);
	}
	return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
