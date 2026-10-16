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
 *
 * Optional -DSTAMP_PORT=...: the copy for the destination with this UDP port
 * (a measurement receiver, fanout-bench stamp-recv) gets its first 16 payload
 * bytes replaced by "kfanstmp" + this program's arrival time (u64 LE,
 * CLOCK_MONOTONIC). Only done when that destination is the last one of its
 * group, since later copies would carry the change too.
 *
 * Multi-CPU fan-out (-DGROUPS=n, n > 1): destinations are split into n
 * groups. Group 0 is sent inline on the CPU that received the shred. For each
 * other group a "carrier" copy of the untouched packet is re-injected into
 * this device's receive path, marked with its group number and given a hash
 * that receive packet steering (RPS on rx queue 0, set up by kfan.sh) maps to
 * that group's own CPU. There this same program sees the mark and sends that
 * group's copies, so the groups go out in parallel.
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

#ifndef STAMP_PORT
#define STAMP_PORT 0
#endif
#define STAMP_MAGIC 0x706d74736e61666bULL /* "kfanstmp" */

#ifndef GROUPS
#define GROUPS 1
#endif
#define MAX_GROUPS 4
#define MAX_PER_GROUP 16
#define CARRIER_MARK 0x6b660000 /* "kf" << 16 | group */
#define CARRIER_MASK 0xffff0000

#define KEY_BYTES 88
#define SEEN_ENTRIES 1048576
#define MAX_DESTS (MAX_GROUPS * MAX_PER_GROUP) /* group g: entries g*16 .. g*16+15 */
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
	STAT_CARRIED,    /* carrier copies handed to another CPU */
	STAT_CARRY_FAIL, /* carrier copies the kernel refused */
	STAT_STAMPED,    /* copies to STAMP_PORT stamped */
	STAT_STAMP_SKIP, /* STAMP_PORT destination not last: sent unstamped */
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

/* Sends the shred to every destination of group g. Rewrites headers in place
 * (UDP source port and checksum are set by the caller). */
static __always_inline void send_group(struct __sk_buff *skb, __u32 g, __u32 l4,
				       __be32 cur_saddr, __be32 cur_daddr, __u64 rx_ns)
{
	struct dest *d;
	__u16 cur_vlan = skb->vlan_present ? skb->vlan_tci : 0;
	__u32 i;

	for (i = 0; i < MAX_PER_GROUP; i++) {
		__u32 k = g * MAX_PER_GROUP + i;

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
		if (STAMP_PORT && d->dport == bpf_htons(STAMP_PORT)) {
			__u32 next = k + 1;
			struct dest *nd = i + 1 < MAX_PER_GROUP ? bpf_map_lookup_elem(&kfan_dests, &next) : 0;

			if (!nd || !nd->ifindex) {
				__u64 stamp[2] = {STAMP_MAGIC, rx_ns};

				bpf_skb_store_bytes(skb, l4 + sizeof(struct udphdr), stamp, sizeof(stamp), 0);
				count(STAT_STAMPED);
			} else {
				count(STAT_STAMP_SKIP);
			}
		}
		if (bpf_clone_redirect(skb, d->ifindex, 0))
			count(STAT_CLONE_FAIL);
		else
			count(STAT_CLONED);
	}
}

SEC("tc")
int kfan(struct __sk_buff *skb)
{
	struct iphdr ip;
	struct udphdr udp;
	struct shred_key key;
	struct dest *d;
	__u64 rx_ns = STAMP_PORT ? bpf_ktime_get_ns() : 0;
	__u8 first_byte;
	__u32 ihl, l4, g = 0, zero = 0;
	__be16 sport;
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

	if ((skb->mark & CARRIER_MASK) == CARRIER_MARK) {
		/* A carrier we sent ourselves, now on its group's CPU. */
		g = skb->mark & 0xffff;
		if (g >= MAX_GROUPS)
			return TC_ACT_SHOT;
	} else {
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

#if GROUPS > 1
		/* Hand groups 1.. to their CPUs first, before any header rewrite:
		 * carriers share the untouched packet data. RPS on rx queue 0 picks
		 * cpus[(hash * n) >> 32] among its n CPUs, so hash idx * 2^32 / n
		 * lands on CPU number idx. */
		skb->queue_mapping = 0;
		for (__u32 c = 1; c < GROUPS && c < MAX_GROUPS; c++) {
			__u32 k = c * MAX_PER_GROUP;

			d = bpf_map_lookup_elem(&kfan_dests, &k);
			if (!d || !d->ifindex)
				continue;
			skb->mark = CARRIER_MARK | c;
			bpf_set_hash(skb, (__u32)((((__u64)(c - 1)) << 32) / (GROUPS - 1)) + 1);
			if (bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS))
				count(STAT_CARRY_FAIL);
			else
				count(STAT_CARRIED);
		}
		skb->mark = 0;
#endif
	}

	/* Same for every copy: sent from the port the shred arrived on, and
	 * without a UDP checksum (0 = none, valid for IPv4). */
	sport = udp.dest;
	bpf_skb_store_bytes(skb, l4 + offsetof(struct udphdr, source), &sport, sizeof(sport), 0);
	bpf_skb_store_bytes(skb, l4 + offsetof(struct udphdr, check), &no_csum, sizeof(no_csum), 0);
	send_group(skb, g, l4, ip.saddr, ip.daddr, rx_ns);
	return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
