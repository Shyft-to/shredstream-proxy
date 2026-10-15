// SPDX-License-Identifier: GPL-2.0
/*
 * xskfwd: AF_XDP shred fan-out.
 *
 * The XDP program (xsk_kern.bpf.c) hands the first copy of every shred to an
 * AF_XDP socket on each receiving port's dedicated queue. One busy-polling
 * thread reads those sockets and, for every shred, builds one frame per
 * destination (Ethernet, optional 802.1Q tag, IPv4, UDP, payload) straight on
 * the send ring of the destination's NIC port. No kernel network stack, no
 * per-copy system call. Local destinations (127.x) get a normal UDP send.
 *
 * It also measures itself: arrival (stamped by the XDP program) to the time
 * the first copy, and all copies, were handed to the NIC.
 *
 * Usage: xskfwd --rx IF[,IF] --queue Q --dests FILE [--pin DIR] [--cpu N]
 *               [--copy] [--report SECS] [--label L] [--results FILE]
 *               [--local-cpu N]   (local sends on their own thread on cpu N)
 *
 * DESTS file, one destination per line (written by fanout/scripts/xsk.sh):
 *   IFNAME DST_MAC SRC_MAC SRC_IP DST_IP DST_PORT VLAN
 *   local DST_IP DST_PORT
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <xdp/xsk.h>

#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define NUM_FRAMES 8192          /* per port: half for receiving, half for sending */
#define RING_SIZE 4096
#define RX_BATCH 64
#define MAX_PORTS 8
#define MAX_DESTS 32
#define QUEUES_PER_SLOT 64
#define META_MAGIC 0x78736b6d65746131ULL
#define LOCAL_RING 1024          /* shreds queued for the local-send thread */
#define LOCAL_MAX 2036           /* largest payload it takes */
#define STALL_NS 20000           /* an idle loop pass longer than this was interrupted */

struct meta {
	uint64_t magic;
	uint64_t rx_ns;
};

/*
 * Latency histogram: 250 ns buckets up to 4.096 ms, then 1 ms buckets up to
 * 68 ms. Adding a sample and reading percentiles are cheap enough for the
 * busy-polling thread (sorting samples there stalled it for milliseconds).
 */
#define H_FINE 16384
#define H_FINE_NS 250
#define H_N (H_FINE + 64)

struct hist {
	uint32_t b[H_N];
	uint64_t n, sum, max;
};

static void h_add(struct hist *h, uint64_t ns)
{
	uint64_t i = ns / H_FINE_NS;

	if (i >= H_FINE) {
		i = H_FINE + (ns - (uint64_t)H_FINE * H_FINE_NS) / 1000000;
		if (i >= H_N)
			i = H_N - 1;
	}
	h->b[i]++;
	h->n++;
	h->sum += ns;
	if (ns > h->max)
		h->max = ns;
}

/* Percentile in microseconds (bucket middle, never above the maximum). */
static double h_pct(const struct hist *h, double p)
{
	uint64_t rank = (uint64_t)(p * h->n + 0.999999), acc = 0, v = h->max;

	if (!h->n)
		return 0;
	if (rank < 1)
		rank = 1;
	for (uint32_t i = 0; i < H_N; i++) {
		acc += h->b[i];
		if (acc >= rank) {
			v = i < H_FINE ? (uint64_t)i * H_FINE_NS + H_FINE_NS / 2
				       : (uint64_t)H_FINE * H_FINE_NS + (uint64_t)(i - H_FINE) * 1000000 + 500000;
			break;
		}
	}
	return (v < h->max ? v : h->max) / 1000.0;
}

struct port {
	char name[IF_NAMESIZE];
	int ifindex;
	int receive;            /* the XDP program hands us packets here */
	void *area;
	struct xsk_umem *umem;
	struct xsk_socket *xsk;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	uint64_t pool[NUM_FRAMES / 2]; /* free send frames */
	uint32_t pool_n;
	uint32_t tx_pending;
	uint32_t slot;
};

struct dest {
	int local;              /* send with a UDP socket instead */
	int port;               /* index into ports */
	uint8_t hdr[64];        /* Ethernet [+ 802.1Q] + IPv4 + UDP, lengths/checksum filled per packet */
	uint32_t hdr_len, ip_off;
	uint32_t ip_sum;        /* IPv4 header sum without tot_len */
	struct sockaddr_in addr;
};

static struct port ports[MAX_PORTS];
static int nports;
static struct dest dests[MAX_DESTS];
static int ndests;
static volatile sig_atomic_t running = 1;
static int local_fd = -1;
static int nlocal;

static struct {
	uint64_t shreds, copies, tx_full, local_fail, no_meta;
	uint64_t busy_ns;        /* time spent handling shreds (capacity use) */
	uint64_t nic_ns, local_ns; /* of which: NIC copies, local sends (inline) */
	uint64_t kicks;          /* send-ring wake-up system calls */
	uint64_t max_batch, stalls, max_stall_ns;
	struct hist wait;        /* arrival -> handling starts (queueing before us) */
	struct hist first, last; /* arrival -> first / last copy handed over */
} st;

/*
 * Optional local-send thread (--local-cpu): the main thread only copies the
 * payload into this ring; the thread does the UDP sends (a loopback send runs
 * the receiver's network stack inline, which is the costly part).
 */
struct lslot {
	uint64_t rx_ns;
	uint32_t len;
	uint8_t data[LOCAL_MAX];
} __attribute__((aligned(64)));

struct lstats {
	uint64_t sent, fail, invol;
	struct hist lat;         /* arrival -> local copies sent */
};

static struct {
	struct lslot *slot;
	_Alignas(64) _Atomic uint32_t head; /* written by the main thread */
	_Alignas(64) _Atomic uint32_t tail; /* written by the local thread */
	_Alignas(64) _Atomic int snap;      /* 1 = main asks for stats, 2 = ready */
	struct lstats cur, out;
	int on;
	uint64_t dropped;        /* ring full (main thread) */
} lq;

static void die(const char *what)
{
	fprintf(stderr, "xskfwd: %s: %s\n", what, strerror(errno));
	exit(1);
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void on_signal(int sig)
{
	(void)sig;
	running = 0;
}

static int port_index(const char *name, int receive)
{
	for (int i = 0; i < nports; i++)
		if (!strcmp(ports[i].name, name)) {
			ports[i].receive |= receive;
			return i;
		}
	if (nports == MAX_PORTS) {
		fprintf(stderr, "xskfwd: too many interfaces\n");
		exit(1);
	}
	struct port *p = &ports[nports];
	snprintf(p->name, sizeof(p->name), "%s", name);
	p->ifindex = if_nametoindex(name);
	if (!p->ifindex) {
		fprintf(stderr, "xskfwd: no interface %s\n", name);
		exit(1);
	}
	p->receive = receive;
	return nports++;
}

static int parse_mac(const char *s, uint8_t *mac)
{
	return sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4],
		      &mac[5]) == 6 ? 0 : -1;
}

static uint32_t sum16(const void *buf, size_t len, uint32_t sum)
{
	const uint8_t *b = buf;

	for (size_t i = 0; i + 1 < len; i += 2)
		sum += (uint32_t)b[i] << 8 | b[i + 1];
	return sum;
}

static uint16_t fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static void load_dests(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[512], ifn[64], dmac[32], smac[32], sip[32], dip[32];
	unsigned dport, vlan;

	if (!f)
		die(path);
	while (fgets(line, sizeof(line), f)) {
		struct dest *d = &dests[ndests];

		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (ndests == MAX_DESTS) {
			fprintf(stderr, "xskfwd: too many destinations\n");
			exit(1);
		}
		memset(d, 0, sizeof(*d));
		if (sscanf(line, "local %31s %u", dip, &dport) == 2) {
			d->local = 1;
			d->addr.sin_family = AF_INET;
			d->addr.sin_port = htons(dport);
			if (inet_pton(AF_INET, dip, &d->addr.sin_addr) != 1)
				goto bad;
			ndests++;
			continue;
		}
		if (sscanf(line, "%63s %31s %31s %31s %31s %u %u", ifn, dmac, smac, sip, dip, &dport, &vlan) != 7)
			goto bad;
		struct in_addr sa, da;
		uint8_t *h = d->hdr;
		uint32_t o = 12;

		if (parse_mac(dmac, h) || parse_mac(smac, h + 6) || inet_pton(AF_INET, sip, &sa) != 1 ||
		    inet_pton(AF_INET, dip, &da) != 1)
			goto bad;
		d->port = port_index(ifn, 0);
		if (vlan) {
			h[o++] = 0x81, h[o++] = 0x00;
			h[o++] = (vlan >> 8) & 0x0f, h[o++] = vlan & 0xff;
		}
		h[o++] = 0x08, h[o++] = 0x00;
		d->ip_off = o;
		uint8_t *ip = h + o;
		ip[0] = 0x45;            /* IPv4, 20-byte header */
		ip[6] = 0x40;            /* don't fragment */
		ip[8] = 64;              /* TTL */
		ip[9] = IPPROTO_UDP;
		memcpy(ip + 12, &sa, 4);
		memcpy(ip + 16, &da, 4);
		d->ip_sum = sum16(ip, 20, 0); /* tot_len and checksum still 0 */
		uint8_t *udp = ip + 20;
		udp[2] = dport >> 8, udp[3] = dport & 0xff;
		d->hdr_len = o + 20 + 8;
		ndests++;
		continue;
bad:
		fprintf(stderr, "xskfwd: bad destination line: %s", line);
		exit(1);
	}
	fclose(f);
	if (!ndests) {
		fprintf(stderr, "xskfwd: no destinations\n");
		exit(1);
	}
}

static void setup_port(struct port *p, uint32_t queue, int copy, int socks_fd, int slots_fd)
{
	struct xsk_umem_config ucfg = {
		.fill_size = RING_SIZE,
		.comp_size = RING_SIZE,
		.frame_size = FRAME_SIZE,
		.frame_headroom = 0,
		.flags = 0,
	};
	struct xsk_socket_config scfg = {
		.rx_size = RING_SIZE,
		.tx_size = RING_SIZE,
		.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_DRV_MODE,
		.bind_flags = (copy ? XDP_COPY : XDP_ZEROCOPY) | XDP_USE_NEED_WAKEUP,
	};
	uint32_t idx, i;
	int err;

	p->area = mmap(NULL, (size_t)NUM_FRAMES * FRAME_SIZE, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (p->area == MAP_FAILED)
		die("mmap packet memory");
	err = xsk_umem__create(&p->umem, p->area, (uint64_t)NUM_FRAMES * FRAME_SIZE, &p->fill, &p->comp, &ucfg);
	if (err) {
		errno = -err;
		die("xsk_umem__create");
	}
	err = xsk_socket__create(&p->xsk, p->name, queue, p->umem, p->receive ? &p->rx : NULL, &p->tx, &scfg);
	if (err) {
		errno = -err;
		fprintf(stderr, "xskfwd: %s queue %u (%s mode): ", p->name, queue, copy ? "copy" : "zero-copy");
		die("xsk_socket__create");
	}
	/* First half of the frames: receive (fill ring). Second half: send pool. */
	if (p->receive) {
		if (xsk_ring_prod__reserve(&p->fill, NUM_FRAMES / 2, &idx) != NUM_FRAMES / 2) {
			fprintf(stderr, "xskfwd: fill ring too small\n");
			exit(1);
		}
		for (i = 0; i < NUM_FRAMES / 2; i++)
			*xsk_ring_prod__fill_addr(&p->fill, idx + i) = (uint64_t)i * FRAME_SIZE;
		xsk_ring_prod__submit(&p->fill, NUM_FRAMES / 2);
	}
	for (i = 0; i < NUM_FRAMES / 2; i++)
		p->pool[i] = (uint64_t)(NUM_FRAMES / 2 + i) * FRAME_SIZE;
	p->pool_n = NUM_FRAMES / 2;

	if (p->receive) {
		uint32_t key = p->slot * QUEUES_PER_SLOT + queue;
		int fd = xsk_socket__fd(p->xsk);

		if (bpf_map_update_elem(socks_fd, &key, &fd, BPF_ANY))
			die("register socket in xsk_socks");
		if (bpf_map_update_elem(slots_fd, &p->ifindex, &p->slot, BPF_ANY))
			die("register port in xsk_slots");
	}
	fprintf(stderr, "xskfwd: %s queue %u: %s%s, %s mode\n", p->name, queue, p->receive ? "receive + " : "",
		"send", copy ? "copy" : "zero-copy");
}

static void kick_tx(struct port *p)
{
	if (xsk_ring_prod__needs_wakeup(&p->tx)) {
		sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		st.kicks++;
	}
}

/* Involuntary context switches of the calling thread (it was preempted). */
static uint64_t invol_switches(void)
{
	struct rusage ru;

	return getrusage(RUSAGE_THREAD, &ru) ? 0 : (uint64_t)ru.ru_nivcsw;
}

static void send_local(const uint8_t *payload, uint32_t plen, uint64_t *sent, uint64_t *fail)
{
	for (int i = 0; i < ndests; i++) {
		if (!dests[i].local)
			continue;
		if (sendto(local_fd, payload, plen, MSG_DONTWAIT, (struct sockaddr *)&dests[i].addr,
			   sizeof(dests[i].addr)) < 0)
			(*fail)++;
		else
			(*sent)++;
	}
}

static void *local_thread(void *arg)
{
	int cpu = (int)(long)arg;
	cpu_set_t set;
	uint32_t tail = 0;
	uint64_t invol0 = invol_switches();

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set))
		fprintf(stderr, "xskfwd: could not pin the local-send thread to cpu %d\n", cpu);
	while (running) {
		uint32_t head = atomic_load_explicit(&lq.head, memory_order_acquire);

		while (tail != head) {
			struct lslot *s = &lq.slot[tail % LOCAL_RING];

			send_local(s->data, s->len, &lq.cur.sent, &lq.cur.fail);
			if (s->rx_ns)
				h_add(&lq.cur.lat, now_ns() - s->rx_ns);
			tail++;
			atomic_store_explicit(&lq.tail, tail, memory_order_release);
		}
		if (atomic_load_explicit(&lq.snap, memory_order_acquire) == 1) {
			uint64_t invol = invol_switches();

			lq.cur.invol = invol - invol0;
			invol0 = invol;
			lq.out = lq.cur;
			memset(&lq.cur, 0, sizeof(lq.cur));
			atomic_store_explicit(&lq.snap, 2, memory_order_release);
		}
	}
	return NULL;
}

/* Hands one shred to the local-send thread; 0 if queued. */
static int queue_local(const uint8_t *payload, uint32_t plen, uint64_t rx_ns)
{
	uint32_t head = atomic_load_explicit(&lq.head, memory_order_relaxed);

	if (plen > LOCAL_MAX || head - atomic_load_explicit(&lq.tail, memory_order_acquire) >= LOCAL_RING)
		return -1;
	struct lslot *s = &lq.slot[head % LOCAL_RING];
	s->rx_ns = rx_ns;
	s->len = plen;
	memcpy(s->data, payload, plen);
	atomic_store_explicit(&lq.head, head + 1, memory_order_release);
	return 0;
}

static void reclaim(struct port *p)
{
	uint32_t idx, n = xsk_ring_cons__peek(&p->comp, RING_SIZE, &idx);

	for (uint32_t i = 0; i < n; i++)
		p->pool[p->pool_n++] = *xsk_ring_cons__comp_addr(&p->comp, idx + i);
	if (n)
		xsk_ring_cons__release(&p->comp, n);
}

/* Queues one copy on the destination's port. Returns 0 if queued. */
static int queue_copy(struct dest *d, const uint8_t *payload, uint32_t plen, uint16_t sport_be)
{
	struct port *q = &ports[d->port];
	uint32_t tidx, len = d->hdr_len + plen;
	struct xdp_desc *desc;
	uint8_t *buf;
	uint64_t addr;

	if (len > FRAME_SIZE - XDP_PACKET_HEADROOM)
		return -1;
	if (!q->pool_n)
		reclaim(q);
	if (!q->pool_n || xsk_ring_prod__reserve(&q->tx, 1, &tidx) != 1) {
		kick_tx(q);
		reclaim(q);
		if (!q->pool_n || xsk_ring_prod__reserve(&q->tx, 1, &tidx) != 1)
			return -1;
	}
	addr = q->pool[--q->pool_n];
	buf = xsk_umem__get_data(q->area, addr);
	memcpy(buf, d->hdr, d->hdr_len);
	uint8_t *ip = buf + d->ip_off, *udp = ip + 20;
	uint16_t tot = 20 + 8 + plen, ulen = 8 + plen, csum;
	ip[2] = tot >> 8, ip[3] = tot & 0xff;
	csum = fold(d->ip_sum + tot);
	ip[10] = csum >> 8, ip[11] = csum & 0xff;
	memcpy(udp, &sport_be, 2);
	udp[4] = ulen >> 8, udp[5] = ulen & 0xff; /* UDP checksum stays 0 (none) */
	memcpy(udp + 8, payload, plen);
	desc = xsk_ring_prod__tx_desc(&q->tx, tidx);
	desc->addr = addr;
	desc->len = len;
	q->tx_pending++;
	return 0;
}

static void handle(uint8_t *pkt, uint32_t len)
{
	struct meta *m = (void *)(pkt - sizeof(struct meta));
	uint32_t off = 14, ihl;
	uint16_t proto = (uint16_t)pkt[12] << 8 | pkt[13];
	uint64_t rx_ns = 0, t_first = 0, t;
	const uint8_t *payload;
	uint32_t plen;
	int sent_any = 0;
	uint64_t t_begin = now_ns();

	if (m->magic == META_MAGIC) {
		rx_ns = m->rx_ns;
		m->magic = 0; /* the frame is reused: never read a stale stamp */
	} else {
		st.no_meta++;
	}
	if (proto == 0x8100 || proto == 0x88a8) {
		proto = (uint16_t)pkt[16] << 8 | pkt[17];
		off = 18;
	}
	if (proto != 0x0800 || len < off + 28)
		return;
	ihl = (pkt[off] & 0x0f) * 4;
	if (len < off + ihl + 8)
		return;
	payload = pkt + off + ihl + 8;
	plen = len - (off + ihl + 8);
	uint16_t sport_be;
	memcpy(&sport_be, pkt + off + ihl + 2, 2); /* copies are sent from the listen port */

	for (int i = 0; i < ndests; i++) {
		if (dests[i].local)
			continue;
		if (queue_copy(&dests[i], payload, plen, sport_be)) {
			st.tx_full++;
			continue;
		}
		st.copies++;
		if (!sent_any) {
			/* Make the first copy go out before building the rest. */
			struct port *q = &ports[dests[i].port];
			xsk_ring_prod__submit(&q->tx, q->tx_pending);
			q->tx_pending = 0;
			kick_tx(q);
			t_first = now_ns();
			sent_any = 1;
		}
	}
	for (int p = 0; p < nports; p++)
		if (ports[p].tx_pending) {
			xsk_ring_prod__submit(&ports[p].tx, ports[p].tx_pending);
			ports[p].tx_pending = 0;
			kick_tx(&ports[p]);
		}
	uint64_t t_nic = now_ns();
	t = t_nic;
	if (nlocal) {
		if (lq.on) {
			if (queue_local(payload, plen, rx_ns))
				lq.dropped++;
		} else {
			send_local(payload, plen, &st.copies, &st.local_fail);
		}
		t = now_ns();
	}
	st.shreds++;
	st.busy_ns += t - t_begin;
	st.nic_ns += t_nic - t_begin;
	st.local_ns += t - t_nic;
	if (rx_ns) {
		h_add(&st.wait, t_begin - rx_ns);
		h_add(&st.first, (sent_any ? t_first : t) - rx_ns);
		/* With the local thread, "all copies" means all NIC copies. */
		h_add(&st.last, (lq.on ? t_nic : t) - rx_ns);
	}
}

static void summary_json(FILE *f, const struct hist *h)
{
	fprintf(f,
		"{\"count\":%lu,\"mean_us\":%.1f,\"p50_us\":%.1f,\"p90_us\":%.1f,\"p99_us\":%.1f,"
		"\"p999_us\":%.1f,\"max_us\":%.1f}",
		(unsigned long)h->n, h->n ? h->sum / 1000.0 / h->n : 0, h_pct(h, .5), h_pct(h, .9), h_pct(h, .99),
		h_pct(h, .999), h->max / 1000.0);
}

/* Takes the local-send thread's stats for this window (it hands them over). */
static void local_snapshot(void)
{
	uint64_t until = now_ns() + 50000000ull;

	if (!lq.on)
		return;
	atomic_store_explicit(&lq.snap, 1, memory_order_release);
	while (atomic_load_explicit(&lq.snap, memory_order_acquire) != 2 && now_ns() < until)
		;
	if (atomic_load_explicit(&lq.snap, memory_order_acquire) != 2)
		memset(&lq.out, 0, sizeof(lq.out));
	atomic_store_explicit(&lq.snap, 0, memory_order_release);
}

static void report(double secs, const char *label, const char *results, uint64_t invol)
{
	double per = st.shreds ? 1000.0 * st.shreds : 1;

	local_snapshot();
	if (st.last.n) {
		printf("[%s] %.0fs: %lu shreds, %lu copies, send ring full %lu, local send failed %lu, "
		       "busy %.1f%% (%.2f us/shred) | "
		       "all copies: p50 %.1f p90 %.1f p99 %.1f p99.9 %.1f max %.1f us | "
		       "first copy: p50 %.1f p99 %.1f us\n",
		       label, secs, (unsigned long)st.shreds, (unsigned long)(st.copies + lq.out.sent),
		       (unsigned long)st.tx_full, (unsigned long)(st.local_fail + lq.out.fail + lq.dropped),
		       st.busy_ns / (secs * 1e7), st.busy_ns / per, h_pct(&st.last, .5), h_pct(&st.last, .9),
		       h_pct(&st.last, .99), h_pct(&st.last, .999), st.last.max / 1000.0, h_pct(&st.first, .5),
		       h_pct(&st.first, .99));
		/* Where the time goes: waiting before we start on a shred, versus our work. */
		printf("   wait before handling: p50 %.1f p99 %.1f p99.9 %.1f max %.1f us | per shred: NIC copies "
		       "%.2f us, local %.2f us, %.2f kicks | max batch %lu | stalls >%dus %lu (max %.0f us), "
		       "preempted %lu",
		       h_pct(&st.wait, .5), h_pct(&st.wait, .99), h_pct(&st.wait, .999), st.wait.max / 1000.0,
		       st.nic_ns / per, st.local_ns / per, st.kicks / (per / 1000.0), (unsigned long)st.max_batch,
		       STALL_NS / 1000, (unsigned long)st.stalls, st.max_stall_ns / 1000.0, (unsigned long)invol);
		if (lq.on)
			printf(" | local thread: p50 %.1f p99 %.1f p99.9 %.1f max %.1f us, preempted %lu",
			       h_pct(&lq.out.lat, .5), h_pct(&lq.out.lat, .99), h_pct(&lq.out.lat, .999),
			       lq.out.lat.max / 1000.0, (unsigned long)lq.out.invol);
		printf("\n");
	} else {
		printf("[%s] %.0fs: %lu shreds, no timed samples (no arrival metadata: %lu)\n", label, secs,
		       (unsigned long)st.shreds, (unsigned long)st.no_meta);
	}
	fflush(stdout);
	if (results && st.last.n) {
		FILE *f = fopen(results, "a");

		if (f) {
			fprintf(f, "{\"label\":\"%s\",\"unix_time\":%ld,\"source\":\"xskfwd\",\"meta\":{},"
				   "\"capture_seconds\":%.1f,\"eligible_shreds\":%lu,\"delivery_pct\":100,"
				   "\"duplicate_sends\":0,\"send_ring_full\":%lu,\"busy_us_per_shred\":%.2f,"
				   "\"nic_us_per_shred\":%.2f,\"local_us_per_shred\":%.2f,\"stalls\":%lu,"
				   "\"preempted\":%lu,\"local_thread\":%d,\"completion\":",
				label, (long)time(NULL), secs, (unsigned long)st.shreds, (unsigned long)st.tx_full,
				st.busy_ns / per, st.nic_ns / per, st.local_ns / per, (unsigned long)st.stalls,
				(unsigned long)invol, lq.on);
			summary_json(f, &st.last);
			fprintf(f, ",\"first_dest\":");
			summary_json(f, &st.first);
			fprintf(f, ",\"wait\":");
			summary_json(f, &st.wait);
			if (lq.on) {
				fprintf(f, ",\"local\":");
				summary_json(f, &lq.out.lat);
			}
			fprintf(f, "}\n");
			fclose(f);
		}
	}
	memset(&st, 0, sizeof(st));
	lq.dropped = 0;
}

int main(int argc, char **argv)
{
	const char *rx_list = NULL, *dests_path = NULL, *pin = "/sys/fs/bpf/xskfwd", *label = "xskfwd";
	const char *results = NULL;
	int queue = -1, cpu = -1, copy = 0, report_s = 10, local_cpu = -1;
	static const struct option opts[] = {
		{"rx", required_argument, 0, 'r'},     {"queue", required_argument, 0, 'q'},
		{"dests", required_argument, 0, 'd'},  {"pin", required_argument, 0, 'p'},
		{"cpu", required_argument, 0, 'c'},    {"copy", no_argument, 0, 'C'},
		{"report", required_argument, 0, 'R'}, {"label", required_argument, 0, 'l'},
		{"results", required_argument, 0, 'o'}, {"local-cpu", required_argument, 0, 'L'},
		{0, 0, 0, 0},
	};
	int o;

	while ((o = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (o) {
		case 'r': rx_list = optarg; break;
		case 'q': queue = atoi(optarg); break;
		case 'd': dests_path = optarg; break;
		case 'p': pin = optarg; break;
		case 'c': cpu = atoi(optarg); break;
		case 'C': copy = 1; break;
		case 'R': report_s = atoi(optarg); break;
		case 'l': label = optarg; break;
		case 'o': results = optarg; break;
		case 'L': local_cpu = atoi(optarg); break;
		default: goto usage;
		}
	}
	if (!rx_list || queue < 0 || !dests_path || report_s < 1)
		goto usage;

	char *list = strdup(rx_list), *tok, *save = NULL;
	for (tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
		port_index(tok, 1);
	free(list);
	load_dests(dests_path);

	char path[256];
	snprintf(path, sizeof(path), "%s/xsk_socks", pin);
	int socks_fd = bpf_obj_get(path);
	snprintf(path, sizeof(path), "%s/xsk_slots", pin);
	int slots_fd = bpf_obj_get(path);
	if (socks_fd < 0 || slots_fd < 0)
		die("open pinned maps (is the XDP program loaded? xsk.sh setup)");

	local_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (local_fd < 0)
		die("local UDP socket");
	for (int i = 0; i < ndests; i++)
		nlocal += dests[i].local;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	for (int i = 0; i < nports; i++) {
		ports[i].slot = i + 1;
		setup_port(&ports[i], queue, copy, socks_fd, slots_fd);
	}
	if (cpu >= 0) {
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		if (sched_setaffinity(0, sizeof(set), &set))
			die("pin to cpu");
	}
	fprintf(stderr, "xskfwd: %d destinations, %d interfaces, busy-polling on cpu %d\n", ndests, nports, cpu);
	pthread_t lt;
	if (nlocal && local_cpu >= 0) {
		lq.slot = aligned_alloc(64, sizeof(struct lslot) * LOCAL_RING);
		if (!lq.slot)
			die("allocate local ring");
		lq.on = 1;
		if (pthread_create(&lt, NULL, local_thread, (void *)(long)local_cpu)) {
			errno = EAGAIN;
			die("start the local-send thread");
		}
		fprintf(stderr, "xskfwd: %d local destination(s) sent by a thread on cpu %d\n", nlocal, local_cpu);
	}

	uint64_t next_report = now_ns() + (uint64_t)report_s * 1000000000ull, start = now_ns();
	uint64_t invol0 = invol_switches();
	while (running) {
		uint64_t t_pass = now_ns(), got = 0;

		for (int p = 0; p < nports; p++) {
			struct port *pp = &ports[p];
			uint32_t idx, fidx, n;

			if (!pp->receive)
				continue;
			n = xsk_ring_cons__peek(&pp->rx, RX_BATCH, &idx);
			if (!n) {
				if (xsk_ring_prod__needs_wakeup(&pp->fill))
					recvfrom(xsk_socket__fd(pp->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
				continue;
			}
			got += n;
			if (n > st.max_batch)
				st.max_batch = n;
			for (uint32_t i = 0; i < n; i++) {
				const struct xdp_desc *d = xsk_ring_cons__rx_desc(&pp->rx, idx + i);
				handle(xsk_umem__get_data(pp->area, d->addr), d->len);
			}
			/* Payloads are copied into send frames: recycle the receive frames now. */
			while (xsk_ring_prod__reserve(&pp->fill, n, &fidx) != n)
				;
			for (uint32_t i = 0; i < n; i++) {
				uint64_t a = xsk_ring_cons__rx_desc(&pp->rx, idx + i)->addr;
				*xsk_ring_prod__fill_addr(&pp->fill, fidx + i) = a - (a % FRAME_SIZE);
			}
			xsk_ring_prod__submit(&pp->fill, n);
			xsk_ring_cons__release(&pp->rx, n);
		}
		for (int p = 0; p < nports; p++)
			reclaim(&ports[p]);
		uint64_t t = now_ns();
		/* A pass with nothing to do takes well under a microsecond; a long
		 * one means this thread was interrupted or preempted. */
		if (!got && t - t_pass > STALL_NS) {
			st.stalls++;
			if (t - t_pass > st.max_stall_ns)
				st.max_stall_ns = t - t_pass;
		}
		if (t >= next_report) {
			uint64_t invol = invol_switches();

			report((t - start) / 1e9, label, results, invol - invol0);
			invol0 = invol;
			t = now_ns();
			start = t;
			next_report = t + (uint64_t)report_s * 1000000000ull;
		}
	}
	if (lq.on)
		pthread_join(lt, NULL);

	/* Stop receiving first, so the XDP program passes shreds up the stack
	 * (to the regular forwarders) before the sockets go away. */
	for (int i = 0; i < nports; i++)
		if (ports[i].receive)
			bpf_map_delete_elem(slots_fd, &ports[i].ifindex);
	for (int i = 0; i < nports; i++) {
		xsk_socket__delete(ports[i].xsk);
		xsk_umem__delete(ports[i].umem);
	}
	fprintf(stderr, "xskfwd: stopped; shreds go to the normal stack again\n");
	return 0;

usage:
	fprintf(stderr, "usage: %s --rx IF[,IF] --queue Q --dests FILE [--pin DIR] [--cpu N] [--copy]\n"
			"       [--report SECS] [--label L] [--results FILE] [--local-cpu N]\n",
		argv[0]);
	return 2;
}
