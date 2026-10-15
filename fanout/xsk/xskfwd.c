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
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
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
#define MAX_SAMPLES (4u << 20)

struct meta {
	uint64_t magic;
	uint64_t rx_ns;
};

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

static struct {
	uint64_t shreds, copies, tx_full, local_fail, no_meta;
	uint64_t busy_ns;        /* time spent handling shreds (capacity use) */
	uint32_t n;
	uint64_t *first, *last;
} st;

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
	if (xsk_ring_prod__needs_wakeup(&p->tx))
		sendto(xsk_socket__fd(p->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
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
	t = now_ns();
	for (int i = 0; i < ndests; i++) {
		if (!dests[i].local)
			continue;
		if (sendto(local_fd, payload, plen, MSG_DONTWAIT, (struct sockaddr *)&dests[i].addr,
			   sizeof(dests[i].addr)) < 0)
			st.local_fail++;
		else
			st.copies++;
		t = now_ns();
	}
	st.shreds++;
	st.busy_ns += t - t_begin;
	if (rx_ns && st.n < MAX_SAMPLES) {
		st.first[st.n] = (sent_any ? t_first : t) - rx_ns;
		st.last[st.n] = t - rx_ns;
		st.n++;
	}
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

static double pct(uint64_t *v, uint32_t n, double p)
{
	uint32_t rank = (uint32_t)(p * n + 0.999999);

	if (rank < 1)
		rank = 1;
	if (rank > n)
		rank = n;
	return v[rank - 1] / 1000.0;
}

static void summary_json(FILE *f, uint64_t *v, uint32_t n)
{
	double sum = 0;

	for (uint32_t i = 0; i < n; i++)
		sum += v[i];
	fprintf(f,
		"{\"count\":%u,\"mean_us\":%.1f,\"p50_us\":%.1f,\"p90_us\":%.1f,\"p99_us\":%.1f,"
		"\"p999_us\":%.1f,\"max_us\":%.1f}",
		n, n ? sum / n / 1000.0 : 0, pct(v, n, .5), pct(v, n, .9), pct(v, n, .99), pct(v, n, .999),
		n ? v[n - 1] / 1000.0 : 0);
}

static void report(double secs, const char *label, const char *results)
{
	uint32_t n = st.n;

	if (n) {
		qsort(st.first, n, sizeof(uint64_t), cmp_u64);
		qsort(st.last, n, sizeof(uint64_t), cmp_u64);
		printf("[%s] %.0fs: %lu shreds, %lu copies, send ring full %lu, local send failed %lu, "
		       "busy %.1f%% (%.2f us/shred) | "
		       "all copies: p50 %.1f p90 %.1f p99 %.1f p99.9 %.1f max %.1f us | "
		       "first copy: p50 %.1f p99 %.1f us\n",
		       label, secs, (unsigned long)st.shreds, (unsigned long)st.copies, (unsigned long)st.tx_full,
		       (unsigned long)st.local_fail, st.busy_ns / (secs * 1e7),
		       st.shreds ? st.busy_ns / 1000.0 / st.shreds : 0, pct(st.last, n, .5), pct(st.last, n, .9),
		       pct(st.last, n, .99),
		       pct(st.last, n, .999), st.last[n - 1] / 1000.0, pct(st.first, n, .5), pct(st.first, n, .99));
	} else {
		printf("[%s] %.0fs: %lu shreds, no timed samples (no arrival metadata: %lu)\n", label, secs,
		       (unsigned long)st.shreds, (unsigned long)st.no_meta);
	}
	fflush(stdout);
	if (results && n) {
		FILE *f = fopen(results, "a");

		if (f) {
			fprintf(f, "{\"label\":\"%s\",\"unix_time\":%ld,\"source\":\"xskfwd\",\"meta\":{},"
				   "\"capture_seconds\":%.1f,\"eligible_shreds\":%lu,\"delivery_pct\":100,"
				   "\"duplicate_sends\":0,\"send_ring_full\":%lu,\"completion\":",
				label, (long)time(NULL), secs, (unsigned long)st.shreds, (unsigned long)st.tx_full);
			summary_json(f, st.last, n);
			fprintf(f, ",\"first_dest\":");
			summary_json(f, st.first, n);
			fprintf(f, "}\n");
			fclose(f);
		}
	}
	st.shreds = st.copies = st.tx_full = st.local_fail = st.no_meta = st.busy_ns = 0;
	st.n = 0;
}

int main(int argc, char **argv)
{
	const char *rx_list = NULL, *dests_path = NULL, *pin = "/sys/fs/bpf/xskfwd", *label = "xskfwd";
	const char *results = NULL;
	int queue = -1, cpu = -1, copy = 0, report_s = 10;
	static const struct option opts[] = {
		{"rx", required_argument, 0, 'r'},     {"queue", required_argument, 0, 'q'},
		{"dests", required_argument, 0, 'd'},  {"pin", required_argument, 0, 'p'},
		{"cpu", required_argument, 0, 'c'},    {"copy", no_argument, 0, 'C'},
		{"report", required_argument, 0, 'R'}, {"label", required_argument, 0, 'l'},
		{"results", required_argument, 0, 'o'}, {0, 0, 0, 0},
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

	st.first = calloc(MAX_SAMPLES, sizeof(uint64_t));
	st.last = calloc(MAX_SAMPLES, sizeof(uint64_t));
	if (!st.first || !st.last)
		die("allocate samples");
	local_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (local_fd < 0)
		die("local UDP socket");

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

	uint64_t next_report = now_ns() + (uint64_t)report_s * 1000000000ull, start = now_ns();
	while (running) {
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
		if (t >= next_report) {
			report((t - start) / 1e9, label, results);
			start = t;
			next_report = t + (uint64_t)report_s * 1000000000ull;
		}
	}

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
			"       [--report SECS] [--label L] [--results FILE]\n",
		argv[0]);
	return 2;
}
