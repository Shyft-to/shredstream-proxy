#!/usr/bin/env python3
"""Kernel fan-out (kfan) on real arrival times, against what the proxies did.

Reads the captures of one `probe.sh box` run taken while the PROXIES forward
(KEEP_PCAP=1). Their receiving CPU only hands packets to sockets, so the
capture's arrival times are the real ones (under kfan the probe stamps a shred
only when the busy CPU picks it up, and misses the wait in the NIC ring).

It then replays every arriving packet through a model of kfan: a CPU handles
its packets in arrival order; a duplicate costs DUP_US; a first copy costs
BASE_US + COPY_US per destination, the copies leaving in table order. Two
placements of the work:
  one CPU    every packet on one CPU (what the measured kfan did for everstake)
  per flow   each incoming flow (NIC port, source, port) on its own CPU, one
             shared duplicate table: whoever starts on a shred first sends it
And it reports, for the proxies (measured) and both models:
  - per shred: true first arrival -> first / last copy leaving
  - for one destination (--focus): per shred, and per FEC set: first shred of
    the set arriving -> its last data shred leaving for that destination
    (a node can only decode the set's transactions once it has them)
  - the incoming flows: share of shreds each delivers first, and its lag

Usage (on the server, as root; captures from KEEP_PCAP=1 probe.sh box):
  kfan-model.py --ports 23998,23999 --dests "$DESTS" --focus 10.182.192.76:8002 \
      /dev/shm/box-STAMP-enp1s0f0.pcap /dev/shm/box-STAMP-enp1s0f1.pcap /dev/shm/box-STAMP-lo.pcap
"""
import argparse
import heapq
import ipaddress
import mmap
import os
import struct
import subprocess
from array import array

KEY_BYTES = 83  # same shred identity as fanout-measure: signature .. FEC set index


def pcap_packets(path):
    """Yields (ts_ns, flow, src_ip, sport, dst_ip, dport, key, payload_head) per UDP/IPv4 packet."""
    iface = os.path.basename(path).rsplit("-", 1)[-1].removesuffix(".pcap")
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        magic = struct.unpack_from("<I", m, 0)[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            e = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            e = ">"
            magic = struct.unpack_from(">I", m, 0)[0]
        else:
            raise SystemExit(f"{path}: not a pcap file")
        frac = 1 if magic == 0xA1B23C4D else 1000
        link = struct.unpack_from(e + "I", m, 20)[0]
        rec = struct.Struct(e + "IIII")
        pos, end = 24, len(m)
        while pos + 16 <= end:
            sec, sub, incl, _ = rec.unpack_from(m, pos)
            pos += 16
            p, stop = pos, pos + incl
            pos = stop
            if link == 1:  # Ethernet, possibly VLAN-tagged
                et = (m[p + 12] << 8) | m[p + 13]
                off = p + 14
                while et in (0x8100, 0x88A8) and off + 4 <= stop:
                    et = (m[off + 2] << 8) | m[off + 3]
                    off += 4
            elif link == 113:  # Linux cooked
                et, off = (m[p + 14] << 8) | m[p + 15], p + 16
            elif link == 276:  # Linux cooked v2
                et, off = (m[p] << 8) | m[p + 1], p + 20
            else:
                raise SystemExit(f"{path}: link type {link} not supported")
            if et != 0x0800 or off + 20 > stop or m[off + 9] != 17:
                continue
            ihl = (m[off] & 0x0F) * 4
            l4 = off + ihl
            if l4 + 8 > stop:
                continue
            sport, dport, ulen = struct.unpack_from("!HHH", m, l4)
            data = l4 + 8
            head = m[data:min(stop, data + KEY_BYTES)]
            key = head + (ulen - 8).to_bytes(2, "big")
            src, dst = bytes(m[off + 12:off + 16]), bytes(m[off + 16:off + 20])
            yield sec * 1_000_000_000 + sub * frac, (iface, src, sport, dport), src, sport, dst, dport, key, head


def shred_fields(head):
    """(slot, fec_set_index, is_data) from the shred's common header, or None."""
    if len(head) < 83:
        return None
    v = head[64]
    is_data = v == 0xA5 or (v & 0xF0) in (0x80, 0x90, 0xA0, 0xB0)
    return struct.unpack_from("<Q", head, 65)[0], struct.unpack_from("<I", head, 79)[0], is_data


def table_order(dests):
    """kfan.sh order: destinations behind a VLAN device after the others, stable."""
    def vlan(d):
        ip = d[0]
        if ip.startswith("127."):
            return 0
        try:
            out = subprocess.run(["ip", "-o", "route", "get", ip], capture_output=True, text=True).stdout
            dev = out.split(" dev ", 1)[1].split()[0]
            return 1 if os.path.exists(f"/proc/net/vlan/{dev}") else 0
        except (IndexError, OSError):
            return 0
    return sorted(range(len(dests)), key=lambda i: vlan(dests[i]))


def pct(vals, ps=(50, 90, 99, 99.9)):
    if not vals:
        return "n=0"
    s = sorted(vals)
    out = []
    for p in ps:
        out.append(f"p{p:g} {s[min(len(s) - 1, int(p / 100 * len(s)))] / 1000:8.1f}")
    return "  ".join(out) + f"  max {s[-1] / 1000:8.1f}  (n={len(s)})"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--ports", required=True, help="source ports, comma separated")
    ap.add_argument("--dests", required=True, help="kfan's destinations ip:port,... (table order is derived)")
    ap.add_argument("--focus", required=True, help="destination to report per FEC set, ip:port")
    ap.add_argument("--copy-us", type=float, default=1.3, help="kfan CPU time per copy (Fra, no capture: ~1.3)")
    ap.add_argument("--dup-us", type=float, default=0.6, help="kfan CPU time per dropped duplicate")
    ap.add_argument("--base-us", type=float, default=1.0, help="kfan CPU time per first copy before sending")
    ap.add_argument("--edge-ms", type=float, default=500, help="ignore shreds this close to the capture's ends")
    a = ap.parse_args()

    ports = {int(p) for p in a.ports.split(",")}
    dests = [(d.rsplit(":", 1)[0], int(d.rsplit(":", 1)[1])) for d in a.dests.split(",") if d]
    didx = {(ipaddress.IPv4Address(ip).packed, port): i for i, (ip, port) in enumerate(dests)}
    fip, fport = a.focus.rsplit(":", 1)
    focus = didx.get((ipaddress.IPv4Address(fip).packed, int(fport)))
    if focus is None:
        raise SystemExit(f"--focus {a.focus} is not in --dests")
    nd = len(dests)
    order = table_order(dests)
    pos = {d: j for j, d in enumerate(order)}  # destination -> position in kfan's table

    sid_of, first_ns, sets, events, flows = {}, [], {}, [], {}
    eg_by_key = {}
    for path in a.pcaps:
        for ts, flow, src, sport, dst, dport, key, head in pcap_packets(path):
            if dport in ports and len(head) >= KEY_BYTES:
                sid = sid_of.get(key)
                if sid is None:
                    sid = sid_of[key] = len(first_ns)
                    first_ns.append(ts)
                    f = shred_fields(head)
                    if f:
                        sets.setdefault((f[0], f[1]), []).append((sid, f[2]))
                elif ts < first_ns[sid]:
                    first_ns[sid] = ts
                fid = flows.setdefault(flow, len(flows))
                events.append((ts, fid, sid))
                continue
            d = didx.get((dst, dport))
            if d is None:
                continue
            row = eg_by_key.get(key)
            if row is None:
                row = eg_by_key[key] = array("q", [-1] * nd)
            if row[d] < 0 or ts < row[d]:
                row[d] = ts
    if not events:
        raise SystemExit("no packets to --ports in the captures")
    n = len(first_ns)
    t0, t1 = min(e[0] for e in events), max(e[0] for e in events)
    edge = int(a.edge_ms * 1e6)
    inwin = [t0 + edge <= first_ns[s] <= t1 - edge for s in range(n)]
    eg = [None] * n
    for key, sid in sid_of.items():
        eg[sid] = eg_by_key.get(key)
    events.sort()
    secs = (t1 - t0) / 1e9
    print(f"{n} shreds, {len(events)} arrivals ({len(events) / max(n, 1):.2f} per shred) in {secs:.1f}s;"
          f" {nd} destinations; focus {a.focus} at table position {pos[focus] + 1}")

    # Bursts, from the real arrival times.
    fa = sorted(first_ns)
    j, burst = 0, 0
    for i, t in enumerate(fa):
        while fa[j] < t - 500_000:
            j += 1
        burst += (i - j) >= 32
    print(f"shreds with 32+ first arrivals in the 500 us before: {100 * burst / n:.1f}%")

    # Incoming flows: who delivers first, and how far behind the others are.
    lag = [[] for _ in flows]
    won = [0] * len(flows)
    seen = {}
    for ts, fid, sid in events:
        if (sid, fid) in seen:
            continue
        seen[(sid, fid)] = 1
        lag[fid].append(ts - first_ns[sid])
        won[fid] += ts == first_ns[sid]
    seen = None
    print("\nincoming flows (port, source, NIC port): first-arrival share; lag behind the first arrival")
    for flow, fid in sorted(flows.items(), key=lambda x: -len(lag[x[1]])):
        iface, src, sport, dport = flow
        later = [x for x in lag[fid] if x > 0]
        print(f"  {dport:5d} from {ipaddress.IPv4Address(src)}:{sport:<5d} on {iface:9s} {len(lag[fid]):8d} shreds,"
              f" first {100 * won[fid] / n:5.1f}%, lag when not first: {pct(later, (50, 90))}")

    C, D, B = a.copy_us * 1000, a.dup_us * 1000, a.base_us * 1000

    def model(per_flow):
        """Start time of each shred's fan-out, and the busiest CPU's share."""
        start = [None] * n
        queues = {}
        for ts, fid, sid in events:
            queues.setdefault(fid if per_flow else 0, []).append((ts, sid))
        free = {c: 0 for c in queues}
        idx = {c: 0 for c in queues}
        busy = {c: 0.0 for c in queues}
        heap = [(q[0][0], c) for c, q in queues.items()]
        heapq.heapify(heap)
        while heap:
            st, c = heapq.heappop(heap)
            ts, sid = queues[c][idx[c]]
            if start[sid] is None:
                start[sid] = st
                cost = B + nd * C
            else:
                cost = D
            free[c] = st + cost
            busy[c] += cost
            idx[c] += 1
            if idx[c] < len(queues[c]):
                heapq.heappush(heap, (max(queues[c][idx[c]][0], free[c]), c))
        return start, max(busy.values()) / (t1 - t0)

    def report(name, at):
        """at(sid, d) -> time the copy for destination d left (None if never)."""
        comp, first, foc = [], [], []
        for s in range(n):
            if not inwin[s]:
                continue
            ts = [at(s, d) for d in range(nd)]
            if all(t is not None for t in ts):
                comp.append(max(ts) - first_ns[s])
                first.append(min(ts) - first_ns[s])
            if ts[focus] is not None:
                foc.append(ts[focus] - first_ns[s])
        fec_focus, fec_all = [], []
        for members in sets.values():
            st = min(first_ns[s] for s, _ in members)
            data = [s for s, is_data in members if is_data]
            if not data or not (t0 + edge <= st <= t1 - edge):
                continue
            tf = [at(s, focus) for s in data]
            if all(t is not None for t in tf):
                fec_focus.append(max(tf) - st)
            ta = [at(s, d) for s in data for d in range(nd)]
            if all(t is not None for t in ta):
                fec_all.append(max(ta) - st)
        print(f"\n== {name} ==  (us, from the real first arrival)")
        print(f"  per shred, last copy      {pct(comp)}")
        print(f"  per shred, first copy     {pct(first)}")
        print(f"  per shred, {a.focus:21s} {pct(foc)}")
        print(f"  FEC set (data), {a.focus:16s} {pct(fec_focus)}")
        print(f"  FEC set (data), all dests {pct(fec_all)}")

    def measured(s, d):
        row = eg[s]
        return row[d] if row is not None and row[d] >= 0 else None

    report("proxies, measured", measured)
    for per_flow in (False, True):
        start, util = model(per_flow)
        name = ("kfan model, one CPU per incoming flow" if per_flow else "kfan model, one CPU") + \
            f" (busiest CPU {100 * util:.0f}%; copy {a.copy_us} us, dup {a.dup_us} us)"
        report(name, lambda s, d, start=start: None if start[s] is None else start[s] + B + (pos[d] + 1) * C)


if __name__ == "__main__":
    main()
