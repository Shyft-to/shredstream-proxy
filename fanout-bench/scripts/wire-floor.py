#!/usr/bin/env python3
"""The best fan-out completion the links allow, on real arrival times.

Reads the captures of one `probe.sh box` run (KEEP_PCAP=1). Every shred's
copies are handed to the links the moment its first copy arrives, as if
forwarding cost no CPU at all; each link then sends one frame at a time at
line rate. What is left is waiting for the wire: the floor no software can
go under on these links. Each destination stays on the NIC port that carried
its copies in the capture (the bond's choice).

Send orders modelled, per link:
  shred-major  copies in the order the shreds arrived, all of one shred's
               copies before the next shred's
  data first   the same, but a waiting data shred goes before a waiting
               coding shred (a node can decode from data shreds alone)
Reports, next to what the capture measured: per shred first arrival -> first
and last copy on the wire, and how busy each link was.

Usage (on the server; captures from KEEP_PCAP=1 probe.sh box):
  wire-floor.py --ports 23998,23999 --dests "$DESTS" /dev/shm/box-STAMP-*.pcap
"""
import argparse
import importlib.util
import ipaddress
import os
from collections import Counter, deque

_spec = importlib.util.spec_from_file_location(
    "kfan_model", os.path.join(os.path.dirname(os.path.abspath(__file__)), "kfan-model.py"))
km = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(km)

# Per frame on the wire besides the UDP datagram: IPv4 20, Ethernet 14,
# FCS 4, preamble 8, inter-frame gap 12.
FRAME_EXTRA = 58


def simulate(shreds, link_of, nlinks, gbps, data_first):
    """shreds: (arrival_ns, sid, is_data, wire_bytes) in arrival order.
    Returns (first, last) on-the-wire end time per sid, and busy ns per link."""
    ns_per_byte = 8 / gbps
    queues = [(deque(), deque()) for _ in range(nlinks)]  # (data, coding) of (sid, count)
    pending = [[] for _ in range(nlinks)]  # per link: shreds in arrival order with copies there
    for t, sid, is_data, size in shreds:
        for link, count in link_of.items():
            if count:
                pending[link].append((t, sid, is_data, size, count))
    first, last, busy = {}, {}, [0] * nlinks
    for link in range(nlinks):
        free, i, items = 0, 0, pending[link]
        data_q, code_q = queues[link]
        while i < len(items) or data_q or code_q:
            if not data_q and not code_q:
                free = max(free, items[i][0])
            while i < len(items) and items[i][0] <= free:
                t, sid, is_data, size, count = items[i]
                (data_q if is_data or not data_first else code_q).append((sid, size, count))
                i += 1
            sid, size, count = (data_q or code_q).popleft()
            dur = (size + FRAME_EXTRA) * ns_per_byte
            first[sid] = min(first.get(sid, float("inf")), free + dur)
            free += dur * count
            busy[link] += dur * count
            last[sid] = max(last.get(sid, 0), free)
    return first, last, busy


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--ports", required=True, help="source ports, comma separated")
    ap.add_argument("--dests", required=True, help="destinations ip:port,...")
    ap.add_argument("--gbps", default="10,25", help="link speeds to model, comma separated")
    ap.add_argument("--edge-ms", type=float, default=500, help="ignore shreds this close to the capture's ends")
    a = ap.parse_args()

    ports = {int(p) for p in a.ports.split(",")}
    dests = [(d.rsplit(":", 1)[0], int(d.rsplit(":", 1)[1])) for d in a.dests.split(",") if d]
    didx = {(ipaddress.IPv4Address(ip).packed, port): i for i, (ip, port) in enumerate(dests)}

    first_ns, info, eg = {}, {}, {}
    dest_iface = [Counter() for _ in dests]
    t0, t1 = None, None
    for path in a.pcaps:
        for ts, flow, src, sport, dst, dport, key, head in km.pcap_packets(path):
            if dport in ports and len(head) >= km.KEY_BYTES:
                if key not in first_ns or ts < first_ns[key]:
                    first_ns[key] = ts
                if key not in info:
                    f = km.shred_fields(head)
                    info[key] = (bool(f and f[2]), int.from_bytes(key[-2:], "big") + 8)
                t0 = ts if t0 is None else min(t0, ts)
                t1 = ts if t1 is None else max(t1, ts)
                continue
            d = didx.get((dst, dport))
            if d is None:
                continue
            dest_iface[d][flow[0]] += 1
            e = eg.setdefault(key, [None, None, 0])
            e[0] = ts if e[0] is None else min(e[0], ts)
            e[1] = ts if e[1] is None else max(e[1], ts)
            e[2] |= 1 << d
    if not first_ns:
        raise SystemExit("no packets to --ports in the captures")

    # Each destination on the NIC port that carried its copies; loopback
    # destinations cost no wire.
    ifaces = sorted({c.most_common(1)[0][0] for c in dest_iface if c} - {"lo"})
    link_of = Counter()
    for d, c in enumerate(dest_iface):
        if not c:
            print(f"warning: no copies to {dests[d][0]}:{dests[d][1]} in the capture; left out")
            continue
        iface = c.most_common(1)[0][0]
        if iface != "lo":
            link_of[ifaces.index(iface)] += 1
    nlinks = len(ifaces)
    print(f"{len(first_ns)} shreds in {(t1 - t0) / 1e9:.1f}s; destinations per link: "
          + ", ".join(f"{ifaces[l]} {link_of[l]}" for l in range(nlinks)))

    edge = int(a.edge_ms * 1e6)
    keys = sorted(first_ns, key=first_ns.get)
    sid = {k: i for i, k in enumerate(keys)}
    inwin = [t0 + edge <= first_ns[k] <= t1 - edge for k in keys]
    shreds = [(first_ns[k], sid[k], info[k][0], info[k][1]) for k in keys]
    live = sum(1 << d for d, c in enumerate(dest_iface) if c)

    m_first = [eg[k][0] - first_ns[k] for k in keys if inwin[sid[k]] and k in eg and eg[k][2] & live == live]
    m_last = [eg[k][1] - first_ns[k] for k in keys if inwin[sid[k]] and k in eg and eg[k][2] & live == live]
    print("\nmeasured (copy handed to the NIC driver; excludes its ring)")
    print(f"  last copy   {km.pct(m_last)}")
    print(f"  first copy  {km.pct(m_first)}")

    secs = (t1 - t0) / 1e9
    for gbps in (float(g) for g in a.gbps.split(",")):
        for data_first in (False, True):
            first, last, busy = simulate(shreds, link_of, nlinks, gbps, data_first)
            name = f"{gbps:g} Gb/s links, {'data first' if data_first else 'shred-major'}"
            lat_last = [last[i] - shreds[i][0] for i in range(len(shreds)) if inwin[i] and i in last]
            lat_first = [first[i] - shreds[i][0] for i in range(len(shreds)) if inwin[i] and i in first]
            lat_data = [last[i] - shreds[i][0] for i in range(len(shreds)) if inwin[i] and i in last and shreds[i][2]]
            print(f"\nfloor, {name} (copy fully on the wire; no CPU cost)")
            print(f"  last copy   {km.pct(lat_last)}")
            print(f"  first copy  {km.pct(lat_first)}")
            print(f"  data shreds, last copy  {km.pct(lat_data)}")
            print("  link busy   " + ", ".join(f"{ifaces[l]} {100 * busy[l] / 1e9 / secs:.1f}% on average"
                                           for l in range(nlinks)))


if __name__ == "__main__":
    main()
