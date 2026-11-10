#!/usr/bin/env python3
"""How the shred sources race each other, per UDP port they arrive on.

Reads an ingress capture (all copies, before the dedup filter drops any:
tcpdump taps the packet before tc ingress) and reports:

  per port      shreds it delivered (% of all unique shreds), how often it
                was first, and how far behind the first copy it was
  A vs B        (--compare A,B) per shred seen on both: A's arrival minus
                B's (negative = A earlier)
  per FEC set   when each port alone has delivered k shreds of a set (k from
                a coding shred's header; any k rebuild the set): which port
                gets there first and by how much, and how much sooner sets
                are complete with A added to B than with B alone (what A is
                worth on top of B)

Capture (on the server, 60 s, headers only):
  sudo timeout 60 tcpdump -i bond0 -nn -s 160 -B 262144 --time-stamp-precision nano \\
      -w /root/pcaps/race.pcap 'udp and (dst port 7733 or dst port 23998)'
Usage:
  source-race.py --compare 7733,23998 /root/pcaps/race.pcap
"""
import argparse
import importlib.util
import os
import struct
from collections import Counter

_spec = importlib.util.spec_from_file_location(
    "kfan_model", os.path.join(os.path.dirname(os.path.abspath(__file__)), "kfan-model.py"))
km = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(km)

HEAD_BYTES = 89  # common header + coding header (num_data_shreds at 83)
SIGNED = (1, 10, 50, 90, 99)


def kth(times, k):
    return sorted(times)[k - 1] if len(times) >= k else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--compare", required=True, help="two ports A,B")
    ap.add_argument("--edge-ms", type=float, default=500, help="ignore shreds/sets this close to the capture's ends")
    a = ap.parse_args()
    pa, pb = (int(p) for p in a.compare.split(","))

    arr = {}  # key -> {port: first ts}
    set_of, k_of, srcs = {}, {}, Counter()
    t0 = t1 = None
    for path in a.pcaps:
        for ts, flow, src, sport, dst, dport, key, head in km.pcap_packets(path, HEAD_BYTES):
            if len(head) < km.KEY_BYTES:
                continue
            per = arr.setdefault(key, {})
            if dport not in per or ts < per[dport]:
                per[dport] = ts
            srcs[(dport, ".".join(map(str, src)), sport)] += 1
            if key not in set_of:
                slot, fec, is_data = km.shred_fields(head)
                set_of[key] = (slot, fec)
                if not is_data and len(head) >= HEAD_BYTES:
                    k_of[(slot, fec)] = struct.unpack_from("<H", head, 83)[0]
            t0 = ts if t0 is None else min(t0, ts)
            t1 = ts if t1 is None else max(t1, ts)
    if not arr:
        raise SystemExit("no shreds in the captures")
    edge = int(a.edge_ms * 1e6)
    lo, hi = t0 + edge, t1 - edge
    keys = [k for k, per in arr.items() if lo <= min(per.values()) <= hi]
    ports = sorted({p for per in arr.values() for p in per})

    print(f"{len(arr)} unique shreds in {(t1 - t0) / 1e9:.1f}s ({len(keys)} away from the edges)")
    print("sources (port <- sender, packets):")
    for (dport, ip, sport), n in sorted(srcs.items(), key=lambda x: -x[1]):
        print(f"  {dport:>6} <- {ip}:{sport:<6} {n}")

    print("\nper port, us behind the first copy of each shred (from any port)")
    for p in ports:
        seen = [k for k in keys if p in arr[k]]
        lag = [arr[k][p] - min(arr[k].values()) for k in seen]
        first = sum(1 for x in lag if x == 0)
        late = [x for x in lag if x > 0]
        print(f"  {p:>6}  delivered {100 * len(seen) / len(keys):5.1f}%  first {100 * first / len(keys):5.1f}%"
              f"  when not first: {km.pct(late)}")

    both = [k for k in keys if pa in arr[k] and pb in arr[k]]
    d = [arr[k][pa] - arr[k][pb] for k in both]
    print(f"\n{pa} minus {pb}, per shred seen on both (negative = {pa} earlier): "
          f"{pa} earlier for {100 * sum(1 for x in d if x < 0) / max(len(d), 1):.1f}%")
    print(f"  {km.pct(d, SIGNED)}")

    sets = {}
    for k in keys:
        sets.setdefault(set_of[k], []).append(k)
    ka, kb, gain_a, gain_b = [], [], [], []
    a_first = b_first = tie = only = 0
    for sk, members in sets.items():
        k = k_of.get(sk)
        if not k:
            continue
        start = min(min(arr[m].values()) for m in members)
        ta = kth([arr[m][pa] for m in members if pa in arr[m]], k)
        tb = kth([arr[m][pb] for m in members if pb in arr[m]], k)
        tu = kth([min(arr[m][p] for p in (pa, pb) if p in arr[m]) for m in members
                  if pa in arr[m] or pb in arr[m]], k)
        if ta is None or tb is None:
            only += 1
        else:
            ka.append(ta - start)
            kb.append(tb - start)
            if ta < tb:
                a_first += 1
            elif tb < ta:
                b_first += 1
            else:
                tie += 1
        if tu is not None and tb is not None:
            gain_a.append(tb - tu)
        if tu is not None and ta is not None:
            gain_b.append(ta - tu)
    n = a_first + b_first + tie
    print(f"\nper FEC set ({n} sets with k shreds from both; {only} complete from only one or neither)")
    print(f"  {pa} has k first for {100 * a_first / max(n, 1):.1f}% of sets, {pb} for {100 * b_first / max(n, 1):.1f}%")
    print(f"  {pa} alone, us to k   {km.pct(ka)}")
    print(f"  {pb} alone, us to k   {km.pct(kb)}")
    print(f"  {pa} added to {pb}: sets complete sooner by  {km.pct(gain_a)}"
          f"  (sooner at all: {100 * sum(1 for x in gain_a if x > 0) / max(len(gain_a), 1):.1f}%)")
    print(f"  {pb} added to {pa}: sets complete sooner by  {km.pct(gain_b)}"
          f"  (sooner at all: {100 * sum(1 for x in gain_b if x > 0) / max(len(gain_b), 1):.1f}%)")


if __name__ == "__main__":
    main()
