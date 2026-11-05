#!/usr/bin/env python3
"""When one destination can rebuild each FEC set, and how much of that is the box.

A Merkle FEC set of k data and m coding shreds can be rebuilt from ANY k of
its shreds, data or coding (k from a coding shred's header). So the moment a
node can decode a set is when it holds k distinct shreds of it, not when the
last data shred arrives. Per FEC set, from the captures of one
`probe.sh box` run (KEEP_PCAP=1):

  arrived      first shred of the set reaches the box -> the box holds k of
               its shreds (the sources' spread; no forwarder can beat it)
  ready        first shred reaches the box -> k distinct shreds of it have
               left for --focus (decodable at the destination, minus the
               network to it)
  box adds     ready - arrived: the forwarding's share, per set
  all data     first shred reaches the box -> the set's last data shred has
               left for --focus (the old, stricter target, for comparison)

"Left" is the capture's egress stamp (handed to the NIC driver); time in the
NIC's ring after that is not seen. Sets whose start is within --edge-ms of
the capture's ends, or with no coding shred seen (k unknown), are skipped.

Usage (on the server; captures from KEEP_PCAP=1 probe.sh box):
  fec-ready.py --ports 23998,23999 --focus 10.182.192.76:8002 /root/pcaps/df-on/box-*.pcap
"""
import argparse
import importlib.util
import ipaddress
import os
import struct

_spec = importlib.util.spec_from_file_location(
    "kfan_model", os.path.join(os.path.dirname(os.path.abspath(__file__)), "kfan-model.py"))
km = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(km)

# Common header (83) + coding header: num_data_shreds u16, num_coding_shreds u16, position u16.
HEAD_BYTES = 89


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--ports", required=True, help="source ports, comma separated")
    ap.add_argument("--focus", required=True, help="destination, ip:port")
    ap.add_argument("--edge-ms", type=float, default=500, help="ignore sets starting this close to the capture's ends")
    a = ap.parse_args()

    ports = {int(p) for p in a.ports.split(",")}
    fip, fport = a.focus.rsplit(":", 1)
    focus = (ipaddress.IPv4Address(fip).packed, int(fport))

    arrive, out, set_of, k_of = {}, {}, {}, {}
    t0 = t1 = None
    for path in a.pcaps:
        for ts, _, _, _, dst, dport, key, head in km.pcap_packets(path, HEAD_BYTES):
            if dport in ports and len(head) >= km.KEY_BYTES:
                if key not in arrive or ts < arrive[key]:
                    arrive[key] = ts
                if key not in set_of:
                    slot, fec, is_data = km.shred_fields(head)
                    set_of[key] = (slot, fec, is_data)
                    if not is_data and len(head) >= HEAD_BYTES:
                        k_of[(slot, fec)] = struct.unpack_from("<H", head, 83)[0]
                t0 = ts if t0 is None else min(t0, ts)
                t1 = ts if t1 is None else max(t1, ts)
            elif (dst, dport) == focus:
                if key not in out or ts < out[key]:
                    out[key] = ts
    if not arrive:
        raise SystemExit("no packets to --ports in the captures")
    if not out:
        raise SystemExit(f"no packets to {a.focus} in the captures")

    sets = {}
    for key, (slot, fec, is_data) in set_of.items():
        sets.setdefault((slot, fec), []).append((key, is_data))

    edge = int(a.edge_ms * 1e6)
    arrived, ready, adds, all_data = [], [], [], []
    no_k = short_in = short_out = 0
    for sk, members in sets.items():
        start = min(arrive[key] for key, _ in members)
        if not (t0 + edge <= start <= t1 - edge):
            continue
        k = k_of.get(sk)
        if not k:
            no_k += 1
            continue
        ins = sorted(arrive[key] for key, _ in members)
        if len(ins) < k:
            short_in += 1
            continue
        outs = sorted(out[key] for key, _ in members if key in out)
        if len(outs) < k:
            short_out += 1
            continue
        arrived.append(ins[k - 1] - start)
        ready.append(outs[k - 1] - start)
        adds.append(outs[k - 1] - ins[k - 1])
        data = [out.get(key) for key, is_data in members if is_data]
        if len(data) == k and None not in data:
            all_data.append(max(data) - start)

    print(f"{len(arrive)} shreds, {len(sets)} FEC sets in {(t1 - t0) / 1e9:.1f}s; focus {a.focus}")
    print(f"sets measured {len(ready)}; skipped: no coding shred seen {no_k}, "
          f"fewer than k reached the box {short_in}, fewer than k left for focus {short_out}")
    print("\nper FEC set, us from the set's first shred reaching the box")
    print(f"  arrived   (box holds k)         {km.pct(arrived)}")
    print(f"  ready     (k left for focus)    {km.pct(ready)}")
    print(f"  box adds  (ready - arrived)     {km.pct(adds)}")
    print(f"  all data  (last data shred out) {km.pct(all_data)}")


if __name__ == "__main__":
    main()
