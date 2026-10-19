#!/usr/bin/env python3
"""Kernel fan-out latency over a window, from kfan's in-kernel histograms.

Measured from the shred's arrival at the NIC driver (xdpstamp.bpf.c) to the
moment each copy was handed to the outgoing device, for every shred, with no
packet capture running. Needs kfan built with LAT_HIST (see kfan.bpf.c).

Usage: kfan_latency.py [SECONDS] [LABEL] [RESULTS_JSONL]   (run as root)
"""
import ipaddress
import json
import subprocess
import sys
import time

LAT_FINE = 1024          # must match kfan.bpf.c
LAT_BUCKETS = LAT_FINE + 16
STAT_FIRST, STAT_SENT, STAT_LAT_NOXDP = 0, 5, 12


def num(v):
    return v if isinstance(v, int) else int.from_bytes(bytes(int(b, 16) for b in v), "little")


def raw(v):
    return bytes(int(b, 16) for b in v) if isinstance(v, list) else b""


def dump(name):
    out = subprocess.run(["bpftool", "-j", "map", "dump", "name", name], capture_output=True, text=True)
    if out.returncode:
        sys.exit(f"cannot read map {name} (is kfan attached?): {out.stderr.strip()}")
    return json.loads(out.stdout)


def array(name):
    """key -> value; per-CPU values are summed."""
    res = {}
    for r in dump(name):
        k = num(r["key"])
        v = r["value"] if "value" in r else r.get("values")
        if isinstance(v, list) and v and isinstance(v[0], dict):
            res[k] = sum(num(x["value"]) for x in v)
        else:
            res[k] = num(v)
    return res


def dest_labels():
    """Destination index -> ip:port, from the table kfan sends with."""
    entries = {num(r["key"]): raw(r["value"]) for r in dump("kfan_dests")}
    labels = []
    for k in range(16):  # group 0; the list ends at the first empty entry
        b = entries.get(k, b"")
        if len(b) < 28 or int.from_bytes(b[0:4], "little") == 0:
            break
        labels.append(f"{ipaddress.IPv4Address(b[20:24])}:{int.from_bytes(b[24:26], 'big')}")
    return labels


def bucket_us(b):
    return b + 0.5 if b < LAT_FINE else LAT_FINE + (b - LAT_FINE) * 1000 + 500


def summary(counts):
    n = sum(counts)
    if not n:
        return None

    def pct(p):
        rank, acc = max(1, int(p * n + 0.999999)), 0
        for b, c in enumerate(counts):
            acc += c
            if acc >= rank:
                return bucket_us(b)
        return bucket_us(len(counts) - 1)

    top = max(b for b, c in enumerate(counts) if c)
    mean = sum(bucket_us(b) * c for b, c in enumerate(counts)) / n
    return {"count": n, "mean_us": round(mean, 1), "p50_us": pct(.5), "p90_us": pct(.9), "p99_us": pct(.99),
            "p999_us": pct(.999), "max_us": bucket_us(top)}


def line(name, s):
    return (f"  {name:<40} p50 {s['p50_us']:8.1f}  p90 {s['p90_us']:8.1f}  p99 {s['p99_us']:8.1f}  "
            f"p99.9 {s['p999_us']:8.1f}  max {s['max_us']:8.1f}  (n={s['count']})")


def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 10
    label = sys.argv[2] if len(sys.argv) > 2 else "kfan-latency"
    results = sys.argv[3] if len(sys.argv) > 3 else None

    a, sa = array("kfan_lat"), array("kfan_stats")
    if len(a) < 2 * LAT_BUCKETS:
        sys.exit("kfan was built without LAT_HIST: set LAT_HIST=2 (kfan.env or environment) and restart it")
    time.sleep(secs)
    b, sb = array("kfan_lat"), array("kfan_stats")
    labels = dest_labels()

    series = (len(b) // LAT_BUCKETS)
    hist = [[b.get(s * LAT_BUCKETS + i, 0) - a.get(s * LAT_BUCKETS + i, 0) for i in range(LAT_BUCKETS)]
            for s in range(series)]
    first, last = summary(hist[0]), summary(hist[1])
    d_first = sb.get(STAT_FIRST, 0) - sa.get(STAT_FIRST, 0)
    d_sent = sb.get(STAT_SENT, 0) - sa.get(STAT_SENT, 0)
    d_noxdp = sb.get(STAT_LAT_NOXDP, 0) - sa.get(STAT_LAT_NOXDP, 0)
    if not last:
        sys.exit(f"no samples in {secs:.0f}s ({d_first} shreds, {d_noxdp} without a driver-level time: "
                 "is xdpstamp.sh attached?)")

    print(f"NORTH STAR  p99 fan-out completion: {last['p99_us']:.1f} us   "
          "(arrival at the NIC driver -> copy handed to the NIC; no capture)")
    print(line("completion (arrival -> last dest)", last))
    print(line("first dest (arrival -> first dest)", first))
    sent_per = d_sent / d_first if d_first else 0
    print(f"guardrails\n  copies per shred {sent_per:.2f} (table has {len(labels)} destinations), "
          f"{d_noxdp} shreds without a driver-level time (left out)")
    per_dest = {}
    if series > 2:
        print("per destination (send order)")
        for i, name in enumerate(labels[:series - 2]):
            s = summary(hist[2 + i])
            if s:
                per_dest[name] = s
                print(line(name, s))
    if results:
        row = {"label": label, "unix_time": int(time.time()), "source": "kfan-hist",
               "meta": {"source": "kfan-hist", "window_s": str(secs)}, "capture_seconds": secs,
               "eligible_shreds": last["count"], "copies_per_shred": round(sent_per, 3),
               "no_xdp_time": d_noxdp, "completion": last, "first_dest": first, "per_dest": per_dest}
        with open(results, "a") as f:
            f.write(json.dumps(row) + "\n")
        print(f"appended to {results}")


if __name__ == "__main__":
    main()
