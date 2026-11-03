#!/usr/bin/env python3
"""Checks that we can predict which bond port the kernel sends a UDP flow on.

The bonding driver (802.3ad / balance-xor with xmit_hash_policy layer3+4)
picks the port as hash % (ports up), with the hash computed from source and
destination address and port (bond_xmit_hash / bond_ip_hash). The proxy's
--balance-bond relies on the same formula to choose source ports that spread
its destinations evenly. This captures a few seconds of outgoing UDP on each
bond port, predicts the port of every flow seen, and reports how many match.
Read-only (passive capture). Run as root:

  bond-hash-check.py [BOND] [SECONDS]      (default bond0, 3 s per port)
"""
import re
import struct
import subprocess
import sys

BOND = sys.argv[1] if len(sys.argv) > 1 else "bond0"
SECS = sys.argv[2] if len(sys.argv) > 2 else "3"


def l34_hash(src, sport, dst, dport):
    """Linux bond layer3+4 hash for IPv4 UDP on a little-endian host."""
    h = int.from_bytes(struct.pack("!HH", sport, dport), "little")
    h ^= int.from_bytes(bytes(map(int, dst.split("."))), "little")
    h ^= int.from_bytes(bytes(map(int, src.split("."))), "little")
    h ^= h >> 16
    h ^= h >> 8
    return h >> 1


def read(f):
    return open(f"/sys/class/net/{BOND}/bonding/{f}").read().strip()


policy, mode = read("xmit_hash_policy"), read("mode")
ports = [s for s in read("slaves").split()
         if open(f"/sys/class/net/{s}/operstate").read().strip() == "up"]
print(f"{BOND}: mode {mode}, policy {policy}, ports up {ports}")
if not policy.startswith("layer3+4"):
    sys.exit("policy is not layer3+4: the source port does not steer the port choice")

line = re.compile(r" IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): UDP")
flows = {}
for idx, port in enumerate(ports):
    out = subprocess.run(["timeout", SECS, "tcpdump", "-i", port, "-nn", "-Q", "out", "-c", "5000", "udp"],
                         capture_output=True, text=True).stdout
    for m in line.finditer(out):
        flows[(m[1], int(m[2]), m[3], int(m[4]))] = idx

ok = [f for f, idx in flows.items() if l34_hash(*f) % len(ports) == idx]
bad = [f for f in flows if f not in ok]
print(f"{len(flows)} flows seen; predicted port right for {len(ok)}, wrong for {len(bad)}")
for f in bad[:10]:
    print(f"  wrong: {f[0]}:{f[1]} > {f[2]}:{f[3]} seen on {ports[flows[f]]}, "
          f"predicted {ports[l34_hash(*f) % len(ports)]}")
print("RESULT:", "formula matches the kernel" if flows and not bad else "formula does NOT match (do not use --balance-bond)")
