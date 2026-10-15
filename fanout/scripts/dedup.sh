#!/usr/bin/env bash
# Kernel cross-source shred dedup (fanout/ebpf/dedup.bpf.c) on tc ingress.
# Run as root. Needs: clang, llvm, libbpf-dev, bpftool, tc.
#
# Usage:
#   dedup.sh attach PORTS     build for PORTS (comma separated, up to 4) and attach
#   dedup.sh detach           remove the filter (instant, no restart of anything)
#   dedup.sh status           attached or not, and the counters
#   dedup.sh cost [SECONDS]   measured kernel CPU time per packet (default 10 s)
#
# Settings (environment): DEV (bond0)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/../ebpf/dedup.bpf.c"
OBJ=/run/fanout-dedup.bpf.o
DEV=${DEV:-bond0}
PREF=7700 # tc filter priority that identifies our filter

attached() { tc filter show dev "$DEV" ingress 2>/dev/null | grep -q "pref $PREF "; }

build() {
    local ports=$1 defs=() names=(A B C D) i=0 p
    for p in ${ports//,/ }; do
        [[ "$p" =~ ^[0-9]+$ ]] || { echo "bad port: $p" >&2; exit 1; }
        [ $i -lt 4 ] || { echo "at most 4 ports" >&2; exit 1; }
        defs+=("-DPORT_${names[$i]}=$p")
        i=$((i + 1))
    done
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
        "${defs[@]}" -c "$SRC" -o "$OBJ"
}

attach() {
    [ $# -eq 1 ] || { echo "usage: dedup.sh attach PORTS" >&2; exit 1; }
    attached && { echo "already attached on $DEV; detach first" >&2; exit 1; }
    build "$1"
    # clsact only adds ingress/egress hooks; it does not replace the root qdisc.
    tc qdisc show dev "$DEV" | grep -q clsact || tc qdisc add dev "$DEV" clsact
    tc filter add dev "$DEV" ingress pref "$PREF" handle 1 bpf direct-action obj "$OBJ" sec tc
    echo "attached on $DEV ingress for ports $1"
}

detach() {
    if attached; then
        tc filter del dev "$DEV" ingress pref "$PREF"
        echo "detached from $DEV"
    else
        echo "not attached"
    fi
}

counters() {
    bpftool -j map dump name dedup_stats 2>/dev/null | python3 -c '
import json, sys
names = ["first (passed)", "duplicate (dropped)", "too short (passed)", "error (passed)"]
def num(v):  # bpftool prints either a number or little-endian hex bytes
    return v if isinstance(v, int) else int.from_bytes(bytes(int(b, 16) for b in v), "little")
try:
    rows = json.load(sys.stdin)
except ValueError:
    sys.exit("no counters (filter not attached?)")
for r in rows:
    r = r.get("formatted", r)
    total = sum(num(v["value"]) for v in r["values"])
    name = names[num(r["key"])]
    print(f"  {name:<22} {total}")
'
}

status() {
    if attached; then
        echo "attached on $DEV ingress (pref $PREF)"
        counters
    else
        echo "not attached"
    fi
}

cost() {
    local secs=${1:-10} prev
    attached || { echo "not attached" >&2; exit 1; }
    prev=$(sysctl -n kernel.bpf_stats_enabled)
    sysctl -qw kernel.bpf_stats_enabled=1
    read_stats() { bpftool -j prog show name dedup | python3 -c '
import json, sys
p = json.load(sys.stdin)
p = p[0] if isinstance(p, list) else p
print(p.get("run_time_ns", 0), p.get("run_cnt", 0))'; }
    local t0 c0 t1 c1
    read -r t0 c0 < <(read_stats)
    sleep "$secs"
    read -r t1 c1 < <(read_stats)
    sysctl -qw kernel.bpf_stats_enabled="$prev"
    python3 -c "
runs = $c1 - $c0
ns = $t1 - $t0
print(f'{runs} packets in ${secs}s, {ns / max(runs, 1):.0f} ns of kernel CPU per packet ({ns / 1e9 / $secs * 100:.3f}% of one core)')"
}

case "${1:-}" in
    attach) shift; attach "$@" ;;
    detach) detach ;;
    status) status ;;
    cost) shift; cost "$@" ;;
    *) sed -n '2,11p' "$0"; exit 1 ;;
esac
