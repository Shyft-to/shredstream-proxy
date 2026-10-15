#!/usr/bin/env bash
# Kernel shred fan-out (fanout/ebpf/kfan.bpf.c) on tc ingress. Run as root.
# Needs: clang, llvm, libbpf-dev, bpftool, tc, python3.
#
# Usage:
#   kfan.sh attach PORTS DESTS   build for PORTS, attach, load DESTS (ip:port,...)
#   kfan.sh refresh DESTS        re-resolve next-hop MACs and reload the table
#   kfan.sh detach               remove it; the forwarders take over instantly
#   kfan.sh status               attached or not, and the counters
#   kfan.sh cost [SECONDS]       measured kernel CPU time per packet (default 10 s)
#
# Shares tc priority 7700 with dedup.sh: only one of the two can be attached.
# Settings (environment): DEV (bond0), DROP_PORTS (up to 2, comma separated:
#   UDP to these ports is dropped, e.g. to switch a source off)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/../ebpf/kfan.bpf.c"
OBJ=/run/fanout-kfan.bpf.o
DEV=${DEV:-bond0}
PREF=7700
MAX_DESTS=32

attached() { tc filter show dev "$DEV" ingress 2>/dev/null | grep -q "pref $PREF "; }
ours() { tc filter show dev "$DEV" ingress 2>/dev/null | grep -A1 "pref $PREF " | grep -q kfan; }

build() {
    local ports=$1 defs=() names=(A B C D) i=0 p
    for p in ${ports//,/ }; do
        [[ "$p" =~ ^[0-9]+$ ]] || { echo "bad port: $p" >&2; exit 1; }
        [ $i -lt 4 ] || { echo "at most 4 ports" >&2; exit 1; }
        defs+=("-DPORT_${names[$i]}=$p")
        i=$((i + 1))
    done
    i=0
    for p in ${DROP_PORTS//,/ }; do
        [[ "$p" =~ ^[0-9]+$ ]] || { echo "bad drop port: $p" >&2; exit 1; }
        [ $i -lt 2 ] || { echo "at most 2 drop ports" >&2; exit 1; }
        defs+=("-DDROP_${names[$i]}=$p")
        i=$((i + 1))
    done
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
        "${defs[@]}" -c "$SRC" -o "$OBJ"
}

hex_le32() { printf '%02x %02x %02x %02x' $(($1 & 255)) $(($1 >> 8 & 255)) $(($1 >> 16 & 255)) $(($1 >> 24 & 255)); }
hex_ip() { local IFS=.; set -- $1; printf '%02x %02x %02x %02x' "$1" "$2" "$3" "$4"; }
hex_mac() { tr ':' ' ' <<<"$1"; }
hex_be16() { printf '%02x %02x' $(($1 >> 8 & 255)) $(($1 & 255)); }

# Prints the 28-byte table entry (hex) for one ip:port destination.
resolve() {
    local ip=${1%:*} port=${1#*:} route dev src via nh mac ifindex smac
    if [[ "$ip" == 127.* ]]; then
        ifindex=$(cat /sys/class/net/lo/ifindex)
        echo "$(hex_le32 "$ifindex") 00 00 00 00 00 00 00 00 00 00 00 00 $(hex_ip "$ip") $(hex_ip "$ip") $(hex_be16 "$port") 00 00"
        echo "  $1 -> dev lo (local delivery), from $ip" >&2
        return
    fi
    route=$(ip -o route get "$ip")
    dev=$(grep -oP ' dev \K\S+' <<<"$route")
    src=$(grep -oP ' src \K\S+' <<<"$route")
    via=$(grep -oP ' via \K\S+' <<<"$route" || true)
    nh=${via:-$ip}
    ping -c1 -W1 -q "$nh" >/dev/null 2>&1 || true
    mac=$(ip neigh show to "$nh" dev "$dev" | grep -oP 'lladdr \K\S+' || true)
    [ -n "$mac" ] || { echo "no MAC for next hop $nh of $1 (dev $dev)" >&2; return 1; }
    ifindex=$(cat "/sys/class/net/$dev/ifindex")
    smac=$(cat "/sys/class/net/$dev/address")
    echo "$(hex_le32 "$ifindex") $(hex_mac "$mac") $(hex_mac "$smac") $(hex_ip "$src") $(hex_ip "$ip") $(hex_be16 "$port") 00 00"
    echo "  $1 -> dev $dev, next hop $nh ($mac), from $src" >&2
}

# Resolves everything first, then writes entries 1..n-1, terminator n, and
# entry 0 last: until entry 0 is set the program passes all traffic on.
load_dests() {
    local dests=() entries=() d i
    IFS=, read -ra dests <<<"$1"
    [ ${#dests[@]} -ge 1 ] && [ ${#dests[@]} -lt $MAX_DESTS ] || { echo "need 1..$((MAX_DESTS - 1)) destinations" >&2; return 1; }
    for d in "${dests[@]}"; do entries+=("$(resolve "$d")") || return 1; done
    for ((i = 1; i < ${#entries[@]}; i++)); do
        bpftool map update name kfan_dests key hex $(hex_le32 $i) value hex ${entries[$i]}
    done
    bpftool map update name kfan_dests key hex $(hex_le32 ${#entries[@]}) value hex $(printf '00 %.0s' $(seq 28))
    bpftool map update name kfan_dests key hex $(hex_le32 0) value hex ${entries[0]}
    echo "loaded ${#entries[@]} destinations"
}

attach() {
    [ $# -eq 2 ] || { echo "usage: kfan.sh attach PORTS DESTS" >&2; exit 1; }
    attached && { echo "a filter is already attached on $DEV (pref $PREF); detach it first" >&2; exit 1; }
    build "$1"
    tc qdisc show dev "$DEV" | grep -q clsact || tc qdisc add dev "$DEV" clsact
    tc filter add dev "$DEV" ingress pref "$PREF" handle 1 bpf direct-action obj "$OBJ" sec tc
    echo "attached on $DEV ingress for ports $1${DROP_PORTS:+, dropping $DROP_PORTS} (passing everything until destinations load)"
    if ! load_dests "$2"; then
        echo "destination load failed; detaching" >&2
        detach
        exit 1
    fi
}

refresh() {
    ours || { echo "kfan is not attached" >&2; exit 1; }
    load_dests "$1"
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
    bpftool -j map dump name kfan_stats 2>/dev/null | python3 -c '
import json, sys
names = ["first copies", "duplicates (dropped)", "too short (passed)", "dedup error (passed)",
         "no destinations (passed)", "copies sent", "copies refused", "ignored port (dropped)"]
def num(v):
    return v if isinstance(v, int) else int.from_bytes(bytes(int(b, 16) for b in v), "little")
try:
    rows = json.load(sys.stdin)
except ValueError:
    sys.exit("no counters (not attached?)")
for r in rows:
    r = r.get("formatted", r)
    total = sum(num(v["value"]) for v in r["values"])
    name = names[num(r["key"])]
    print(f"  {name:<26} {total}")
'
}

status() {
    if ours; then
        echo "kfan attached on $DEV ingress (pref $PREF)"
        counters
    elif attached; then
        echo "another filter (dedup?) is attached on $DEV at pref $PREF"
    else
        echo "not attached"
    fi
}

cost() {
    local secs=${1:-10} prev t0 c0 t1 c1
    ours || { echo "kfan is not attached" >&2; exit 1; }
    prev=$(sysctl -n kernel.bpf_stats_enabled)
    sysctl -qw kernel.bpf_stats_enabled=1
    read_stats() { bpftool -j prog show name kfan | python3 -c '
import json, sys
p = json.load(sys.stdin)
p = p[0] if isinstance(p, list) else p
print(p.get("run_time_ns", 0), p.get("run_cnt", 0))'; }
    read -r t0 c0 < <(read_stats)
    sleep "$secs"
    read -r t1 c1 < <(read_stats)
    sysctl -qw kernel.bpf_stats_enabled="$prev"
    python3 -c "
runs = $c1 - $c0
ns = $t1 - $t0
print(f'{runs} packets in ${secs}s, {ns / max(runs, 1):.0f} ns of kernel CPU per packet on average, {ns / 1e9 / $secs * 100:.2f}% of one core in total')"
}

case "${1:-}" in
    attach) shift; attach "$@" ;;
    refresh) shift; refresh "$@" ;;
    detach) detach ;;
    status) status ;;
    cost) shift; cost "$@" ;;
    *) sed -n '2,15p' "$0"; exit 1 ;;
esac
