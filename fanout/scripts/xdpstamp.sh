#!/usr/bin/env bash
# Front end of the kernel fan-out at the NIC driver (fanout/ebpf/xdpstamp.bpf.c):
# arrival-time stamps, and with DEDUP=1 duplicates dropped before the kernel
# builds packet buffers for them. Run as root. Needs: clang, bpftool, iproute2.
#
# Usage:
#   xdpstamp.sh attach PORTS    build for PORTS, load once (maps pinned under PIN) and
#                               attach to each member port of DEV, one at a time;
#                               replaces a program loaded earlier by this script.
#                               Attaching resets that port's queues for a moment (the
#                               bond does not notice): if the kernel fan-out service is
#                               running, its copies are first moved to the other port
#                               (see kfan.sh EXCLUDE), then back.
#   xdpstamp.sh detach          unload (one port at a time, same handling)
#   xdpstamp.sh status          where it is loaded, and its counters
#
# Settings (environment): DEV (bond0), DEDUP (0; 1 = drop duplicates here),
#   PIN (/sys/fs/bpf/xdpstamp)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/../ebpf/xdpstamp.bpf.c"
BUILD="$(cd "$DIR/../.." && pwd)/target/xdpstamp"
OBJ=$BUILD/xdpstamp.bpf.o
DEV=${DEV:-bond0}
DEDUP=${DEDUP:-0}
PIN=${PIN:-/sys/fs/bpf/xdpstamp}

ifaces() {
    if [ -e "/sys/class/net/$DEV/bonding/slaves" ]; then
        tr ' ' '\n' <"/sys/class/net/$DEV/bonding/slaves" | grep -v '^$'
    else
        echo "$DEV"
    fi
}

loaded_on() { ip -d link show dev "$1" | grep -q 'prog/xdp'; }
ours_on() { ip -d link show dev "$1" | grep -q 'prog/xdp .*name xdpstamp'; }

EXCLUDE=/run/fanout-kfan.exclude
# Never leave a port excluded, whatever happens.
trap 'rm -f "$EXCLUDE"' EXIT
# The fan-out service's watch loop re-checks the ports every second.
kfan_running() { systemctl is-active --quiet shred-kfan 2>/dev/null; }

wait_link() { # IFACE: wait until it is up again (and back in the bond)
    local i
    for i in $(seq 1 60); do
        if [ "$(cat "/sys/class/net/$1/operstate" 2>/dev/null)" = up ] &&
            [ "$(cat "/sys/class/net/$1/bonding_slave/mii_status" 2>/dev/null || echo up)" = up ]; then
            return 0
        fi
        sleep 0.5
    done
    echo "WARNING: $1 is not up after 30 s" >&2
    return 1
}

# Moves the fan-out's copies off IFACE while CMD runs on it, then back.
off_port() { # IFACE CMD...
    local iface=$1
    shift
    if kfan_running; then
        echo "$iface" >"$EXCLUDE"
        echo "  kernel fan-out: copies moved off $iface"
        sleep 3
    fi
    "$@"
    echo "  waiting for the link"
    wait_link "$iface" || true
    sleep 2
    if [ -e "$EXCLUDE" ]; then
        rm -f "$EXCLUDE"
        echo "  kernel fan-out: $iface back in use"
        sleep 3
    fi
}

build() {
    local ports=$1 defs=() names=(A B C D) i=0 p
    for p in ${ports//,/ }; do
        [[ "$p" =~ ^[0-9]+$ ]] || { echo "bad port: $p" >&2; exit 1; }
        [ $i -lt 4 ] || { echo "at most 4 ports" >&2; exit 1; }
        defs+=("-DPORT_${names[$i]}=$p")
        i=$((i + 1))
    done
    [[ "$DEDUP" =~ ^[01]$ ]] || { echo "DEDUP must be 0 or 1" >&2; exit 1; }
    mkdir -p "$BUILD"
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
        "${defs[@]}" -DDEDUP="$DEDUP" -c "$SRC" -o "$OBJ"
}

attach() {
    [ $# -eq 1 ] || { echo "usage: xdpstamp.sh attach PORTS" >&2; exit 1; }
    local iface new
    for iface in $(ifaces); do
        if loaded_on "$iface" && ! ours_on "$iface"; then
            echo "$iface: another XDP program is loaded; remove it first" >&2
            exit 1
        fi
    done
    build "$1"
    # The pins need a bpf filesystem (mounted on /sys/fs/bpf normally).
    mkdir -p "$(dirname "$PIN")"
    if [ "$(stat -f -c %T "$(dirname "$PIN")")" != bpf_fs ]; then
        mount -t bpf bpf "$(dirname "$PIN")"
    fi
    # Load once; both ports share the program and its duplicate table.
    new="${PIN}_new" # bpffs does not allow "." in names
    rm -rf "$new"
    mkdir -p "$new"
    bpftool prog loadall "$OBJ" "$new/prog" pinmaps "$new/maps"
    for iface in $(ifaces); do
        echo "--- $iface"
        off_port "$iface" bpftool net attach xdpdrv pinned "$new/prog/xdpstamp" dev "$iface" overwrite
        echo "  attached (native)"
    done
    # The previous program (if any) is no longer attached anywhere.
    rm -rf "$PIN"
    mv "$new" "$PIN"
    echo "stamping UDP $1 at the driver$(if [ "$DEDUP" = 1 ]; then echo ", dropping duplicates"; fi) on: $(ifaces | paste -sd' ')"
}

detach() {
    local iface
    for iface in $(ifaces); do
        loaded_on "$iface" || continue
        echo "--- $iface: unloading"
        off_port "$iface" ip link set dev "$iface" xdpdrv off
    done
    rm -rf "$PIN" "${PIN}_new"
    echo "detached"
}

status() {
    local iface
    for iface in $(ifaces); do
        if loaded_on "$iface"; then
            echo "$iface: $(ip -d link show dev "$iface" | grep -o 'prog/xdp id [0-9]* name [^ ]*' | head -1)"
        else
            echo "$iface: no XDP program"
        fi
    done
    [ -e "$PIN/maps/xdps_stats" ] || return 0
    bpftool -j map dump pinned "$PIN/maps/xdps_stats" | python3 -c '
import json, sys
names = ["stamped", "first copies (dedup)", "duplicates dropped", "too short (left to kfan)",
         "table error (left to kfan)"]
def num(v):
    return v if isinstance(v, int) else int.from_bytes(bytes(int(b, 16) for b in v), "little")
for r in json.load(sys.stdin):
    r = r.get("formatted", r)
    name, total = names[num(r["key"])], sum(num(v["value"]) for v in r["values"])
    print(f"  {name:<28} {total}")
'
}

case "${1:-}" in
    attach) shift; attach "$@" ;;
    detach) detach ;;
    status) status ;;
    *) sed -n '2,18p' "$0"; exit 1 ;;
esac
