#!/usr/bin/env bash
# Measurement only: arrival-time stamps at the NIC driver (fanout/ebpf/xdpstamp.bpf.c)
# for the kernel fan-out's measurement copies. Run as root.
# Needs: clang, iproute2.
#
# Usage:
#   xdpstamp.sh attach PORTS    build for PORTS and load on each member port of DEV,
#                               one at a time. Loading XDP resets that port's queues
#                               for a moment (the bond does not notice): if the kernel
#                               fan-out service is running, its copies are first moved
#                               to the other port (see kfan.sh EXCLUDE), then back.
#   xdpstamp.sh detach          unload (one port at a time, same handling)
#   xdpstamp.sh status          where it is loaded
#
# Then run the kernel fan-out with STAMP_PORT set and the receivers' ip:STAMP_PORT
# in its destinations; their stamp-recv shows mode "kfan-xdp".
# Settings (environment): DEV (bond0)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/../ebpf/xdpstamp.bpf.c"
BUILD="$(cd "$DIR/../.." && pwd)/target/xdpstamp"
OBJ=$BUILD/xdpstamp.bpf.o
DEV=${DEV:-bond0}

ifaces() {
    if [ -e "/sys/class/net/$DEV/bonding/slaves" ]; then
        tr ' ' '\n' <"/sys/class/net/$DEV/bonding/slaves" | grep -v '^$'
    else
        echo "$DEV"
    fi
}

loaded_on() { ip -d link show dev "$1" | grep -q 'prog/xdp'; }

EXCLUDE=/run/fanout-kfan.exclude
# The fan-out service's watch loop re-checks the ports every second.
kfan_running() { systemctl is-active --quiet shred-kfan 2>/dev/null; }

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

build() {
    local ports=$1 defs=() names=(A B C D) i=0 p
    for p in ${ports//,/ }; do
        [[ "$p" =~ ^[0-9]+$ ]] || { echo "bad port: $p" >&2; exit 1; }
        [ $i -lt 4 ] || { echo "at most 4 ports" >&2; exit 1; }
        defs+=("-DPORT_${names[$i]}=$p")
        i=$((i + 1))
    done
    mkdir -p "$BUILD"
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
        "${defs[@]}" -c "$SRC" -o "$OBJ"
}

attach() {
    [ $# -eq 1 ] || { echo "usage: xdpstamp.sh attach PORTS" >&2; exit 1; }
    build "$1"
    local iface
    for iface in $(ifaces); do
        if loaded_on "$iface"; then
            echo "$iface: an XDP program is already loaded; detach it first" >&2
            exit 1
        fi
    done
    for iface in $(ifaces); do
        echo "--- $iface"
        off_port "$iface" ip link set dev "$iface" xdpdrv obj "$OBJ" sec xdp
        echo "  loaded (native)"
    done
    echo "stamping UDP $1 at the driver on: $(ifaces | paste -sd' ')"
}

detach() {
    local iface
    for iface in $(ifaces); do
        loaded_on "$iface" || continue
        echo "--- $iface: unloading"
        off_port "$iface" ip link set dev "$iface" xdpdrv off
    done
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
}

case "${1:-}" in
    attach) shift; attach "$@" ;;
    detach) detach ;;
    status) status ;;
    *) sed -n '2,19p' "$0"; exit 1 ;;
esac
