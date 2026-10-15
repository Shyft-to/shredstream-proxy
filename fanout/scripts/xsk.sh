#!/usr/bin/env bash
# AF_XDP shred fan-out (fanout/xsk). Run as root.
# Needs: clang, gcc, libbpf-dev, libxdp-dev, xdp-tools, ethtool, bpftool, python3.
#
# Usage:
#   xsk.sh build PORTS          compile the XDP program (for PORTS) and the forwarder
#   xsk.sh setup PORTS          per interface, one at a time: steer UDP PORTS to queue
#                               QUEUE, pin that queue's interrupt, load the XDP program.
#                               Loading XDP briefly pauses traffic on that interface;
#                               the bond keeps the other one carrying traffic.
#   xsk.sh run DESTS [LABEL]    resolve DESTS (ip:port,...) and run the forwarder in the
#                               foreground. Ctrl-C stops it; shreds then go to the normal
#                               stack (the regular forwarders) again.
#   xsk.sh teardown             unload XDP (one interface at a time), remove the steering
#                               rules, restore interrupt affinity, remove pinned maps
#   xsk.sh status               what is set up, and the XDP program's counters
#
# Settings (environment):
#   DEV (bond0)        its member ports are the interfaces (or DEV itself if not a bond)
#   QUEUE (47)         dedicated queue on each interface
#   IRQ_CPUS (29,30)   CPU for each interface's QUEUE interrupt, in interface order
#   FWD_CPU (28)       CPU the forwarder busy-polls on
#   LOCAL_CPU (unset)  if set, local (127.x) destinations are sent by a second
#                      busy-polling thread on this CPU instead of inline
#   MODE (zc)         zc = zero-copy; copy = copy mode (e.g. virtual devices in the lab)
#   STEER (1)          0 = no flow rules (devices without ntuple support)
#   PIN (/sys/fs/bpf/xskfwd)  where the shared maps are pinned; its parent must be
#                      a bpf filesystem. Inside network namespaces (the lab) use one
#                      mounted outside /sys, e.g. /run/xsk-bpf/xskfwd.
#   OUT (./bench-results)  the forwarder appends its own latency results here
set -euo pipefail
# libxdp keeps its own state on a bpf filesystem; point it at ours.
export LIBXDP_BPFFS=${LIBXDP_BPFFS:-$(dirname "${PIN:-/sys/fs/bpf/xskfwd}")}

DIR="$(cd "$(dirname "$0")" && pwd)"
XSK_DIR="$(cd "$DIR/../xsk" && pwd)"
# Not /run: it is mounted noexec on Ubuntu, so the forwarder could not start.
BUILD="$(cd "$DIR/../.." && pwd)/target/xsk"
OBJ=$BUILD/xsk_kern.bpf.o
FWD=$BUILD/xskfwd
PIN=${PIN:-/sys/fs/bpf/xskfwd}
STATE=/run/fanout-xsk.state
DEV=${DEV:-bond0}
QUEUE=${QUEUE:-47}
IRQ_CPUS=${IRQ_CPUS:-29,30}
FWD_CPU=${FWD_CPU:-28}
LOCAL_CPU=${LOCAL_CPU:-}
MODE=${MODE:-zc}
STEER=${STEER:-1}
OUT=${OUT:-./bench-results}

ifaces() {
    if [ -e "/sys/class/net/$DEV/bonding/slaves" ]; then
        tr ' ' '\n' <"/sys/class/net/$DEV/bonding/slaves" | grep -v '^$'
    else
        echo "$DEV"
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
    mkdir -p "$BUILD"
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
        "${defs[@]}" -c "$XSK_DIR/xsk_kern.bpf.c" -o "$OBJ"
    gcc -O2 -g -Wall -pthread -o "$FWD" "$XSK_DIR/xskfwd.c" -lxdp -lbpf -lelf -lz
    echo "built $OBJ (ports $ports) and $FWD"
}

irq_of() { # IFACE QUEUE -> IRQ number of that queue's interrupt, if any
    # No match is normal (virtual devices have no per-queue interrupt).
    { grep -E "[-[:space:]]$1-TxRx-$2\$" /proc/interrupts || true; } | awk -F: '{ gsub(/ /, "", $1); print $1 }' | head -1
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

setup() {
    local ports=$1 k=0 iface p irq old cpus=()
    [ ! -e "$STATE" ] || { echo "already set up ($STATE exists); run teardown first" >&2; exit 1; }
    build "$ports"
    IFS=, read -ra cpus <<<"$IRQ_CPUS"
    local fs
    fs=$(stat -f -c %T "$(dirname "$PIN")" 2>/dev/null || true)
    if [ "$fs" != bpf_fs ]; then
        mkdir -p "$(dirname "$PIN")"
        mount -t bpf bpf "$(dirname "$PIN")"
    fi
    mkdir -p "$PIN"
    : >"$STATE"
    # Any failure from here on undoes everything done so far.
    trap 'echo "setup failed; undoing what was set up" >&2; trap - ERR; teardown' ERR
    for iface in $(ifaces); do
        echo "--- $iface"
        if [ "$STEER" = 1 ]; then
            local out id
            for p in ${ports//,/ }; do
                # Let the driver pick the rule slot (the valid range varies by NIC).
                out=$(ethtool -N "$iface" flow-type udp4 dst-port "$p" action "$QUEUE" 2>&1) ||
                    { echo "  steering rule for UDP $p refused: $out" >&2; false; }
                id=$(grep -oP 'ID \K[0-9]+' <<<"$out" || true)
                [ -n "$id" ] || { echo "  steering rule for UDP $p: no rule ID in: $out" >&2; false; }
                echo "rule $iface $id" >>"$STATE"
            done
            echo "  UDP ports $ports -> queue $QUEUE"
        fi
        irq=$(irq_of "$iface" "$QUEUE")
        if [ -n "$irq" ] && [ -n "${cpus[$k]:-}" ]; then
            old=$(cat "/proc/irq/$irq/smp_affinity_list")
            echo "irq $irq $old" >>"$STATE"
            echo "${cpus[$k]}" >"/proc/irq/$irq/smp_affinity_list"
            echo "  queue $QUEUE interrupt (irq $irq) -> cpu ${cpus[$k]} (was $old)"
        fi
        echo "xdp $iface" >>"$STATE"
        xdp-loader load -m native -p "$PIN" "$iface" "$OBJ"
        echo "  XDP program loaded; waiting for the link"
        wait_link "$iface" || true
        sleep 2
        k=$((k + 1))
    done
    trap - ERR
    echo "setup done; start the forwarder with: xsk.sh run DESTS"
}

teardown() {
    [ -e "$STATE" ] || { echo "nothing set up"; return 0; }
    local kind a b
    # Unload XDP first (one interface at a time), then rules, then interrupts.
    while read -r kind a b; do
        [ "$kind" = xdp ] || continue
        echo "--- $a: unloading XDP"
        xdp-loader unload "$a" --all || true
        wait_link "$a" || true
        sleep 2
    done <"$STATE"
    while read -r kind a b; do
        case "$kind" in
            rule) ethtool -N "$a" delete "$b" 2>/dev/null || true ;;
            irq) echo "$b" >"/proc/irq/$a/smp_affinity_list" 2>/dev/null || true ;;
        esac
    done <"$STATE"
    rm -rf "$PIN" "$STATE"
    echo "torn down: XDP unloaded, steering removed, interrupt affinity restored"
}

# Active member ports of a bond (in the active 802.3ad aggregator, link up),
# or the device itself.
ports_of() {
    local dev=$1 agg s
    if [ ! -e "/sys/class/net/$dev/bonding/slaves" ]; then
        echo "$dev"
        return
    fi
    agg=$(cat "/sys/class/net/$dev/bonding/ad_aggregator" 2>/dev/null || true)
    for s in $(cat "/sys/class/net/$dev/bonding/slaves"); do
        [ "$(cat "/sys/class/net/$s/operstate")" = up ] || continue
        [ "$(cat "/sys/class/net/$s/bonding_slave/mii_status" 2>/dev/null || echo up)" = up ] || continue
        if [ -n "$agg" ] && [ -e "/sys/class/net/$s/bonding_slave/ad_aggregator_id" ]; then
            [ "$(cat "/sys/class/net/$s/bonding_slave/ad_aggregator_id")" = "$agg" ] || continue
        fi
        echo "$s"
    done
}

# One line of the forwarder's destination file for ip:port, spreading
# destinations over the active ports by index $2.
resolve() {
    local ip=${1%:*} port=${1#*:} n=$2 route dev src via nh mac out vlan=0 ports smac
    if [[ "$ip" == 127.* ]]; then
        echo "local $ip $port"
        echo "  $1 -> local UDP socket" >&2
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
    smac=$(cat "/sys/class/net/$dev/address")
    out=$dev
    if [ -e "/proc/net/vlan/$dev" ]; then
        vlan=$(awk '/VID:/ { print $3 }' "/proc/net/vlan/$dev")
        out=$(awk '/^Device:/ { print $2 }' "/proc/net/vlan/$dev")
    fi
    mapfile -t ports < <(ports_of "$out")
    [ ${#ports[@]} -gt 0 ] || { echo "no active port under $out" >&2; return 1; }
    out=${ports[$((n % ${#ports[@]}))]}
    echo "$out $mac $smac $src $ip $port $vlan"
    echo "  $1 -> $out$(if [ "$vlan" != 0 ]; then echo " (VLAN $vlan)"; fi), next hop $nh ($mac), from $src" >&2
}

run() {
    local dests=() d j=0 file=$BUILD/dests label=${2:-xskfwd}
    [ -e "$STATE" ] || { echo "not set up; run: xsk.sh setup PORTS" >&2; exit 1; }
    IFS=, read -ra dests <<<"$1"
    : >"$file"
    for d in "${dests[@]}"; do
        resolve "$d" "$j" >>"$file"
        j=$((j + 1))
    done
    mkdir -p "$OUT"
    local rx
    rx=$(ifaces | paste -sd,)
    exec "$FWD" --rx "$rx" --queue "$QUEUE" --dests "$file" --pin "$PIN" --cpu "$FWD_CPU" \
        $(if [ "$MODE" = copy ]; then echo --copy; fi) \
        $(if [ -n "$LOCAL_CPU" ]; then echo --local-cpu "$LOCAL_CPU"; fi) --label "$label" \
        --results "$OUT/xsk-results.jsonl"
}

status() {
    if [ ! -e "$STATE" ]; then
        echo "not set up"
        return
    fi
    echo "set up:"
    sed 's/^/  /' "$STATE"
    xdp-loader status 2>/dev/null | grep -E "$(ifaces | paste -sd'|')" || true
    bpftool -j map dump pinned "$PIN/xsk_stats" 2>/dev/null | python3 -c '
import json, sys
names = ["first copies", "duplicates (dropped)", "to forwarder", "to normal stack",
         "too short (passed)", "dedup error (passed)", "no arrival stamp"]
def num(v):
    return v if isinstance(v, int) else int.from_bytes(bytes(int(b, 16) for b in v), "little")
rows = json.load(sys.stdin)
if not isinstance(rows, list):
    sys.exit("  (no counters yet: " + str(rows.get("error", rows)) + ")")
for r in rows:
    r = r.get("formatted", r)
    name = names[num(r["key"])]
    total = sum(num(v["value"]) for v in r["values"])
    print(f"  {name:<22} {total}")
' || echo "  (no counters)"
}

case "${1:-}" in
    build) shift; build "$@" ;;
    setup) shift; setup "$@" ;;
    run) shift; run "$@" ;;
    teardown) teardown ;;
    status) status ;;
    *) sed -n '2,28p' "$0"; exit 1 ;;
esac
