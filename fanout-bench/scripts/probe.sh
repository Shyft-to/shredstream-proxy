#!/usr/bin/env bash
# Production side of the fan-out bench. Passive: it only captures packets and
# reads /proc; the running forwarders are not touched. Run as root.
#
# Usage:
#   probe.sh measure PORT [SECONDS] [LABEL]   north star for the live instance listening on PORT
#   probe.sh corpus PORT [SECONDS] [FILE]     record full ingress packets to replay in the test bed
#
# Settings (environment):
#   IN_IF    interface that carries ingress and network egress  (bond0)
#   OUT      results directory                                   (./bench-results)
#   CAP_DIR  where captures are written (RAM by default)         (/dev/shm)
#   KEEP_PCAP=1  keep the capture
set -euo pipefail

BIN=${BIN:-"$(cd "$(dirname "$0")/../.." && pwd)/target/release"}
IN_IF=${IN_IF:-bond0}
OUT=${OUT:-./bench-results}
CAP_DIR=${CAP_DIR:-/dev/shm}

cpu_ms() {
    awk -v hz="$(getconf CLK_TCK)" '{ sub(/^.*\) /, ""); print int(($12 + $13) * 1000 / hz) }' "/proc/$1/stat"
}

nstat_line() {
    nstat -z 2>/dev/null | awk '/UdpRcvbufErrors|UdpSndbufErrors|UdpInErrors/ { printf "%s=%s ", $1, $2 }'
}

measure() {
    local port=$1 secs=${2:-10} label=${3:-prod-$1}
    local pid
    pid=$(ss -ulnpH "sport = :$port" | grep -oP 'pid=\K[0-9]+' | head -1)
    [ -n "$pid" ] || { echo "nothing is listening on UDP port $port" >&2; exit 1; }

    # The instance's own sending sockets: every UDP port it owns except the listen port.
    local src_ports
    src_ports=$(ss -uanpH | grep "pid=$pid," | awk '{ print $4 }' | sed 's/.*://' | sort -un | grep -vx "$port" | paste -sd,)
    [ -n "$src_ports" ] || { echo "pid $pid has no sending sockets" >&2; exit 1; }

    # Destinations from the instance's command line.
    local dests
    dests=$(tr '\0' '\n' <"/proc/$pid/cmdline" |
        awk -F= 'f { print; exit } $1 == "--dest-ip-ports" { if (NF > 1) { print $2; exit } f = 1 }')
    [ -n "$dests" ] || { echo "could not read --dest-ip-ports for pid $pid" >&2; exit 1; }

    local filter="udp and (dst port $port"
    local p
    for p in ${src_ports//,/ }; do filter+=" or src port $p"; done
    filter+=")"

    mkdir -p "$OUT"
    local stamp net_pcap lo_pcap
    stamp=$(date +%Y%m%d-%H%M%S)
    net_pcap="$CAP_DIR/probe-$port-$stamp-net.pcap"
    lo_pcap="$CAP_DIR/probe-$port-$stamp-lo.pcap"
    echo "pid $pid, $(echo "$dests" | tr ',' '\n' | wc -l) destinations, $(echo "$src_ports" | tr ',' '\n' | wc -l) sending sockets, ${secs}s capture"

    # One capture per interface instead of "any": with "any" every private send
    # is seen three times (VLAN device, bond, slave), tripling the volume.
    # The bond sees ingress plus all network egress; loopback sees local consumers.
    nstat -n
    local c0
    c0=$(cpu_ms "$pid")
    timeout --signal=INT "$secs" tcpdump -i "$IN_IF" -nn -s 160 -B 262144 --time-stamp-precision nano \
        -w "$net_pcap" "$filter" 2>"$net_pcap.log" &
    local t1=$!
    timeout --signal=INT "$secs" tcpdump -i lo -nn -s 160 -B 65536 --time-stamp-precision nano \
        -w "$lo_pcap" "$filter" 2>"$lo_pcap.log" &
    local t2=$!
    wait "$t1" "$t2" || true
    local c1 drops
    c1=$(cpu_ms "$pid")
    drops=$(nstat_line)

    local d1 d2
    d1=$(grep -oP '\d+(?= packets dropped by kernel)' "$net_pcap.log" || echo unknown)
    d2=$(grep -oP '\d+(?= packets dropped by kernel)' "$lo_pcap.log" || echo unknown)
    local dropped=$d1
    [ "$d1" = "0" ] && [ "$d2" = "0" ] || dropped="$d1+$d2"
    [ "$dropped" = "0" ] || echo "WARNING: tcpdump dropped packets ($dropped); treat this result with caution" >&2
    echo "kernel UDP errors during capture: ${drops:-none}"

    "$BIN/fanout-measure" analyze --pcap "$net_pcap" --pcap "$lo_pcap" --listen-port "$port" \
        --dests "$dests" --egress-src-ports "$src_ports" --label "$label" \
        --results "$OUT/prod-results.jsonl" --cpu-ms "$((c1 - c0))" \
        --meta "source=production" --meta "pid=$pid" --meta "tcpdump_dropped=$dropped" \
        --meta "kernel_udp_errors=${drops:-none}"

    if [ "${KEEP_PCAP:-0}" = "1" ]; then
        echo "captures kept: $net_pcap $lo_pcap"
    else
        rm -f "$net_pcap" "$lo_pcap"
    fi
    rm -f "$net_pcap.log" "$lo_pcap.log"
}

corpus() {
    local port=$1 secs=${2:-30} file=${3:-./corpus.pcap}
    echo "recording ${secs}s of ingress to UDP port $port on $IN_IF into $file"
    timeout --signal=INT "$secs" tcpdump -i "$IN_IF" -nn -s 0 -B 262144 --time-stamp-precision nano \
        -w "$file" "udp and dst port $port" || true
    ls -lh "$file"
}

case "${1:-}" in
    measure) shift; measure "$@" ;;
    corpus) shift; corpus "$@" ;;
    *) sed -n '2,13p' "$0"; exit 1 ;;
esac
