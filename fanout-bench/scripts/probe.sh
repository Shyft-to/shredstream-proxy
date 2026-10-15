#!/usr/bin/env bash
# Production side of the fan-out bench. Passive: it only captures packets and
# reads /proc; the running forwarders are not touched. Run as root.
#
# Usage:
#   probe.sh measure PORT [SECONDS] [LABEL]   north star for the live instance listening on PORT
#   probe.sh box PORTS [SECONDS] [LABEL]      box-level north star across the forwarders on PORTS
#                                             (comma separated); results in box-results.jsonl
#   probe.sh corpus PORT [SECONDS] [FILE]     record full ingress packets to replay in the test bed
#
# Settings (environment):
#   IN_IF    interface that carries ingress and network egress  (bond0)
#   OUT      results directory: prod-results.jsonl (one JSON line   (./bench-results)
#            per run) and LABEL-TIMESTAMP.txt (printed report) 
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

# Per thread: "tid comm run-queue-wait-ns" (time ready to run but not on a CPU).
sched_snapshot() {
    local t
    for t in /proc/"$1"/task/*; do
        printf '%s %s %s\n' "${t##*/}" "$(tr ' ' '_' <"$t/comm" 2>/dev/null)" "$(awk '{ print $2 }' "$t/schedstat" 2>/dev/null)"
    done
}

# Total run-queue wait (ms) of all threads between two snapshots.
runq_total_ms() {
    awk 'NR == FNR { w[$1] = $3; next } ($1 in w) { s += ($3 - w[$1]) / 1e6 } END { printf "%.1f", s }' "$1" "$2"
}

# Prints the threads that waited longest for a CPU between two snapshots.
sched_report() {
    local before=$1 after=$2 secs=$3
    echo "waiting for a CPU during capture: $(runq_total_ms "$before" "$after") ms over all threads; longest:"
    awk 'NR == FNR { w[$1] = $3; next } ($1 in w) { print ($3 - w[$1]) / 1e6, $2, $1 }' "$before" "$after" |
        sort -rn | head -5 |
        awk -v secs="$secs" '{ printf "  %-16s tid %-7s %8.1f ms  (%.2f%% of the capture)\n", $2, $3, $1, $1 / (secs * 10) }'
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
    local c0 sched_before sched_after
    c0=$(cpu_ms "$pid")
    sched_before=$(mktemp)
    sched_after=$(mktemp)
    sched_snapshot "$pid" >"$sched_before"
    timeout --signal=INT "$secs" tcpdump -i "$IN_IF" -nn -s 160 -B 262144 --time-stamp-precision nano \
        -w "$net_pcap" "$filter" 2>"$net_pcap.log" &
    local t1=$!
    timeout --signal=INT "$secs" tcpdump -i lo -nn -s 160 -B 65536 --time-stamp-precision nano \
        -w "$lo_pcap" "$filter" 2>"$lo_pcap.log" &
    local t2=$!
    wait "$t1" "$t2" || true
    local c1 drops
    c1=$(cpu_ms "$pid")
    sched_snapshot "$pid" >"$sched_after"
    drops=$(nstat_line)

    local d1 d2
    d1=$(grep -oP '\d+(?= packets dropped by kernel)' "$net_pcap.log" || echo unknown)
    d2=$(grep -oP '\d+(?= packets dropped by kernel)' "$lo_pcap.log" || echo unknown)
    local dropped=$d1
    [ "$d1" = "0" ] && [ "$d2" = "0" ] || dropped="$d1+$d2"
    [ "$dropped" = "0" ] || echo "WARNING: tcpdump dropped packets ($dropped); treat this result with caution" >&2
    echo "kernel UDP errors during capture: ${drops:-none}"
    local runq_ms
    runq_ms=$(runq_total_ms "$sched_before" "$sched_after")
    sched_report "$sched_before" "$sched_after" "$secs" | tee "$OUT/$label-$stamp-sched.txt"
    rm -f "$sched_before" "$sched_after"

    "$BIN/fanout-measure" analyze --pcap "$net_pcap" --pcap "$lo_pcap" --listen-port "$port" \
        --dests "$dests" --egress-src-ports "$src_ports" --label "$label" \
        --results "$OUT/prod-results.jsonl" --cpu-ms "$((c1 - c0))" \
        --meta "source=production" --meta "pid=$pid" --meta "tcpdump_dropped=$dropped" \
        --meta "kernel_udp_errors=${drops:-none}" --meta "runq_wait_ms=$runq_ms" |
        tee "$OUT/$label-$stamp.txt"

    if [ "${KEEP_PCAP:-0}" = "1" ]; then
        echo "captures kept: $net_pcap $lo_pcap"
    else
        rm -f "$net_pcap" "$lo_pcap"
    fi
    rm -f "$net_pcap.log" "$lo_pcap.log"
}

# Box-level north star across several forwarders: a shred's arrival is its
# first arrival on any of the ports; each destination's time is the first copy
# any of the forwarders sends it.
box() {
    local ports=$1 secs=${2:-10} label=${3:-box}
    local port_re pids=() src_ports="" all_dests="" first_dests="" p pid d
    port_re="^($(tr ',' '|' <<<"$ports"))\$"
    for p in ${ports//,/ }; do
        pid=$(ss -ulnpH "sport = :$p" | grep -oP 'pid=\K[0-9]+' | head -1)
        [ -n "$pid" ] || { echo "nothing is listening on UDP port $p" >&2; exit 1; }
        pids+=("$pid")
        src_ports+=",$(ss -uanpH | grep "pid=$pid," | awk '{ print $4 }' | sed 's/.*://' | sort -un | grep -vE "$port_re" | paste -sd,)"
        d=$(tr '\0' '\n' <"/proc/$pid/cmdline" |
            awk -F= 'f { print; exit } $1 == "--dest-ip-ports" { if (NF > 1) { print $2; exit } f = 1 }' |
            tr ',' '\n' | sort -u | paste -sd,)
        [ -n "$first_dests" ] || first_dests=$d
        [ "$d" = "$first_dests" ] ||
            echo "WARNING: port $p forwards to a different destination list; with dedup, destinations missing from some forwarders will miss shreds" >&2
        all_dests+=",$d"
    done
    src_ports=$(tr ',' '\n' <<<"${src_ports#,}" | grep -v '^$' | sort -un | paste -sd,)
    all_dests=$(tr ',' '\n' <<<"${all_dests#,}" | grep -v '^$' | sort -u | paste -sd,)

    local filter="udp and (" sep=""
    for p in ${ports//,/ }; do filter+="${sep}dst port $p"; sep=" or "; done
    for p in ${src_ports//,/ }; do filter+=" or src port $p"; done
    filter+=")"

    mkdir -p "$OUT"
    local stamp net_pcap lo_pcap
    stamp=$(date +%Y%m%d-%H%M%S)
    net_pcap="$CAP_DIR/box-$stamp-net.pcap"
    lo_pcap="$CAP_DIR/box-$stamp-lo.pcap"
    echo "ports $ports (pids ${pids[*]}), $(tr ',' '\n' <<<"$all_dests" | wc -l) destinations, ${secs}s capture"

    # One process may own several ports; count each process once.
    cpu_sum() { local s=0 x; for x in $(printf '%s\n' "${pids[@]}" | sort -u); do s=$((s + $(cpu_ms "$x"))); done; echo "$s"; }
    nstat -n
    local c0 c1 drops
    c0=$(cpu_sum)
    timeout --signal=INT "$secs" tcpdump -i "$IN_IF" -nn -s 160 -B 262144 --time-stamp-precision nano \
        -w "$net_pcap" "$filter" 2>"$net_pcap.log" &
    local t1=$!
    timeout --signal=INT "$secs" tcpdump -i lo -nn -s 160 -B 65536 --time-stamp-precision nano \
        -w "$lo_pcap" "$filter" 2>"$lo_pcap.log" &
    local t2=$!
    wait "$t1" "$t2" || true
    c1=$(cpu_sum)
    drops=$(nstat_line)

    local d1 d2 dropped
    d1=$(grep -oP '\d+(?= packets dropped by kernel)' "$net_pcap.log" || echo unknown)
    d2=$(grep -oP '\d+(?= packets dropped by kernel)' "$lo_pcap.log" || echo unknown)
    dropped=$d1
    [ "$d1" = "0" ] && [ "$d2" = "0" ] || dropped="$d1+$d2"
    [ "$dropped" = "0" ] || echo "WARNING: tcpdump dropped packets ($dropped); treat this result with caution" >&2
    echo "kernel UDP errors during capture: ${drops:-none}"

    "$BIN/fanout-measure" analyze --pcap "$net_pcap" --pcap "$lo_pcap" --listen-port "$ports" \
        --dests "$all_dests" --egress-src-ports "$src_ports" --label "$label" \
        --results "$OUT/box-results.jsonl" --cpu-ms "$((c1 - c0))" \
        --meta "source=box" --meta "ports=$ports" --meta "tcpdump_dropped=$dropped" \
        --meta "kernel_udp_errors=${drops:-none}" |
        tee "$OUT/$label-$stamp.txt"

    # Keep the evidence when something went missing.
    local delivery
    delivery=$(grep -oP 'delivery \K[0-9.]+' "$OUT/$label-$stamp.txt" || echo 100)
    if awk -v d="$delivery" 'BEGIN { exit !(d < 99.9) }'; then
        echo "delivery ${delivery}% is below 99.9%: keeping the captures"
        KEEP_PCAP=1
    fi
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
    box) shift; box "$@" ;;
    corpus) shift; corpus "$@" ;;
    *) sed -n '2,16p' "$0"; exit 1 ;;
esac
