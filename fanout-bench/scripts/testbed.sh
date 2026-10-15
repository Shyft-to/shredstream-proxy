#!/usr/bin/env bash
# Isolated fan-out test bed: three network namespaces joined by veth pairs.
#
#   fb-src (replayer)  ---veth--->  fb-fwd (forwarder under test)  ---veth--->  fb-sink (N receivers)
#   198.18.1.1-4                    198.18.1.254 | 198.19.0.254                 198.19.0.1..N
#
# Everything lives inside the three namespaces (198.18.0.0/15 is the RFC 2544
# benchmarking range), so the host's own interfaces, routes and production
# traffic are never touched. Run as root.
#
# Usage:
#   testbed.sh setup
#   testbed.sh run LABEL RUNS -- FORWARDER COMMAND...   ({LISTEN} and {DESTS} are substituted)
#   testbed.sh compare BASELINE_LABEL CANDIDATE_LABEL [METRIC]
#   testbed.sh teardown
#
# Settings (environment):
#   CORPUS        full-snaplen ingress capture from `probe.sh corpus`     (./corpus.pcap)
#   CORPUS_PORT   UDP port the corpus traffic was addressed to            (5544)
#   LOOPS         times to play the corpus per run                        (1)
#   DESTS_N       number of destinations                                  (20)
#   FWD_CPUS      cores for the forwarder                                 (30-33)
#   REPLAY_CPU / SINK_CPU / TCPDUMP_CPU  one core each                    (34 / 35 / 36)
#   OUT           results directory                                       (./bench-results)
#   KEEP_PCAP=1   keep each run's capture
set -euo pipefail

BIN=${BIN:-"$(cd "$(dirname "$0")/../.." && pwd)/target/release"}
CORPUS=${CORPUS:-./corpus.pcap}
CORPUS_PORT=${CORPUS_PORT:-5544}
LOOPS=${LOOPS:-1}
DESTS_N=${DESTS_N:-20}
DEST_PORT=${DEST_PORT:-8002}
LISTEN_PORT=${LISTEN_PORT:-5544}
FWD_CPUS=${FWD_CPUS:-30-33}
REPLAY_CPU=${REPLAY_CPU:-34}
SINK_CPU=${SINK_CPU:-35}
TCPDUMP_CPU=${TCPDUMP_CPU:-36}
FWD_STARTUP_S=${FWD_STARTUP_S:-3}
OUT=${OUT:-./bench-results}
SRC_IPS=198.18.1.1,198.18.1.2,198.18.1.3,198.18.1.4
FWD_IP=198.18.1.254

dests() {
    local s="" i
    for i in $(seq 1 "$DESTS_N"); do s+="${s:+,}198.19.0.$i:$DEST_PORT"; done
    echo "$s"
}

# Forwarder CPU time (user + sys, all threads) in ms.
cpu_ms() {
    awk -v hz="$(getconf CLK_TCK)" '{ sub(/^.*\) /, ""); print int(($12 + $13) * 1000 / hz) }' "/proc/$1/stat"
}

setup() {
    ip netns add fb-src
    ip netns add fb-fwd
    ip netns add fb-sink
    ip link add fb-src0 netns fb-src type veth peer name fb-in netns fb-fwd
    ip link add fb-out netns fb-fwd type veth peer name fb-sink0 netns fb-sink
    for ns in fb-src fb-fwd fb-sink; do ip -n "$ns" link set lo up; done

    local i
    for i in 1 2 3 4; do ip -n fb-src addr add "198.18.1.$i/24" dev fb-src0; done
    ip -n fb-fwd addr add "$FWD_IP/24" dev fb-in
    ip -n fb-fwd addr add 198.19.0.254/24 dev fb-out
    for i in $(seq 1 "$DESTS_N"); do ip -n fb-sink addr add "198.19.0.$i/24" dev fb-sink0; done

    ip -n fb-src link set fb-src0 up
    ip -n fb-fwd link set fb-in up
    ip -n fb-fwd link set fb-out up
    ip -n fb-sink link set fb-sink0 up

    # Resolve every neighbour up front so ARP is not part of the first runs.
    for i in $(seq 1 "$DESTS_N"); do ip netns exec fb-fwd ping -c1 -W1 "198.19.0.$i" >/dev/null || true; done
    ip netns exec fb-src ping -c1 -W1 "$FWD_IP" >/dev/null || true
    echo "test bed ready: $DESTS_N destinations, forwarder address $FWD_IP"
}

teardown() {
    ip netns del fb-src 2>/dev/null || true
    ip netns del fb-fwd 2>/dev/null || true
    ip netns del fb-sink 2>/dev/null || true
    echo "test bed removed"
}

run() {
    local label=$1 runs=$2
    shift 2
    [ "${1:-}" = "--" ] && shift
    local tmpl="$*" all_dests
    all_dests=$(dests)
    [ -f "$CORPUS" ] || { echo "corpus not found: $CORPUS (capture one with probe.sh corpus)" >&2; exit 1; }
    ip netns list | grep -q '^fb-fwd' || { echo "run '$0 setup' first" >&2; exit 1; }

    local cmd=${tmpl//\{LISTEN\}/$LISTEN_PORT}
    cmd=${cmd//\{DESTS\}/$all_dests}
    local git_rev
    git_rev=$(git -C "$(dirname "$0")" rev-parse --short HEAD 2>/dev/null || echo none)

    local r
    for r in $(seq 1 "$runs"); do
        local dir="$OUT/$label/run$r"
        mkdir -p "$dir"
        echo "--- $label run $r/$runs"

        ip netns exec fb-sink taskset -c "$SINK_CPU" "$BIN/udp-sink" --bind "0.0.0.0:$DEST_PORT" >"$dir/sink.log" 2>&1 &
        local sink=$!
        # `ip netns exec` and `taskset` both exec, so $! is the forwarder itself.
        ip netns exec fb-fwd taskset -c "$FWD_CPUS" bash -c "exec $cmd" >"$dir/forwarder.log" 2>&1 &
        local fwd=$!
        sleep "$FWD_STARTUP_S"
        if ! kill -0 "$fwd" 2>/dev/null; then
            echo "forwarder exited during startup; see $dir/forwarder.log" >&2
            kill "$sink" 2>/dev/null || true
            exit 1
        fi

        # CAPTURE=fwd (default): inside the forwarder's namespace.
        # CAPTURE=ends: where packets leave the source and reach the sinks,
        # outside the forwarder, so designs the kernel's taps cannot see
        # (AF_XDP) are measured the same way as the others.
        local pcaps=() logs=() tpids=()
        if [ "${CAPTURE:-fwd}" = ends ]; then
            pcaps=("$dir/src.pcap" "$dir/sink.pcap")
            logs=("$dir/tcpdump-src.log" "$dir/tcpdump-sink.log")
            ip netns exec fb-src taskset -c "$TCPDUMP_CPU" \
                tcpdump -i fb-src0 -nn -s 160 -B 262144 --time-stamp-precision nano -w "${pcaps[0]}" udp \
                2>"${logs[0]}" &
            tpids+=($!)
            ip netns exec fb-sink taskset -c "$TCPDUMP_CPU" \
                tcpdump -i fb-sink0 -nn -s 160 -B 262144 --time-stamp-precision nano -w "${pcaps[1]}" udp \
                2>"${logs[1]}" &
            tpids+=($!)
        else
            pcaps=("$dir/capture.pcap")
            logs=("$dir/tcpdump.log")
            ip netns exec fb-fwd taskset -c "$TCPDUMP_CPU" \
                tcpdump -i any -nn -s 160 -B 262144 --time-stamp-precision nano -w "${pcaps[0]}" udp \
                2>"${logs[0]}" &
            tpids+=($!)
        fi
        sleep 1

        local c0 c1
        c0=$(cpu_ms "$fwd")
        ip netns exec fb-src taskset -c "$REPLAY_CPU" "$BIN/shred-replay" \
            --pcap "$CORPUS" --port "$CORPUS_PORT" --target "$FWD_IP:$LISTEN_PORT" \
            --src-ips "$SRC_IPS" --loops "$LOOPS" --salt "$(date +%s%N | cut -c6-14)" >"$dir/replay.log" 2>&1
        sleep 1
        c1=$(cpu_ms "$fwd")

        kill -INT "${tpids[@]}"; wait "${tpids[@]}" 2>/dev/null || true
        kill "$fwd" "$sink" 2>/dev/null || true
        wait "$fwd" "$sink" 2>/dev/null || true

        local dropped=0 d lateness log pcap_args=() p
        for log in "${logs[@]}"; do
            d=$(grep -oP '\d+(?= packets dropped by kernel)' "$log" || echo unknown)
            [ "$d" = "0" ] || dropped=$d
        done
        lateness=$(grep -oP 'REPLAY_LATENESS_P99_US=\K[0-9.]+' "$dir/replay.log" || echo unknown)
        [ "$dropped" = "0" ] || echo "WARNING: tcpdump dropped $dropped packets; this run will be excluded" >&2
        for p in "${pcaps[@]}"; do pcap_args+=(--pcap "$p"); done

        "$BIN/fanout-measure" analyze "${pcap_args[@]}" --listen-port "$LISTEN_PORT" --dests "$all_dests" \
            --label "$label" --results "$OUT/results.jsonl" --cpu-ms "$((c1 - c0))" \
            --meta "run=$r" --meta "source=testbed" --meta "git=$git_rev" --meta "capture=${CAPTURE:-fwd}" \
            --meta "tcpdump_dropped=$dropped" --meta "replay_lateness_p99_us=$lateness" \
            --show-dests 5 | tee "$dir/summary.txt"

        [ "${KEEP_PCAP:-0}" = "1" ] || rm -f "${pcaps[@]}"
    done
}

compare() {
    "$BIN/fanout-measure" compare --results "$OUT/results.jsonl" --baseline "$1" --candidate "$2" \
        ${3:+--metric "$3"}
}

case "${1:-}" in
    setup) setup ;;
    teardown) teardown ;;
    run) shift; run "$@" ;;
    compare) shift; compare "$@" ;;
    *) sed -n '2,30p' "$0"; exit 1 ;;
esac
