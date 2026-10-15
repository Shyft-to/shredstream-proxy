#!/usr/bin/env bash
# A/B test two forwarder binaries across ALL the forwarders at once, measured
# at box level, on live production traffic. Run as root.
#
# Usage:
#   fleet.sh PORTS PAIRS A_LABEL A_BINARY B_LABEL B_BINARY
#
# For every port in PORTS (comma separated) it reads the running instance's
# arguments, RUST_LOG and working directory, then stops all their systemd
# services and alternates: all ports on A, then all ports on B (each: warm up,
# probe.sh box), PAIRS times. On exit, normal or not, it stops the test
# processes, starts the services again and restores the kernel dedup filter
# to detached.
#
# Settings (environment):
#   DEDUP=on|off   kernel dedup filter during the whole test (default off)
#   B_SINGLE=1     run side B as ONE process listening on all PORTS (first
#                  port's arguments, with --src-bind-port set to PORTS)
#   WARMUP_S (10), MEASURE_S (10), OUT (./bench-results)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BIN=${BIN:-"$ROOT/target/release"}
DEDUP_SH="$ROOT/fanout/scripts/dedup.sh"
OUT=${OUT:-./bench-results}
WARMUP_S=${WARMUP_S:-10}
MEASURE_S=${MEASURE_S:-10}
DEDUP=${DEDUP:-off}

[ $# -eq 6 ] || { sed -n '2,20p' "$0"; exit 1; }
PORTS=$1 PAIRS=$2 A_LABEL=$3 A_BIN=$4 B_LABEL=$5 B_BIN=$6
for b in "$A_BIN" "$B_BIN"; do [ -x "$b" ] || { echo "not executable: $b" >&2; exit 1; }; done
[[ "$DEDUP" == on || "$DEDUP" == off ]] || { echo "DEDUP must be on or off" >&2; exit 1; }

port_pid() { ss -ulnpH "sport = :$1" | grep -oP 'pid=\K[0-9]+' | head -1; }

wait_port_free() {
    local i
    for i in $(seq 1 30); do
        [ -z "$(port_pid "$1")" ] && return 0
        sleep 0.5
    done
    echo "port $1 still in use" >&2
    return 1
}

# Per port: service unit, NUL-separated arguments file, RUST_LOG, working dir.
declare -A UNIT ARGS_FILE RUST_LOG_OF CWD
run_id=$(date +%Y%m%d-%H%M)
logdir="$OUT/fleet-$run_id"
mkdir -p "$logdir"
for p in ${PORTS//,/ }; do
    pid=$(port_pid "$p")
    [ -n "$pid" ] || { echo "nothing is listening on UDP port $p" >&2; exit 1; }
    UNIT[$p]=$(ps -o unit= -p "$pid" | tr -d ' ')
    [[ "${UNIT[$p]}" == *.service ]] || { echo "port $p (pid $pid) is not run by a systemd service" >&2; exit 1; }
    ARGS_FILE[$p]="$logdir/args-$p"
    tail -z -n +2 <"/proc/$pid/cmdline" >"${ARGS_FILE[$p]}"
    RUST_LOG_OF[$p]=$(tr '\0' '\n' <"/proc/$pid/environ" | grep '^RUST_LOG=' | cut -d= -f2- || true)
    CWD[$p]=$(readlink "/proc/$pid/cwd")
    echo "port $p: ${UNIT[$p]} (pid $pid)"
done

a_label="$A_LABEL-dedup$DEDUP@$run_id"
b_label="$B_LABEL-dedup$DEDUP@$run_id"
[ "${B_SINGLE:-0}" = "1" ] && b_label="$B_LABEL-single-dedup$DEDUP@$run_id"
echo "plan: $PAIRS pairs of $a_label / $b_label, filter $DEDUP, ${WARMUP_S}s warmup + ${MEASURE_S}s measure each"

children=()
stop_children() {
    local c p
    for c in "${children[@]}"; do kill "$c" 2>/dev/null || true; done
    for c in "${children[@]}"; do wait "$c" 2>/dev/null || true; done
    children=()
    for p in ${PORTS//,/ }; do wait_port_free "$p" || true; done
}

restore() {
    set +e
    trap '' HUP INT TERM
    stop_children
    local p
    for p in ${PORTS//,/ }; do systemctl start "${UNIT[$p]}"; done
    "$DEDUP_SH" detach >/dev/null
    sleep 2
    for p in ${PORTS//,/ }; do
        echo "restored: ${UNIT[$p]} is $(systemctl is-active "${UNIT[$p]}"), port $p pid $(port_pid "$p")"
    done
    echo "kernel dedup filter: $("$DEDUP_SH" status | head -1)"
}

"$DEDUP_SH" detach >/dev/null
for p in ${PORTS//,/ }; do systemctl stop "${UNIT[$p]}"; done
trap restore EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for p in ${PORTS//,/ }; do wait_port_free "$p"; done
[ "$DEDUP" = on ] && "$DEDUP_SH" attach "$PORTS"

start_one() { # PORT BINARY LOGFILE ARGS...
    local p=$1 bin=$2 log=$3
    shift 3
    (cd "${CWD[$p]}" && exec env ${RUST_LOG_OF[$p]:+RUST_LOG="${RUST_LOG_OF[$p]}"} "$bin" "$@") >"$log" 2>&1 &
    children+=($!)
}

# Rewrites --src-bind-port in the array named $1 to $2.
set_ports() {
    local -n arr=$1
    local i
    for i in "${!arr[@]}"; do
        case "${arr[$i]}" in
        --src-bind-port) arr[$((i + 1))]=$2 ;;
        --src-bind-port=*) arr[$i]="--src-bind-port=$2" ;;
        esac
    done
}

run_side() {
    local label=$1 bin=$2 n=$3 single=${4:-0} p args=()
    echo "--- $label ($n/$PAIRS)"
    if [ "$single" = "1" ]; then
        local first=${PORTS%%,*}
        mapfile -d '' args <"${ARGS_FILE[$first]}"
        set_ports args "$PORTS"
        start_one "$first" "$bin" "$logdir/$label-all-$n.log" "${args[@]}"
    else
        for p in ${PORTS//,/ }; do
            mapfile -d '' args <"${ARGS_FILE[$p]}"
            start_one "$p" "$bin" "$logdir/$label-$p-$n.log" "${args[@]}"
        done
    fi
    sleep "$WARMUP_S"
    for p in ${PORTS//,/ }; do
        [ -n "$(port_pid "$p")" ] || { echo "$bin is not listening on $p; see $logdir/$label-$p-$n.log" >&2; return 1; }
    done
    OUT="$OUT" "$DIR/probe.sh" box "$PORTS" "$MEASURE_S" "$label" |
        grep -E 'NORTH STAR|delivery|duplicate|cpu |keeping'
    stop_children
}

for n in $(seq 1 "$PAIRS"); do
    run_side "$a_label" "$A_BIN" "$n"
    run_side "$b_label" "$B_BIN" "$n" "${B_SINGLE:-0}"
done

for metric in completion.p99_us completion.p50_us first_dest.p50_us cpu_ms; do
    echo
    "$BIN/fanout-measure" compare --results "$OUT/box-results.jsonl" \
        --baseline "$a_label" --candidate "$b_label" --metric "$metric"
done
