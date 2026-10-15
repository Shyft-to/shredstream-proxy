#!/usr/bin/env bash
# A/B test two forwarder binaries on live production traffic. Run as root.
#
# Usage:
#   ab.sh PORT PAIRS A_LABEL A_BINARY B_LABEL B_BINARY
#
# Takes over the instance listening on PORT: reads its arguments, RUST_LOG
# and working directory, stops its systemd service, then alternates A and B
# (each: warm up, measure with probe.sh), PAIRS times. On exit, normal or not,
# it stops the test binary and starts the service again.
#
# Settings (environment): WARMUP_S (10), MEASURE_S (10), OUT (./bench-results)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN=${BIN:-"$(cd "$DIR/../.." && pwd)/target/release"}
OUT=${OUT:-./bench-results}
WARMUP_S=${WARMUP_S:-10}
MEASURE_S=${MEASURE_S:-10}

[ $# -eq 6 ] || { sed -n '2,12p' "$0"; exit 1; }
PORT=$1 PAIRS=$2 A_LABEL=$3 A_BIN=$4 B_LABEL=$5 B_BIN=$6
for b in "$A_BIN" "$B_BIN"; do [ -x "$b" ] || { echo "not executable: $b" >&2; exit 1; }; done

port_pid() { ss -ulnpH "sport = :$PORT" | grep -oP 'pid=\K[0-9]+' | head -1; }

wait_port_free() {
    local i
    for i in $(seq 1 30); do
        [ -z "$(port_pid)" ] && return 0
        sleep 0.5
    done
    echo "port $PORT still in use" >&2
    return 1
}

pid=$(port_pid)
[ -n "$pid" ] || { echo "nothing is listening on UDP port $PORT" >&2; exit 1; }
unit=$(ps -o unit= -p "$pid" | tr -d ' ')
[[ "$unit" == *.service ]] || { echo "pid $pid is not run by a systemd service (unit: '$unit')" >&2; exit 1; }
mapfile -d '' args <"/proc/$pid/cmdline"
args=("${args[@]:1}")
rust_log=$(tr '\0' '\n' <"/proc/$pid/environ" | grep '^RUST_LOG=' | cut -d= -f2- || true)
workdir=$(readlink "/proc/$pid/cwd")

run_id=$(date +%Y%m%d-%H%M)
a_label="$A_LABEL@$run_id"
b_label="$B_LABEL@$run_id"
logdir="$OUT/ab-$run_id"
mkdir -p "$logdir"

echo "service:  $unit (pid $pid)"
echo "args:     ${args[*]}"
echo "RUST_LOG: ${rust_log:-<unset>}   cwd: $workdir"
echo "plan:     $PAIRS pairs of $a_label / $b_label, ${WARMUP_S}s warmup + ${MEASURE_S}s measure each"

child=""
restore() {
    # Best effort from here on: getting the service back matters more than
    # any individual step failing.
    set +e
    trap '' HUP INT TERM
    if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
        kill "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    wait_port_free || true
    systemctl start "$unit"
    sleep 2
    echo "restored: $unit is $(systemctl is-active "$unit"), listening pid $(port_pid)"
}
# Stopping via systemd (not kill) matters: with Restart= the service would come
# back and, because the proxy uses SO_REUSEPORT, silently split traffic with
# the test binary.
systemctl stop "$unit"
trap restore EXIT
# Turn hang-up (e.g. SSH drops), Ctrl-C and kill into a normal exit so the
# EXIT trap always restarts the service. Run long tests inside tmux anyway.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
wait_port_free

run_side() {
    local label=$1 bin=$2 n=$3
    echo "--- $label ($n/$PAIRS)"
    (cd "$workdir" && exec env ${rust_log:+RUST_LOG="$rust_log"} "$bin" "${args[@]}") \
        >"$logdir/$label-$n.log" 2>&1 &
    child=$!
    sleep "$WARMUP_S"
    if [ "$(port_pid)" != "$child" ]; then
        echo "$bin is not listening on $PORT; see $logdir/$label-$n.log" >&2
        return 1
    fi
    OUT="$OUT" "$DIR/probe.sh" measure "$PORT" "$MEASURE_S" "$label" | grep -E 'NORTH STAR|delivery|duplicate|cpu '
    kill "$child"
    wait "$child" 2>/dev/null || true
    child=""
    wait_port_free
}

for n in $(seq 1 "$PAIRS"); do
    run_side "$a_label" "$A_BIN" "$n"
    run_side "$b_label" "$B_BIN" "$n"
done

for metric in completion.p99_us completion.p50_us first_dest.p50_us cpu_us_per_send; do
    echo
    "$BIN/fanout-measure" compare --results "$OUT/prod-results.jsonl" \
        --baseline "$a_label" --candidate "$b_label" --metric "$metric"
done
