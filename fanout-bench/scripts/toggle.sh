#!/usr/bin/env bash
# A/B test of the kernel dedup filter on live traffic. The forwarders keep
# running untouched; only the filter is attached and detached between runs.
# Run as root.
#
# Usage:
#   toggle.sh PORTS PAIRS
#
# Alternates filter off / on, PAIRS times: each turn waits WARMUP_S, then
# measures the box-level north star (probe.sh box) for MEASURE_S. Compares
# the two labels at the end. On exit (normal or not) the filter is detached,
# unless KEEP_ATTACHED=1.
#
# Settings (environment): WARMUP_S (10), MEASURE_S (10), OUT (./bench-results)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BIN=${BIN:-"$ROOT/target/release"}
DEDUP="$ROOT/fanout/scripts/dedup.sh"
OUT=${OUT:-./bench-results}
WARMUP_S=${WARMUP_S:-10}
MEASURE_S=${MEASURE_S:-10}

[ $# -eq 2 ] || { sed -n '2,14p' "$0"; exit 1; }
PORTS=$1 PAIRS=$2

run_id=$(date +%Y%m%d-%H%M)
off_label="dedup-off@$run_id"
on_label="dedup-on@$run_id"

finish() {
    set +e
    trap '' HUP INT TERM
    if [ "${KEEP_ATTACHED:-0}" = "1" ]; then
        "$DEDUP" status
    else
        "$DEDUP" detach
    fi
}
"$DEDUP" detach >/dev/null
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for n in $(seq 1 "$PAIRS"); do
    echo "--- $off_label ($n/$PAIRS)"
    "$DEDUP" detach >/dev/null
    sleep "$WARMUP_S"
    OUT="$OUT" "$DIR/probe.sh" box "$PORTS" "$MEASURE_S" "$off_label" | grep -E 'NORTH STAR|delivery|duplicate|cpu '

    echo "--- $on_label ($n/$PAIRS)"
    "$DEDUP" attach "$PORTS"
    sleep "$WARMUP_S"
    OUT="$OUT" "$DIR/probe.sh" box "$PORTS" "$MEASURE_S" "$on_label" | grep -E 'NORTH STAR|delivery|duplicate|cpu '
    "$DEDUP" status | tail -4
done

for metric in completion.p99_us completion.p50_us first_dest.p50_us cpu_ms; do
    echo
    "$BIN/fanout-measure" compare --results "$OUT/box-results.jsonl" \
        --baseline "$off_label" --candidate "$on_label" --metric "$metric"
done
