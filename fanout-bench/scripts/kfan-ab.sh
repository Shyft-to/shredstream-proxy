#!/usr/bin/env bash
# A/B test on live traffic: kernel dedup + userspace forwarders (A) vs kernel
# fan-out, where the kernel sends every copy itself (B). The forwarders keep
# running throughout; under B they simply receive nothing. Run as root.
#
# Usage:
#   kfan-ab.sh PORTS DESTS PAIRS
#
# DESTS must be the forwarders' destination list (ip:port,...). On exit,
# normal or not, whichever filter is attached is removed.
#
# Settings (environment): WARMUP_S (10), MEASURE_S (10), OUT (./bench-results)
#   A_KFAN=1        side A is the kernel fan-out too (instead of dedup + forwarders)
#   A_DROP, B_DROP  ports the kernel fan-out drops on that side (kfan.sh DROP_PORTS)
#   A_DIRECT=1, B_DIRECT=1  kernel fan-out sends straight to the NIC ports (kfan.sh DIRECT)
#   A_GROUPS, B_GROUPS      multi-CPU fan-out groups on that side (kfan.sh KFAN_GROUPS),
#                           using KFAN_CPUS (shared by both sides)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BIN=${BIN:-"$ROOT/target/release"}
DEDUP="$ROOT/fanout/scripts/dedup.sh"
KFAN="$ROOT/fanout/scripts/kfan.sh"
OUT=${OUT:-./bench-results}
WARMUP_S=${WARMUP_S:-10}
MEASURE_S=${MEASURE_S:-10}

[ $# -eq 3 ] || { sed -n '2,18p' "$0"; exit 1; }
PORTS=$1 DESTS=$2 PAIRS=$3

run_id=$(date +%Y%m%d-%H%M)
direct_suffix() { if [ "$1" = 1 ]; then echo -direct; fi; }
groups_suffix() { if [ "${1:-1}" -gt 1 ]; then echo "-g$1"; fi; }
if [ "${A_KFAN:-0}" = "1" ]; then
    a_label="kfan${A_DROP:+-drop$A_DROP}$(direct_suffix "${A_DIRECT:-0}")$(groups_suffix "${A_GROUPS:-1}")@$run_id"
else
    a_label="dedup@$run_id"
fi
b_label="kfan${B_DROP:+-drop$B_DROP}$(direct_suffix "${B_DIRECT:-0}")$(groups_suffix "${B_GROUPS:-1}")@$run_id"
[ "$a_label" != "$b_label" ] || { echo "A and B are the same setup" >&2; exit 1; }

finish() {
    set +e
    trap '' HUP INT TERM
    "$KFAN" status
    "$KFAN" detach
}
"$KFAN" detach >/dev/null
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for n in $(seq 1 "$PAIRS"); do
    echo "--- $a_label ($n/$PAIRS)"
    "$KFAN" detach >/dev/null
    if [ "${A_KFAN:-0}" = "1" ]; then
        DROP_PORTS="${A_DROP:-}" DIRECT="${A_DIRECT:-0}" KFAN_GROUPS="${A_GROUPS:-1}" "$KFAN" attach "$PORTS" "$DESTS" | grep -v '^  '
    else
        "$DEDUP" attach "$PORTS" >/dev/null
    fi
    sleep "$WARMUP_S"
    OUT="$OUT" "$DIR/probe.sh" box "$PORTS" "$MEASURE_S" "$a_label" | grep -E 'NORTH STAR|delivery|duplicate|keeping'

    echo "--- $b_label ($n/$PAIRS)"
    "$KFAN" detach >/dev/null
    DROP_PORTS="${B_DROP:-}" DIRECT="${B_DIRECT:-0}" KFAN_GROUPS="${B_GROUPS:-1}" "$KFAN" attach "$PORTS" "$DESTS" | grep -v '^  '
    sleep "$WARMUP_S"
    OUT="$OUT" "$DIR/probe.sh" box "$PORTS" "$MEASURE_S" "$b_label" | grep -E 'NORTH STAR|delivery|duplicate|keeping|hand-off'
    "$KFAN" status | grep -E 'copies|no destinations|ignored|carriers|by CPU'
done
"$KFAN" detach >/dev/null

for metric in completion.p99_us completion.p50_us first_dest.p50_us; do
    echo
    "$BIN/fanout-measure" compare --results "$OUT/box-results.jsonl" \
        --baseline "$a_label" --candidate "$b_label" --metric "$metric"
done
