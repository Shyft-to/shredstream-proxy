#!/usr/bin/env bash
# Profiles a live forward-only instance. Read-only: attaches probes and
# samples, never changes the process. Run as root.
#
# Usage:
#   profile.sh stages PORT [SECONDS] [LABEL]   per-stage latency histograms (bpftrace)
#   profile.sh cpu PORT [SECONDS] [LABEL]      where the process spends CPU (perf)
#
# Output is printed and saved under OUT (./bench-results) as
# stages-LABEL-TIMESTAMP.txt / cpu-LABEL-TIMESTAMP.txt.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT=${OUT:-./bench-results}

find_pid() {
    local pid
    pid=$(ss -ulnpH "sport = :$1" | grep -oP 'pid=\K[0-9]+' | head -1)
    [ -n "$pid" ] || { echo "nothing is listening on UDP port $1" >&2; exit 1; }
    echo "$pid"
}

stages() {
    local port=$1 secs=${2:-10} label=${3:-$1}
    local pid
    pid=$(find_pid "$port")
    mkdir -p "$OUT"
    bpftrace "$DIR/stages.bt" "$pid" "$port" "$secs" 2>&1 |
        tee "$OUT/stages-$label-$(date +%Y%m%d-%H%M%S).txt"
}

cpu() {
    local port=$1 secs=${2:-10} label=${3:-$1}
    local pid data
    pid=$(find_pid "$port")
    mkdir -p "$OUT"
    data=$(mktemp /dev/shm/perf-XXXXXX.data)
    perf record -q -F 999 -p "$pid" -o "$data" -- sleep "$secs"
    {
        echo "== CPU by thread"
        perf report -i "$data" --stdio --no-children --sort comm --percent-limit 1 2>/dev/null | grep -v '^$'
        echo
        echo "== CPU by function (all threads)"
        perf report -i "$data" --stdio --no-children --sort sym --percent-limit 0.5 2>/dev/null | grep -v '^$'
    } | tee "$OUT/cpu-$label-$(date +%Y%m%d-%H%M%S).txt"
    rm -f "$data"
}

case "${1:-}" in
    stages) shift; stages "$@" ;;
    cpu) shift; cpu "$@" ;;
    *) sed -n '2,10p' "$0"; exit 1 ;;
esac
