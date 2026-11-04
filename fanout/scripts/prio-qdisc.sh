#!/usr/bin/env bash
# Priority queueing on the bond's ports, for the proxy's DATA_FIRST: every
# transmit queue gets pfifo_fast, whose first band (socket priority 6, data
# shreds) always goes before its normal band (priority 0: coding shreds and
# all other traffic). Only changes anything while a queue has a backlog.
# Run as root.
#
# Usage:
#   prio-qdisc.sh apply     mq root with a pfifo_fast per transmit queue
#   prio-qdisc.sh revert    back to the kernel default (mq + net.core.default_qdisc)
#   prio-qdisc.sh status    queue disciplines, packets sent and dropped
#
# Settings (environment): BOND (bond0)
set -euo pipefail

BOND=${BOND:-bond0}
read -ra DEVS <"/sys/class/net/$BOND/bonding/slaves"

apply() {
    local d n i
    for d in "${DEVS[@]}"; do
        if ! tc qdisc show dev "$d" root | grep -q '^qdisc mq '; then
            echo "$d: root is not mq ($(tc qdisc show dev "$d" root)); not touching it" >&2
            exit 1
        fi
    done
    for d in "${DEVS[@]}"; do
        n=$(find "/sys/class/net/$d/queues" -maxdepth 1 -name 'tx-*' | wc -l)
        # Replacing the root drops what is queued at that instant (normally
        # nothing: the queues are idle ~95% of the time).
        tc qdisc replace dev "$d" root handle 1: mq
        for ((i = 1; i <= n; i++)); do
            tc qdisc replace dev "$d" parent "1:$(printf '%x' "$i")" pfifo_fast
        done
        echo "$d: pfifo_fast on $n transmit queues"
    done
}

revert() {
    local d
    for d in "${DEVS[@]}"; do
        tc qdisc del dev "$d" root 2>/dev/null || true
        echo "$d: back to $(tc qdisc show dev "$d" | awk 'NR == 2 { print $2 }') per queue (kernel default)"
    done
}

status() {
    local d
    for d in "${DEVS[@]}"; do
        echo "$d: $(tc qdisc show dev "$d" | awk 'NR > 1 { print $2 }' | sort | uniq -c | xargs) under $(tc qdisc show dev "$d" root | awk '{ print $2 }')"
        tc -s qdisc show dev "$d" | awk '/^ Sent/ { s += $2; p += $4; d += $7 } END { printf "  sent %d bytes, %d packets, dropped %d\n", s / 2, p / 2, d / 2 }'
    done
}

case "${1:-}" in
    apply) apply ;;
    revert) revert ;;
    status) status ;;
    *) sed -n '2,13p' "$0"; exit 1 ;;
esac
