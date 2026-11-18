#!/usr/bin/env bash
# Experiment: send some destinations' copies ahead of everything else when the
# NIC's transmit queues have a backlog. No proxy change, no restart:
#   - an nftables table of its own (inet shred_prio) sets socket priority 6 on
#     outgoing UDP to the destinations (other tables and rules untouched);
#   - prio-qdisc.sh puts pfifo_fast on the bond's transmit queues, which
#     sends priority 6 (its first band) before priority 0 (everything else).
# Only reorders packets waiting in the same transmit queue; packets already
# handed to the NIC go out in order. Run as root.
#
# Usage:
#   prio-dest.sh on DEST...    DEST = IP:PORT, or IP for all its UDP ports;
#                              replaces any earlier list, e.g.
#                              prio-dest.sh on 10.182.192.76:8002 10.182.192.45
#   prio-dest.sh off           remove the rules and restore the default queueing
#   prio-dest.sh status        rules (with packet counts) and queueing
#
# Settings (environment): BOND (bond0)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
TABLE="inet shred_prio"

on() {
    local dest rules=""
    for dest in "$@"; do
        if [[ "$dest" =~ ^([0-9]+(\.[0-9]+){3}):([0-9]+)$ ]]; then
            rules+="        ip daddr ${BASH_REMATCH[1]} udp dport ${BASH_REMATCH[3]} counter meta priority set 0:6"$'\n'
        elif [[ "$dest" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
            rules+="        ip daddr $dest meta l4proto udp counter meta priority set 0:6"$'\n'
        else
            echo "not IP or IP:PORT: $dest" >&2; exit 1
        fi
    done
    "$DIR/prio-qdisc.sh" apply
    nft delete table $TABLE 2>/dev/null || true
    nft -f - <<EOF
table $TABLE {
    chain out {
        type filter hook output priority mangle; policy accept;
$rules    }
}
EOF
    echo "copies to $* now go first in their transmit queue"
}

off() {
    nft delete table $TABLE 2>/dev/null && echo "rule removed" || echo "no rule"
    "$DIR/prio-qdisc.sh" revert
}

status() {
    nft list table $TABLE 2>/dev/null | grep -E 'daddr' | sed 's/^\s*/rule: /' || echo "rule: none"
    "$DIR/prio-qdisc.sh" status
}

case "${1:-}" in
    on) shift; [ $# -ge 1 ] || { echo "usage: prio-dest.sh on DEST..." >&2; exit 1; }; on "$@" ;;
    off) off ;;
    status) status ;;
    *) sed -n '2,19p' "$0"; exit 1 ;;
esac
