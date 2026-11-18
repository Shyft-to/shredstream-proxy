#!/usr/bin/env bash
# Experiment: send one destination's copies ahead of everything else when the
# NIC's transmit queues have a backlog. No proxy change, no restart:
#   - an nftables table of its own (inet shred_prio) sets socket priority 6 on
#     outgoing UDP to the destination (other tables and rules untouched);
#   - prio-qdisc.sh puts pfifo_fast on the bond's transmit queues, which
#     sends priority 6 (its first band) before priority 0 (everything else).
# Only reorders packets waiting in the same transmit queue; packets already
# handed to the NIC go out in order. Run as root.
#
# Usage:
#   prio-dest.sh on IP:PORT    e.g. prio-dest.sh on 10.182.192.76:8002
#   prio-dest.sh off           remove the rule and restore the default queueing
#   prio-dest.sh status        rule (with packet count) and queueing
#
# Settings (environment): BOND (bond0)
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
TABLE="inet shred_prio"

on() {
    local dest=$1 ip port
    ip=${dest%:*}
    port=${dest#*:}
    [[ "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ && "$port" =~ ^[0-9]+$ ]] || { echo "usage: prio-dest.sh on IP:PORT" >&2; exit 1; }
    "$DIR/prio-qdisc.sh" apply
    nft delete table $TABLE 2>/dev/null || true
    nft -f - <<EOF
table $TABLE {
    chain out {
        type filter hook output priority mangle; policy accept;
        ip daddr $ip udp dport $port counter meta priority set 0:6
    }
}
EOF
    echo "copies to $ip:$port now go first in their transmit queue"
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
    on) shift; [ $# -eq 1 ] || { echo "usage: prio-dest.sh on IP:PORT" >&2; exit 1; }; on "$1" ;;
    off) off ;;
    status) status ;;
    *) sed -n '2,17p' "$0"; exit 1 ;;
esac
