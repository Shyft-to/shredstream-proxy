#!/usr/bin/env bash
# Proves that local destinations (127.x in DESTS) really receive the kernel
# fan-out's copies: counts datagrams queued on each local port's socket (a
# kprobe on the kernel's UDP socket enqueue, via bpftrace) and compares them
# with the shreds kfan fanned out in the same window. A capture on lo cannot
# do this: it shows copies the kernel then drops (the 2026-10-16 incident).
# Read-only. Run as root; needs bpftrace (apt install bpftrace).
#
#   local-check.sh [SECONDS] [DESTS]   (default 30 s; DESTS from /etc/shred-fanout/kfan.env)
#
# With kfan attached: PASS when every local port received >= 99% as many
# datagrams as kfan fanned out shreds. Without kfan: prints what the proxies
# deliver, as a reference.
set -euo pipefail

SECS=${1:-30}
DESTS=${2:-$(. /etc/shred-fanout/kfan.env 2>/dev/null; echo "${DESTS:-}")}
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 2; }
command -v bpftrace >/dev/null || { echo "bpftrace missing: apt install bpftrace" >&2; exit 2; }
ports=$(tr ',' '\n' <<<"$DESTS" | grep '^127\.' | sed 's/.*://' | sort -un | paste -sd' ')
[ -n "$ports" ] || { echo "no local (127.x) destination in DESTS" >&2; exit 2; }

echo "local ports: $ports; lo route_localnet=$(sysctl -n net.ipv4.conf.lo.route_localnet)" \
    "accept_local=$(sysctl -n net.ipv4.conf.lo.accept_local)"
for p in $ports; do
    ss -ulnpH "sport = :$p" | grep -q . || echo "WARNING: nothing listens on UDP $p"
done

# Shreds kfan fanned out so far (counter 0 of kfan_stats, summed over CPUs); empty if not attached.
kfan_first() {
    bpftool -j map dump name kfan_stats 2>/dev/null | python3 -c '
import json, sys
def num(v):
    return v if isinstance(v, int) else int.from_bytes(bytes(int(b, 16) for b in v), "little")
for r in json.load(sys.stdin):
    if num(r["key"]) == 0:
        print(sum(num(x["value"]) for x in r["values"]))' 2>/dev/null || true
}
udp_in() { nstat -az UdpInDatagrams | awk '/UdpInDatagrams/ { print $2 }'; }

echo "starting bpftrace (can take ~20 s)..."
cond=$(for p in $ports; do printf '$p == %s || ' "$p"; done)
out=$(mktemp)
trap 'rm -f "$out"' EXIT
bpftrace -e "
kprobe:__udp_enqueue_schedule_skb
{
    \$p = ((struct sock *)arg0)->__sk_common.skc_num;
    if (${cond% || }) { @queued[\$p] = count(); }
}" >"$out" 2>&1 &
bt=$!
for _ in $(seq 300); do grep -q Attaching "$out" && break; kill -0 $bt 2>/dev/null || break; sleep 0.2; done
grep -q Attaching "$out" || { cat "$out" >&2; echo "bpftrace did not start" >&2; exit 1; }

f0=$(kfan_first) u0=$(udp_in)
echo "counting for ${SECS}s..."
sleep "$SECS"
f1=$(kfan_first) u1=$(udp_in)
kill -INT $bt
wait $bt || true

echo "window ${SECS}s: UdpInDatagrams (whole box) +$((u1 - u0))"
if [ -n "$f0" ] && [ -n "$f1" ]; then
    first=$((f1 - f0))
    echo "kfan fanned out $first shreds ($((first / SECS))/s)"
else
    first=""
    echo "kfan is not attached: counts below are what the proxies deliver"
fi
fails=0
for p in $ports; do
    n=$(grep -oP "@queued\\[$p\\]: \\K\\d+" "$out" || echo 0)
    if [ -z "$first" ]; then
        echo "port $p: $n datagrams queued ($((n / SECS))/s)"
    elif [ "$first" -gt 0 ] && [ $((n * 100)) -ge $((first * 99)) ]; then
        echo "PASS  port $p: $n datagrams queued for $first shreds"
    else
        echo "FAIL  port $p: $n datagrams queued for $first shreds"
        fails=$((fails + 1))
    fi
done
[ "$fails" -eq 0 ]
