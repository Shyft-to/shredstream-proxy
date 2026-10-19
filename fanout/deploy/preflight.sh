#!/usr/bin/env bash
# Read-only checks before starting shred-kfan on a server. Changes nothing on the
# network path: the program is compiled and passed through the kernel verifier,
# but never attached. Run as root from the repository:
#
#   sudo fanout/deploy/preflight.sh [ENV_FILE]     (default /etc/shred-fanout/kfan.env,
#                                                   else fanout/deploy/kfan.env.example)
#
# Prints PASS / WARN / FAIL per check; exits 1 if anything FAILed.
set -uo pipefail

# Works from the repository (fanout/deploy/) and from the installed copy (/opt/shred-fanout/).
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -x "$HERE/scripts/kfan.sh" ]; then SRC=$HERE; else SRC="$(cd "$HERE/.." && pwd)"; fi
KFAN="$SRC/scripts/kfan.sh"
ENV_FILE=${1:-/etc/shred-fanout/kfan.env}
[ -e "$ENV_FILE" ] || ENV_FILE="$SRC/deploy/kfan.env.example"
fails=0 warns=0

pass() { echo "PASS  $*"; }
warn() { echo "WARN  $*"; warns=$((warns + 1)); }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
indent() { sed 's/^/        /'; }

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 2; }
echo "config: $ENV_FILE    kernel: $(uname -r)    host: $(hostname)"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
DEV=${DEV:-bond0}

# 1. Tools
missing=""
for t in clang bpftool tc python3 ip sysctl; do command -v "$t" >/dev/null || missing+=" $t"; done
if [ -z "$missing" ]; then pass "tools: clang bpftool tc python3 ip sysctl"; else fail "missing tools:$missing"; fi
[ -e /usr/include/bpf/bpf_helpers.h ] || [ -e /usr/include/x86_64-linux-gnu/bpf/bpf_helpers.h ] ||
    fail "libbpf headers missing (apt install libbpf-dev)"

# 2. Configuration
n=$(tr ',' '\n' <<<"${DESTS:-}" | grep -c .)
if [ -n "${PORTS:-}" ] && [ "$n" -gt 0 ]; then
    pass "config: ports $PORTS, $n destinations, DIRECT=${DIRECT:-0}, DEV=$DEV"
else
    fail "config: PORTS and DESTS must be set in $ENV_FILE"
fi
[ "$n" -le 16 ] || fail "config: $n destinations, at most 16 per group"
if [ -n "${STAMP_PORT:-}${LAT_HIST:-}${SHADOW:-}" ]; then
    warn "config: measurement options set (STAMP_PORT/LAT_HIST); not part of v1"
fi

# 3. Network device
if [ ! -e "/sys/class/net/$DEV" ]; then
    fail "device $DEV does not exist (set DEV)"
elif [ -e "/sys/class/net/$DEV/bonding/slaves" ]; then
    slaves=$(cat "/sys/class/net/$DEV/bonding/slaves")
    up=0
    for s in $slaves; do [ "$(cat "/sys/class/net/$s/operstate")" = up ] && up=$((up + 1)); done
    pass "device $DEV: bond ($(cat "/sys/class/net/$DEV/bonding/mode" | cut -d' ' -f1)), ports: $slaves ($up up)"
    [ "$up" -gt 0 ] || fail "no bond port is up"
else
    pass "device $DEV: not a bond"
fi

# 4. Nothing else in the way
if tc filter show dev "$DEV" ingress 2>/dev/null | grep -q "pref 7700 "; then
    if systemctl is-active --quiet shred-kfan; then
        pass "tc pref 7700 on $DEV: used by the running shred-kfan"
    else
        fail "tc pref 7700 on $DEV is taken by something else (dedup.sh/kfan.sh by hand?)"
    fi
else
    pass "tc pref 7700 on $DEV: free"
fi
for i in $DEV $( [ -e "/sys/class/net/$DEV/bonding/slaves" ] && cat "/sys/class/net/$DEV/bonding/slaves"); do
    if ip -d link show dev "$i" | grep -q 'prog/xdp'; then
        warn "$i has an XDP program loaded ($(ip -d link show dev "$i" | grep -o 'name [^ ]*' | head -1)); not part of v1"
    fi
done

# 5. Destinations: same list as the proxies, and every next hop resolvable
out=$("$KFAN" check-dests "$DESTS" 2>&1)
if grep -q DIFFERENT <<<"$out"; then
    warn "destinations differ from a running proxy:"; indent <<<"$out"
elif grep -q "no running process" <<<"$out"; then
    warn "no running proxy found to compare destinations with"
else
    pass "destinations match the running proxies"; indent <<<"$out"
fi
if out=$(DIRECT=${DIRECT:-0} DEV=$DEV "$KFAN" resolve "$DESTS" 2>&1); then
    pass "$(tail -1 <<<"$out")"
else
    fail "destinations:"; indent <<<"$out"
fi
if [[ ",$DESTS" == *,127.* ]]; then
    pass "local destinations present: lo route_localnet/accept_local will be set at start (now $(sysctl -n net.ipv4.conf.lo.route_localnet)/$(sysctl -n net.ipv4.conf.lo.accept_local))"
fi

# 6. Build and kernel verifier (loaded without attaching, then removed)
obj=$(mktemp /tmp/kfan-preflight.XXXXXX.o)
if out=$(OBJ="$obj" "$KFAN" build "$PORTS" 2>&1); then
    pass "build"
    pin=/sys/fs/bpf/kfan_preflight
    mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
    rm -f "$pin"
    if out=$(bpftool prog load "$obj" "$pin" type classifier 2>&1); then
        pass "kernel verifier accepts the program"
    else
        fail "kernel verifier rejected the program:"; tail -15 <<<"$out" | indent
    fi
    rm -f "$pin"
else
    fail "build:"; tail -15 <<<"$out" | indent
fi
rm -f "$obj"

# 7. NIC receive interrupt delay (information; the measured setup used 0)
for i in $( [ -e "/sys/class/net/$DEV/bonding/slaves" ] && cat "/sys/class/net/$DEV/bonding/slaves" || echo "$DEV"); do
    v=$(ethtool -c "$i" 2>/dev/null | awk '/^rx-usecs:/ { print $2 }')
    [ -n "$v" ] && echo "INFO  $i rx-usecs $v (measured setup: 0; not persistent across reboots)"
done

echo
if [ "$fails" -gt 0 ]; then
    echo "RESULT: $fails FAIL, $warns WARN - do not start shred-kfan here yet"
    exit 1
fi
echo "RESULT: ready ($warns WARN) - next: sudo fanout/deploy/install.sh && sudo systemctl start shred-kfan"
