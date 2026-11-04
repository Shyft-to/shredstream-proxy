#!/usr/bin/env bash
# Tests the kernel dedup filter's fail-open and TO_PORT behaviour in a
# throwaway network namespace (veth pair 198.18.9.1 <-> 198.18.9.2, test
# ports 41001/41002). Never touches bond0 or any production port; the
# namespace is removed on exit. Run as root from the repository:
#
#   fanout/scripts/dedup-failover-test.sh
#
# Each case sends N fake shreds, every one twice (one copy per port, the
# "first" port first), and counts what each port's socket receives:
#   1  both forwarders up                 -> first port gets N, other 0
#   2  first port's forwarder down        -> other port gets N (late, not lost)
#   3  TO_PORT=41001, copies hit 41002 first, both up   -> 41001 gets N, 41002 0
#   4  TO_PORT=41001, 41001 down          -> 41002 gets N
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
NS=dedupt N=500 A=41001 B=41002
export OBJ=/run/fanout-dedup-test.bpf.o

cleanup() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del dt0 2>/dev/null || true
    rm -f "$OBJ"
}
trap cleanup EXIT
cleanup

ip netns add "$NS"
ip link add dt0 type veth peer name dt1
ip link set dt1 netns "$NS"
ip addr add 198.18.9.1/30 dev dt0 && ip link set dt0 up
ip netns exec "$NS" ip addr add 198.18.9.2/30 dev dt1
ip netns exec "$NS" ip link set dt1 up
ip netns exec "$NS" ip link set lo up

# Receivers on the given ports (inside the namespace) for SECS seconds; prints "port count".
receive() {
    ip netns exec "$NS" python3 - "$@" <<'EOF' &
import select, socket, sys, time
socks = {}
for p in map(int, sys.argv[1:]):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", p))
    s.setblocking(False)
    socks[s] = [p, 0]
end = time.time() + 3
while time.time() < end:
    for s in select.select(list(socks), [], [], 0.1)[0]:
        while True:
            try:
                s.recv(2048)
                socks[s][1] += 1
            except BlockingIOError:
                break
for p, c in socks.values():
    print(p, c)
EOF
}

# N shreds, each sent to FIRST then to SECOND, unique per case.
send() {
    python3 - "$1" "$2" "$3" "$N" <<'EOF'
import socket, struct, sys, time
case, first, second, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(n):
    p = (case.encode() + struct.pack("<I", i)).ljust(1200, b"\x01")
    s.sendto(p, ("198.18.9.2", first))
    s.sendto(p, ("198.18.9.2", second))
    time.sleep(0.0005)
EOF
}

fails=0
run_case() {
    local name=$1 to_port=$2 first=$3 second=$4 listeners=$5 expect_port=$6 out got other
    ip netns exec "$NS" env DEV=dt1 TO_PORT="$to_port" "$DIR/dedup.sh" attach "$A,$B" >/dev/null
    out=$(mktemp)
    # shellcheck disable=SC2086
    receive $listeners >"$out"
    sleep 0.5
    send "$name" "$first" "$second"
    wait
    ip netns exec "$NS" env DEV=dt1 "$DIR/dedup.sh" detach >/dev/null
    got=$(awk -v p="$expect_port" '$1 == p { print $2 }' "$out")
    other=$(awk -v p="$expect_port" '$1 != p { s += $2 } END { print s + 0 }' "$out")
    if [ "${got:-0}" -eq "$N" ] && [ "$other" -eq 0 ]; then
        echo "PASS  case $name: port $expect_port got $got/$N, other ports $other"
    else
        echo "FAIL  case $name: port $expect_port got ${got:-0}/$N, other ports $other ($(tr '\n' ' ' <"$out"))"
        fails=$((fails + 1))
    fi
    rm -f "$out"
}

run_case 1 "" "$A" "$B" "$A $B" "$A"
run_case 2 "" "$A" "$B" "$B" "$B"
run_case 3 "$A" "$B" "$A" "$A $B" "$A"
run_case 4 "$A" "$B" "$A" "$B" "$B"

[ "$fails" -eq 0 ] && echo "RESULT: all cases passed" || { echo "RESULT: $fails case(s) failed"; exit 1; }
