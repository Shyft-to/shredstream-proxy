#!/usr/bin/env bash
# Kernel shred fan-out (fanout/ebpf/kfan.bpf.c) on tc ingress. Run as root.
# Needs: clang, llvm, libbpf-dev, bpftool, tc, python3.
#
# Usage:
#   kfan.sh attach PORTS DESTS   build for PORTS, attach, load DESTS (ip:port,...)
#   kfan.sh refresh DESTS        re-resolve next-hop MACs and reload the table
#   kfan.sh detach               remove it; the forwarders take over instantly
#   kfan.sh status               attached or not, and the counters
#   kfan.sh cost [SECONDS]       measured kernel CPU time per packet (default 10 s)
#   kfan.sh watch DESTS          keep the table current: reload when bond ports
#                                go up/down, re-resolve MACs every REFRESH_S (60)
#   kfan.sh build PORTS          compile only (OBJ=path to choose the output)
#   kfan.sh resolve DESTS        dry run: how each destination would be sent; fails if
#                                any cannot be resolved (nothing is loaded)
#   kfan.sh run PORTS DESTS      for a service: (re)attach, then watch, logging the
#                                counters every LOG_S (60); detaches on SIGTERM
#   kfan.sh check-dests DESTS    compare DESTS with the running proxies'
#                                --dest-ip-ports / DEST_IP_PORTS
#   kfan.sh latency [SECONDS] [LABEL] [RESULTS]
#                                arrival at the NIC driver -> each copy handed to the
#                                NIC, over a window (needs LAT_HIST and xdpstamp.sh)
#
# Shares tc priority 7700 with dedup.sh: only one of the two can be attached.
# Settings (environment): DEV (bond0), DROP_PORTS (up to 2, comma separated:
#   UDP to these ports is dropped, e.g. to switch a source off), DIRECT=1
#   (send straight to the physical NIC ports: skips the VLAN and bond layers;
#   the NIC adds the VLAN tag; destinations are spread over the bond's ports),
#   KFAN_GROUPS=n (1..4, default 1) with KFAN_CPUS=c1,c2,.. (n-1 CPUs): multi-CPU
#   fan-out. Destinations are split into n groups; group 0 is sent on the
#   receiving CPU, group i on CPU ci (receive packet steering on DEV rx-0).
#   Also raises net.core.netdev_max_backlog to >= 10000. Detach restores both.
#   STAMP_PORT=p: copies to destinations with UDP port p (fanout-bench
#   stamp-recv receivers) carry the arrival time (driver level if
#   xdpstamp.sh is attached); see kfan.bpf.c.
#   LAT_HIST=1|2: in-kernel latency histograms for `latency` (1: first and last
#   copy; 2: also per destination). Needs xdpstamp.sh attached.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/../ebpf/kfan.bpf.c"
OBJ=${OBJ:-/run/fanout-kfan.bpf.o}
DEV=${DEV:-bond0}
DROP_PORTS=${DROP_PORTS:-}
DIRECT=${DIRECT:-0}
STAMP_PORT=${STAMP_PORT:-}
LAT_HIST=${LAT_HIST:-}
KFAN_GROUPS=${KFAN_GROUPS:-1}
KFAN_CPUS=${KFAN_CPUS:-}
PREF=7700
PER_GROUP=16
STATE=/run/fanout-kfan.state
LO_STATE=/run/fanout-kfan.lo-sysctl

attached() { tc filter show dev "$DEV" ingress 2>/dev/null | grep -q "pref $PREF "; }
ours() { tc filter show dev "$DEV" ingress 2>/dev/null | grep -A1 "pref $PREF " | grep -q kfan; }

build() {
    local ports=$1 defs=() names=(A B C D) i=0 p
    for p in ${ports//,/ }; do
        [[ "$p" =~ ^[0-9]+$ ]] || { echo "bad port: $p" >&2; exit 1; }
        [ $i -lt 4 ] || { echo "at most 4 ports" >&2; exit 1; }
        defs+=("-DPORT_${names[$i]}=$p")
        i=$((i + 1))
    done
    i=0
    for p in ${DROP_PORTS//,/ }; do
        [[ "$p" =~ ^[0-9]+$ ]] || { echo "bad drop port: $p" >&2; exit 1; }
        [ $i -lt 2 ] || { echo "at most 2 drop ports" >&2; exit 1; }
        defs+=("-DDROP_${names[$i]}=$p")
        i=$((i + 1))
    done
    defs+=("-DGROUPS=$KFAN_GROUPS")
    if [ -n "$STAMP_PORT" ]; then
        [[ "$STAMP_PORT" =~ ^[0-9]+$ ]] || { echo "bad STAMP_PORT: $STAMP_PORT" >&2; exit 1; }
        defs+=("-DSTAMP_PORT=$STAMP_PORT")
    fi
    if [ -n "$LAT_HIST" ]; then
        [[ "$LAT_HIST" =~ ^[012]$ ]] || { echo "LAT_HIST must be 0, 1 or 2" >&2; exit 1; }
        defs+=("-DLAT_HIST=$LAT_HIST")
    fi
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
        "${defs[@]}" -c "$SRC" -o "$OBJ"
}

hex_le32() { printf '%02x %02x %02x %02x' $(($1 & 255)) $(($1 >> 8 & 255)) $(($1 >> 16 & 255)) $(($1 >> 24 & 255)); }
hex_ip() { local IFS=.; set -- $1; printf '%02x %02x %02x %02x' "$1" "$2" "$3" "$4"; }
hex_mac() { tr ':' ' ' <<<"$1"; }
hex_be16() { printf '%02x %02x' $(($1 >> 8 & 255)) $(($1 & 255)); }

hex_le16() { printf '%02x %02x' $(($1 & 255)) $(($1 >> 8 & 255)); }

# Ports listed here (one per line) are left out, as if down: xdpstamp.sh puts
# a port here while it loads or unloads XDP on it, which resets that port's
# queues without the bond noticing (direct copies to it would be refused).
EXCLUDE=/run/fanout-kfan.exclude

# Active member ports of a bond (in the active 802.3ad aggregator, link up),
# or the device itself if it is not a bond.
ports_of() {
    local dev=$1 agg s
    if [ ! -e "/sys/class/net/$dev/bonding/slaves" ]; then
        echo "$dev"
        return
    fi
    agg=$(cat "/sys/class/net/$dev/bonding/ad_aggregator" 2>/dev/null || true)
    for s in $(cat "/sys/class/net/$dev/bonding/slaves"); do
        [ "$(cat "/sys/class/net/$s/operstate")" = up ] || continue
        [ "$(cat "/sys/class/net/$s/bonding_slave/mii_status" 2>/dev/null || echo up)" = up ] || continue
        if [ -e "$EXCLUDE" ] && grep -qx "$s" "$EXCLUDE"; then continue; fi
        if [ -n "$agg" ] && [ -e "/sys/class/net/$s/bonding_slave/ad_aggregator_id" ]; then
            [ "$(cat "/sys/class/net/$s/bonding_slave/ad_aggregator_id")" = "$agg" ] || continue
        fi
        echo "$s"
    done
}

# Prints "VLAN HEX" for one ip:port destination: the VLAN tag (0 = none) and
# the 28-byte table entry. $2 picks the physical port when DIRECT=1.
resolve() {
    local ip=${1%:*} port=${1#*:} n=$2 route dev src via nh mac out vlan=0 ports smac
    if [[ "$ip" == 127.* ]]; then
        echo "0 $(hex_le32 "$(cat /sys/class/net/lo/ifindex)") 00 00 00 00 00 00 00 00 00 00 00 00 $(hex_ip "$ip") $(hex_ip "$ip") $(hex_be16 "$port") 00 00"
        echo "  $1 -> dev lo (local delivery), from $ip" >&2
        return
    fi
    route=$(ip -o route get "$ip")
    dev=$(grep -oP ' dev \K\S+' <<<"$route")
    src=$(grep -oP ' src \K\S+' <<<"$route")
    via=$(grep -oP ' via \K\S+' <<<"$route" || true)
    nh=${via:-$ip}
    ping -c1 -W1 -q "$nh" >/dev/null 2>&1 || true
    mac=$(ip neigh show to "$nh" dev "$dev" | grep -oP 'lladdr \K\S+' || true)
    [ -n "$mac" ] || { echo "no MAC for next hop $nh of $1 (dev $dev)" >&2; return 1; }
    smac=$(cat "/sys/class/net/$dev/address")
    out=$dev
    if [ "$DIRECT" = 1 ]; then
        # Through the VLAN device and the bond, down to a physical port.
        if [ -e "/proc/net/vlan/$dev" ]; then
            vlan=$(awk '/VID:/ { print $3 }' "/proc/net/vlan/$dev")
            out=$(awk '/^Device:/ { print $2 }' "/proc/net/vlan/$dev")
        fi
        mapfile -t ports < <(ports_of "$out")
        [ ${#ports[@]} -gt 0 ] || { echo "no active port under $out" >&2; return 1; }
        out=${ports[$((n % ${#ports[@]}))]}
    fi
    echo "$vlan $(hex_le32 "$(cat "/sys/class/net/$out/ifindex")") $(hex_mac "$mac") $(hex_mac "$smac") $(hex_ip "$src") $(hex_ip "$ip") $(hex_be16 "$port") $(hex_le16 "$vlan")"
    echo "  $1 -> dev $out$([ "$out" != "$dev" ] && echo " (for $dev$([ "$vlan" != 0 ] && echo ", VLAN $vlan"))"), next hop $nh ($mac), from $src" >&2
}

# Resolves everything first. Destination j goes to group j % KFAN_GROUPS; within a
# group, entries are ordered by VLAN tag (the program changes the tag at most
# once per group). Writes every group's entries and terminator, and entry 0 of
# group 0 last: until it is set the program passes all traffic on.
# Local destinations (127.x): the copy is handed to lo as a raw packet, with no
# route attached (a normal local send carries one). The kernel then checks it
# like a packet from outside and drops it twice over: a 127.x destination
# (route_localnet) and a local source address (accept_local). Allowing both
# on lo only fixes delivery; it affects only packets that reach lo without a
# route, which does not happen otherwise. The previous values are restored on
# detach.
lo_local_on() {
    local k
    if [ ! -e "$LO_STATE" ]; then
        printf 'route_localnet=%s\naccept_local=%s\n' "$(sysctl -n net.ipv4.conf.lo.route_localnet)" \
            "$(sysctl -n net.ipv4.conf.lo.accept_local)" >"$LO_STATE"
    fi
    for k in route_localnet accept_local; do
        [ "$(sysctl -n "net.ipv4.conf.lo.$k")" = 1 ] || sysctl -qw "net.ipv4.conf.lo.$k=1"
    done
}

lo_local_off() {
    [ -e "$LO_STATE" ] || return 0
    local k v
    for k in route_localnet accept_local; do
        v=$(grep "^$k=" "$LO_STATE" | cut -d= -f2)
        [ -z "$v" ] || sysctl -qw "net.ipv4.conf.lo.$k=$v" || true
    done
    rm -f "$LO_STATE"
}

load_dests() {
    local dests=() groups=() entries=() d j=0 g i n line first=""
    IFS=, read -ra dests <<<"$1"
    [ ${#dests[@]} -ge 1 ] || { echo "no destinations" >&2; return 1; }
    # Before any local copy is sent (see lo_local_on).
    if [[ ",$1" == *,127.* ]]; then
        lo_local_on
        echo "local destinations: lo route_localnet=1 accept_local=1 (restored on detach)"
    fi
    for ((g = 0; g < KFAN_GROUPS; g++)); do groups[g]=""; done
    for d in "${dests[@]}"; do
        line=$(resolve "$d" "$j") || return 1
        g=$((j % KFAN_GROUPS))
        groups[g]+="$line"$'\n'
        j=$((j + 1))
    done
    for ((g = KFAN_GROUPS - 1; g >= 0; g--)); do
        mapfile -t entries < <(printf '%s' "${groups[$g]}" | sort -s -n -k1,1 | cut -d' ' -f2-)
        n=${#entries[@]}
        [ "$n" -le $PER_GROUP ] || { echo "group $g has $n destinations, max $PER_GROUP" >&2; return 1; }
        for ((i = (g == 0 ? 1 : 0); i < n; i++)); do
            bpftool map update name kfan_dests key hex $(hex_le32 $((g * PER_GROUP + i))) value hex ${entries[$i]}
        done
        if [ "$n" -lt $PER_GROUP ]; then
            bpftool map update name kfan_dests key hex $(hex_le32 $((g * PER_GROUP + n))) value hex $(printf '00 %.0s' $(seq 28))
        fi
        if [ "$g" -eq 0 ]; then first=${entries[0]}; fi
    done
    bpftool map update name kfan_dests key hex $(hex_le32 0) value hex $first
    echo "loaded ${#dests[@]} destinations in $KFAN_GROUPS group(s)$(if [ "$DIRECT" = 1 ]; then echo ", direct to NIC ports"; fi)"
}

# Multi-CPU fan-out: steer DEV rx queue 0 (only our re-injected carriers use
# it) to KFAN_CPUS, and make sure each CPU's hand-off queue is large enough.
# Saves the previous values for detach.
steer_on() {
    local mask_file="/sys/class/net/$DEV/queues/rx-0/rps_cpus" mask
    [ -e "$mask_file" ] || { echo "$mask_file missing (RPS not available?)" >&2; return 1; }
    mask=$(python3 -c '
import sys
m = 0
for c in sys.argv[1].split(","):
    m |= 1 << int(c)
h = format(m, "x")
h = h.zfill((len(h) + 7) // 8 * 8)
print(",".join(h[i:i + 8] for i in range(0, len(h), 8)))' "$KFAN_CPUS")
    # Keep the original values if a previous run left its state behind.
    [ -e "$STATE" ] || printf 'rps=%s\nbacklog=%s\n' "$(cat "$mask_file")" "$(sysctl -n net.core.netdev_max_backlog)" >"$STATE"
    echo "$mask" >"$mask_file"
    if [ "$(sysctl -n net.core.netdev_max_backlog)" -lt 10000 ]; then
        sysctl -qw net.core.netdev_max_backlog=10000
    fi
    echo "groups 1..$((KFAN_GROUPS - 1)) on CPUs $KFAN_CPUS (rps mask $mask on $DEV rx-0); netdev_max_backlog $(sysctl -n net.core.netdev_max_backlog)"
}

steer_off() {
    [ -e "$STATE" ] || return 0
    local rps backlog
    rps=$(grep '^rps=' "$STATE" | cut -d= -f2)
    backlog=$(grep '^backlog=' "$STATE" | cut -d= -f2)
    echo "${rps:-0}" >"/sys/class/net/$DEV/queues/rx-0/rps_cpus" || true
    if [ -n "$backlog" ]; then sysctl -qw net.core.netdev_max_backlog="$backlog" || true; fi
    rm -f "$STATE"
    echo "restored rps on $DEV rx-0 and netdev_max_backlog"
}

# One line of counters with the change since the previous call (for the logs).
log_counters() {
    bpftool -j map dump name kfan_stats 2>/dev/null | python3 -c '
import json, sys
names = ["first", "dup", "short", "error", "no_dests", "sent", "refused", "ignored",
         "carried", "carry_fail", "stamped", "stamp_noxdp", "lat_noxdp", "xdp_checked"]
show = ["first", "dup", "sent", "refused", "no_dests", "error", "short"]
def num(v):
    return v if isinstance(v, int) else int.from_bytes(bytes(int(b, 16) for b in v), "little")
try:
    rows = json.load(sys.stdin)
except ValueError:
    sys.exit("counters unavailable")
tot = {}
for r in rows:
    r = r.get("formatted", r)
    tot[names[num(r["key"])]] = sum(num(v["value"]) for v in r["values"])
prev_file = "/run/fanout-kfan.counters"
try:
    prev = json.load(open(prev_file))
except (OSError, ValueError):
    prev = {}
# Duplicates dropped earlier, at the NIC driver, by xdpstamp (if loaded with DEDUP=1).
import subprocess
try:
    xs = json.loads(subprocess.run(["bpftool", "-j", "map", "dump", "name", "xdps_stats"],
                                   capture_output=True, text=True).stdout or "[]")
    for r in xs:
        if num(r["key"]) == 2:
            tot["xdp_dup"] = sum(num(v["value"]) for v in r["values"])
except (ValueError, KeyError):
    pass
if tot.get("xdp_checked", 0) or "xdp_dup" in tot:
    show[2:2] = ["xdp_dup", "xdp_checked"]
json.dump(tot, open(prev_file, "w"))
line = " ".join(f"{k}=+{tot.get(k, 0) - prev.get(k, 0)}" for k in show)
bad = [k for k in ("refused", "no_dests", "error") if tot.get(k, 0) - prev.get(k, 0) > 0]
print(("WARNING " + ",".join(bad) + " increasing | " if bad else "") + line)
'
}

# Reloads the table whenever the set of active bond ports changes, and
# re-resolves MACs every REFRESH_S seconds. Runs until interrupted.
watch_ports() {
    local dests=$1 last="" now t=0 lt=0 out
    ours || { echo "kfan is not attached" >&2; exit 1; }
    while true; do
        now=$(for b in /sys/class/net/*/bonding; do ports_of "$(basename "$(dirname "$b")")"; done | sort | paste -sd,)
        if [ "$now" != "$last" ] || [ $t -ge "${REFRESH_S:-60}" ]; then
            [ -n "$last" ] && [ "$now" != "$last" ] && echo "$(date +%T) active ports changed: $last -> $now"
            # Routine MAC refreshes stay quiet; port changes and failures are logged.
            if out=$(load_dests "$dests" 2>&1); then
                [ -n "$last" ] && [ "$now" != "$last" ] && echo "$(date +%T) $(tail -1 <<<"$out")"
            else
                echo "$(date +%T) reload failed, keeping the previous table: $(tail -1 <<<"$out")" >&2
            fi
            last=$now
            t=0
        fi
        sleep 1
        t=$((t + 1))
        lt=$((lt + 1))
        if [ "${LOG_S:-0}" -gt 0 ] && [ $lt -ge "$LOG_S" ]; then
            echo "$(date +%T) $(log_counters)"
            lt=0
        fi
    done
}

attach() {
    [ $# -eq 2 ] || { echo "usage: kfan.sh attach PORTS DESTS" >&2; exit 1; }
    attached && { echo "a filter is already attached on $DEV (pref $PREF); detach it first" >&2; exit 1; }
    [[ "$KFAN_GROUPS" =~ ^[1-4]$ ]] || { echo "KFAN_GROUPS must be 1..4" >&2; exit 1; }
    if [ "$KFAN_GROUPS" -gt 1 ] && [ "$(tr ',' '\n' <<<"$KFAN_CPUS" | grep -c .)" -ne $((KFAN_GROUPS - 1)) ]; then
        echo "KFAN_CPUS must list exactly $((KFAN_GROUPS - 1)) CPUs for KFAN_GROUPS=$KFAN_GROUPS" >&2
        exit 1
    fi
    build "$1"
    tc qdisc show dev "$DEV" | grep -q clsact || tc qdisc add dev "$DEV" clsact
    tc filter add dev "$DEV" ingress pref "$PREF" handle 1 bpf direct-action obj "$OBJ" sec tc
    echo "attached on $DEV ingress for ports $1${DROP_PORTS:+, dropping $DROP_PORTS} (passing everything until destinations load)"
    if [ "$KFAN_GROUPS" -gt 1 ] && ! steer_on; then
        echo "CPU steering failed; detaching" >&2
        detach
        exit 1
    fi
    if ! load_dests "$2"; then
        echo "destination load failed; detaching" >&2
        detach
        exit 1
    fi
}

# Service mode: always attach a freshly built program (so config changes take
# effect), keep the table current, detach on stop. While detached the
# proxies forward as before.
run() {
    [ $# -eq 2 ] || { echo "usage: kfan.sh run PORTS DESTS" >&2; exit 1; }
    if ours; then
        echo "replacing the attached kfan program"
        tc filter del dev "$DEV" ingress pref "$PREF"
    fi
    attach "$1" "$2"
    trap 'echo "stopping"; detach; exit 0' TERM INT
    LOG_S=${LOG_S:-60}
    log_counters >/dev/null || true
    watch_ports "$2"
}

# Compares DESTS with the destinations of every running process that has
# --dest-ip-ports or DEST_IP_PORTS (the proxies). Prints nothing else of
# their command lines or environments.
check_dests() {
    python3 - "$1" <<'EOF'
import os, sys

want = {d for d in sys.argv[1].split(",") if d}
found = 0
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        args = open(f"/proc/{pid}/cmdline", "rb").read().decode(errors="replace").split("\0")
        env = open(f"/proc/{pid}/environ", "rb").read().decode(errors="replace").split("\0")
    except OSError:
        continue
    val = None
    for i, a in enumerate(args):
        if a == "--dest-ip-ports" and i + 1 < len(args):
            val = args[i + 1]
        elif a.startswith("--dest-ip-ports="):
            val = a.split("=", 1)[1]
    if val is None:
        val = next((e.split("=", 1)[1] for e in env if e.startswith("DEST_IP_PORTS=")), None)
    if val is None:
        continue
    found += 1
    have = {d for d in val.split(",") if d}
    name = os.path.basename(args[0]) if args and args[0] else "?"
    only_proxy, only_kfan = sorted(have - want), sorted(want - have)
    if not only_proxy and not only_kfan:
        print(f"pid {pid} ({name}): same {len(have)} destinations")
    else:
        print(f"pid {pid} ({name}): DIFFERENT")
        for d in only_proxy:
            print(f"  only in the proxy: {d}")
        for d in only_kfan:
            print(f"  only in DESTS:     {d}")
if not found:
    print("no running process with --dest-ip-ports / DEST_IP_PORTS found")
EOF
}

# Dry run of load_dests: prints how each destination would be sent.
resolve_all() {
    local d j=0 bad=0
    IFS=, read -ra all <<<"$1"
    for d in "${all[@]}"; do
        resolve "$d" "$j" >/dev/null || bad=$((bad + 1))
        j=$((j + 1))
    done
    [ "$bad" -eq 0 ] || { echo "$bad of ${#all[@]} destinations could not be resolved" >&2; return 1; }
    echo "all ${#all[@]} destinations resolve"
}

latency() {
    ours || { echo "kfan is not attached" >&2; exit 1; }
    python3 "$DIR/kfan_latency.py" "$@"
}

refresh() {
    ours || { echo "kfan is not attached" >&2; exit 1; }
    load_dests "$1"
}

detach() {
    if attached; then
        tc filter del dev "$DEV" ingress pref "$PREF"
        echo "detached from $DEV"
    else
        echo "not attached"
    fi
    steer_off
    lo_local_off
}

counters() {
    bpftool -j map dump name kfan_stats 2>/dev/null | python3 -c '
import json, sys
names = ["first copies", "duplicates (dropped)", "too short (passed)", "dedup error (passed)",
         "no destinations (passed)", "copies sent", "copies refused", "ignored port (dropped)",
         "carriers to other CPUs", "carriers refused", "stamped copies", "stamped without XDP time",
         "latency: no XDP time (left out)", "first copies deduplicated by XDP"]
def num(v):
    return v if isinstance(v, int) else int.from_bytes(bytes(int(b, 16) for b in v), "little")
try:
    rows = json.load(sys.stdin)
except ValueError:
    sys.exit("no counters (not attached?)")
per_cpu = {}
for r in rows:
    r = r.get("formatted", r)
    total = sum(num(v["value"]) for v in r["values"])
    key = num(r["key"])
    print(f"  {names[key]:<26} {total}")
    if names[key] == "copies sent":
        per_cpu = {v["cpu"]: num(v["value"]) for v in r["values"] if num(v["value"])}
if per_cpu:
    busiest = sorted(per_cpu.items(), key=lambda kv: -kv[1])[:8]
    print("  copies sent by CPU:       " + ", ".join(f"{c}:{n}" for c, n in busiest))
'
}

status() {
    if ours; then
        echo "kfan attached on $DEV ingress (pref $PREF)"
        counters
    elif attached; then
        echo "another filter (dedup?) is attached on $DEV at pref $PREF"
    else
        echo "not attached"
    fi
}

cost() {
    local secs=${1:-10} prev t0 c0 t1 c1
    ours || { echo "kfan is not attached" >&2; exit 1; }
    prev=$(sysctl -n kernel.bpf_stats_enabled)
    sysctl -qw kernel.bpf_stats_enabled=1
    read_stats() { bpftool -j prog show name kfan | python3 -c '
import json, sys
p = json.load(sys.stdin)
p = p[0] if isinstance(p, list) else p
print(p.get("run_time_ns", 0), p.get("run_cnt", 0))'; }
    read -r t0 c0 < <(read_stats)
    sleep "$secs"
    read -r t1 c1 < <(read_stats)
    sysctl -qw kernel.bpf_stats_enabled="$prev"
    python3 -c "
runs = $c1 - $c0
ns = $t1 - $t0
print(f'{runs} packets in ${secs}s, {ns / max(runs, 1):.0f} ns of kernel CPU per packet on average, {ns / 1e9 / $secs * 100:.2f}% of one core in total')"
}

case "${1:-}" in
    attach) shift; attach "$@" ;;
    refresh) shift; refresh "$@" ;;
    detach) detach ;;
    status) status ;;
    cost) shift; cost "$@" ;;
    watch) shift; watch_ports "$@" ;;
    run) shift; run "$@" ;;
    build) shift; [ $# -eq 1 ] || { echo "usage: kfan.sh build PORTS" >&2; exit 1; }; build "$1"; echo "built $OBJ" ;;
    resolve) shift; [ $# -eq 1 ] || { echo "usage: kfan.sh resolve DESTS" >&2; exit 1; }; resolve_all "$1" ;;
    check-dests) shift; check_dests "$@" ;;
    latency) shift; latency "$@" ;;
    *) sed -n '2,37p' "$0"; exit 1 ;;
esac
