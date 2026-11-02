#!/usr/bin/env bash
# Read-only survey of a server before the kernel fan-out goes on it: what the
# proxies listen on and forward to, how the shreds arrive, the state of every
# destination, and anything already attached. Ends with a draft kfan.env.
# Changes nothing (no ping, no attach, no sysctl); the only active step is a
# 3 s passive capture per port to see which interface the shreds arrive on.
# Run as root from the repository:
#
#   sudo fanout/deploy/survey.sh
#
# Prints PASS / WARN / FAIL / INFO lines; paste the whole output for review.
set -uo pipefail

warns=0 fails=0
pass() { echo "PASS  $*"; }
warn() { echo "WARN  $*"; warns=$((warns + 1)); }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
info() { echo "INFO  $*"; }
indent() { sed 's/^/        /'; }

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 2; }

echo "== host"
info "$(hostname), kernel $(uname -r), $(nproc) CPUs, $(uptime -p 2>/dev/null || uptime)"
info "git $(git -C "$(dirname "$0")" rev-parse --short HEAD 2>/dev/null || echo unknown)"

echo "== tools"
missing=""
for t in clang bpftool tc python3 ip ethtool tcpdump nstat cargo; do command -v "$t" >/dev/null || missing+=" $t"; done
if [ -z "$missing" ]; then pass "tools: all present"; else warn "missing:$missing (kfan: clang bpftool tc python3; probe: tcpdump nstat cargo)"; fi
[ -e /usr/include/bpf/bpf_helpers.h ] || [ -e /usr/include/x86_64-linux-gnu/bpf/bpf_helpers.h ] ||
    warn "libbpf headers missing (apt install libbpf-dev)"
command -v python3 >/dev/null || { fail "python3 is needed for the rest of this survey"; exit 1; }

# One line per proxy: pid|name|unit|listen port|dests|discovery url|cpu % over 5 s.
echo "== proxies (processes with --dest-ip-ports / DEST_IP_PORTS)"
proxies=$(python3 - <<'EOF'
import os, time

def arg(args, env, name, var):
    val = None
    for i, a in enumerate(args):
        if a == name and i + 1 < len(args):
            val = args[i + 1]
        elif a.startswith(name + "="):
            val = a.split("=", 1)[1]
    if val is None:
        val = next((e.split("=", 1)[1] for e in env if e.startswith(var + "=")), None)
    return val

def cpu(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])

found = []
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        args = open(f"/proc/{pid}/cmdline", "rb").read().decode(errors="replace").split("\0")
        env = open(f"/proc/{pid}/environ", "rb").read().decode(errors="replace").split("\0")
        cg = open(f"/proc/{pid}/cgroup").read()
    except OSError:
        continue
    dests = arg(args, env, "--dest-ip-ports", "DEST_IP_PORTS")
    if dests is None:
        continue
    port = arg(args, env, "--src-bind-port", "SRC_BIND_PORT") or "20000"
    disc = arg(args, env, "--endpoint-discovery-url", "ENDPOINT_DISCOVERY_URL") or ""
    unit = next((p for p in cg.strip().split("/") if p.endswith(".service")), "-")
    found.append([pid, os.path.basename(args[0]), unit, port, dests, disc])

hz = os.sysconf("SC_CLK_TCK")
c0 = {p[0]: cpu(p[0]) for p in found}
time.sleep(5)
for p in found:
    try:
        pct = (cpu(p[0]) - c0[p[0]]) / hz / 5 * 100
    except OSError:
        pct = -1
    print("|".join(p + [f"{pct:.0f}"]))
EOF
)
if [ -z "$proxies" ]; then
    fail "no proxy found; nothing to take over"
    exit 1
fi
ports="" all_dests="" first_list=""
while IFS='|' read -r pid name unit port dests disc pct; do
    n=$(tr ',' '\n' <<<"$dests" | grep -c .)
    if ss -ulnH "sport = :$port" | grep -q .; then lst="listening"; else lst="NOT listening"; fi
    info "pid $pid $name ($unit): port $port $lst, $n destinations, CPU ${pct}% of a core"
    dups=$(tr ',' '\n' <<<"$dests" | grep . | sort | uniq -d | paste -sd' ')
    [ -z "$dups" ] || warn "pid $pid lists these destinations more than once (each copy is sent again): $dups"
    [ -z "$disc" ] || warn "pid $pid also discovers destinations from $disc; kfan only follows the static list"
    ports+=",$port"
    sorted=$(tr ',' '\n' <<<"$dests" | grep . | sort -u | paste -sd,)
    if [ -z "$first_list" ]; then
        first_list=$sorted
    elif [ "$sorted" != "$first_list" ]; then
        warn "pid $pid forwards to a different destination list than the first proxy:"
        diff <(tr ',' '\n' <<<"$first_list") <(tr ',' '\n' <<<"$sorted") | grep '^[<>]' | indent
    fi
    # Union, in the order of first appearance.
    for d in ${dests//,/ }; do [[ ",$all_dests," == *",$d,"* ]] || all_dests+=",$d"; done
done <<<"$proxies"
ports=$(tr ',' '\n' <<<"${ports#,}" | grep . | sort -un | paste -sd,)
all_dests=${all_dests#,}
np=$(tr ',' '\n' <<<"$ports" | grep -c .)
nd=$(tr ',' '\n' <<<"$all_dests" | grep -c .)
if [ "$np" -le 4 ]; then pass "$np source ports: $ports"; else fail "$np source ports; kfan handles at most 4"; fi
if [ "$nd" -le 16 ]; then pass "$nd destinations in total"; else fail "$nd destinations; kfan handles at most 16"; fi

echo "== destinations (neighbour state as cached; nothing is probed)"
for d in ${all_dests//,/ }; do
    ip=${d%:*} port=${d#*:}
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        fail "$d: not an IPv4 address; kfan needs IP:port"
        continue
    fi
    if [[ "$ip" == 127.* ]]; then
        if l=$(ss -ulnpH "sport = :$port" | head -1) && [ -n "$l" ]; then
            pass "$d local, listener: $(grep -oP 'users:\(\("\K[^"]+' <<<"$l" || echo '?') on $(awk '{ print $4 }' <<<"$l")"
        else
            warn "$d local, but nothing listens on UDP $port (dead destination: costs latency today)"
        fi
        continue
    fi
    route=$(ip -o route get "$ip" 2>/dev/null) || { fail "$d: no route"; continue; }
    dev=$(grep -oP ' dev \K\S+' <<<"$route")
    via=$(grep -oP ' via \K\S+' <<<"$route" || true)
    nh=${via:-$ip}
    state=$(ip neigh show to "$nh" dev "$dev" | awk '{ print $NF }')
    case "$state" in
        REACHABLE|STALE|DELAY|PROBE|PERMANENT) pass "$d via ${via:-direct} dev $dev, neighbour $state" ;;
        FAILED|INCOMPLETE) warn "$d via ${via:-direct} dev $dev, neighbour $state (dead destination?)" ;;
        *) warn "$d via ${via:-direct} dev $dev, neighbour not cached (kfan resolves it at start)" ;;
    esac
done

echo "== where the shreds arrive (3 s capture per port)"
arrive=""
for p in ${ports//,/ }; do
    ifs=$(timeout 3 tcpdump -i any -nn -c 200 "udp and dst port $p" 2>/dev/null |
        awk 'NF > 2 { print $2 }' | sort | uniq -c | sort -rn | awk '{ printf "%s(%s) ", $2, $1 }')
    info "port $p: ${ifs:-no packets in 3 s}"
    arrive+=" $ifs"
done

echo "== network devices"
dev=""
for b in /sys/class/net/*/bonding; do
    [ -e "$b" ] || continue
    b=$(basename "$(dirname "$b")")
    info "bond $b: mode $(cut -d' ' -f1 <"/sys/class/net/$b/bonding/mode"), ports $(cat "/sys/class/net/$b/bonding/slaves")"
    [[ "$arrive" == *"$b("* ]] && dev=$b
    for s in $(cat "/sys/class/net/$b/bonding/slaves"); do
        drv=$(ethtool -i "$s" 2>/dev/null | awk '/^driver:/ { print $2 }')
        info "  $s: $(cat "/sys/class/net/$s/operstate"), $(cat "/sys/class/net/$s/speed" 2>/dev/null || echo ?) Mb/s, driver ${drv:-?}, rx-usecs $(ethtool -c "$s" 2>/dev/null | awk '/^rx-usecs:/ { print $2 }')"
    done
done
for v in /proc/net/vlan/*; do
    [ "$(basename "$v")" = config ] || [ ! -e "$v" ] && continue
    info "vlan $(basename "$v"): VID $(awk '/VID:/ { print $3 }' "$v") on $(awk '/^Device:/ { print $2 }' "$v")"
done
if [ -z "$dev" ]; then
    # No bond in the capture: the first non-VLAN interface the shreds came in on.
    for i in $arrive; do
        i=${i%%(*}
        [ -e "/sys/class/net/$i" ] || continue  # old tcpdump prints no interface names
        [ -e "/proc/net/vlan/$i" ] && i=$(awk '/^Device:/ { print $2 }' "/proc/net/vlan/$i")
        [ "$i" != lo ] && { dev=$i; break; }
    done
fi
if [ -n "$dev" ]; then pass "shreds arrive on $dev (DEV)"; else warn "could not tell which device the shreds arrive on; set DEV by hand"; fi
info "net.core.gro_normal_batch $(sysctl -n net.core.gro_normal_batch 2>/dev/null || echo ?), netdev_max_backlog $(sysctl -n net.core.netdev_max_backlog)"

echo "== already attached / installed"
if [ -n "$dev" ]; then
    for i in $dev $( [ -e "/sys/class/net/$dev/bonding/slaves" ] && cat "/sys/class/net/$dev/bonding/slaves"); do
        f=$(tc filter show dev "$i" ingress 2>/dev/null)
        if [ -n "$f" ]; then warn "$i has tc ingress filters:"; indent <<<"$f"; else pass "$i: no tc ingress filters"; fi
        ip -d link show dev "$i" | grep -q 'prog/xdp' && warn "$i has an XDP program loaded"
    done
fi
for u in shred-kfan shred-dedup; do
    systemctl list-unit-files "$u.service" 2>/dev/null | grep -q "^$u" &&
        warn "$u.service exists: $(systemctl is-active "$u") / $(systemctl is-enabled "$u")"
done
[ -e /etc/shred-fanout/kfan.env ] && warn "/etc/shred-fanout/kfan.env already exists"

echo "== draft /etc/shred-fanout/kfan.env (check before using)"
echo "PORTS=$ports"
echo "DESTS=$all_dests"
echo "DIRECT=1"
echo "DEV=${dev:-bond0}"
echo "REFRESH_S=60"
echo "LOG_S=60"
echo
echo "RESULT: $fails FAIL, $warns WARN"
[ "$fails" -eq 0 ]
