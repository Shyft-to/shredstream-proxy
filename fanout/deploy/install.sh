#!/usr/bin/env bash
# Installs the kernel shred fan-out and the kernel dedup as systemd services
# (starts neither; they share a tc hook, so only one runs at a time).
#   /opt/shred-fanout/{scripts/kfan.sh, scripts/dedup.sh, ebpf/*.bpf.c, README.md}
#   /etc/shred-fanout/{kfan,dedup}.env  (only if missing: never overwritten)
#   /etc/systemd/system/shred-{kfan,dedup}.service
# Re-run after a git pull to update the installed copy; then
# `systemctl restart shred-kfan` (or shred-dedup) to load it. Run as root.
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
OPT=/opt/shred-fanout
ETC=/etc/shred-fanout

for tool in clang bpftool tc python3; do
    command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done

install -d "$OPT/scripts" "$OPT/ebpf" "$ETC"
install -m 0755 "$SRC/scripts/kfan.sh" "$OPT/scripts/kfan.sh"
install -m 0755 "$SRC/scripts/kfan_latency.py" "$OPT/scripts/kfan_latency.py"
install -m 0755 "$SRC/scripts/local-check.sh" "$OPT/scripts/local-check.sh"
install -m 0644 "$SRC/ebpf/kfan.bpf.c" "$OPT/ebpf/kfan.bpf.c"
install -m 0755 "$SRC/scripts/dedup.sh" "$OPT/scripts/dedup.sh"
install -m 0644 "$SRC/ebpf/dedup.bpf.c" "$OPT/ebpf/dedup.bpf.c"
install -m 0644 "$SRC/deploy/README.md" "$OPT/README.md"
install -m 0755 "$SRC/deploy/preflight.sh" "$OPT/preflight.sh"
if [ -e "$ETC/kfan.env" ]; then
    echo "kept existing $ETC/kfan.env"
else
    install -m 0644 "$SRC/deploy/kfan.env.example" "$ETC/kfan.env"
    echo "wrote $ETC/kfan.env (check DESTS before starting)"
fi
if [ -e "$ETC/dedup.env" ]; then
    echo "kept existing $ETC/dedup.env"
else
    install -m 0644 "$SRC/deploy/dedup.env.example" "$ETC/dedup.env"
    echo "wrote $ETC/dedup.env (check PORTS, TO_PORT, STANDBY_PORT before starting)"
fi
install -m 0644 "$SRC/deploy/shred-kfan.service" /etc/systemd/system/shred-kfan.service
install -m 0644 "$SRC/deploy/shred-dedup.service" /etc/systemd/system/shred-dedup.service
systemctl daemon-reload
echo "installed (git $(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)); not started."
echo "start: systemctl start shred-kfan  or  shred-dedup (starting one stops the other)"
echo "boot:  systemctl enable one of them, never both"
