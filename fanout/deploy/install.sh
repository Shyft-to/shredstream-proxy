#!/usr/bin/env bash
# Installs the kernel shred fan-out as a systemd service (does not start it).
#   /opt/shred-fanout/{scripts/kfan.sh, ebpf/kfan.bpf.c, README.md}
#   /etc/shred-fanout/kfan.env          (only if missing: never overwritten)
#   /etc/systemd/system/shred-kfan.service
# Re-run after a git pull to update the installed copy; then
# `systemctl restart shred-kfan` to load it. Run as root.
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
install -m 0644 "$SRC/ebpf/kfan.bpf.c" "$OPT/ebpf/kfan.bpf.c"
install -m 0644 "$SRC/deploy/README.md" "$OPT/README.md"
if [ -e "$ETC/kfan.env" ]; then
    echo "kept existing $ETC/kfan.env"
else
    install -m 0644 "$SRC/deploy/kfan.env.example" "$ETC/kfan.env"
    echo "wrote $ETC/kfan.env (check DESTS before starting)"
fi
install -m 0644 "$SRC/deploy/shred-kfan.service" /etc/systemd/system/shred-kfan.service
systemctl daemon-reload
echo "installed (git $(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)); not started."
echo "start: systemctl start shred-kfan    boot: systemctl enable shred-kfan"
