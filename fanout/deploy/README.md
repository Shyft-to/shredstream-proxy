# Kernel shred fan-out: runbook

One eBPF program on `bond0` receive (tc ingress) takes every shred arriving
on the watched ports, drops later copies of the same shred (the three sources
deliver ~99% of shreds three times), and sends the first copy straight to
every destination on the bond's physical ports. The proxies keep running but
receive nothing on these ports while it is attached.

**Fail-open:** stopped, crashed, or with an empty destination table, the
program is detached or passes everything on, and the proxies forward exactly
as before, within milliseconds. Destinations deduplicate, so a short overlap
during switch-over is harmless.

Measured on a real receiver (2026-10-16, see `progress/chapter-03`):
first arrival on the server → receiver p50 ~53 µs, p99 ~93 µs.

## Files

| Path | What |
|---|---|
| `/etc/shred-fanout/kfan.env` | ports, destinations, options |
| `/opt/shred-fanout/` | installed `kfan.sh` and `kfan.bpf.c` (built at start) |
| `shred-kfan.service` | attaches, keeps MACs / bond ports current, logs counters every 60 s |

## Operate

```bash
sudo systemctl status shred-kfan
sudo journalctl -u shred-kfan -f                 # counters every 60 s; WARNING lines on trouble
sudo /opt/shred-fanout/scripts/kfan.sh status    # totals, copies per CPU
sudo systemctl stop shred-kfan                   # roll back: proxies forward again at once
```

Healthy log line: `first=+N dup=+M sent=+15·N refused=+0 no_dests=+0 error=+0`.
A `WARNING` line means copies are being refused (`refused`), shreds are going
to the proxies because the table is empty (`no_dests`), or the dedup table
failed (`error`).

## Change the destinations

1. Edit `DESTS` in `/etc/shred-fanout/kfan.env` (same list as the proxies).
2. `sudo /opt/shred-fanout/scripts/kfan.sh check-dests "$(. /etc/shred-fanout/kfan.env; echo $DESTS)"`
3. `sudo systemctl restart shred-kfan`

## Update the code

```bash
cd /root/fanout-opt && git pull && sudo fanout/deploy/install.sh
sudo systemctl restart shred-kfan
```

## Notes

- A destination whose next-hop MAC cannot be resolved makes the start fail
  (the service retries every 10 s; the proxies forward meanwhile). At
  runtime a failed refresh keeps the previous table.
- When a bond port goes down, the table is reloaded within ~1 s onto the
  remaining port; copies sent to the failed port in that second are lost
  (the proxies' copies are not sent while attached).
- Destinations the proxies discover dynamically (`--endpoint-discovery-url`)
  are not followed: the list here is static.
