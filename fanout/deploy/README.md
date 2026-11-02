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

Measured on the first server (2026-10-16/19, box probe, 15 destinations,
see `progress/`): first arrival → last copy leaves p50 ~82 µs, p99 ~245 µs;
delivery 100%, no duplicate sends, ~0.2 core. Before (3 proxies): p50
321 µs, p99 5.4 ms, ~8 cores.

## Version 1

v1 is `shred-kfan.service` with DIRECT=1 and its own duplicate dropping.
Not part of v1 (measurement / experiments; leave them off on new servers):
`xdpstamp.sh`, `LAT_HIST`, `STAMP_PORT`, the AF_XDP forwarder (`fanout/xsk`),
and any `gro_normal_batch` change.

## Deploy to a new server

1. **Prerequisites:** the proxies (one per source port) run and forward to
   the destinations; `sudo apt install -y clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r)`
   (for `bpftool`); a checkout of the `fanout-opt` branch.
   Survey (read-only): `sudo fanout/deploy/survey.sh`. It finds the proxies,
   their ports and destinations, dead destinations, the arrival device and
   anything already attached, and prints a draft `kfan.env`.
   Baseline: see "Benchmark before and after" below, before any change.
2. **Configure:**
   `sudo mkdir -p /etc/shred-fanout && sudo cp fanout/deploy/kfan.env.example /etc/shred-fanout/kfan.env`,
   then set `PORTS` (the source ports), `DESTS` (exactly the proxies'
   `--dest-ip-ports`) and `DEV` (the bond or interface the shreds arrive on)
   from the survey's draft. The example's `DESTS` are the first server's.
3. **Check (read-only):** `sudo fanout/deploy/preflight.sh`. It compares the
   destinations with the running proxies, resolves every next hop, and passes
   the program through this kernel's verifier without attaching it. Do not
   go on with any FAIL; read every WARN.
4. **Install and start:** `sudo fanout/deploy/install.sh && sudo systemctl start shred-kfan`.
5. **Verify within the first minutes:**
   - journal (`sudo journalctl -u shred-kfan -f`): `loaded N destinations`;
     after 60 s `sent` ≈ N × `first`, `refused` / `no_dests` / `error` +0;
   - **every local destination (127.x) receives data, checked at the
     consuming service itself** (a capture cannot show this);
   - the proxies' CPU drops (they no longer receive the shreds).
   - Problem → `sudo systemctl stop shred-kfan` (proxies forward again at once).
6. **After an hour without problems:** `sudo systemctl enable shred-kfan`.

## Benchmark before and after

Same method as the first server's numbers above (box probe: first arrival on
any port → each destination's copy leaving the box, from captures). Needs
`tcpdump` and the probe built once:
`cargo build --release -p fanout-bench && chmod +x fanout-bench/scripts/*.sh`.

```bash
# PORTS from the survey; 6 runs of 60 s, 10 min apart (about an hour). Use tmux.
for i in 1 2 3 4 5 6; do
  sudo OUT=/root/bench-results fanout-bench/scripts/probe.sh box "$PORTS" 60 baseline
  [ $i = 6 ] || sleep 540
done
```

After the switch, the same loop with label `kfan`, plus the program's own
CPU (`sudo /opt/shred-fanout/scripts/kfan.sh cost 20`; the probe only counts
the proxies' CPU). Then:

```bash
target/release/fanout-measure compare --results /root/bench-results/box-results.jsonl \
  --baseline baseline --candidate kfan
```

Runs before and after are not interleaved, so compare the number of shreds
in each report (same 60 s window): a much quieter or busier hour skews the
result.

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

- **Local destinations (127.x):** the copy is handed to `lo` without a route,
  which the kernel drops unless `net.ipv4.conf.lo.route_localnet=1` and
  `net.ipv4.conf.lo.accept_local=1`. kfan.sh sets both (on `lo` only) when
  DESTS has a 127.x entry and restores them on stop. A capture on `lo` shows
  these copies even when they are dropped, so check delivery at the consuming
  service itself.

- A destination whose next-hop MAC cannot be resolved makes the start fail
  (the service retries every 10 s; the proxies forward meanwhile). At
  runtime a failed refresh keeps the previous table.
- When a bond port goes down, the table is reloaded within ~1 s onto the
  remaining port; copies sent to the failed port in that second are lost
  (the proxies' copies are not sent while attached).
- Destinations the proxies discover dynamically (`--endpoint-discovery-url`)
  are not followed: the list here is static.
