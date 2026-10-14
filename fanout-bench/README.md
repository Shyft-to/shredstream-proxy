# fanout-bench

Measures how fast a UDP forwarder fans shreds out to its destinations, the same
way for every implementation (current proxy, a rewrite, eBPF), on synthetic
replays and on live production traffic.

## North star

**p99 fan-out completion latency (µs), lower is better.**

For each unique shred: the time from its **first arrival** at the forwarder
host to the moment its copy for the **last** destination is handed to the
network device. Reported at p99 over all shreds in the window.

- **Why completion (last destination):** fan-out cost shows up as the slowest
  destination waiting behind the others. Per-send averages hide that.
- **Why p99:** shreds arrive in bursts (~20 packets ~80 µs apart). Later
  packets in a burst queue behind earlier ones, so the tail is where the
  forwarder's design shows. A good mean can hide a bad tail.
- **Why first arrival:** with several sources, the shred is available as soon
  as the first copy lands. Dedup and the later copies must not delay it.
- **How it is measured:** kernel packet-tap timestamps on the forwarder host
  (`tcpdump`, nanosecond precision), matched by shred identity (the first 83
  payload bytes: signature, variant, slot, index, version, FEC set index).
  Nothing in the forwarder is instrumented, so implementations compare fairly.

### Guardrails (a change must not trade these for latency)

| Guardrail | Rule |
|---|---|
| Delivery ratio | Sends seen / sends expected. Must not drop more than 0.05 points below baseline. It is not exactly 100% today: the proxy's deduper has a 0.1% false-positive rate. |
| Duplicate sends | The same shred sent twice to one destination. Must be 0. |
| CPU cost | Forwarder CPU µs per send. Reported, to weigh against the latency gain. |

### Secondary readings

- `first_dest`: first arrival to first destination. Isolates the receive path
  (wakeup, dedup) from fan-out.
- Per-destination p99: shows whether some destinations are always served last.

### What it does not see

- Time before the kernel stack sees the packet (NIC interrupt coalescing, IRQ
  delivery). The `rx-usecs` change will not show up here. i40e has no
  hardware timestamps for all packets.
- Wire time and the receivers' own processing.
- The capture itself adds a little per-packet cost. It is the same for every
  candidate, so comparisons stay fair; absolute numbers are slightly
  pessimistic.

## Tools

| Binary | Does |
|---|---|
| `fanout-measure analyze` | Computes the north star and guardrails from captures; appends a JSON line per run. |
| `fanout-measure compare` | Compares two labels and gives a verdict. |
| `shred-replay` | Replays a capture at its original timing, keeping each source separate. |
| `udp-sink` | Receives and discards; stands in for destinations. |

| Script | Does |
|---|---|
| `scripts/testbed.sh` | Isolated lab in three network namespaces. Never touches the host network. |
| `scripts/probe.sh` | Production: passive north-star measurement of a live instance, and corpus capture. |
| `scripts/profile.sh` | Profiling a live instance: per-stage latency histograms (`stages`, via `stages.bt`) and CPU by function (`cpu`, via `perf`). |

## Workflow

Build on the server (all commands as root):

```bash
cargo build --release -p fanout-bench
chmod +x fanout-bench/scripts/*.sh
```

1. **Record a corpus** of real ingress, once (and again if traffic changes shape):
   ```bash
   sudo fanout-bench/scripts/probe.sh corpus 5544 30 ./corpus.pcap
   ```
2. **Production baseline** for each instance, several times across the day:
   ```bash
   sudo fanout-bench/scripts/probe.sh measure 5544 10
   ```
3. **Lab baseline** of the current build, 5 runs:
   ```bash
   sudo fanout-bench/scripts/testbed.sh setup
   sudo fanout-bench/scripts/testbed.sh run baseline 5 -- \
     ./target/release/jito-shredstream-proxy forward-only --src-bind-port {LISTEN} \
     --dest-ip-ports {DESTS} --public-ip 198.18.1.254
   ```
4. **Every candidate change**: same corpus, same cores, 5 runs, then compare:
   ```bash
   sudo fanout-bench/scripts/testbed.sh run candidate-x 5 -- <command with {LISTEN} {DESTS}>
   sudo fanout-bench/scripts/testbed.sh compare baseline candidate-x
   ```
5. **Confirm in production** only if the lab says IMPROVED: deploy on one
   instance, run `probe.sh measure` before and after, compare.

### Decision rule

`compare` reports the median and range of the metric over the runs for each
label:

- **IMPROVED**: every candidate run beat every baseline run. With 5 runs each,
  the chance of that happening when the change does nothing is 1 in 252 (0.4%).
- **REGRESSED**: every candidate run was worse.
- **NO SIGNIFICANT CHANGE**: the ranges overlap. The change did not move the
  north star beyond run-to-run noise.

Runs are excluded when `tcpdump` dropped packets or the replayer ran more than
50 µs (p99) behind schedule, because then the measurement or the input was not
faithful.

## Test bed layout

```
fb-src (replayer)  --veth-->  fb-fwd (forwarder under test)  --veth-->  fb-sink (N receivers)
198.18.1.1-4                  198.18.1.254 | 198.19.0.254                198.19.0.1..N
```

Defaults: 20 destinations, forwarder on cores 30-33, replayer 34, sink 35,
tcpdump 36. Override with `DESTS_N`, `FWD_CPUS`, `REPLAY_CPU`, `SINK_CPU`,
`TCPDUMP_CPU`. Pick cores that are idle on the host (`mpstat -P ALL 5`), and
keep them the same for every run you intend to compare.
