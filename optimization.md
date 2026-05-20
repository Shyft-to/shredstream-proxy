# Shredstream-Proxy Fanout Latency — Full Investigation & Decisions

**Status (2026-05-20): investigation complete. The forwarder is NOT the
bottleneck.** A downstream A/B test against a third-party (Triton) feed showed
both the worker-tier (production) build and the experimental sharded+connected
build deliver shreds with essentially identical user-visible latency
(~2.8 ms p50, ~14–15% win rate). The architectural changes are **not being
deployed**. The only change kept is the end-to-end latency metric (this
branch, `run4-metrics`), which is what made that conclusion measurable.

---

## TL;DR

| Question | Answer |
|---|---|
| Did we make the proxy faster internally? | Yes — recv→last-send dropped from ~117 µs (worker-tier) to ~48 µs (sharded+connected) measured end-to-end. |
| Did that help the downstream consumer? | **No.** The inter-host network path is ~2.8 ms; a ~70 µs internal win is below the noise floor. |
| Are we deploying the sharded + connected-socket change? | **No.** Minor invisible gain, real new operational risk (N busy-spin cores per instance). |
| What are we keeping? | The **end-to-end barrier metric** (`avg_end_to_end_us` / `max_end_to_end_us`). It is the only honest measure of proxy-internal latency. |
| Where is the real latency? | Network path / source-and-consumer proximity / single-region ingress. Not in this codebase. |

---

## The problem

`shredstream-proxy` forwards every received shred to every address in
`--dest-ip-ports` plus any addresses from the discovery service. The original
symptom: **end-to-end latency for the last destination grew linearly with the
number of destinations `D`.** The fanout loop was serial on one socket:

```rust
local_dest_sockets.iter().for_each(|dest| {
    let packets_with_dest = batch.iter()
        .filter_map(|pkt| Some((pkt.data(..)?, dest)))
        .collect::<Vec<_>>();      // per-dest heap alloc
    batch_send(send_socket, &packets_with_dest);  // per-dest sendmmsg, serial
});
```

Three costs scaled with `D`: serial sends (dest `i+1` waits for `i`), `D`
syscalls per batch, and `D` heap allocations per batch.

---

## Cost model

End-to-end fanout latency decomposes into competing terms:

```
total ≈ recv_path + dispatch + slowest_sender_send

  dispatch          ≈ N × t_wake          (waking N sender threads, serial on coordinator)
  slowest_send      ≈ t_syscall + (D/N) × t_datagram
```

| Term | Value | Meaning |
|---|---|---|
| `recv_path` | ~3 µs | recv → dedup → Arc wrap |
| `t_wake` | ~1.5 µs | channel send + `FUTEX_WAKE` per parked thread (serial on coordinator) |
| `t_syscall` | ~2 µs | `sendmmsg` entry/exit, amortized over the batch |
| `t_datagram` | ~4 µs unconnected / ~1 µs connected | per-(packet,dest) in-kernel work (route lookup, skb alloc, NIC queue) |

The two movable terms (`N × t_wake` and `(D/N) × t_datagram`) only **move work
around**. The only levers that shrink the *total* in-kernel send work are
connected sockets (route-lookup caching) and `io_uring`. Everything else is
re-balancing dispatch cost against per-sender send cost.

---

## What we measured — run-by-run

(Full per-window data and charts live in the dashboard,
`fanout_optimization.html`, on the `opt_1_1` branch. Summary below.)

| Run | Date | Build | avg_total_us | avg_worker_send_us | avg_end_to_end_us | Notes |
|---|---|---|---|---|---|---|
| 1 | 05-12 | master, no opt | — | — | — | baseline |
| 2 | 05-12 | opt 1+2+3 | — | — | — | initial worker-tier |
| 3–4 | 05-12 | parallel worker dispatch | ~33 µs | ~6 µs | (no e2e metric yet) | D parked workers |
| 5 | 05-14 | opt 1.1–1.4 on worker-tier | **~33 µs** | ~6 µs | — | **the deployed baseline**. `avg_fanout_dispatch_us` ~30 µs = `D × FUTEX_WAKE` |
| 6a | 05-14 | flat single `batch_send`, no workers | ~105 µs | — | — | **REGRESSED** — serialized all kernel send work |
| 6b | 05-15 | Strategy 1: busy-spin per-dest workers | ~7 µs | ~10 µs | — | mean win, but 27 spinners on 32 cores → tail blow-up (`max_worker_send_us` 3–8 ms) |
| 7 | 05-16 | Strategy 3: sharded busy-spin pool N=8 | ~2 µs | ~17 µs | — | lab: end-to-end ~19 µs (est.), tails 4–10× better than 6b, 8 cores pinned |
| 8 | 05-16 | Strategy 3, PRODUCTION, 2 co-located instances | ~2 µs | ~19 µs | — | tails degraded (16 spinners on 32 cores → CPU contention) |
| 9 | 05-18 | **sharded + connected sockets + e2e barrier** | ~3 µs | ~21 µs | **~48 µs** | first honest e2e number. Connected sockets net-neutral at P=1 |
| 10 | 05-18 | **worker-tier + e2e barrier** (this branch) | ~33 µs | ~7 µs | **~117 µs** | honest e2e for the production architecture |

The decisive comparison is **Run 9 vs Run 10**: the sharded+connected build is
~2.4× faster end-to-end (48 µs vs 117 µs). Real, but see "the decisive
finding" below.

---

## Optimizations — tried, kept, rejected

### TRIED & REVERTED (no measurable gain or regressed)

| # | Optimization | Why reverted |
|---|---|---|
| 1.1–1.4 | Micro-opts on dedup / stats / reconstruct-clone / dispatch container | Each targeted <2 µs of a ~30 µs path; all already ~0 µs at 1 packet/batch. No measurable gain. |
| — | Single flat `batch_send`, no worker threads | **Regressed to ~105 µs** (Run 6a). Collapsing all sends to one thread serializes the in-kernel work; worker parallelism is load-bearing. |
| — | Strategy 1: pure busy-spin per-destination workers (D spinners) | Mean improved (Run 6b) but D=27 spinners on a 32-core box oversubscribed the CPU → tail latency 3–8 ms. Superseded by the N-shard pool. |

### TRIED & WORKS, but NOT DEPLOYED (the experiment, on `opt_1_1`)

| # | Optimization | Result | Why not deployed |
|---|---|---|---|
| — | Strategy 3: fixed N-shard busy-spin pool (`N = available_parallelism/4`, clamp 2–16) | Run 7: end-to-end ~19 µs lab, tails 4–10× better than per-dest spin | Real internal win, BUT see "the decisive finding". |
| — | Connected sockets (one connected `UdpSocket` per dest per shard, custom `sendmmsg(msg_name=NULL)`) | Run 9: e2e ~48 µs. **Net-neutral at P=1** — the per-syscall overhead of one `sendmmsg` per dest cancels the ~3 µs/datagram route-lookup saving | Marginal even internally; would pay off only at P>1, which is rare in this workload. |

The sharded+connected build also carries **operational risk**: each instance
spawns N busy-spin threads at 100% CPU. Four instances on a 32-core box = 32
pinned cores → scheduler preemption, tail blow-up, cloud CPU throttling, power
draw, and co-tenant starvation. The `compute_send_shards()` heuristic assumes
one instance per machine and does not coordinate across co-located instances.

### TRIED & KEPT

| # | Optimization | Status |
|---|---|---|
| — | **End-to-end barrier metric** (`BatchTrace` + per-sender `AcqRel fetch_sub`; last sender records `recv → its sendmmsg returned`) | **Kept on `run4-metrics`.** The only honest proxy-internal latency measure. Emitted as `avg_end_to_end_us` / `max_end_to_end_us` / `e2e_batches`, gated on `forwarder=trace`. |

### NOT TRIED (with reasons)

| Optimization | Reason not pursued |
|---|---|
| `UDP_GSO` / `UDP_SEGMENT` | Wrong shape. GSO splits one buffer into MTU-sized datagrams to **one** destination; shreds go to **many** destinations. Doesn't fit fanout. |
| Larger `SO_SNDBUF` | Mitigates a downstream amplifier (send-buffer-full blocking under burst), not the root cause. Worth it only if `worker_dropped_batches > 0` is observed; it isn't. |
| Compiler flags (`lto="fat"`, `codegen-units=1`, `target-cpu=native`) + mimalloc | ~5–15% across the board, but multiplicative on a path that's already invisible downstream. Not worth the build/deploy churn. |
| `core_affinity` pinning of sender threads | Only relevant if the spinning architecture ships, which it isn't. Was the mitigation for Run 8's co-located-instance tails. |
| `io_uring` rewrite | Largest theoretical win (eliminates `t_syscall`, batches recv+send) but a full I/O-layer rewrite — unjustifiable given the proxy isn't the bottleneck. |
| `tokio::sync::broadcast`-style queue | Still wakes D workers; the shard pool addressed the same cost more directly. |
| Multicast | Already supported via `multicast_config.rs` for operators with multicast-capable networks. Doesn't work over WAN / most cloud VPCs / NAT. |

---

## The decisive finding — the proxy is not the bottleneck

A downstream test timed how often each endpoint delivered a shred *first*,
comparing our service ("RabbitStream", running this forwarder) against a
third-party feed (Triton), over many 3000-tx windows:

| | sharded+connected (`opt_1_1`) | worker-tier (`production`) |
|---|---|---|
| win-rate vs Triton | ~14% | ~15% |
| p50 latency | ~2.8 ms | ~2.8 ms |
| p99 latency | ~13.4 ms | ~17 ms |

**Both builds are statistically identical downstream.** The reason is scale:

| latency component | scale | in our control? |
|---|---|---|
| proxy recv → sendmmsg-done | 20–120 µs | yes (we optimized this) |
| wire time proxy → downstream | 0.5–10 ms | no (network/topology) |
| upstream leader → proxy | 0.5–10 ms | no (peering/topology) |
| inter-flight jitter (qdisc, NIC, route) | 0.1–10 ms | no |

Our entire optimization budget (~70 µs) lives ~50× below the noise floor of
the network path. Even a 0 µs proxy would barely move the downstream number.
Triton's ~2.8 ms lead is **structural** — they are almost certainly closer to
leaders and/or run multiple ingress regions and race the copies.

---

## What would actually move the needle (future direction — NOT proxy code)

1. **Multi-region ingress + first-wins merger.** Run the proxy in 3–5 regions,
   each subscribed to a local relay; a merger co-located with the consumer
   dedupes by shred ID and ships the first arrival. This is how a service wins
   the 80% Triton currently takes — latency diversity, not faster code.
2. **Validator-adjacent peering.** Pull shreds directly from leader Turbine
   instead of through a relay hop.
3. **Co-locate proxy and consumer** (same machine / loopback) to delete wire
   time entirely, where the consumer is our own service.

These are deployment/topology investments, tracked separately from this
forwarder thread.

---

## What is deployed where

| Branch | Contents | Deploy status |
|---|---|---|
| `production` | Worker-tier fanout (D parked per-dest workers). | **Deployed.** |
| `run4-metrics` | `production` + the end-to-end barrier metric (this branch). | Candidate — tiny additive metric patch, safe to merge to `production`. |
| `opt_1_1` | Sharded busy-spin pool + connected sockets + e2e metric + full dashboard. | **Shelved.** Archived for reference; not deploying. |

---

## Configurable settings (worker-tier / `production` + `run4-metrics`)

### Module constants (`proxy/src/forwarder.rs`, require rebuild)

| Constant | Value | Tuning guidance |
|---|---|---|
| `DEST_CHANNEL_CAPACITY` | `1024` | Raise if `worker_dropped_batches > 0` and memory allows; lower to bound memory at the cost of more drops to slow dests. |
| `DEST_SCRATCH_INITIAL_CAPACITY` | `128` | Set near typical packets-per-batch to avoid warmup reallocs. Startup-cost knob only. |
| `DEST_RECONCILE_INTERVAL` | `5s` | Lower for faster worker spin-up on destination churn; raise to reduce reconcile overhead. |
| `DEDUPER_*` | (pre-existing) | Bloom-filter sizing / reset cycle. |

### CLI / env (no rebuild)

| Flag | Default | Effect |
|---|---|---|
| `--num-threads <N>` | `min(available_parallelism, 4)` | Parallelizes the recv side only; send side parallelizes per destination regardless. |
| `--metrics-report-interval-ms` | `15000` | Datapoint emission period. |
| `--debug-trace-shred` | `false` | Upstream→local trace-shred latency. Per-packet decode cost; keep off in prod. |
| `RUST_LOG=...forwarder=trace` | off | Gates ALL perf instrumentation, including `avg_end_to_end_us`. Zero runtime cost when off (no `Instant::now`, no atomic updates, no `BatchTrace` allocation). |

### The end-to-end metric (kept)

`shredstream_proxy-forwarding_perf` now emits, under `forwarder=trace`:

| Field | Meaning |
|---|---|
| `e2e_batches` | Batches whose barrier completed (every sender for that batch finished). ≈ `batches` in steady state. |
| `avg_end_to_end_us` | **Canonical** recv → last sender's `sendmmsg` returned, per batch. |
| `max_end_to_end_us` | Worst single-batch end-to-end this interval (tail). |

Mechanism: the coordinator allocates one `Arc<BatchTrace>` per batch
(counter = number of workers dispatched to), each worker does an `AcqRel
fetch_sub` after its send, and the worker that drives the counter to 0 records
the elapsed time. The coordinator compensates on `try_send` failures so the
invariant "exactly N decrements per batch" holds. `avg_total_us` (coordinator
path only) and `avg_worker_send_us` (per-worker send only) are retained as
diagnostics but are **not** the headline number — only `avg_end_to_end_us` is.
