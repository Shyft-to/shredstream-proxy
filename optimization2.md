# Latency Optimization — Findings & Next Steps

Status as of 2026-05-15. Present code: worker-tier fanout (D per-destination
threads, `optimization.md` #1+#2+#3). Opts 1.1–1.4 were tried and reverted
(no measurable gain). The flat single-`batch_send` revert was tried and
regressed (~105 µs).

## Measured baseline

`fra-shred-proxy`, 20 destinations, 1 packet/batch, `forwarder=trace`:

| Metric | Value |
|---|---|
| `avg_total_us` (coordinator) | ~33 µs |
| `avg_fanout_dispatch_us` | **~30 µs** (~93% of the coordinator path) |
| `avg_dedup_us` / `avg_stats_us` / `avg_reconstruct_clone_us` | ~1 µs / 0 / 0 (already negligible) |
| `avg_worker_send_us` | ~6 µs (parallel across 20 workers) |
| End-to-end (dispatch + slowest worker) | **~36–39 µs** |

## Cost model

End-to-end fanout latency decomposes into two competing terms:

```
total ≈ recv_path + N × t_wake + slowest_thread_send

  where  slowest_thread_send ≈ t_syscall + (D/N) × t_datagram
```

- `t_wake ≈ 1.5 µs` — channel send + `FUTEX_WAKE` per worker, serial on the
  coordinator
- `t_syscall ≈ 2 µs` — `sendmmsg` entry/exit, amortized over the whole batch
- `t_datagram ≈ 4 µs` — per-(packet, dest) **in-kernel work**: route lookup
  on the unconnected socket, skb alloc, NIC queue
- `recv_path ≈ 3 µs` — recv → dedup → Arc wrap

Plug in the cases:

| Config | N | dispatch (N·t_wake) | slowest send | **end-to-end** |
|---|---|---|---|---|
| Current (workers) | 20 | 30 µs | 2 + 4 = 6 µs | **~39 µs** |
| Sharded pool | 10 | 15 µs | 2 + 8 = 10 µs | ~28 µs |
| Sharded pool | **8** | 12 µs | 2 + 10 = 12 µs | **~27 µs** |
| Sharded pool | 4 | 6 µs | 2 + 20 = 22 µs | ~31 µs |
| Flat (tried) | 1 | ~0 | 2 + 80 = 82 µs | **~85+ µs** ✗ regressed |

### Take-aways

1. **The current bottleneck is `D × t_wake`** — 20 worker wakeups, serial on
   the coordinator. That's the ~30 µs `avg_fanout_dispatch_us`.
2. **Sharding alone is shallow.** Best case N≈8 → ~27 µs end-to-end, a
   ~25–30 % improvement. Not 3×. N=4 is the same as today.
3. **The flat revert was lethal** — collapsing send to one thread serializes
   all the kernel work. Worker parallelism is load-bearing.
4. **`avg_total_us` is a misleading metric** in isolation. It stops at the
   end of dispatch and excludes the sends, so a low-N sharded config will
   *look* like a huge win (33 → ~15 µs) while end-to-end barely moves. The
   number to trust is `avg_total_us` **+** `max_worker_send_us`.

## What actually shrinks total work

Both `N × t_wake` and `(D/N) × t_datagram` are "move the work around." The
only levers that shrink the *total* `D × t_datagram` of in-kernel send work
are:

- **Connected sockets** (`connect()` caches the route lookup). Drops
  `t_datagram` from ~4 µs to ~1 µs.
- **`io_uring`** (long-term). Eliminates `t_syscall` per send and can batch
  recv + sends.

`UDP_GSO` does **not** fit this workload — GSO splits one buffer into
MTU-sized datagrams to **one destination**; shreds go to many destinations.
Dropped from the list.

---

## Final list — what can really bring latency down

Listed in priority order. The first item is the only one that meaningfully
moves the needle on its own; the rest compound.

### 1. Sharded send pool + connected sockets — **bundled, not separately**

Either alone is marginal. Together they collapse the curve:

| | `t_datagram = 4` µs | `t_datagram = 1` µs (connected) |
|---|---|---|
| N = 20 (current) | ~39 µs | ~36 µs (dispatch-bound, send savings invisible) |
| N = 8 sharded | **~27 µs** | **~19 µs** |
| N = 5 sharded | ~29 µs | **~17 µs** ← shifts lower with cheaper sends |

**Sharded pool (`optimization.md` #7).** Replace D per-destination worker
threads with **N fixed send-worker threads** (start with N = 8). Each owns
an `ArcSwap<Vec<SocketAddr>>` with its slice; the dest-manager re-shards on
reconcile. Workers spawn once at startup and never churn — this also
*removes* the per-destination spawn/drop logic, simplifying the file.

**Connected sockets (`optimization.md` #8 / 1.11).** Each send-worker holds
**one connected `UdpSocket` per destination in its slice**. `connect()`
pins the route in the socket, so each `sendmmsg` skips the per-datagram
route lookup. Requires writing a `sendmmsg(msg_name = NULL)` helper —
`solana_streamer::batch_send` calls `send_to`, which is illegal on a
connected socket. Use `nix::sys::socket::sendmmsg` or a small `libc`
wrapper (~20 lines of unsafe, audited once).

**Expected end-to-end:** ~39 µs → ~17–19 µs, **~50 % reduction**. With
cheaper `t_datagram`, the optimum N drops to ~5; tune by measurement.

**How to actually measure the win** (since `avg_total_us` lies here):

- Watch `avg_total_us + max_worker_send_us` as a derived end-to-end proxy.
- Or add a metric: timestamp at coordinator entry → timestamp when the last
  worker's `sendmmsg` returns (would need a small completion signal).

### 2. Compiler flags + allocator — free, do alongside

Zero algorithmic change, ~5–15 % across the board, multiplicative with
everything else.

- `[profile.release]`: add `lto = "fat"` (currently `"thin"`) and
  `codegen-units = 1`. Build production with `RUSTFLAGS="-C target-cpu=x86-64-v3"`
  (or `=native` if built on the target host).
- `#[global_allocator] static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;`
  in `main.rs` — 4 lines. Helps the cross-thread `Arc<PacketBatch>`
  alloc/free pattern that workers (and the new sharded pool) create.

### 3. Tail latency — `SO_SNDBUF` + CPU-pin send threads

Steady state is fine; this flattens spikes. `max_worker_send_us` shows
occasional multi-ms outliers (worst observed ~8.7 ms) — isolated to one
worker, not coordinator-wide.

- Per-send-socket `setsockopt(SO_SNDBUF, ...)` to 4–16 MB. Pair with a
  documented `sysctl net.core.wmem_max` bump.
- `core_affinity` to pin the N send threads to dedicated cores. Pays off
  more once N is small and fixed (after step 1).

### 4. Long-term — `io_uring` rewrite

Only justified if steps 1–3 don't get latency low enough.

- One submission ring per recv socket + send socket; no syscall transitions
  between recv and the fan-out sends.
- Eliminates `t_syscall` per send and most context-switch jitter.
- Full I/O-layer rewrite; estimate another 20–30 % on top of (1) + (2).

---

## Explicitly dropped

These were in the earlier catalog and are **not** worth pursuing:

- **Opts 1.1–1.4** — reverted; targeted dedup / stats / reconstruct /
  dispatch-container, all already ~0 µs at 1 packet/batch.
- **Single flat `batch_send`, no workers** — tried and regressed to ~105 µs
  (dashboard Run 6).
- **`UDP_GSO`** — wrong shape (one packet to many dests, not many packets
  to one dest).
- **Merge listener+coordinator, SPSC ring, drop deduper / stats thread /
  trace-shred path, stack-alloc the 1-element Vec, eliminate `PacketBatch`** —
  each targets <2 µs of a ~30 µs path. Hygiene at best.
- **`tokio::sync::broadcast`-style queue** — still wakes D workers; the
  sharded pool addresses the same cost more directly.

---

## Realistic latency floor (from this code path)

Steps 1+2 plausibly land **~17 µs end-to-end**, down from ~39 µs (~55 %).
Step 4 (`io_uring`) could push toward **~10 µs**. Below that requires
either kernel-bypass (DPDK / AF_XDP) or eliminating the user-space split
entirely — neither is on the table here.
