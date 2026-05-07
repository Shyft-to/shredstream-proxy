# Fanout Optimization

This document describes a class of latency problems specific to UDP fanout in
the shredstream-proxy forwarder, the available optimizations, their tradeoffs,
and what was implemented in this iteration.

---

## The problem

`shredstream-proxy` forwards every received shred to every address listed in
`--dest-ip-ports` (and any addresses returned by the discovery service). The
observed symptom is that **end-to-end latency for the last destination grows
linearly with the number of destinations** `D`. With 1 destination it is fast;
with 20 destinations the last one sees roughly 20× the per-destination cost.

### Root cause

Before this change, `recv_from_channel_and_send_multiple_dest` in
`proxy/src/forwarder.rs` used the following structure:

```rust
local_dest_sockets.iter().for_each(|dest| {
    let packets_with_dest = packet_batch_vec[0]
        .iter()
        .filter_map(|pkt| Some((pkt.data(..)?, dest)))
        .collect::<Vec<(&[u8], &SocketAddr)>>();   // (1) per-destination Vec alloc
    batch_send(send_socket, &packets_with_dest);    // (2) per-destination sendmmsg
});
```

Three compounding costs scale with `D`:

1. **Serial loop, single send socket.** Destination `i+1` could not begin
   sending until destination `i`'s `batch_send` had returned from the kernel.
   The last destination observed `D × T_per_dest`.

2. **`batch_send` is itself O(P) in kernel work** (P = packets per batch). It
   issues `sendmmsg` syscalls (up to `UIO_MAXIOV` = 1024 iovecs each), so each
   call is a real round-trip into the kernel. Total: D syscalls per batch.

3. **Per-destination `Vec<(&[u8], &SocketAddr)>` allocation.** The vec only
   varies by the address; the byte slices are identical for every destination.
   Yet a fresh heap allocation of size P happened D times per batch.

Secondary amplifiers:

- **Single shared `send_socket`.** All D destinations share one UDP socket;
  the kernel send buffer becomes a contended resource.
- **Default `SO_SNDBUF`** (~200–400 KB on Linux). Once full, `sendmmsg` blocks
  and tail latency for late destinations grows non-linearly.
- **No connected sockets.** `send_to` re-runs route lookup per call;
  connected sockets cache the route.
- **No GSO** (Linux). Every datagram is its own kernel walk.

---

## Catalog of fanout optimizations

Listed in roughly descending ROI for this codebase. Each entry includes the
mechanism, the tradeoff, and the expected effect on latency vs. `D`.

### 1. Single `batch_send` for all `(packet, dest)` pairs (IMPLEMENTED)

Build one flat `Vec<(&[u8], &SocketAddr)>` of length `P * D` and call
`batch_send` once. `sendmmsg` already packs up to 1024 iovecs into a single
syscall regardless of destination address.

**Effect:** D syscalls → `ceil(P*D / 1024)` syscalls. For typical
`P=64, D=10`: **10 syscalls → 1 syscall** per batch. End-to-end fanout cost
becomes effectively flat in D within the iovec budget.

**Tradeoffs**
- (+) Latency stops scaling linearly with D in the common case.
- (+) One vec allocation per batch instead of D.
- (−) On partial send failure, per-destination attribution is lost
  (`SendPktsError::IoError(_, num_failed)` reports a count, not which
  destination). Production logs already aggregated, so this is acceptable.
- (−) Slightly larger transient memory: the flat vec is `P*D` references
  rather than `P` references per call.

### 2. Reused scratch `Vec` across batches (IMPLEMENTED)

The send thread owns a `Vec<(&'static [u8], &'static SocketAddr)>` and passes
`&mut` references into the function for each batch. The function transmutes
the lifetime to the call-local one, fills, sends, and `clear()`s the vec
before returning. The `'static` tag is purely a phantom lifetime to satisfy
`Vec<T>`'s invariance; the transmute changes only type-level information.

**Effect:** Eliminates the remaining per-batch allocation introduced by
optimization #1. After the first few batches the underlying buffer reaches a
stable capacity and never reallocates.

**Tradeoffs**
- (+) Zero allocations on the steady-state hot path of UDP fanout.
- (−) Uses an `unsafe { std::mem::transmute }` block, contained to the
  forwarder send loop, with a debug-assert that the buffer is empty on entry
  and a guaranteed `clear()` before return. The unsafe block is annotated with
  a SAFETY comment.

### 3. Per-destination connected sockets + parallel sends (NOT IMPLEMENTED)

For each destination, bind a separate `UdpSocket` and call `connect(dest)`,
then spawn a small dedicated send task per destination that reads from a
fan-out channel. D sends happen in parallel.

**Effect:** Latency for any one destination becomes `T_per_dest` regardless
of `D`. Slow destinations no longer block fast ones.

**Tradeoffs**
- (+) Truly O(1) per-destination latency in `D`.
- (+) Connected UDP sockets are 10–20% faster (kernel route-cache hit).
- (−) D additional sockets and D threads/tasks.
- (−) More complex shutdown and error reporting.
- (−) For small D (≤ 4), the channel-hop cost outweighs the parallelism.

This is the right structural fix when D grows past ~20. Combine with #1 to
also collapse per-destination work into a single syscall.

### 4. `UDP_GSO` / `UDP_SEGMENT` (Linux ≥ 4.18) (NOT IMPLEMENTED)

Set `UDP_SEGMENT` via `setsockopt`. The kernel splits one large buffer of
`N × MTU` into N UDP datagrams in a single `sendmsg`. Combined with #1, an
entire batch (`P × D` packets) can leave the host in a single syscall.

**Tradeoffs**
- (+) Massive: one syscall for arbitrarily large fanout.
- (−) Linux-specific; doesn't work on macOS dev machines.
- (−) All destinations must share segment size; mismatched MTU causes
  fragmentation.
- (−) Per-packet error info is lost.

### 5. Larger `SO_SNDBUF` (NOT IMPLEMENTED)

Raise the send-side socket buffer to 8–16 MB via `solana_net_utils::SocketConfig`.

**Tradeoffs**
- (+) Reduces probability that `sendmmsg` blocks under bursty traffic with
  large `D`.
- (−) Larger kernel memory footprint per send socket.
- (−) Doesn't help when the actual cost is per-destination iteration; this is
  a downstream amplifier mitigation, not a root-cause fix.

### 6. Multicast (NOT IMPLEMENTED — already supported via separate path)

When destinations live on a multicast-capable network, send once and let the
network duplicate. `D` disappears from the cost equation entirely.

**Tradeoffs**
- (+) Optimal where applicable.
- (−) Requires multicast-capable network. Doesn't work over WAN, most cloud
  VPCs, or NAT-ed environments. The codebase already supports multicast via
  `multicast_config.rs`, so this option exists for operators with the right
  network topology.

### 7. Shard destinations across send threads (NOT IMPLEMENTED)

If there are `N` forwarder send threads and `D` destinations, currently each
thread performs the full D-way fanout for every batch it sees. Instead, each
thread could be assigned only a slice of destinations.

**Tradeoffs**
- (+) Parallelizes D-way fanout across the existing thread pool without new
  resources.
- (−) Requires N ≥ D for full parallelism; with D >> N the benefit caps out.
- (−) Each batch has to be fanned out `min(D, N)` times — once per shard —
  which means duplicating the receive→reconstruct path or routing the same
  batch to multiple send threads.

### 8. Skip route lookups via `send_to` → `send` on connected sockets (PART OF #3)

Folded into optimization #3. Listed separately because in some deployments
operators can connect a single `UdpSocket` to a single destination already
(degenerate case of #3 with D=1).

---

## What was implemented in this iteration

### Code changes (`proxy/src/forwarder.rs`)

1. **Optimization #1 — single `batch_send` over all (packet, dest) pairs.**
   The per-destination `for_each` loop and per-destination `collect()` are
   gone. The function now builds one flat `Vec<(&[u8], &SocketAddr)>` and
   issues exactly one `batch_send` per batch.

2. **Optimization #2 — reused scratch buffer across batches.**
   `recv_from_channel_and_send_multiple_dest` now takes
   `packets_with_dest_scratch: &mut Vec<(&'static [u8], &'static SocketAddr)>`.
   The send thread owns this buffer and passes it across calls; the function
   `clear()`s it before returning so no call-local references can outlive the
   stack frame. Initial capacity hints `PACKETS_PER_BATCH_HINT * MAX_DESTS_HINT`
   are set so typical batches do not reallocate.

3. **Metrics correctness side-effect.**
   The previous implementation incremented `metrics.duplicate` *D times per
   batch* (once per destination), which was a multiplicative bug — `num_deduped`
   is per-batch, not per-destination. The new implementation increments it
   once. `metrics.fail_forward` now reflects the actual count of failed
   `(packet, dest)` pairs reported by `SendPktsError::IoError(_, num_failed)`,
   not the entire batch size. `metrics.success_forward` continues to count
   total `(packet, dest)` pairs successfully sent.

### Tests added (`proxy/src/forwarder.rs::tests`)

| Test | Purpose |
|---|---|
| `test_2shreds_3destinations` | Existing test, ported to the new signature; verifies fanout to 3 destinations and per-destination ordering. |
| `test_fanout_many_destinations` | 5 packets × 12 destinations. Verifies every destination receives every packet, ordering is preserved, and `success_forward` equals exactly `P*D` (no over-counting). |
| `test_scratch_buffer_reused_across_batches` | Runs 3 back-to-back batches through a single scratch Vec; verifies the Vec is empty on entry/exit and capacity does not change when batches fit. |
| `test_zero_destinations_is_noop` | `D=0` edge case: function must not panic, must record `received` but `success_forward = 0`, scratch buffer must remain empty. |
| `test_single_destination_preserves_order` | `D=1` sanity check: 8 packets arrive in send order. |
| `test_scratch_grows_then_reuses` | Forces a Vec grow on a large batch, then checks the next smaller batch reuses the grown allocation without shrinking. |

All tests pass under `cargo test -p jito-shredstream-proxy`.

### Expected impact

For a representative workload (P=64 packets per batch, D=10 destinations):

| Cost component | Before | After |
|---|---|---|
| `sendmmsg` syscalls per batch | 10 | 1 |
| Heap allocations per batch | 10 | 0 (steady state) |
| `for_each` iterations through P packets | 10 (P each) | 1 (P*D each) |
| Last-destination latency | `~10 × T_per_dest` | `~T_per_dest` |

The linear-in-D growth in the user-observed latency should disappear in this
regime. Beyond `P*D ≈ 1024` (the `UIO_MAXIOV` budget), the syscall count
re-enters at `ceil(P*D / 1024)`, still much less than `D`.

---

## What is left to do

The structural fixes for very large `D` (#3 — per-destination connected
sockets + parallel sends, #4 — UDP_GSO) are not implemented in this
iteration. They become worthwhile when `D` grows past ~20, or when the
deployment kernel supports GSO. The recommended sequencing is:

1. Ship #1 + #2 (this iteration) and measure.
2. If latency-vs-D is still problematic, layer #4 (UDP_GSO) on Linux
   deployments.
3. If destinations exceed ~20 and slow destinations are observed poisoning
   fast ones, implement #3 (per-destination parallel sends).
