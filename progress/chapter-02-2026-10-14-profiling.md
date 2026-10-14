# Chapter 2 — 2026-10-14: Profiling the forwarder path

Items marked **[Hypothesis]** are not yet established beyond doubt.

## Summary

- We measured every stage of the proxy's path on the live 23998 instance
  (10 s, `profile.sh stages` and `profile.sh cpu`).
- **The biggest cost is the coordinator waking the ~15 worker threads one
  after another**: typically 64–128 µs from the first to the last wake. This
  is most of the gap between the first and the last destination.
- Each thread hand-off (receive → coordinator → worker) costs ~10–13 µs,
  of which ~6–8 µs is waiting to be put on a CPU after the wakeup.
- Each send is expensive: a `sendmmsg` usually carries 1 packet and takes
  4–8 µs, with netfilter/conntrack, IOMMU mapping and CPU-vulnerability
  mitigations all visible on the per-packet transmit path.

## Path and measured stage times

```
packet queued ─► receive thread ─► coordinator ─► wakes worker 1 … worker 15 ─► sendmmsg (each)
```

| Stage | Typical (histogram peak) | Average |
|---|---|---|
| S1 Packet queued → receive thread has it | 8–16 µs | 21.5 µs |
| S2 Receive thread woken → running | 8–16 µs | 12.8 µs |
| S3 Receive done → coordinator woken | 4–8 µs | 5.1 µs |
| S4 Coordinator woken → running | 4–16 µs | 10.6 µs |
| **S5b Coordinator running → last worker woken** | **64–128 µs** | 259 µs |
| S6 Worker woken → running | 8–16 µs | 11.1 µs |
| S7 Worker running → `sendmmsg` starts | 1–4 µs | 2.3 µs |
| S8 `sendmmsg` duration | 4–8 µs | 15.4 µs |
| Run-queue delay, any thread (woken → on CPU) | 4–8 µs | 6–8 µs |

Other observations:

- **Almost no batching.** Most `recvmmsg` calls return 1 packet, and most
  `sendmmsg` calls send 1 packet. Each burst packet becomes its own batch
  and its own round of ~15 worker wakeups (~27k worker wakeups/s).
- **The coordinator often does not get back to sleep.** Most wakeups
  dispatch one batch (8–16 worker wakes), but many run for 16 to 1,000+
  worker wakes, meaning new batches kept arriving while it dispatched.
- CPU: the workers use ~87% of the process's CPU. Top items are
  crossbeam channel spinning before parking (5%), CPU-vulnerability
  mitigation thunks (`srso_*`, ~4%), netfilter/conntrack (`nft_do_chain`,
  `nf_conntrack_*`, ~4%), `memset` (1.5%), IOMMU page mapping (1.3%),
  route lookups (~1.5%) and skb allocation/copy.

## Does it add up?

- Last destination ≈ first destination + dispatch spread. Median
  completion 213 µs − first destination 90 µs ≈ 120 µs, in line with S5b.
- First destination: the stages (S1, S3, S4, first worker wake, S6, S7, S8)
  add up to roughly 50 µs against the measured ~90 µs. **[Hypothesis]** The
  rest is the kernel receive path before the socket (including netfilter
  input hooks), which this profile does not cover, plus probe overhead.
- The probes themselves add roughly 1–2 µs per traced event, so absolute
  stage times are somewhat inflated.

## Ranked bottlenecks

1. **Serial worker wakeups by the coordinator** (~65–130 µs per shred).
2. **Three thread hand-offs**, each ~10–13 µs (~35 µs in total), half of it
   run-queue delay.
3. **Per-packet send cost** (4–8 µs per 1-packet `sendmmsg`) × 15
   destinations, raised by netfilter/conntrack, IOMMU and mitigations.

**[Hypothesis]** The millisecond tail (p99) comes from queueing during
bursts. Packets in a burst arrive ~80 µs apart, which is about as long as
one dispatch round takes, so the coordinator falls behind and a backlog
builds. Supported by the long dispatch runs above, but not proven.

## What this means for the design

- Moving work between threads only shifts these costs around. Sending all
  copies from one thread costs ~15 × 4–8 µs serially; spreading them over
  workers costs a wakeup per worker. Earlier notes found the same trade-off.
- The two ways out are to **remove the wakeups** (threads that never sleep,
  pinned to cores) and to **make each send cheaper** (fewer kernel layers per
  packet), or both. An eBPF fan-out in the kernel does both: no thread
  hand-offs, and no per-copy syscall, socket or netfilter pass.
- **[Hypothesis]** Cheaper sends are also available without new code:
  skipping conntrack for this traffic, IOMMU passthrough (`iommu=pt`, needs
  a reboot). Mitigation changes trade security for speed and are not
  proposed.

## Update, same day: kernel receive path and load

Second run on 23998 (~9.2k shreds/s), with two new measurements.

**Kernel receive path is fast.** From the kernel seeing the packet to it
being queued on the socket (S0): typically 2–8 µs, average 4.4 µs. The
hypothesis above that this path hides 30–40 µs is **rejected**.

**Latency depends strongly on load: queueing is the main cause of the
tail.** Shreds grouped by how many shreds arrived in the 500 µs before them:

| Recent arrivals | Shreds | Completion p50 | Completion p99 | First dest p50 |
|---|---|---|---|---|
| 0–5 | 12% | 67–78 µs | 485–845 µs | 35–43 µs |
| 6 or more | 86% | 332 µs | 3,873 µs | 119 µs |

- With little recent traffic, the current design delivers to all 15
  destinations in ~70 µs (p50). That is its floor.
- Under normal load (most shreds) the same forwarder is ~4.5× slower at
  p50 and ~5–8× slower at p99. The work per shred did not change, so the
  extra time is spent waiting behind earlier shreds.
- **[Hypothesis]** The queue forms mainly at the coordinator's serial
  worker wakeups. Supported by the long dispatch runs, not yet isolated.

The 500 µs window put 86% of shreds in one bucket; the breakdown now uses
finer buckets (up to 32+) to show how latency grows with load.

## Next

- Record a corpus and set up the lab test bed, so candidate changes can be
  compared on identical traffic.
- Measure the existing busy-spin experiment (branch `opt_1_1`: sharded
  non-sleeping senders, connected sockets) with the north star in the lab.
- Check the firewall rules to see whether forwarder traffic can skip
  conntrack.
- Prototype the two candidate designs (pinned non-sleeping sender threads;
  eBPF fan-out) and measure both against the baseline in the lab.
