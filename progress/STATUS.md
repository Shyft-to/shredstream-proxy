# Fan-out latency — status

_Updated 2026-10-15_

## Goal

Forward each incoming shred to all destinations (5–20 servers, mostly in the
same data center) as fast as possible.

**North star:** p99 fan-out completion latency — time from a shred arriving
on the server to its copy for the *last* destination leaving the server.
Lower is better. Measured from kernel packet timestamps, so any forwarder
implementation is measured the same way
([how](../fanout-bench/README.md)).

## Current baseline

| Where | Date | Runs | p50 | p90 | p99 | CPU per send |
|---|---|---|---|---|---|---|
| Production, port 23998 (15 destinations) | 2026-10-14 | 2 | 245 µs | 813 µs | 3.3 ms | 11.4 µs |
| Production, port 23998, A/B baseline side | 2026-10-15 | 6 | 195 µs | — | 2.0 ms (median) | 12.2 µs |
| **Box level**, 3 forwarders, kernel dedup **off** | 2026-10-15 | 8 | 321 µs | — | 5.4 ms (median) | ~8.0 cores in total |
| **Box level**, 3 forwarders, kernel dedup **on** | 2026-10-15 | 8 | **185 µs** | — | **2.4 ms** (median) | **~1.6 cores** in total |
| **Box level, kernel fan-out** (no userspace forwarding) | 2026-10-15 | 6 | **89 µs** | — | **0.31 ms** (median) | **~0.23 cores** (kernel) |
| **Box level, kernel fan-out, direct to NIC ports** (measured at the ports) | 2026-10-15 | 6 | **82 µs** | — | **0.26 ms** (median) | kernel only |
| Lab, 4 cores — _not representative_ | 2026-10-14 | 5 | 1.3 ms | 5.6 ms | 14.1 ms | 8.0 µs |

Box level (since 2026-10-15) is the north star: first arrival on any of the
three ports → first copy leaving the box for each destination. Earlier rows
are per forwarder and not directly comparable. The production row rests on
2 runs; other runs put p99 between 1.2 and
3.5 ms. The lab is ~5× slower than production (likely too few cores), so
candidates are now tested on production traffic with alternating A/B runs.

## Key findings

1. **Kernel fan-out cuts the tail 7.5×.** One eBPF program on `bond0`
   receive drops duplicate copies and clones each shred directly to all 15
   destinations. Against kernel dedup + 3 proxies (6 vs 6): p99 2.35 →
   0.31 ms (−87%, very stable), p50 137 → 89 µs (−35%), first destination
   −17%. Since the start: p99 6.2 → 0.31 ms.
2. **Kernel dedup across the three sources works.** Dropping later copies of
   each shred in an eBPF filter (forwarders unchanged), 8 vs 8 runs: p99
   −55% (5.45 → 2.43 ms), p50 −42% (321 → 185 µs), first destination −36%,
   forwarder CPU −80% (~8 → ~1.6 cores). All proven; delivery unaffected.
   Filter cost: 625 ns of kernel CPU per packet (~2.6% of one core).
3. **The three sources deliver the same shreds.** 98.8% of shreds arrive on
   all three ports (5544, 23997, 23998), and all three forwarders send to the
   same 15 destinations, so the box does ~3× the necessary send work.
   23997 and 23998 each deliver first about half the time; 5544 is never
   first (12 ms behind at p50), and ~40% of its traffic is re-sent old
   shreds (4 s–1 min old).
4. **Traffic is very bursty:** 46% of shreds arrive in bursts of over 64k
   shreds/s, so send capacity during bursts matters as much as per-shred
   speed.
5. **Most of the tail is queueing.** When little traffic arrived just before
   a shred, the forwarder delivers it everywhere in ~70 µs (p50). Under normal
   load (86% of shreds) the same shred takes ~4.5× longer at p50 and 5–8× at
   p99, because it waits behind earlier shreds.
6. **The biggest single cost is the coordinator waking the ~15 destination
   worker threads one after another:** 65–130 µs per shred. Each extra thread
   hand-off costs ~10–13 µs, and each send ~4–8 µs.
7. **Dead destinations are expensive.** Removing one local destination with
   no listener halved p99 (6.2 → 3.1 ms) and sped up every other destination.

## Ruled out

- **CPU sleep states (C2):** disabling them changed nothing (verified the
  setting took effect).
- **Kernel receive path:** only 2–8 µs from the kernel seeing a packet to it
  reaching the proxy's socket.
- **`shred-fanout` threads being switched out:** they waited for a CPU only
  ~17 ms in 10 s.
- **Queueing in the bond/VLAN devices:** both use `noqueue`.
- **Switching the 5544 source off:** no latency gain, and it loses ~0.13%
  of live shreds that only 5544 delivers.
- **Lost shreds in the delivery dips:** every "missing" shred was a stale
  re-send (4 s–1 min old) from the 5544 source, already forwarded live; no
  live shred was missing. The probe now excludes stale re-sends.
- **Batching delay in the receiver:** the proxy does not hold packets back.

## Open questions

- Where do the ~4.6 µs per copy go, and how far can they be cut? Send
  capacity limits `shred-fanout` (confirmed: 8 senders reach the first
  destination 5× faster, completion only matches baseline, at 9 spinning
  cores). Options: kernel tuning (conntrack, IOMMU) or bypassing the UDP/IP
  stack (`AF_PACKET`, eBPF). The CPU profile shows the per-copy cost
  spread across many kernel layers; tuning alone likely saves only 10–20%.
- How cheap can each kernel copy get? Today ~1.9 µs, mostly the VLAN and
  bond device layers (~36%) and IOMMU mapping/unmapping; a burst's copies
  all land on one CPU, which saturates (p50 ~90 µs, p99 ~300 µs). Plan:
  send straight to the NIC ports, then IOMMU passthrough; spread over CPUs
  only if still needed.
- Which process still sends to the old dead IPs (`FAILED` in the neighbour
  table)?
- Is the queue mainly at the coordinator's serial wakeups? Likely, not yet
  isolated.
- How much would skipping connection tracking (firewall) for this traffic
  save per send?

## Changes made in production

- Removed destinations with failed ARP, and `127.0.0.1:20300` (no listener)
  from the 23998 instance.
- NIC interrupt delay `rx-usecs` 8 → 0 on both bond ports. **Not persistent
  across reboot.**

## Next

1. A/A test on production (baseline vs itself) to validate the A/B method
   and its noise level.
2. Confirm delivery (slot-age breakdown) and measure the kernel fan-out's
   CPU cost; then decide what to deploy: kernel dedup (ready) or kernel
   fan-out (needs MAC refresh, one destination list, monitoring).
3. Then cut the cost per copy (bypass the UDP/IP stack) if still needed.

## Log

| Chapter | Date | Summary |
|---|---|---|
| [1](chapter-01-2026-10-14.md) | 2026-10-14 | North star defined, production baseline, profile of the forwarder, queueing identified |
| [2](chapter-02-2026-10-15.md) | 2026-10-15 | Candidate testing moved to live production traffic (A/B); `shred-fanout` v1 limited by send capacity; sources overlap 98.8%; kernel dedup proven (p99 −55%); userspace fan-out variants; kernel fan-out: p99 −87% vs dedup + proxies |
