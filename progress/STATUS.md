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
| Lab, 4 cores — _not representative_ | 2026-10-14 | 5 | 1.3 ms | 5.6 ms | 14.1 ms | 8.0 µs |

The production row rests on 2 runs; other runs put p99 between 1.2 and
3.5 ms. The lab is ~5× slower than production (likely too few cores), so
candidates are now tested on production traffic with alternating A/B runs.

## Key findings

1. **Most of the tail is queueing.** When little traffic arrived just before
   a shred, the forwarder delivers it everywhere in ~70 µs (p50). Under normal
   load (86% of shreds) the same shred takes ~4.5× longer at p50 and 5–8× at
   p99, because it waits behind earlier shreds.
2. **The biggest single cost is the coordinator waking the ~15 destination
   worker threads one after another:** 65–130 µs per shred. Each extra thread
   hand-off costs ~10–13 µs, and each send ~4–8 µs.
3. **Dead destinations are expensive.** Removing one local destination with
   no listener halved p99 (6.2 → 3.1 ms) and sped up every other destination.

## Ruled out

- **CPU sleep states (C2):** disabling them changed nothing (verified the
  setting took effect).
- **Kernel receive path:** only 2–8 µs from the kernel seeing a packet to it
  reaching the proxy's socket.
- **Batching delay in the receiver:** the proxy does not hold packets back.

## Open questions

- Why is `shred-fanout` v1 slower than the current proxy (p50 439 vs
  195 µs)? Suspected: its spinning threads share their cores with other
  work and get switched out.

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
2. Find out why `shred-fanout` v1 (busy-polling receiver, pinned senders)
   is slower, and fix it.
3. Then an eBPF fan-out (no threads at all, cheaper per copy).

## Log

| Chapter | Date | Summary |
|---|---|---|
| [1](chapter-01-2026-10-14.md) | 2026-10-14 | North star defined, production baseline, profile of the forwarder, queueing identified |
| [2](chapter-02-2026-10-15.md) | 2026-10-15 | Candidate testing moved to live production traffic (A/B); `shred-fanout` v1 built, slower than baseline |
