# Chapter 1 — 2026-10-14: Baseline

Items marked **[Hypothesis]** are not yet established beyond doubt.

## Summary

- North-star metric defined: **p99 fan-out completion latency**. The tooling
  that measures it is on branch `fanout-bench`.
- First production baseline (port 23998): **p99 6.2 ms, p50 757 µs**. That is
  far above the ~117 µs mean in [optimization.md](../optimization.md), which
  only measured from the moment packets reached userspace.
- After removing a dead destination: **p99 3.1 ms, p50 213 µs**.

## North-star metric

For each unique shred: time from its first arrival at the server to the
moment its copy for the last destination is handed to the network device. We
report the p99; lower is better.

- Measured with kernel packet timestamps (`tcpdump`), so the forwarder needs
  no instrumentation and any implementation is measured the same way.
- Guardrails: delivery ratio, zero duplicate sends, CPU per send.
- Not covered: NIC/IRQ delay before the kernel sees the packet, wire time.

Details: [fanout-bench/README.md](../fanout-bench/README.md).

## Server context

- Bare metal, EPYC 7443P (48 threads, ~80% idle), i40e NICs in an LACP bond,
  kernel 6.8.
- About 80% of receivers are on the same private VLAN, so the forwarder's
  latency is comparable to wire time for them.
- Port 23998: ~7–8k shreds/s from one source, sent in bursts (~20 shreds,
  ~80 µs apart), forwarded to ~15 destinations.

## Changes made

| Change | Outcome |
|---|---|
| Removed destinations with failed ARP | Done |
| NIC `rx-usecs` 8 → 0 | No measurable CPU cost. Not persistent across reboot. **[Hypothesis]** saves up to 8 µs per packet; not visible in our metric. |
| Removed `127.0.0.1:20300` (no listener) from 23998 | p99 halved (see below) |
| NIC ring size increase | Skipped: no current drops, and it would flap the link |

## Baseline — production, port 23998

Single 10 s captures.

| | With dead destination | Dead destination removed |
|---|---|---|
| **Completion p99** | **6,227 µs** | **3,141 µs** |
| Completion p50 | 757 µs | 213 µs |
| First destination p50 | 174 µs | 90 µs |
| Delivery / duplicates | 99.999% / 0 | 100% / 0 |
| CPU per send | 10.3 µs | 11.5 µs |

**[Hypothesis]** The halving is caused by removing the dead destination.
Each send to it triggered ICMP handling that slowed the other workers too.
These are single runs with slightly different traffic; the 5-vs-5 test has
not been done.

## Findings

- With one source, only 1 of 4 receive threads and 1 coordinator do any
  work; the 15 workers each sleep ~95% of the time.
- CPU idle state C2 (30 µs declared exit latency) is entered constantly.
- The proxy's receiver does not hold packets back: it uses zero coalesce wait.

## Hypotheses to test

1. **[Hypothesis]** Each shred passes ~3 thread wakeups in series (receive →
   coordinator → workers), and those wakeups make up most of the 90 µs
   first-destination p50.
   - **Rejected:** that the cost comes from cores waking out of C2. An A/B
     test (4 alternating runs each, C2 on vs off) showed no change:
     first-destination p50 87.0 vs 88.4 µs, completion p99 2,323 vs
     2,292 µs, with overlapping ranges. Verified that the disable took
     effect: 0 C2 entries in 10 s while disabled (1.19 M with it enabled),
     and C2 residency 0% vs 49%.
2. **[Hypothesis]** CPU per send (~11 µs vs 1–4 µs normal) comes from
   per-batch overhead: every burst packet becomes its own batch with ~15
   wakeups.
3. **[Hypothesis]** The p99 is driven by queueing during bursts and by the
   slowest of ~15 independent workers.

## Next

- Production completion p99 varies 1.2–3.3 ms between 10 s runs, so small
  effects need the lab test bed or many runs.
- Check other instances for dead local destinations; baseline 5544 and 23997.
- Profile the path (eBPF stage timings, `perf` flame graph, scheduler
  analysis) to rank bottlenecks.
