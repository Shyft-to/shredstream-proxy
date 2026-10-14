# Fan-out latency R&D — progress log

Goal: forward UDP shreds received on one port to 5–20 destinations as fast as
possible, measured by the north-star metric defined in Chapter 1.

Each chapter briefly records where we stood on a given date: what we changed,
what we measured, and what we decided next. Anything not established beyond
doubt is tagged **[Hypothesis]**. Chapters are not rewritten after the fact;
corrections go into a later chapter.

| Chapter | Date | Topic |
|---|---|---|
| [Chapter 1](chapter-01-2026-10-14-baseline.md) | 2026-10-14 | Server survey, quick fixes, north-star metric, first production baseline |
