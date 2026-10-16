//! Shared pieces of the fan-out bench: a pcap reader, latency summaries, and
//! clocks / receive timestamps for one-way measurement.

pub mod pcap;
pub mod stats;
#[cfg(target_os = "linux")]
pub mod ts;
