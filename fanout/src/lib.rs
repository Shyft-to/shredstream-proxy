//! Building blocks of the fan-out forwarder.

pub mod dedup;
pub mod ring;

#[cfg(target_os = "linux")]
pub mod net;
