//! Runs on the forwarder host. Answers `stamp-recv`'s clock probes with this
//! host's CLOCK_MONOTONIC (the clock the forwarders stamp shreds with), taken
//! from the kernel receive timestamp and just before the reply is sent, so the
//! receiver can map stamps onto its own clock (NTP-style, four timestamps).

use std::{error::Error, net::SocketAddrV4, net::UdpSocket};

use clap::Parser;
use fanout_bench::ts;

#[derive(Parser)]
#[command(about = "Answer stamp-recv clock probes with this host's monotonic clock")]
struct Args {
    /// Address to listen on (the receiver must be able to reach it).
    #[arg(long, default_value = "0.0.0.0:9911")]
    bind: SocketAddrV4,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let sock = UdpSocket::bind(args.bind)?;
    ts::enable_rx_timestamps(&sock)?;
    eprintln!("clock-echo: answering on {}", args.bind);
    let mut buf = [0u8; 64];
    let mut answered = 0u64;
    loop {
        let (n, src, rx_real) = ts::recv_ts(&sock, &mut buf)?;
        if n < 16 || &buf[..8] != ts::CLOCK_REQ {
            continue;
        }
        let rx_mono = (rx_real as i64 - ts::realtime_minus_monotonic()) as u64;
        let mut rep = [0u8; 32];
        rep[..8].copy_from_slice(ts::CLOCK_REP);
        rep[8..16].copy_from_slice(&buf[8..16]);
        rep[16..24].copy_from_slice(&rx_mono.to_le_bytes());
        rep[24..32].copy_from_slice(&ts::monotonic_ns().to_le_bytes());
        sock.send_to(&rep, src)?;
        answered += 1;
        if answered == 1 || answered % 100_000 == 0 {
            eprintln!("clock-echo: {answered} probes answered (latest from {src})");
        }
    }
}
