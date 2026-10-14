//! Receives and discards UDP packets so the test-bed destinations exist
//! (no ICMP port-unreachable replies), and prints the receive rate.

use std::{
    error::Error,
    net::{SocketAddrV4, UdpSocket},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use clap::Parser;

#[derive(Parser)]
#[command(about = "Discard UDP packets and report the receive rate")]
struct Args {
    /// Addresses to bind (comma separated). 0.0.0.0:PORT covers every local IP.
    #[arg(long, value_delimiter = ',', default_value = "0.0.0.0:8002")]
    bind: Vec<SocketAddrV4>,

    #[arg(long, default_value_t = 5)]
    report_secs: u64,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let received = Arc::new(AtomicU64::new(0));
    for addr in &args.bind {
        let socket = UdpSocket::bind(addr)?;
        let received = received.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while socket.recv_from(&mut buf).is_ok() {
                received.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
    let mut last = 0;
    loop {
        thread::sleep(Duration::from_secs(args.report_secs));
        let now = received.load(Ordering::Relaxed);
        println!(
            "received {} total, {:.0} pkts/s",
            now,
            (now - last) as f64 / args.report_secs as f64
        );
        last = now;
    }
}
