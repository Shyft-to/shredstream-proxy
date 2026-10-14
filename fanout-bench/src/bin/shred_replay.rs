//! Replays UDP packets from a pcap at their original timing, preserving which
//! source sent each packet, so a forwarder sees production-shaped traffic
//! (bursts, and the same shred arriving from several sources).

use std::{
    collections::HashMap,
    error::Error,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::Parser;
use fanout_bench::{pcap::PcapReader, stats::summarize};

#[derive(Parser)]
#[command(about = "Replay captured UDP traffic at its original timing")]
struct Args {
    /// pcap captured with full snap length (`tcpdump -s 0`).
    #[arg(long)]
    pcap: PathBuf,

    /// Replay only packets that were addressed to this UDP port.
    #[arg(long)]
    port: Option<u16>,

    /// Where to send the packets (the forwarder under test).
    #[arg(long)]
    target: SocketAddrV4,

    /// Local IPs to send from (comma separated). Each distinct original source
    /// gets its own socket, assigned round-robin to these IPs.
    #[arg(long, value_delimiter = ',', required = true)]
    src_ips: Vec<Ipv4Addr>,

    /// Play the capture this many times back to back. Each extra loop flips
    /// two signature bytes so the shreds are new to the forwarder's deduper.
    #[arg(long, default_value_t = 1)]
    loops: u32,

    /// Time scale: 2.0 plays twice as fast.
    #[arg(long, default_value_t = 1.0)]
    speed: f64,
}

struct Pkt {
    src: usize,
    rel_ns: u64,
    data: Vec<u8>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let mut sources: HashMap<SocketAddrV4, usize> = HashMap::new();
    let mut pkts = Vec::new();
    let mut truncated = 0u64;
    let mut first_ts = None;
    let mut reader = PcapReader::open(&args.pcap)?;
    while let Some(p) = reader.next_udp()? {
        if args.port.is_some_and(|port| p.dst.port() != port) {
            continue;
        }
        if p.payload.len() < p.payload_len {
            truncated += 1;
            continue;
        }
        let t0 = *first_ts.get_or_insert(p.ts_ns);
        let next_src = sources.len();
        let src = *sources.entry(p.src).or_insert(next_src);
        pkts.push(Pkt {
            src,
            rel_ns: p.ts_ns.saturating_sub(t0),
            data: p.payload.to_vec(),
        });
    }
    if pkts.is_empty() {
        return Err("no replayable packets in the capture".into());
    }
    if truncated > 0 {
        eprintln!("skipped {truncated} packets truncated by the capture snap length");
    }

    let sockets = (0..sources.len())
        .map(|i| UdpSocket::bind(SocketAddrV4::new(args.src_ips[i % args.src_ips.len()], 0)))
        .collect::<Result<Vec<_>, _>>()?;

    let span_ns = pkts.last().map_or(0, |p| p.rel_ns) + 1_000_000;
    println!(
        "replaying {} packets from {} sources over {:.1}s x {} loops to {}",
        pkts.len(),
        sources.len(),
        span_ns as f64 / 1e9 / args.speed,
        args.loops,
        args.target
    );

    let mut lateness = Vec::with_capacity(pkts.len() * args.loops as usize);
    let mut scratch = Vec::with_capacity(2048);
    let (mut sent, mut errors) = (0u64, 0u64);
    let start = Instant::now() + Duration::from_millis(200);

    for lp in 0..args.loops {
        for p in &pkts {
            let offset_ns = ((lp as u64 * span_ns + p.rel_ns) as f64 / args.speed) as u64;
            let due = start + Duration::from_nanos(offset_ns);
            // Spin rather than sleep: sleep wakeups are tens of microseconds late,
            // which would smear the burst shape we are trying to reproduce.
            let now = loop {
                let now = Instant::now();
                if now >= due {
                    break now;
                }
                std::hint::spin_loop();
            };
            lateness.push((now - due).as_nanos() as u64);

            let data: &[u8] = if lp == 0 || p.data.len() < 64 {
                &p.data
            } else {
                scratch.clear();
                scratch.extend_from_slice(&p.data);
                scratch[63] ^= lp as u8;
                scratch[62] ^= (lp >> 8) as u8;
                &scratch
            };
            match sockets[p.src].send_to(data, args.target) {
                Ok(_) => sent += 1,
                Err(_) => errors += 1,
            }
        }
    }

    let late = summarize(&mut lateness);
    println!(
        "sent {sent}, errors {errors}; lateness vs schedule p50 {:.1}us p99 {:.1}us max {:.1}us",
        late.p50_us, late.p99_us, late.max_us
    );
    // Parsed by testbed.sh to reject runs where the input was not faithful.
    println!("REPLAY_LATENESS_P99_US={:.1}", late.p99_us);
    Ok(())
}
