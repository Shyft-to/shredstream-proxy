//! shred-fanout: receives UDP shreds on one port and forwards every unique
//! shred to a list of destinations, with as little latency as possible.
//!
//! Design (from the profile of jito-shredstream-proxy, see progress/):
//! - One receive thread busy-polls the socket, so no thread is ever woken to
//!   handle a packet. Duplicates are dropped inline.
//! - Each unique shred is copied once into a broadcast ring.
//! - K pinned sender threads busy-poll the ring. Each owns a fixed share of
//!   the destinations and sends a shred to all of them in one `sendmmsg`.
//!
//! Command line is compatible with `jito-shredstream-proxy forward-only`, so
//! it can replace that binary directly (e.g. in fanout-bench's ab.sh).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("shred-fanout runs on Linux only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket},
        os::fd::AsRawFd,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        thread,
        time::Duration,
    };

    use clap::{Args, Parser, Subcommand};
    use log::{error, info, warn};
    use shred_fanout::{
        dedup::Deduper,
        net::{pin_current_thread, set_recv_buffer, set_send_buffer, RecvBatch, SendBatch},
        ring::{broadcast, Consumer, Producer},
    };

    /// Datagrams fetched per `recvmmsg` call.
    const RECV_BATCH: usize = 64;
    /// Most shreds a sender takes from the ring per round.
    const MAX_SHREDS_PER_ROUND: u64 = 64;
    const RECV_BUFFER_BYTES: usize = 64 << 20;
    const SEND_BUFFER_BYTES: usize = 8 << 20;

    #[derive(Parser)]
    #[command(about = "Low-latency UDP shred fan-out")]
    struct Cli {
        #[command(subcommand)]
        cmd: Cmd,
    }

    #[derive(Subcommand)]
    enum Cmd {
        /// Receive shreds on one port and forward them to every destination.
        ForwardOnly(ForwardArgs),
    }

    #[derive(Args)]
    struct ForwardArgs {
        /// Address to receive shreds on.
        #[arg(long, env, default_value_t = Ipv4Addr::UNSPECIFIED)]
        src_bind_addr: Ipv4Addr,

        /// Port(s) to receive shreds on, comma separated. With several ports,
        /// one receiver polls them all and duplicates across ports are dropped,
        /// so each shred is forwarded once, from whichever port got it first.
        #[arg(long, env, value_delimiter = ',', default_value = "20000")]
        src_bind_port: Vec<u16>,

        /// Destinations, comma separated: `10.0.0.1:8001,host:8002`.
        #[arg(long, env, value_delimiter = ',', required = true)]
        dest_ip_ports: Vec<String>,

        /// Number of sender threads; destinations are split evenly across them.
        #[arg(long, env = "FANOUT_SENDERS", default_value_t = 4)]
        sender_threads: usize,

        /// CPUs to pin to, comma separated: the first for the receiver, the
        /// rest for the senders. Unpinned if omitted.
        #[arg(long, env = "FANOUT_CPUS", value_delimiter = ',')]
        cpus: Vec<usize>,

        /// Ring slots between the receiver and the senders.
        #[arg(long, env = "FANOUT_RING_SLOTS", default_value_t = 8192)]
        ring_slots: usize,

        /// Unique shreds per dedup generation; the window covers 1-2 generations.
        #[arg(long, env = "FANOUT_DEDUP_GENERATION", default_value_t = 262_144)]
        dedup_generation: usize,

        /// Seconds between stats log lines.
        #[arg(long, env = "FANOUT_STATS_SECS", default_value_t = 10)]
        stats_secs: u64,

        // Accepted for drop-in compatibility with jito-shredstream-proxy; unused.
        #[arg(long, hide = true)]
        public_ip: Option<String>,
        #[arg(long, hide = true)]
        num_threads: Option<usize>,
        #[arg(long, hide = true)]
        metrics_report_interval_ms: Option<u64>,
    }

    #[derive(Default)]
    struct Stats {
        received: AtomicU64,
        duplicates: AtomicU64,
        truncated: AtomicU64,
        ring_full: AtomicU64,
        sent: AtomicU64,
        send_failed: AtomicU64,
    }

    pub fn main() {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
        let Cmd::ForwardOnly(args) = Cli::parse().cmd;
        if let Err(e) = run(args) {
            error!("{e}");
            std::process::exit(1);
        }
    }

    fn resolve_dests(specs: &[String]) -> Result<Vec<SocketAddrV4>, String> {
        let mut dests = Vec::new();
        for spec in specs.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let addr = spec
                .to_socket_addrs()
                .map_err(|e| format!("cannot resolve destination {spec}: {e}"))?
                .find_map(|a| match a {
                    SocketAddr::V4(v4) => Some(v4),
                    SocketAddr::V6(_) => None,
                })
                .ok_or_else(|| format!("destination {spec} has no IPv4 address"))?;
            if !dests.contains(&addr) {
                dests.push(addr);
            }
        }
        if dests.is_empty() {
            return Err("no destinations".into());
        }
        Ok(dests)
    }

    fn run(args: ForwardArgs) -> Result<(), String> {
        let dests = resolve_dests(&args.dest_ip_ports)?;
        let senders = args.sender_threads.clamp(1, dests.len());

        let mut recv_sockets = Vec::new();
        for &port in &args.src_bind_port {
            let socket = UdpSocket::bind(SocketAddrV4::new(args.src_bind_addr, port))
                .map_err(|e| format!("cannot bind {}:{port}: {e}", args.src_bind_addr))?;
            socket.set_nonblocking(true).map_err(|e| e.to_string())?;
            if let Err(e) = set_recv_buffer(socket.as_raw_fd(), RECV_BUFFER_BYTES) {
                warn!("could not set receive buffer on port {port}: {e}");
            }
            recv_sockets.push(socket);
        }

        let stats = Arc::new(Stats::default());
        let (producer, consumers) = broadcast(args.ring_slots, senders);
        let cpu_for = |i: usize| args.cpus.get(i).copied();

        // Destination i goes to sender i % senders.
        for (id, consumer) in consumers.into_iter().enumerate() {
            let mine: Vec<SocketAddrV4> = dests.iter().copied().skip(id).step_by(senders).collect();
            let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                .map_err(|e| e.to_string())?;
            if let Err(e) = set_send_buffer(socket.as_raw_fd(), SEND_BUFFER_BYTES) {
                warn!("could not set send buffer: {e}");
            }
            info!(
                "sender {id}: {} destinations from {}, cpu {:?}",
                mine.len(),
                socket
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_default(),
                cpu_for(id + 1)
            );
            let stats = stats.clone();
            let cpu = cpu_for(id + 1);
            thread::Builder::new()
                .name(format!("fanSend{id}"))
                .spawn(move || sender_loop(consumer, socket, &mine, cpu, &stats))
                .map_err(|e| e.to_string())?;
        }

        {
            let stats = stats.clone();
            let cpu = cpu_for(0);
            let dedup_generation = args.dedup_generation;
            thread::Builder::new()
                .name("fanRecv".into())
                .spawn(move || {
                    receive_loop(
                        recv_sockets,
                        producer,
                        Deduper::new(dedup_generation),
                        cpu,
                        &stats,
                    )
                })
                .map_err(|e| e.to_string())?;
        }

        info!(
            "forwarding {} port(s) {:?} to {} destinations with {} senders",
            args.src_bind_addr,
            args.src_bind_port,
            dests.len(),
            senders
        );
        report_stats(&stats, args.stats_secs.max(1))
    }

    fn pin(cpu: Option<usize>, who: &str) {
        if let Some(cpu) = cpu {
            if let Err(e) = pin_current_thread(cpu) {
                warn!("{who}: could not pin to cpu {cpu}: {e}");
            }
        }
    }

    fn receive_loop(
        sockets: Vec<UdpSocket>,
        mut producer: Producer,
        mut dedup: Deduper,
        cpu: Option<usize>,
        stats: &Stats,
    ) {
        pin(cpu, "receiver");
        let fds: Vec<_> = sockets.iter().map(|s| s.as_raw_fd()).collect();
        let mut batch = RecvBatch::new(RECV_BATCH);
        let mut idle = 0;
        // Poll the sockets in turn; spin only after a full round found nothing.
        for &fd in fds.iter().cycle() {
            let n = match batch.recv(fd) {
                Ok(0) => {
                    idle += 1;
                    if idle >= fds.len() {
                        idle = 0;
                        std::hint::spin_loop();
                    }
                    continue;
                }
                Ok(n) => n,
                Err(e) => {
                    error!("receive failed: {e}");
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            idle = 0;
            let (mut dups, mut truncated, mut full) = (0, 0, 0);
            for i in 0..n {
                match batch.packet(i) {
                    None => truncated += 1,
                    Some(p) if !dedup.is_new(p) => dups += 1,
                    Some(p) => full += !producer.publish(p) as u64,
                }
            }
            producer.flush();
            stats.received.fetch_add(n as u64, Ordering::Relaxed);
            stats.duplicates.fetch_add(dups, Ordering::Relaxed);
            stats.truncated.fetch_add(truncated, Ordering::Relaxed);
            stats.ring_full.fetch_add(full, Ordering::Relaxed);
        }
    }

    fn sender_loop(
        mut consumer: Consumer,
        socket: UdpSocket,
        dests: &[SocketAddrV4],
        cpu: Option<usize>,
        stats: &Stats,
    ) {
        pin(cpu, "sender");
        let fd = socket.as_raw_fd();
        let mut batch = SendBatch::new(dests);
        loop {
            let available = consumer.available();
            if available == 0 {
                std::hint::spin_loop();
                continue;
            }
            // Shred-major order: every destination gets shred 1 before any gets shred 2.
            let mut taken = 0;
            while taken < available.min(MAX_SHREDS_PER_ROUND) && !batch.is_full() {
                let packet = consumer.packet(taken);
                for d in 0..batch.dest_count() {
                    batch.push(packet, d);
                }
                taken += 1;
            }
            let (sent, failed) = batch.send(fd);
            consumer.advance(taken);
            stats.sent.fetch_add(sent as u64, Ordering::Relaxed);
            stats
                .send_failed
                .fetch_add(failed as u64, Ordering::Relaxed);
        }
    }

    fn report_stats(stats: &Stats, secs: u64) -> ! {
        let read = |s: &Stats| {
            [
                s.received.load(Ordering::Relaxed),
                s.duplicates.load(Ordering::Relaxed),
                s.truncated.load(Ordering::Relaxed),
                s.ring_full.load(Ordering::Relaxed),
                s.sent.load(Ordering::Relaxed),
                s.send_failed.load(Ordering::Relaxed),
            ]
        };
        let mut last = read(stats);
        loop {
            thread::sleep(Duration::from_secs(secs));
            let now = read(stats);
            let d: Vec<u64> = now.iter().zip(&last).map(|(n, l)| n - l).collect();
            info!(
                "last {secs}s: received {} ({}/s), duplicates {}, truncated {}, ring full {}, sent {} ({}/s), send failed {}",
                d[0],
                d[0] / secs,
                d[1],
                d[2],
                d[3],
                d[4],
                d[4] / secs,
                d[5]
            );
            last = now;
        }
    }
}
