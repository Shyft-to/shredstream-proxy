//! Runs on a destination host. Receives the stamped shred copies that the
//! forwarders (kfan with STAMP_PORT, xskfwd with --stamp-port) send to this
//! port, and reports the one-way latency from the shred's first arrival on the
//! forwarder host to its arrival here (kernel receive timestamp). Modes:
//! "kfan-xdp" (arrival = NIC driver, xdpstamp.sh), "kfan" (arrival = when the
//! kernel fan-out started on it), "xsk" (AF_XDP forwarder).
//!
//! The stamp is the forwarder host's CLOCK_MONOTONIC. A second thread keeps
//! mapping that clock onto this host's clock by probing `clock-echo` on the
//! forwarder host (NTP-style: four timestamps; the fastest probes in each
//! half second are fitted with a line, so clock drift is followed). Path
//! asymmetry stays as a constant error of at most half the fastest probe's
//! round trip (reported); it is the same for every forwarder measured, so
//! comparisons are not affected.

use std::{
    collections::{BTreeMap, VecDeque},
    error::Error,
    fs::OpenOptions,
    io::Write,
    net::{SocketAddrV4, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use fanout_bench::{stats, ts};
use serde_json::json;

#[derive(Parser)]
#[command(about = "Measure forwarder-to-receiver latency of stamped shreds")]
struct Args {
    /// Where the stamped copies arrive (the forwarders' STAMP_PORT).
    #[arg(long, default_value = "0.0.0.0:9910")]
    bind: SocketAddrV4,

    /// clock-echo on the forwarder host.
    #[arg(long)]
    clock_server: SocketAddrV4,

    /// Interval between clock probes, ms.
    #[arg(long, default_value_t = 10)]
    probe_ms: u64,

    #[arg(long, default_value_t = 10)]
    report_secs: u64,

    #[arg(long, default_value = "stamp-recv")]
    label: String,

    /// Append one JSON line per mode and window here.
    #[arg(long)]
    results: Option<String>,
}

const BUCKET_NS: u64 = 500_000_000;
const BUCKETS: usize = 20; // fit over the last 10 s

#[derive(Clone, Copy)]
struct Probe {
    t: u64,      // local CLOCK_REALTIME, middle of the probe
    offset: f64, // forwarder monotonic minus local realtime, ns
    rtt: u64,    // round trip without the responder's own time, ns
}

/// Forwarder clock = local clock + offset(t), offset(t) = off + slope * (t - t0).
#[derive(Clone, Copy)]
struct Model {
    t0: u64,
    off: f64,
    slope: f64,
    min_rtt: u64,
    used: usize,
    last_probe: u64,
}

impl Model {
    fn offset_at(&self, t: u64) -> f64 {
        self.off + self.slope * (t as f64 - self.t0 as f64)
    }
}

/// Fits the fastest probe of each recent bucket; probes much slower than the
/// fastest overall are left out (queueing on the way).
fn fit(buckets: &VecDeque<Probe>) -> Option<Model> {
    let min_rtt = buckets.iter().map(|p| p.rtt).min()?;
    let good: Vec<&Probe> = buckets.iter().filter(|p| p.rtt <= min_rtt + 20_000).collect();
    let t0 = good.last()?.t;
    let n = good.len() as f64;
    let mx = good.iter().map(|p| p.t as f64 - t0 as f64).sum::<f64>() / n;
    let my = good.iter().map(|p| p.offset).sum::<f64>() / n;
    let (mut sxy, mut sxx) = (0.0, 0.0);
    for p in &good {
        let x = p.t as f64 - t0 as f64 - mx;
        sxy += x * (p.offset - my);
        sxx += x * x;
    }
    let slope = if good.len() >= 3 && sxx > 0.0 { sxy / sxx } else { 0.0 };
    Some(Model { t0, off: my - slope * mx, slope, min_rtt, used: good.len(), last_probe: t0 })
}

fn sync_loop(server: SocketAddrV4, every: Duration, model: Arc<Mutex<Option<Model>>>) {
    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind clock probe socket");
    ts::enable_rx_timestamps(&sock).expect("enable receive timestamps");
    sock.set_read_timeout(Some(Duration::from_millis(100))).ok();
    let mut buckets: VecDeque<(u64, Probe)> = VecDeque::new();
    let mut buf = [0u8; 64];
    let mut warned = false;
    loop {
        thread::sleep(every);
        let mut req = [0u8; 16];
        req[..8].copy_from_slice(ts::CLOCK_REQ);
        let t1 = ts::realtime_ns();
        req[8..16].copy_from_slice(&t1.to_le_bytes());
        if sock.send_to(&req, server).is_err() {
            continue;
        }
        let (n, _, t4) = match ts::recv_ts(&sock, &mut buf) {
            Ok(r) => r,
            Err(_) => {
                if !warned {
                    eprintln!("stamp-recv: no answer from clock-echo at {server} (firewall? running?)");
                    warned = true;
                }
                continue;
            }
        };
        if n < 32 || &buf[..8] != ts::CLOCK_REP || buf[8..16] != t1.to_le_bytes() {
            continue; // a late answer to an earlier probe
        }
        let b_rx = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let b_tx = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let held = b_tx.saturating_sub(b_rx);
        let rtt = (t4 - t1).saturating_sub(held);
        let offset = ((b_rx as f64 - t1 as f64) + (b_tx as f64 - t4 as f64)) / 2.0;
        let p = Probe { t: t1 + (t4 - t1) / 2, offset, rtt };
        let id = p.t / BUCKET_NS;
        match buckets.back_mut() {
            Some((bid, best)) if *bid == id => {
                if p.rtt < best.rtt {
                    *best = p;
                }
            }
            _ => buckets.push_back((id, p)),
        }
        while buckets.len() > BUCKETS {
            buckets.pop_front();
        }
        let probes: VecDeque<Probe> = buckets.iter().map(|(_, p)| *p).collect();
        if let Some(mut m) = fit(&probes) {
            m.last_probe = p.t;
            *model.lock().unwrap() = Some(m);
        }
    }
}

#[derive(Default)]
struct Window {
    lat: Vec<u64>,
    negative: u64,
}

fn mode_of(magic: &[u8]) -> Option<&'static str> {
    match magic {
        // Kernel fan-out, time taken when its program started on the shred
        // (excludes queueing before it).
        b"kfanstmp" => Some("kfan"),
        // Kernel fan-out, time taken at the NIC driver (xdpstamp.sh).
        b"kfanxdps" => Some("kfan-xdp"),
        b"xskstamp" => Some("xsk"),
        _ => None,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let sock = UdpSocket::bind(args.bind)?;
    ts::enable_rx_timestamps(&sock)?;
    ts::set_recv_buffer(&sock, 32 << 20);
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;

    let model = Arc::new(Mutex::new(None::<Model>));
    {
        let model = model.clone();
        let (server, every) = (args.clock_server, Duration::from_millis(args.probe_ms));
        thread::spawn(move || sync_loop(server, every, model));
    }
    eprintln!("stamp-recv: listening on {}, clock from {}", args.bind, args.clock_server);

    let mut windows: BTreeMap<&'static str, Window> = BTreeMap::new();
    let (mut unstamped, mut unsynced) = (0u64, 0u64);
    let mut buf = [0u8; 2048];
    let report_ns = args.report_secs * 1_000_000_000;
    let mut start = ts::realtime_ns();
    loop {
        match ts::recv_ts(&sock, &mut buf) {
            Ok((n, _, rx)) => {
                let mode = if n >= 16 { mode_of(&buf[..8]) } else { None };
                match (mode, *model.lock().unwrap()) {
                    (None, _) => unstamped += 1,
                    // No clock mapping yet, or the clock probes stopped answering.
                    (Some(_), None) => unsynced += 1,
                    (Some(_), Some(m)) if rx.saturating_sub(m.last_probe) > 5_000_000_000 => unsynced += 1,
                    (Some(mode), Some(m)) => {
                        let stamp = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                        let lat = rx as f64 + m.offset_at(rx) - stamp as f64;
                        let w = windows.entry(mode).or_default();
                        if lat < 0.0 {
                            w.negative += 1;
                            w.lat.push(0);
                        } else {
                            w.lat.push(lat as u64);
                        }
                    }
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) => return Err(e.into()),
        }

        let now = ts::realtime_ns();
        if now - start < report_ns {
            continue;
        }
        let secs = (now - start) as f64 / 1e9;
        start = now;
        let m = *model.lock().unwrap();
        let sync = match m {
            Some(m) => format!(
                "clock: fastest probe {:.1} us (error bound +-{:.1} us), drift {:.2} ppm, {} buckets",
                m.min_rtt as f64 / 1e3,
                m.min_rtt as f64 / 2e3,
                m.slope * 1e6,
                m.used
            ),
            None => "clock: not synced yet".to_string(),
        };
        if windows.is_empty() {
            println!(
                "[{}] {secs:.0}s: no stamped shreds (unstamped {unstamped}, before clock sync {unsynced}) | {sync}",
                args.label
            );
        }
        let unix = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        for (mode, w) in windows.iter_mut() {
            let s = stats::summarize(&mut w.lat);
            println!(
                "[{}] {secs:.0}s {mode}: {} shreds | forwarder arrival -> here: p50 {:.1} p90 {:.1} p99 {:.1} p99.9 {:.1} max {:.1} us{} | {sync}",
                args.label,
                s.count,
                s.p50_us,
                s.p90_us,
                s.p99_us,
                s.p999_us,
                s.max_us,
                if w.negative > 0 { format!(" ({} below 0, counted as 0)", w.negative) } else { String::new() }
            );
            if let Some(path) = &args.results {
                if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
                    let line = json!({
                        "label": args.label, "unix_time": unix, "source": "stamp-recv", "mode": mode,
                        "window_s": secs, "negative": w.negative, "unstamped": unstamped,
                        "unsynced": unsynced, "latency": s,
                        "sync": m.map(|m| json!({
                            "min_rtt_us": m.min_rtt as f64 / 1e3, "drift_ppm": m.slope * 1e6, "buckets": m.used,
                        })),
                    });
                    let _ = writeln!(f, "{line}");
                }
            }
        }
        std::io::stdout().flush().ok();
        windows.clear();
        unstamped = 0;
        unsynced = 0;
    }
}
