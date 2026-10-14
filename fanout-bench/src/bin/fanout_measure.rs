//! Computes the fan-out north-star metric from packet captures, and compares
//! labelled runs to decide whether a change moved it.
//!
//! North star: p99 fan-out completion latency. For each unique shred, the time
//! from its first arrival at the forwarder host to the moment its copy for the
//! *last* destination was handed to the network. Both timestamps come from the
//! kernel packet taps, so the measurement does not depend on the forwarder's
//! implementation (userspace proxy, eBPF, ...).

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs::{File, OpenOptions},
    hash::{DefaultHasher, Hash, Hasher},
    io::{BufRead, BufReader, Write},
    net::SocketAddrV4,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Args, Parser, Subcommand};
use fanout_bench::{
    pcap::PcapReader,
    stats::{summarize, Summary},
};
use serde::Serialize;
use serde_json::Value;

type Res<T> = Result<T, Box<dyn Error>>;

#[derive(Parser)]
#[command(about = "Fan-out north-star latency: analyze captures, compare runs")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compute the north star and guardrails from one or more captures.
    Analyze(AnalyzeArgs),
    /// Compare two labels in a results file and say whether the metric moved.
    Compare(CompareArgs),
}

#[derive(Args)]
struct AnalyzeArgs {
    /// pcap file(s) from `tcpdump -w`, ideally with `--time-stamp-precision nano`.
    /// Several files are merged (e.g. one per interface); they must share a clock.
    #[arg(long, required = true)]
    pcap: Vec<PathBuf>,

    /// UDP port the forwarder listens on. Packets to it are ingress.
    #[arg(long)]
    listen_port: u16,

    /// Expected destinations (comma separated). Packets to other addresses are
    /// ignored. If omitted, every destination that received a matched shred counts.
    #[arg(long, value_delimiter = ',')]
    dests: Vec<SocketAddrV4>,

    /// Only count egress sent from these local UDP ports (comma separated).
    /// Use in production to isolate one instance's sockets.
    #[arg(long, value_delimiter = ',')]
    egress_src_ports: Vec<u16>,

    /// Leading payload bytes that identify a shred: signature (64) + variant,
    /// slot, index, version, fec_set_index.
    #[arg(long, default_value_t = 83)]
    key_bytes: usize,

    /// Ignore shreds that first arrived within this many ms of the start or
    /// end of the capture, so partially captured fan-outs are not counted.
    #[arg(long, default_value_t = 500)]
    edge_ms: u64,

    /// Label recorded with the result (e.g. "baseline", "rx-usecs-0").
    #[arg(long, default_value = "unlabelled")]
    label: String,

    /// Append the result as one JSON line to this file.
    #[arg(long)]
    results: Option<PathBuf>,

    /// Forwarder CPU time (user + sys) during the capture, in ms. Enables the
    /// CPU-cost guardrail.
    #[arg(long)]
    cpu_ms: Option<f64>,

    /// Extra key=value pairs to record with the result (repeatable).
    #[arg(long = "meta", value_parser = parse_kv)]
    meta: Vec<(String, String)>,

    /// Number of destinations to list in the per-destination table.
    #[arg(long, default_value_t = 30)]
    show_dests: usize,

    /// Window for the "latency vs recent load" breakdown: each shred is
    /// grouped by how many shreds arrived in this many µs before it.
    #[arg(long, default_value_t = 500)]
    load_window_us: u64,
}

#[derive(Args)]
struct CompareArgs {
    /// JSON-lines results file written by `analyze --results`.
    #[arg(long)]
    results: PathBuf,

    #[arg(long)]
    baseline: String,

    #[arg(long)]
    candidate: String,

    /// Metric to compare, as a dotted path into the result. Lower is better.
    #[arg(long, default_value = "completion.p99_us")]
    metric: String,

    /// Runs whose replayer fell further behind schedule than this (p99, us)
    /// are excluded: the input traffic was not faithful.
    #[arg(long, default_value_t = 50.0)]
    max_replay_lateness_us: f64,

    /// Allowed drop in delivery ratio (percentage points) before the
    /// candidate fails the delivery guardrail.
    #[arg(long, default_value_t = 0.05)]
    delivery_tolerance_pct: f64,
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected key=value, got `{s}`"))
}

fn main() -> Res<()> {
    match Cli::parse().cmd {
        Cmd::Analyze(a) => analyze(a),
        Cmd::Compare(c) => compare(c),
    }
}

// ---------------------------------------------------------------- analyze --

struct Ingress {
    first_ns: u64,
    first_src: SocketAddrV4,
    multi_source: bool,
}

struct Egress {
    first_ns: u64,
    /// Interface the first copy was seen on. Copies are only counted on that
    /// interface, because one send shows up on every layer it crosses
    /// (VLAN device, bond, slave) in an "any" capture.
    first_if: u32,
    copies: u32,
}

#[derive(Serialize)]
struct DestResult {
    dest: String,
    latency: Summary,
}

#[derive(Serialize)]
struct LoadBucket {
    /// Shreds that arrived in the load window before this one ("6+" = 6 or more).
    recent_arrivals: String,
    completion: Summary,
    first_dest: Summary,
}

/// Largest "recent arrivals" bucket; everything above it is grouped together.
const LOAD_BUCKETS: usize = 6;

#[derive(Serialize)]
struct AnalyzeResult {
    label: String,
    unix_time: u64,
    pcaps: Vec<String>,
    meta: HashMap<String, String>,
    capture_seconds: f64,
    nanosecond_timestamps: bool,
    dests: usize,
    /// Unique shreds seen arriving, over the whole capture.
    ingress_unique: usize,
    /// Shreds inside the measurement window (capture minus edges).
    eligible_shreds: u64,
    /// Share of eligible shreds that arrived from two or more sources.
    multi_source_pct: f64,
    complete_shreds: u64,
    /// Expected (shred, destination) sends that never appeared.
    missing_sends: u64,
    /// Extra copies of a shred sent to the same destination (dedup leaks).
    duplicate_sends: u64,
    /// Sends delivered / sends expected, in percent.
    delivery_pct: f64,
    /// Egress whose shred was never seen arriving (usually arrived before
    /// the capture started).
    orphan_egress: usize,
    /// Packets whose captured payload was shorter than `key_bytes`.
    short_key_packets: u64,
    /// Sends whose egress timestamp preceded the ingress (clamped to 0).
    negative_latencies: u64,
    egress_sends_per_s: f64,
    cpu_us_per_send: Option<f64>,
    /// NORTH STAR: first arrival -> last destination's copy handed to the NIC.
    completion: Summary,
    /// First arrival -> first destination's copy (receive-path cost).
    first_dest: Summary,
    /// Every (shred, destination) send.
    per_send: Summary,
    per_dest: Vec<DestResult>,
    load_window_us: u64,
    /// Latency grouped by how busy the forwarder was just before the shred
    /// arrived. Rising latency with load means queueing.
    by_recent_arrivals: Vec<LoadBucket>,
}

fn shred_key(payload: &[u8], key_bytes: usize, wire_len: usize) -> u64 {
    let mut h = DefaultHasher::new();
    wire_len.hash(&mut h);
    payload[..payload.len().min(key_bytes)].hash(&mut h);
    h.finish()
}

fn analyze(a: AnalyzeArgs) -> Res<()> {
    let fixed_dests = !a.dests.is_empty();
    let mut dest_list: Vec<SocketAddrV4> = a.dests.clone();
    let mut dest_idx: HashMap<SocketAddrV4, u16> = dest_list
        .iter()
        .enumerate()
        .map(|(i, d)| (*d, i as u16))
        .collect();
    let src_filter: HashSet<u16> = a.egress_src_ports.iter().copied().collect();

    let mut ingress: HashMap<u64, Ingress> = HashMap::new();
    let mut egress: HashMap<(u64, u16), Egress> = HashMap::new();
    let (mut t_min, mut t_max) = (u64::MAX, 0u64);
    let mut short_key_packets = 0u64;
    let mut all_nanos = true;

    for path in &a.pcap {
        let mut reader = PcapReader::open(path)?;
        all_nanos &= reader.has_nanos();
        while let Some(p) = reader.next_udp()? {
            t_min = t_min.min(p.ts_ns);
            t_max = t_max.max(p.ts_ns);
            if p.payload.len() < a.key_bytes.min(p.payload_len) {
                short_key_packets += 1;
            }
            let key = shred_key(p.payload, a.key_bytes, p.payload_len);

            if p.dst.port() == a.listen_port {
                ingress
                    .entry(key)
                    .and_modify(|i| {
                        i.first_ns = i.first_ns.min(p.ts_ns);
                        i.multi_source |= p.src != i.first_src;
                    })
                    .or_insert(Ingress {
                        first_ns: p.ts_ns,
                        first_src: p.src,
                        multi_source: false,
                    });
                continue;
            }

            if !src_filter.is_empty() && !src_filter.contains(&p.src.port()) {
                continue;
            }
            let d = match dest_idx.get(&p.dst) {
                Some(&d) => d,
                None if fixed_dests => continue,
                None => {
                    let d = dest_list.len() as u16;
                    dest_list.push(p.dst);
                    dest_idx.insert(p.dst, d);
                    d
                }
            };
            egress
                .entry((key, d))
                .and_modify(|e| {
                    e.first_ns = e.first_ns.min(p.ts_ns);
                    if p.ifindex == e.first_if {
                        e.copies += 1;
                    }
                })
                .or_insert(Egress {
                    first_ns: p.ts_ns,
                    first_if: p.ifindex,
                    copies: 1,
                });
        }
    }

    if ingress.is_empty() {
        return Err(format!("no ingress packets to port {} in the capture", a.listen_port).into());
    }

    // Destinations to judge completeness against. Without an explicit list,
    // only those that received at least one shred we saw arrive.
    let active: Vec<u16> = if fixed_dests {
        (0..dest_list.len() as u16).collect()
    } else {
        let matched: HashSet<u16> = egress
            .keys()
            .filter(|(k, _)| ingress.contains_key(k))
            .map(|&(_, d)| d)
            .collect();
        let mut v: Vec<u16> = matched.into_iter().collect();
        v.sort_unstable();
        v
    };

    let edge_ns = a.edge_ms * 1_000_000;
    let (win_lo, win_hi) = (t_min + edge_ns, t_max.saturating_sub(edge_ns));

    let mut per_dest: Vec<Vec<u64>> = vec![Vec::new(); dest_list.len()];
    let mut per_send = Vec::new();
    let mut completion = Vec::new();
    let mut first_dest = Vec::new();
    let mut timed: Vec<(u64, u64, u64)> = Vec::new();
    let (mut eligible, mut multi, mut missing, mut dups, mut negative) = (0u64, 0u64, 0u64, 0u64, 0u64);

    for (key, ing) in &ingress {
        if ing.first_ns < win_lo || ing.first_ns > win_hi {
            continue;
        }
        eligible += 1;
        multi += ing.multi_source as u64;
        let (mut worst, mut best, mut complete) = (0u64, u64::MAX, true);
        for &d in &active {
            match egress.get(&(*key, d)) {
                Some(e) => {
                    let lat = match e.first_ns.checked_sub(ing.first_ns) {
                        Some(l) => l,
                        None => {
                            negative += 1;
                            0
                        }
                    };
                    per_dest[d as usize].push(lat);
                    per_send.push(lat);
                    worst = worst.max(lat);
                    best = best.min(lat);
                    dups += (e.copies - 1) as u64;
                }
                None => {
                    missing += 1;
                    complete = false;
                }
            }
        }
        if complete && !active.is_empty() {
            completion.push(worst);
            first_dest.push(best);
            timed.push((ing.first_ns, worst, best));
        }
    }

    // Latency vs recent load: count arrivals in the window before each shred.
    let mut arrivals: Vec<u64> = ingress.values().map(|i| i.first_ns).collect();
    arrivals.sort_unstable();
    let window_ns = a.load_window_us * 1_000;
    let mut load_completion: Vec<Vec<u64>> = vec![Vec::new(); LOAD_BUCKETS + 1];
    let mut load_first: Vec<Vec<u64>> = vec![Vec::new(); LOAD_BUCKETS + 1];
    for &(t, worst, best) in &timed {
        let recent = arrivals.partition_point(|&x| x < t) - arrivals.partition_point(|&x| x < t.saturating_sub(window_ns));
        let b = recent.min(LOAD_BUCKETS);
        load_completion[b].push(worst);
        load_first[b].push(best);
    }
    let by_recent_arrivals: Vec<LoadBucket> = (0..=LOAD_BUCKETS)
        .map(|b| LoadBucket {
            recent_arrivals: if b == LOAD_BUCKETS { format!("{b}+") } else { b.to_string() },
            completion: summarize(&mut load_completion[b]),
            first_dest: summarize(&mut load_first[b]),
        })
        .collect();

    let orphan_egress = egress.keys().filter(|(k, _)| !ingress.contains_key(k)).count();
    let capture_seconds = t_max.saturating_sub(t_min) as f64 / 1e9;
    let expected = eligible * active.len() as u64;
    let delivered = expected - missing;

    let mut dest_results: Vec<DestResult> = active
        .iter()
        .map(|&d| DestResult {
            dest: dest_list[d as usize].to_string(),
            latency: summarize(&mut per_dest[d as usize]),
        })
        .collect();
    dest_results.sort_by(|x, y| y.latency.p99_us.total_cmp(&x.latency.p99_us));

    let result = AnalyzeResult {
        label: a.label.clone(),
        unix_time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        pcaps: a.pcap.iter().map(|p| p.display().to_string()).collect(),
        meta: a.meta.iter().cloned().collect(),
        capture_seconds,
        nanosecond_timestamps: all_nanos,
        dests: active.len(),
        ingress_unique: ingress.len(),
        eligible_shreds: eligible,
        multi_source_pct: pct(multi, eligible),
        complete_shreds: completion.len() as u64,
        missing_sends: missing,
        duplicate_sends: dups,
        delivery_pct: pct(delivered, expected),
        orphan_egress,
        short_key_packets,
        negative_latencies: negative,
        egress_sends_per_s: if capture_seconds > 0.0 {
            egress.len() as f64 / capture_seconds
        } else {
            0.0
        },
        cpu_us_per_send: a
            .cpu_ms
            .filter(|_| !egress.is_empty())
            .map(|ms| ms * 1_000.0 / egress.len() as f64),
        completion: summarize(&mut completion),
        first_dest: summarize(&mut first_dest),
        per_send: summarize(&mut per_send),
        per_dest: dest_results,
        load_window_us: a.load_window_us,
        by_recent_arrivals,
    };

    print_report(&result, a.show_dests);

    if let Some(path) = &a.results {
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(f, "{}", serde_json::to_string(&result)?)?;
    }
    Ok(())
}

fn pct(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 * 100.0 / den as f64
    }
}

fn fmt_summary(s: &Summary) -> String {
    format!(
        "p50 {:>8.1}  p90 {:>8.1}  p99 {:>8.1}  p99.9 {:>8.1}  max {:>9.1}  (n={})",
        s.p50_us, s.p90_us, s.p99_us, s.p999_us, s.max_us, s.count
    )
}

fn print_report(r: &AnalyzeResult, show_dests: usize) {
    println!("== {} ==", r.label);
    println!(
        "NORTH STAR  p99 fan-out completion: {:.1} us",
        r.completion.p99_us
    );
    println!("  completion (first arrival -> last dest)  {}", fmt_summary(&r.completion));
    println!("  first dest (first arrival -> first dest) {}", fmt_summary(&r.first_dest));
    println!("  every send                               {}", fmt_summary(&r.per_send));
    println!("guardrails");
    println!(
        "  delivery {:.3}%  (missing {}, complete shreds {}/{})",
        r.delivery_pct, r.missing_sends, r.complete_shreds, r.eligible_shreds
    );
    println!("  duplicate sends {}", r.duplicate_sends);
    match r.cpu_us_per_send {
        Some(c) => println!("  cpu {c:.3} us per send"),
        None => println!("  cpu (not measured)"),
    }
    println!(
        "traffic  {:.1}s captured, {} unique shreds, {:.1}% from 2+ sources, {} dests, {:.0} sends/s",
        r.capture_seconds, r.ingress_unique, r.multi_source_pct, r.dests, r.egress_sends_per_s
    );
    if !r.nanosecond_timestamps {
        println!("WARNING: capture has microsecond timestamps; use tcpdump --time-stamp-precision nano");
    }
    if r.short_key_packets > 0 {
        println!(
            "WARNING: {} packets captured with fewer than key-bytes of payload; raise the snap length",
            r.short_key_packets
        );
    }
    if r.negative_latencies > 0 {
        println!("WARNING: {} sends timestamped before their ingress", r.negative_latencies);
    }
    println!(
        "latency vs recent load (shreds that arrived in the {} us before)",
        r.load_window_us
    );
    println!(
        "  {:>8} {:>9} {:>16} {:>16} {:>16}",
        "arrivals", "shreds", "completion p50", "completion p99", "first dest p50"
    );
    for b in r.by_recent_arrivals.iter().filter(|b| b.completion.count > 0) {
        println!(
            "  {:>8} {:>9} {:>16.1} {:>16.1} {:>16.1}",
            b.recent_arrivals, b.completion.count, b.completion.p50_us, b.completion.p99_us, b.first_dest.p50_us
        );
    }
    println!("per destination (slowest p99 first)");
    for d in r.per_dest.iter().take(show_dests) {
        println!("  {:<22} {}", d.dest, fmt_summary(&d.latency));
    }
}

// ---------------------------------------------------------------- compare --

struct Side {
    values: Vec<f64>,
    delivery: Vec<f64>,
    duplicate_sends: u64,
    excluded: usize,
}

fn load_side(rows: &[Value], label: &str, pointer: &str, c: &CompareArgs) -> Side {
    let mut side = Side {
        values: Vec::new(),
        delivery: Vec::new(),
        duplicate_sends: 0,
        excluded: 0,
    };
    for row in rows.iter().filter(|r| r["label"] == label) {
        let meta = &row["meta"];
        let tcpdump_dropped = meta["tcpdump_dropped"].as_str().unwrap_or("0");
        let lateness = meta["replay_lateness_p99_us"]
            .as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        let Some(v) = row.pointer(pointer).and_then(Value::as_f64) else {
            side.excluded += 1;
            continue;
        };
        if tcpdump_dropped != "0" || lateness > c.max_replay_lateness_us {
            side.excluded += 1;
            continue;
        }
        side.values.push(v);
        side.delivery.push(row["delivery_pct"].as_f64().unwrap_or(0.0));
        side.duplicate_sends += row["duplicate_sends"].as_u64().unwrap_or(0);
    }
    side
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    let n = s.len();
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

fn min_max(v: &[f64]) -> (f64, f64) {
    v.iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &x| (lo.min(x), hi.max(x)))
}

/// Probability that every candidate run beats every baseline run by chance
/// alone, if the change did nothing: 1 / C(n1 + n2, n1).
fn chance_of_full_separation(n1: usize, n2: usize) -> f64 {
    let (n, k) = (n1 + n2, n1.min(n2));
    let combos = (0..k).fold(1.0, |acc, i| acc * (n - i) as f64 / (i + 1) as f64);
    1.0 / combos
}

fn compare(c: CompareArgs) -> Res<()> {
    let rows: Vec<Value> = BufReader::new(File::open(&c.results)?)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect();
    let pointer = format!("/{}", c.metric.replace('.', "/"));
    let base = load_side(&rows, &c.baseline, &pointer, &c);
    let cand = load_side(&rows, &c.candidate, &pointer, &c);

    println!("metric: {} (lower is better)", c.metric);
    println!("{:<12} {:>5} {:>10} {:>10} {:>10} {:>9}", "", "runs", "median", "min", "max", "excluded");
    for (name, s) in [(&c.baseline, &base), (&c.candidate, &cand)] {
        if s.values.is_empty() {
            println!("{name:<12} {:>5} {:>10} {:>10} {:>10} {:>9}", 0, "-", "-", "-", s.excluded);
            continue;
        }
        let (lo, hi) = min_max(&s.values);
        println!(
            "{name:<12} {:>5} {:>10.1} {:>10.1} {:>10.1} {:>9}",
            s.values.len(),
            median(&s.values),
            lo,
            hi,
            s.excluded
        );
    }

    if base.values.len() < 3 || cand.values.len() < 3 {
        println!("verdict: NOT ENOUGH RUNS (need at least 3 valid runs per side; 5 recommended)");
        return Ok(());
    }

    let (b_med, c_med) = (median(&base.values), median(&cand.values));
    let (b_lo, b_hi) = min_max(&base.values);
    let (c_lo, c_hi) = min_max(&cand.values);
    let change = (c_med - b_med) / b_med * 100.0;
    let chance = chance_of_full_separation(base.values.len(), cand.values.len());
    let verdict = if c_hi < b_lo {
        format!("IMPROVED (every candidate run beat every baseline run; chance if no real effect {:.1}%)", chance * 100.0)
    } else if c_lo > b_hi {
        format!("REGRESSED (every candidate run was worse; chance if no real effect {:.1}%)", chance * 100.0)
    } else {
        "NO SIGNIFICANT CHANGE (run ranges overlap)".to_string()
    };
    println!("change: {change:+.1}% (median)   verdict: {verdict}");

    let (b_del, c_del) = (median(&base.delivery), median(&cand.delivery));
    let delivery_ok = c_del >= b_del - c.delivery_tolerance_pct;
    let dups_ok = cand.duplicate_sends == 0;
    println!(
        "guardrails: delivery {c_del:.3}% vs {b_del:.3}% {}   duplicate sends {} {}",
        if delivery_ok { "OK" } else { "FAIL" },
        cand.duplicate_sends,
        if dups_ok { "OK" } else { "FAIL" }
    );
    Ok(())
}
