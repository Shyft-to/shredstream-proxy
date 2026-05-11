use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    thread::{Builder, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use crossbeam_channel::{Receiver, RecvError};
use dashmap::DashMap;
use itertools::Itertools;
use jito_protos::shredstream::{Entry as PbEntry, TraceShred};
use log::{debug, error, info, log_enabled, trace, warn, Level};
use prost::Message;
use solana_client::client_error::reqwest;
use solana_ledger::shred::ReedSolomonCache;
use solana_metrics::{datapoint_info, datapoint_warn};
use solana_net_utils::SocketConfig;
use solana_perf::{
    deduper::Deduper,
    packet::{PacketBatch, PacketBatchRecycler},
    recycler::Recycler,
};
use solana_sdk::clock::Slot;
use solana_streamer::{
    sendmmsg::{batch_send, SendPktsError},
    streamer::{self, StreamerReceiveStats},
};
use tokio::sync::broadcast::Sender;

use crate::{
    deshred,
    deshred::{ComparableShred, ShredsStateTracker},
    resolve_hostname_port, ShredstreamProxyError,
};

// values copied from https://github.com/solana-labs/solana/blob/33bde55bbdde13003acf45bb6afe6db4ab599ae4/core/src/sigverify_shreds.rs#L20
pub const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
pub const DEDUPER_NUM_BITS: u64 = 637_534_199; // 76MB
pub const DEDUPER_RESET_CYCLE: Duration = Duration::from_secs(5 * 60);

// Initial-capacity hints for the per-thread packets_with_dest scratch buffer.
// Sized so typical batches don't trigger reallocations; the Vec grows naturally
// if a batch ever exceeds this. Cost is O(hint) memory per send thread.
const PACKETS_PER_BATCH_HINT: usize = 64;
const MAX_DESTS_HINT: usize = 16;

/// Log target for per-batch latency trace lines. Enable with
/// `RUST_LOG=shredstream::latency=trace`. Each batch emits one JSON line
/// prefixed with `LATENCY_TRACE` so log captures can be grep'd and rendered
/// by an offline HTML viewer.
pub const LATENCY_TRACE_TARGET: &str = "shredstream::latency";

/// Per-send-thread context for latency tracing. The send thread owns the
/// counter; the function bumps it on each call. Kept tiny so the hot path
/// pays only an `Instant::now()` per stage when the trace target is off.
pub struct LatencyTraceCtx<'a> {
    pub thread_id: usize,
    pub batch_seq: &'a mut u64,
    pub queue_len: usize,
}

/// Bind to ports and start forwarding shreds
#[allow(clippy::too_many_arguments)]
pub fn start_forwarder_threads(
    unioned_dest_sockets: Arc<ArcSwap<Vec<SocketAddr>>>, /* sockets shared between endpoint discovery thread and forwarders */
    src_addr: IpAddr,
    src_port: u16,
    maybe_multicast_socket: Option<Vec<UdpSocket>>,
    num_threads: Option<usize>,
    deduper: Arc<RwLock<Deduper<2, [u8]>>>,
    should_reconstruct_shreds: bool,
    entry_sender: Arc<Sender<PbEntry>>,
    debug_trace_shred: bool,
    use_discovery_service: bool,
    forward_stats: Arc<StreamerReceiveStats>,
    metrics: Arc<ShredMetrics>,
    shutdown_receiver: Receiver<()>,
    exit: Arc<AtomicBool>,
) -> Vec<JoinHandle<()>> {
    let num_threads = num_threads
        .unwrap_or_else(|| usize::from(std::thread::available_parallelism().unwrap()).min(4));

    let recycler: PacketBatchRecycler = Recycler::warmed(100, 1024);

    // multi_bind_in_range returns (port, Vec<UdpSocket>)
    let (_port, sockets) = solana_net_utils::multi_bind_in_range_with_config(
        src_addr,
        (src_port, src_port + 1),
        SocketConfig::default().reuseport(true),
        num_threads,
    )
    .unwrap_or_else(|_| {
        panic!("Failed to bind listener sockets. Check that port {src_port} is not in use.")
    });

    let (reconstruct_tx, reconstruct_rx) = crossbeam_channel::bounded(1_024);
    let mut thread_hdls = Vec::with_capacity(num_threads + 1);

    if should_reconstruct_shreds {
        let metrics = metrics.clone();
        let exit = exit.clone();
        // receives shreds from recv_from_channel_and_send_multiple_dest and calls deshred::reconstruct_shreds
        let hdl = std::thread::Builder::new()
            .name("shred_reconstructor".to_string())
            .spawn(move || {
                let mut all_shreds = ahash::HashMap::<
                    Slot,
                    (
                        ahash::HashMap<u32, HashSet<ComparableShred>>,
                        ShredsStateTracker,
                    ),
                >::default();
                let mut slot_fec_indexes_to_iterate = Vec::<(Slot, u32)>::new();
                let mut deshredded_entries =
                    Vec::<(Slot, Vec<solana_entry::entry::Entry>, Vec<u8>)>::new();
                let mut highest_slot_seen: Slot = 0;
                let rs_cache = ReedSolomonCache::default();

                while !exit.load(Ordering::Relaxed) {
                    match reconstruct_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(pkt_batch) => {
                            deshred::reconstruct_shreds(
                                pkt_batch,
                                &mut all_shreds,
                                &mut slot_fec_indexes_to_iterate,
                                &mut deshredded_entries,
                                &mut highest_slot_seen,
                                &rs_cache,
                                &metrics,
                            );

                            deshredded_entries.drain(..).for_each(
                                |(slot, _entries, entries_bytes)| {
                                    let _ = entry_sender.send(PbEntry {
                                        slot,
                                        entries: entries_bytes,
                                    });
                                },
                            );
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {} // do nothing
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .unwrap();
        thread_hdls.push(hdl);
    };

    sockets
        .into_iter()
        .chain(maybe_multicast_socket.into_iter().flatten())
        .enumerate()
        .flat_map(|(thread_id, incoming_shred_socket)| {
            let (packet_sender, packet_receiver) = crossbeam_channel::unbounded();
            let listen_thread = streamer::receiver(
                format!("ssListen{thread_id}"),
                Arc::new(incoming_shred_socket),
                exit.clone(),
                packet_sender,
                recycler.clone(),
                forward_stats.clone(),
                Duration::default(),
                false,
                None,
                false,
            );

            let deduper = deduper.clone();
            let unioned_dest_sockets = unioned_dest_sockets.clone();
            let metrics = metrics.clone();
            let shutdown_receiver = shutdown_receiver.clone();
            let reconstruct_tx = reconstruct_tx.clone();
            let exit = exit.clone();

            let send_thread = Builder::new()
                .name(format!("ssPxyTx_{thread_id}"))
                .spawn(move || {
                    let send_socket =
                        UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
                            .expect("to bind to udp port for forwarding");
                    let mut local_dest_sockets = unioned_dest_sockets.load();

                    let refresh_subscribers_tick = if use_discovery_service {
                        crossbeam_channel::tick(Duration::from_secs(30))
                    } else {
                        crossbeam_channel::tick(Duration::MAX)
                    };

                    // Reused across batches: holds (packet_data, dest_addr) pairs handed to
                    // a single sendmmsg-backed batch_send call. Typed as 'static to allow
                    // capacity reuse across calls; the function transmutes to a call-local
                    // lifetime, fills, sends, and clears before returning.
                    let mut packets_with_dest_scratch: Vec<(&'static [u8], &'static SocketAddr)> =
                        Vec::with_capacity(PACKETS_PER_BATCH_HINT * MAX_DESTS_HINT);

                    // Per-thread monotonic batch counter for latency trace lines.
                    // Pairs with `thread_id` to give a globally-unique batch id
                    // for offline analysis.
                    let mut batch_seq: u64 = 0;

                    while !exit.load(Ordering::Relaxed) {
                        crossbeam_channel::select! {
                            // forward packets
                            recv(packet_receiver) -> maybe_packet_batch => {
                                // Sample queue depth at receive — proxy for upstream pressure
                                // since we cannot instrument the streamer recv thread.
                                let queue_len = packet_receiver.len();
                                let res = recv_from_channel_and_send_multiple_dest(
                                    maybe_packet_batch,
                                    &deduper,
                                    &send_socket,
                                    &local_dest_sockets,
                                    should_reconstruct_shreds,
                                    &reconstruct_tx,
                                    debug_trace_shred,
                                    &metrics,
                                    &mut packets_with_dest_scratch,
                                    LatencyTraceCtx {
                                        thread_id,
                                        batch_seq: &mut batch_seq,
                                        queue_len,
                                    },
                                );

                                // If the channel is closed or error, break out
                                if res.is_err() {
                                    break;
                                }
                            }

                            // refresh thread-local subscribers
                            recv(refresh_subscribers_tick) -> _ => {
                                local_dest_sockets = unioned_dest_sockets.load();
                            }

                            // handle shutdown (avoid using sleep since it can hang)
                            recv(shutdown_receiver) -> _ => {
                                break;
                            }
                        }
                    }
                    info!("Exiting forwarder thread {thread_id}.");
                })
                .unwrap();

            vec![listen_thread, send_thread]
        })
        .collect::<Vec<JoinHandle<()>>>()
}

/// Broadcasts the same packet to multiple recipients, parses it into a Shred if possible,
/// and stores that shred in `all_shreds`.
///
/// Fanout is performed via a single `batch_send` call over all (packet, dest)
/// pairs, so destination count contributes to syscall count only via
/// `ceil(P*D / UIO_MAXIOV)` rather than D per batch. The `packets_with_dest_scratch`
/// buffer is owned by the caller and reused across batches to avoid per-batch
/// allocations.
#[allow(clippy::too_many_arguments)]
fn recv_from_channel_and_send_multiple_dest(
    maybe_packet_batch: Result<PacketBatch, RecvError>,
    deduper: &RwLock<Deduper<2, [u8]>>,
    send_socket: &UdpSocket,
    local_dest_sockets: &[SocketAddr],
    should_reconstruct_shreds: bool,
    reconstruct_tx: &crossbeam_channel::Sender<PacketBatch>,
    debug_trace_shred: bool,
    metrics: &ShredMetrics,
    packets_with_dest_scratch: &mut Vec<(&'static [u8], &'static SocketAddr)>,
    latency_ctx: LatencyTraceCtx<'_>,
) -> Result<(), ShredstreamProxyError> {
    // t0: batch is in hand from the channel. Captured unconditionally because
    // Instant::now() is ~tens of ns; the costlier format/write is gated by
    // the trace log level on LATENCY_TRACE_TARGET.
    let t0 = Instant::now();
    let recv_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let packet_batch = maybe_packet_batch.map_err(ShredstreamProxyError::RecvError)?;
    let trace_shred_received_time = SystemTime::now();
    let packets_received_in_batch = packet_batch.len();
    metrics
        .received
        .fetch_add(packet_batch.len() as u64, Ordering::Relaxed);
    debug!(
        "Got batch of {} packets, total size in bytes: {}",
        packet_batch.len(),
        packet_batch.iter().map(|x| x.meta().size).sum::<usize>()
    );

    if should_reconstruct_shreds {
        let _ = reconstruct_tx.try_send(packet_batch.clone());
    }

    let mut packet_batch_vec = vec![packet_batch];

    let num_deduped = solana_perf::deduper::dedup_packets_and_count_discards(
        &deduper.read().unwrap(),
        &mut packet_batch_vec,
    );
    // t1: dedup pass complete. dedup_us = t1 - t0.
    let t1 = Instant::now();
    // Store stats for each Packet
    packet_batch_vec.iter().for_each(|batch| {
        batch.iter().for_each(|packet| {
            metrics
                .packets_received
                .entry(packet.meta().addr)
                .and_modify(|(discarded, not_discarded)| {
                    *discarded += packet.meta().discard() as u64;
                    *not_discarded += (!packet.meta().discard()) as u64;
                })
                .or_insert_with(|| {
                    (
                        packet.meta().discard() as u64,
                        (!packet.meta().discard()) as u64,
                    )
                });
        });
    });

    // Reuse the caller-owned scratch buffer. The buffer is typed as
    // `Vec<(&'static [u8], &'static SocketAddr)>` so its allocation can persist
    // across calls; we transmute it to a call-local lifetime, fill it, send,
    // and clear it before returning. The 'static lifetime is purely a phantom
    // tag to satisfy Rust's invariance on Vec<T>.
    //
    // SAFETY: The transmute changes only phantom lifetime parameters of the Vec
    // contents, not the in-memory representation. We invariantly clear the Vec
    // at the end of this function (and assert it is empty on entry), so no
    // call-local references can outlive this stack frame.
    debug_assert!(
        packets_with_dest_scratch.is_empty(),
        "scratch buffer must be empty on entry; caller must not push into it"
    );
    let packets_with_dest: &mut Vec<(&[u8], &SocketAddr)> =
        unsafe { std::mem::transmute(packets_with_dest_scratch) };

    // Build a single (packet, dest) flat list. sendmmsg packs up to UIO_MAXIOV
    // (1024 on Linux) iovecs per syscall, so for a typical P=64, D=10 batch the
    // entire fanout becomes ONE syscall instead of D.
    let packet_count_before_filter = packet_batch_vec[0].len();
    for pkt in packet_batch_vec[0].iter() {
        if let Some(data) = pkt.data(..) {
            for dest in local_dest_sockets.iter() {
                packets_with_dest.push((data, dest));
            }
        }
    }
    let pairs_to_send = packets_with_dest.len();
    // t2: flat (packet, dest) list built. pack_us = t2 - t1.
    let t2 = Instant::now();

    let send_result = batch_send(send_socket, packets_with_dest);
    // t3: sendmmsg returned. send_us = t3 - t2.
    let t3 = Instant::now();
    // Captured before the match below moves the inner Io error.
    let send_ok = send_result.is_ok();

    // Clear before returning so no call-local refs outlive this frame.
    packets_with_dest.clear();

    match send_result {
        Ok(_) => {
            metrics
                .success_forward
                .fetch_add(pairs_to_send as u64, Ordering::Relaxed);
            // num_deduped is per-batch (not per-destination); count once.
            // NOTE: this differs from the prior implementation, which incremented
            // the duplicate counter D times per batch — a multiplicative bug in
            // the old per-destination loop.
            metrics
                .duplicate
                .fetch_add(num_deduped as u64, Ordering::Relaxed);
        }
        Err(SendPktsError::IoError(err, num_failed)) => {
            metrics
                .fail_forward
                .fetch_add(num_failed as u64, Ordering::Relaxed);
            // Successful sends in a partial-failure case still counted.
            metrics
                .success_forward
                .fetch_add((pairs_to_send.saturating_sub(num_failed)) as u64, Ordering::Relaxed);
            metrics
                .duplicate
                .fetch_add(num_deduped as u64, Ordering::Relaxed);
            error!(
                "Failed to fan out batch (packets={packet_count_before_filter}, dests={}, pairs={pairs_to_send}). \
                 {num_failed} of {pairs_to_send} packet/dest pairs failed. Error: {err}",
                local_dest_sockets.len()
            );
        }
    }

    // Per-batch latency trace. Gated on the dedicated target so the format!
    // cost is paid only when latency capture is explicitly enabled with
    // `RUST_LOG=shredstream::latency=trace`. The `LATENCY_TRACE` prefix is
    // a stable grep anchor for the offline HTML viewer.
    if log_enabled!(target: LATENCY_TRACE_TARGET, Level::Trace) {
        let dedup_us = t1.duration_since(t0).as_micros();
        let pack_us = t2.duration_since(t1).as_micros();
        let send_us = t3.duration_since(t2).as_micros();
        let total_us = t3.duration_since(t0).as_micros();
        *latency_ctx.batch_seq += 1;
        trace!(
            target: LATENCY_TRACE_TARGET,
            "LATENCY_TRACE {{\"batch_seq\":{},\"thread_id\":{},\"queue_len\":{},\"packets\":{},\"dests\":{},\"pairs\":{},\"deduped\":{},\"dedup_us\":{},\"pack_us\":{},\"send_us\":{},\"total_us\":{},\"send_ok\":{},\"recv_unix_ns\":{}}}",
            *latency_ctx.batch_seq,
            latency_ctx.thread_id,
            latency_ctx.queue_len,
            packets_received_in_batch,
            local_dest_sockets.len(),
            pairs_to_send,
            num_deduped,
            dedup_us,
            pack_us,
            send_us,
            total_us,
            send_ok as u8,
            recv_unix_ns,
        );
    }

    // Count TraceShred shreds
    if debug_trace_shred {
        packet_batch_vec[0]
            .iter()
            .filter_map(|p| TraceShred::decode(p.data(..)?).ok())
            .filter(|t| t.created_at.is_some())
            .for_each(|trace_shred| {
                let elapsed = trace_shred_received_time
                    .duration_since(SystemTime::try_from(trace_shred.created_at.unwrap()).unwrap())
                    .unwrap_or_default();

                datapoint_info!(
                    "shredstream_proxy-trace_shred_latency",
                    "trace_region" => trace_shred.region,
                    ("trace_seq_num", trace_shred.seq_num as i64, i64),
                    ("elapsed_micros", elapsed.as_micros(), i64),
                );
            });
    }

    Ok(())
}

/// Starts a thread that updates our destinations used by the forwarder threads
pub fn start_destination_refresh_thread(
    endpoint_discovery_url: String,
    discovered_endpoints_port: u16,
    static_dest_sockets: Vec<(SocketAddr, String)>,
    unioned_dest_sockets: Arc<ArcSwap<Vec<SocketAddr>>>,
    shutdown_receiver: Receiver<()>,
    exit: Arc<AtomicBool>,
) -> JoinHandle<()> {
    Builder::new().name("ssPxyDstRefresh".to_string()).spawn(move || {
        let fetch_socket_tick = crossbeam_channel::tick(Duration::from_secs(30));
        let metrics_tick = crossbeam_channel::tick(Duration::from_secs(30));
        let mut socket_count = static_dest_sockets.len();
        while !exit.load(Ordering::Relaxed) {
            crossbeam_channel::select! {
                    recv(fetch_socket_tick) -> _ => {
                        let fetched = fetch_unioned_destinations(
                            &endpoint_discovery_url,
                            discovered_endpoints_port,
                            &static_dest_sockets,
                        );
                        let new_sockets = match fetched {
                            Ok(s) => {
                                info!("Sending shreds to {} destinations: {s:?}", s.len());
                                s
                            }
                            Err(e) => {
                                warn!("Failed to fetch from discovery service, retrying. Error: {e}");
                                datapoint_warn!("shredstream_proxy-destination_refresh_error",
                                                ("prev_unioned_dest_count", socket_count, i64),
                                                ("errors", 1, i64),
                                                ("error_str", e.to_string(), String),
                                );
                                continue;
                            }
                        };
                        socket_count = new_sockets.len();
                        unioned_dest_sockets.store(Arc::new(new_sockets));
                    }
                    recv(metrics_tick) -> _ => {
                        datapoint_info!("shredstream_proxy-destination_refresh_stats",
                                        ("destination_count", socket_count, i64),
                        );
                    }
                    recv(shutdown_receiver) -> _ => {
                        break;
                    }
                }
        }
    }).unwrap()
}

/// Returns dynamically discovered endpoints with CLI arg defined endpoints
fn fetch_unioned_destinations(
    endpoint_discovery_url: &str,
    discovered_endpoints_port: u16,
    static_dest_sockets: &[(SocketAddr, String)],
) -> Result<Vec<SocketAddr>, ShredstreamProxyError> {
    let bytes = reqwest::blocking::get(endpoint_discovery_url)?.bytes()?;

    let sockets_json = match serde_json::from_slice::<Vec<IpAddr>>(&bytes) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "Failed to parse json from: {:?}",
                std::str::from_utf8(&bytes)
            );
            return Err(ShredstreamProxyError::from(e));
        }
    };

    // resolve again since ip address could change
    let static_dest_sockets = static_dest_sockets
        .iter()
        .filter_map(|(_socketaddr, hostname_port)| {
            Some(resolve_hostname_port(hostname_port).ok()?.0)
        })
        .collect::<Vec<_>>();

    let unioned_dest_sockets = sockets_json
        .into_iter()
        .map(|ip| SocketAddr::new(ip, discovered_endpoints_port))
        .chain(static_dest_sockets)
        .unique()
        .collect::<Vec<SocketAddr>>();
    Ok(unioned_dest_sockets)
}

/// Reset dedup + send metrics to influx
pub fn start_forwarder_accessory_thread(
    deduper: Arc<RwLock<Deduper<2, [u8]>>>,
    metrics: Arc<ShredMetrics>,
    metrics_update_interval_ms: u64,
    shutdown_receiver: Receiver<()>,
    exit: Arc<AtomicBool>,
) -> JoinHandle<()> {
    Builder::new()
        .name("ssPxyAccessory".to_string())
        .spawn(move || {
            let metrics_tick =
                crossbeam_channel::tick(Duration::from_millis(metrics_update_interval_ms));
            let deduper_reset_tick = crossbeam_channel::tick(Duration::from_secs(2));
            let mut rng = rand::thread_rng();
            while !exit.load(Ordering::Relaxed) {
                crossbeam_channel::select! {
                    // reset deduper to avoid false positives
                    recv(deduper_reset_tick) -> _ => {
                        deduper
                            .write()
                            .unwrap()
                            .maybe_reset(&mut rng, DEDUPER_FALSE_POSITIVE_RATE, DEDUPER_RESET_CYCLE);
                    }

                    // send metrics to influx
                    recv(metrics_tick) -> _ => {
                        metrics.report();
                        metrics.reset();
                    }

                    // handle SIGINT shutdown
                    recv(shutdown_receiver) -> _ => {
                        break;
                    }
                }
            }
        })
        .unwrap()
}

pub struct ShredMetrics {
    // receive stats
    /// Total number of shreds received. Includes duplicates when receiving shreds from multiple regions
    pub received: AtomicU64,
    /// Total number of shreds successfully forwarded, accounting for all destinations
    pub success_forward: AtomicU64,
    /// Total number of shreds failed to forward, accounting for all destinations
    pub fail_forward: AtomicU64,
    /// Number of duplicate shreds received
    pub duplicate: AtomicU64,
    /// (discarded, not discarded, from other shredstream instances)
    pub packets_received: DashMap<IpAddr, (u64, u64)>,

    // service metrics
    pub enabled_grpc_service: bool,
    /// Number of data shreds recovered using coding shreds
    pub recovered_count: AtomicU64,
    /// Number of Solana entries decoded from shreds
    pub entry_count: AtomicU64,
    /// Number of transactions decoded from shreds
    pub txn_count: AtomicU64,
    /// Number of times we couldn't find the previous DATA_COMPLETE_SHRED flag
    pub unknown_start_position_count: AtomicU64,
    /// Number of FEC recovery errors
    pub fec_recovery_error_count: AtomicU64,
    /// Number of bincode Entry deserialization errors
    pub bincode_deserialize_error_count: AtomicU64,
    /// Number of times we couldn't find the previous DATA_COMPLETE_SHRED flag but tried to deshred+deserialize, and failed
    pub unknown_start_position_error_count: AtomicU64,

    // cumulative metrics (persist after reset)
    pub agg_received_cumulative: AtomicU64,
    pub agg_success_forward_cumulative: AtomicU64,
    pub agg_fail_forward_cumulative: AtomicU64,
    pub duplicate_cumulative: AtomicU64,
}

impl Default for ShredMetrics {
    fn default() -> Self {
        Self::new(false)
    }
}

impl ShredMetrics {
    pub fn new(enabled_grpc_service: bool) -> Self {
        Self {
            enabled_grpc_service,
            received: Default::default(),
            success_forward: Default::default(),
            fail_forward: Default::default(),
            duplicate: Default::default(),
            packets_received: DashMap::with_capacity(10),
            recovered_count: Default::default(),
            entry_count: Default::default(),
            txn_count: Default::default(),
            unknown_start_position_count: Default::default(),
            fec_recovery_error_count: Default::default(),
            bincode_deserialize_error_count: Default::default(),
            unknown_start_position_error_count: Default::default(),
            agg_received_cumulative: Default::default(),
            agg_success_forward_cumulative: Default::default(),
            agg_fail_forward_cumulative: Default::default(),
            duplicate_cumulative: Default::default(),
        }
    }

    pub fn report(&self) {
        datapoint_info!(
            "shredstream_proxy-connection_metrics",
            ("received", self.received.load(Ordering::Relaxed), i64),
            (
                "success_forward",
                self.success_forward.load(Ordering::Relaxed),
                i64
            ),
            (
                "fail_forward",
                self.fail_forward.load(Ordering::Relaxed),
                i64
            ),
            ("duplicate", self.duplicate.load(Ordering::Relaxed), i64),
        );

        if self.enabled_grpc_service {
            datapoint_info!(
                "shredstream_proxy-service_metrics",
                (
                    "recovered_count",
                    self.recovered_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "entry_count",
                    self.entry_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                ("txn_count", self.txn_count.swap(0, Ordering::Relaxed), i64),
                (
                    "unknown_start_position_count",
                    self.unknown_start_position_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "fec_recovery_error_count",
                    self.fec_recovery_error_count.swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "bincode_deserialize_error_count",
                    self.bincode_deserialize_error_count
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
                (
                    "unknown_start_position_error_count",
                    self.unknown_start_position_error_count
                        .swap(0, Ordering::Relaxed),
                    i64
                ),
            );
        }

        self.packets_received
            .retain(|addr, (discarded_packets, not_discarded_packets)| {
                datapoint_info!("shredstream_proxy-receiver_stats",
                    "addr" => addr.to_string(),
                    ("discarded_packets", *discarded_packets, i64),
                    ("not_discarded_packets", *not_discarded_packets, i64),
                );
                false
            });
    }

    /// resets current values, increments cumulative values
    pub fn reset(&self) {
        self.agg_received_cumulative
            .fetch_add(self.received.swap(0, Ordering::Relaxed), Ordering::Relaxed);
        self.agg_success_forward_cumulative.fetch_add(
            self.success_forward.swap(0, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.agg_fail_forward_cumulative.fetch_add(
            self.fail_forward.swap(0, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.duplicate_cumulative
            .fetch_add(self.duplicate.swap(0, Ordering::Relaxed), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
        str::FromStr,
        sync::{
            atomic::Ordering,
            Arc, Mutex, RwLock,
        },
        thread,
        thread::sleep,
        time::Duration,
    };

    use solana_perf::{
        deduper::Deduper,
        packet::{Meta, Packet, PacketBatch},
    };
    use solana_sdk::packet::{PacketFlags, PACKET_DATA_SIZE};

    use crate::forwarder::{recv_from_channel_and_send_multiple_dest, LatencyTraceCtx, ShredMetrics};

    /// Test helper: a no-op latency trace context. The trace log target is
    /// gated by env_logger, so when tests run without `RUST_LOG` set this
    /// is effectively zero cost.
    fn noop_ctx(seq: &mut u64) -> LatencyTraceCtx<'_> {
        LatencyTraceCtx {
            thread_id: 0,
            batch_seq: seq,
            queue_len: 0,
        }
    }

    fn listen_and_collect(listen_socket: UdpSocket, received_packets: Arc<Mutex<Vec<Vec<u8>>>>) {
        let mut buf = [0u8; PACKET_DATA_SIZE];
        loop {
            match listen_socket.recv(&mut buf) {
                Ok(_) => received_packets.lock().unwrap().push(Vec::from(buf)),
                Err(_) => return,
            }
        }
    }

    /// Build a packet whose data is all `marker` bytes.
    fn marker_packet(marker: u8, port: u16) -> Packet {
        Packet::new(
            [marker; PACKET_DATA_SIZE],
            Meta {
                size: PACKET_DATA_SIZE,
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port,
                flags: PacketFlags::empty(),
            },
        )
    }

    fn fresh_deduper() -> Arc<RwLock<Deduper<2, [u8]>>> {
        Arc::new(RwLock::new(Deduper::<2, [u8]>::new(
            &mut rand::thread_rng(),
            crate::forwarder::DEDUPER_NUM_BITS,
        )))
    }

    /// Bind N UDP listener sockets on ephemeral ports, return their addrs and
    /// shared collectors that the listener threads append into.
    fn spawn_listeners(num: usize) -> Vec<(SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>)> {
        let mut out = Vec::with_capacity(num);
        for _ in 0..num {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
            let addr = sock.local_addr().unwrap();
            let collector = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
            let collector_for_thread = collector.clone();
            thread::spawn(move || listen_and_collect(sock, collector_for_thread));
            out.push((addr, collector));
        }
        out
    }

    /// Existing test, ported to the new function signature.
    /// Two shreds, three destinations — every destination must receive both shreds.
    #[test]
    fn test_2shreds_3destinations() {
        let packet_batch = PacketBatch::new(vec![
            marker_packet(1, 48289),
            marker_packet(2, 9999),
        ]);
        let (packet_sender, packet_receiver) = crossbeam_channel::unbounded::<PacketBatch>();
        packet_sender.send(packet_batch).unwrap();

        let dest_socketaddrs = vec![
            SocketAddr::from_str("0.0.0.0:32881").unwrap(),
            SocketAddr::from_str("0.0.0.0:33881").unwrap(),
            SocketAddr::from_str("0.0.0.0:34881").unwrap(),
        ];

        let test_listeners = dest_socketaddrs
            .iter()
            .map(|socketaddr| {
                let sock = UdpSocket::bind(socketaddr).unwrap();
                sock.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
                let collector = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
                let collector_for_thread = collector.clone();
                thread::spawn(move || listen_and_collect(sock, collector_for_thread));
                (*socketaddr, collector)
            })
            .collect::<Vec<_>>();

        let udp_sender = UdpSocket::bind("0.0.0.0:10000").unwrap();

        let (reconstruct_tx, _reconstruct_rx) = crossbeam_channel::bounded(10_240);
        let mut scratch = Vec::with_capacity(32);
        let mut seq: u64 = 0;
        recv_from_channel_and_send_multiple_dest(
            packet_receiver.recv(),
            &fresh_deduper(),
            &udp_sender,
            &Arc::new(dest_socketaddrs),
            true,
            &reconstruct_tx,
            false,
            &Arc::new(ShredMetrics::default()),
            &mut scratch,
            noop_ctx(&mut seq),
        )
        .unwrap();

        sleep(Duration::from_millis(500));

        for (_, results) in test_listeners.iter() {
            let received = results.lock().unwrap();
            assert_eq!(received.len(), 2, "each destination should receive both packets");
            assert!(received.iter().all(|p| p.len() == PACKET_DATA_SIZE));
            // Order is preserved: packet 1 (marker=1) then packet 2 (marker=2).
            assert_eq!(received[0], [1; PACKET_DATA_SIZE]);
            assert_eq!(received[1], [2; PACKET_DATA_SIZE]);
        }
        assert_eq!(
            test_listeners
                .iter()
                .fold(0, |acc, (_, c)| acc + c.lock().unwrap().len()),
            6
        );
    }

    /// Fanout correctness with a large destination count: every destination
    /// must still receive every packet, exercising the single-batch_send path
    /// across many `(packet, dest)` pairs.
    #[test]
    fn test_fanout_many_destinations() {
        const NUM_DESTS: usize = 12;
        const NUM_PACKETS: usize = 5;

        let packet_batch = PacketBatch::new(
            (0..NUM_PACKETS)
                .map(|i| marker_packet((i as u8) + 10, 7000 + i as u16))
                .collect(),
        );

        let listeners = spawn_listeners(NUM_DESTS);
        let dest_addrs: Vec<SocketAddr> = listeners.iter().map(|(a, _)| *a).collect();
        let udp_sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        let (reconstruct_tx, _reconstruct_rx) = crossbeam_channel::bounded(1_024);
        let metrics = Arc::new(ShredMetrics::default());
        let mut scratch = Vec::with_capacity(NUM_PACKETS * NUM_DESTS);
        let mut seq: u64 = 0;

        recv_from_channel_and_send_multiple_dest(
            Ok(packet_batch),
            &fresh_deduper(),
            &udp_sender,
            &dest_addrs,
            false,
            &reconstruct_tx,
            false,
            &metrics,
            &mut scratch,
            noop_ctx(&mut seq),
        )
        .unwrap();

        sleep(Duration::from_millis(500));

        for (addr, collector) in listeners.iter() {
            let got = collector.lock().unwrap();
            assert_eq!(
                got.len(),
                NUM_PACKETS,
                "destination {addr} received {}/{NUM_PACKETS} packets",
                got.len()
            );
            // Per-destination order must match packet send order.
            for (i, packet) in got.iter().enumerate() {
                assert_eq!(
                    packet[0],
                    (i as u8) + 10,
                    "destination {addr} got out-of-order packet at index {i}: marker={}",
                    packet[0]
                );
            }
        }

        // success_forward should equal NUM_PACKETS * NUM_DESTS exactly once
        // (no per-destination over-counting from the old implementation).
        assert_eq!(
            metrics.success_forward.load(Ordering::Relaxed),
            (NUM_PACKETS * NUM_DESTS) as u64
        );
        assert_eq!(metrics.fail_forward.load(Ordering::Relaxed), 0);
    }

    /// The scratch buffer's allocation must be reused across calls. We verify
    /// (a) the Vec is empty on entry/exit, (b) capacity does not shrink and
    /// is reused for a subsequent batch, and (c) deliveries remain correct
    /// across multiple back-to-back batches.
    #[test]
    fn test_scratch_buffer_reused_across_batches() {
        let listeners = spawn_listeners(4);
        let dest_addrs: Vec<SocketAddr> = listeners.iter().map(|(a, _)| *a).collect();
        let udp_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (reconstruct_tx, _reconstruct_rx) = crossbeam_channel::bounded(1_024);
        let metrics = Arc::new(ShredMetrics::default());
        let deduper = fresh_deduper();

        // Pre-allocated capacity hint; we expect this to stay constant.
        let mut scratch: Vec<(&'static [u8], &'static SocketAddr)> = Vec::with_capacity(64);
        let mut seq: u64 = 0;
        let initial_capacity = scratch.capacity();

        for round in 0..3u8 {
            assert!(scratch.is_empty(), "scratch must be empty on entry");
            let batch = PacketBatch::new(vec![
                marker_packet(round * 10 + 1, 8001),
                marker_packet(round * 10 + 2, 8002),
            ]);
            recv_from_channel_and_send_multiple_dest(
                Ok(batch),
                &deduper,
                &udp_sender,
                &dest_addrs,
                false,
                &reconstruct_tx,
                false,
                &metrics,
                &mut scratch,
                noop_ctx(&mut seq),
            )
            .unwrap();
            assert!(scratch.is_empty(), "scratch must be empty on exit");
            assert_eq!(
                scratch.capacity(),
                initial_capacity,
                "capacity must not grow when batch fits in initial capacity"
            );
        }

        sleep(Duration::from_millis(500));

        for (_, collector) in listeners.iter() {
            let got = collector.lock().unwrap();
            // 3 rounds * 2 packets = 6 packets per destination
            assert_eq!(got.len(), 6);
            // First packets of each round: 1, 11, 21
            assert_eq!(got[0][0], 1);
            assert_eq!(got[2][0], 11);
            assert_eq!(got[4][0], 21);
        }

        // Total successful sends across 3 rounds, 2 packets, 4 destinations.
        assert_eq!(metrics.success_forward.load(Ordering::Relaxed), 3 * 2 * 4);
    }

    /// With zero destinations, `batch_send` becomes a no-op and metrics must
    /// reflect that nothing was sent — but the function must not panic and the
    /// scratch buffer must be left empty.
    #[test]
    fn test_zero_destinations_is_noop() {
        let udp_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (reconstruct_tx, _reconstruct_rx) = crossbeam_channel::bounded(1_024);
        let metrics = Arc::new(ShredMetrics::default());
        let mut scratch = Vec::with_capacity(8);
        let mut seq: u64 = 0;

        let batch = PacketBatch::new(vec![marker_packet(7, 9001)]);
        recv_from_channel_and_send_multiple_dest(
            Ok(batch),
            &fresh_deduper(),
            &udp_sender,
            &[],
            false,
            &reconstruct_tx,
            false,
            &metrics,
            &mut scratch,
            noop_ctx(&mut seq),
        )
        .unwrap();

        assert_eq!(metrics.received.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.success_forward.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.fail_forward.load(Ordering::Relaxed), 0);
        assert!(scratch.is_empty());
    }

    /// A single destination must still receive every packet exactly once and
    /// the per-destination ordering must hold (sanity check that the new
    /// flat-list layout iterates packets in order).
    #[test]
    fn test_single_destination_preserves_order() {
        const NUM_PACKETS: usize = 8;
        let listeners = spawn_listeners(1);
        let dest_addrs: Vec<SocketAddr> = listeners.iter().map(|(a, _)| *a).collect();
        let udp_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (reconstruct_tx, _reconstruct_rx) = crossbeam_channel::bounded(1_024);
        let metrics = Arc::new(ShredMetrics::default());
        let mut scratch = Vec::with_capacity(16);
        let mut seq: u64 = 0;

        let batch = PacketBatch::new(
            (0..NUM_PACKETS)
                .map(|i| marker_packet(100 + i as u8, 10_000 + i as u16))
                .collect(),
        );

        recv_from_channel_and_send_multiple_dest(
            Ok(batch),
            &fresh_deduper(),
            &udp_sender,
            &dest_addrs,
            false,
            &reconstruct_tx,
            false,
            &metrics,
            &mut scratch,
            noop_ctx(&mut seq),
        )
        .unwrap();

        sleep(Duration::from_millis(400));

        let got = listeners[0].1.lock().unwrap();
        assert_eq!(got.len(), NUM_PACKETS);
        for (i, packet) in got.iter().enumerate() {
            assert_eq!(packet[0], 100 + i as u8, "out-of-order at index {i}");
        }
        assert_eq!(metrics.success_forward.load(Ordering::Relaxed), NUM_PACKETS as u64);
    }

    /// Scratch buffer that grows beyond its initial capacity on a large batch
    /// must still produce correct deliveries on the same call and on the next.
    #[test]
    fn test_scratch_grows_then_reuses() {
        let listeners = spawn_listeners(6);
        let dest_addrs: Vec<SocketAddr> = listeners.iter().map(|(a, _)| *a).collect();
        let udp_sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (reconstruct_tx, _reconstruct_rx) = crossbeam_channel::bounded(1_024);
        let metrics = Arc::new(ShredMetrics::default());

        // Intentionally small initial capacity to force a grow on the first batch.
        let mut scratch: Vec<(&'static [u8], &'static SocketAddr)> = Vec::with_capacity(2);
        let mut seq: u64 = 0;

        let big_batch = PacketBatch::new(
            (0..10).map(|i| marker_packet(i as u8 + 1, 11_000 + i as u16)).collect(),
        );
        recv_from_channel_and_send_multiple_dest(
            Ok(big_batch),
            &fresh_deduper(),
            &udp_sender,
            &dest_addrs,
            false,
            &reconstruct_tx,
            false,
            &metrics,
            &mut scratch,
            noop_ctx(&mut seq),
        )
        .unwrap();

        let cap_after_grow = scratch.capacity();
        assert!(cap_after_grow >= 60, "capacity should have grown to fit 10*6 pairs");
        assert!(scratch.is_empty(), "scratch must be empty post-call");

        // Second smaller batch should reuse the grown allocation, not shrink.
        let small_batch = PacketBatch::new(vec![marker_packet(99, 12_000)]);
        recv_from_channel_and_send_multiple_dest(
            Ok(small_batch),
            &fresh_deduper(),
            &udp_sender,
            &dest_addrs,
            false,
            &reconstruct_tx,
            false,
            &metrics,
            &mut scratch,
            noop_ctx(&mut seq),
        )
        .unwrap();
        assert_eq!(scratch.capacity(), cap_after_grow, "capacity must not shrink across calls");

        sleep(Duration::from_millis(500));

        for (_, collector) in listeners.iter() {
            let got = collector.lock().unwrap();
            assert_eq!(got.len(), 11, "10 + 1 packets per destination");
        }
    }
}
