use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    thread::{Builder, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

// `AsRawFd` is only needed by the Linux `sendmmsg(2)` path; pull it in
// locally there to avoid an unused-import warning on macOS dev builds.
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

use arc_swap::ArcSwap;
use crossbeam_channel::{Receiver, RecvError, TryRecvError, TrySendError};
use dashmap::DashMap;
use itertools::Itertools;
use jito_protos::shredstream::{Entry as PbEntry, TraceShred};
use log::{error, info, log_enabled, warn, Level};
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
use solana_streamer::streamer::{self, StreamerReceiveStats};
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

/// Bounded capacity of each shard's batch channel. A coordinator's `try_send`
/// drops batches for that one shard (counted in `worker_dropped_batches`)
/// when full. Other shards keep flowing.
const SHARD_CHANNEL_CAPACITY: usize = 1024;
/// Initial scratch-buffer capacity per shard for the flat (packet, dest)
/// Vec. Sized so a typical batch (P × (D/N) pairs) fits without growing.
const SHARD_SCRATCH_INITIAL_CAPACITY: usize = 256;
/// How often the shard manager re-distributes the destination set across
/// the (fixed) shard threads.
const SHARD_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// Clamp on the number of busy-spinning send-shard threads. N is fixed at
/// startup based on `available_parallelism()`; only the per-shard
/// destination ASSIGNMENT changes when D changes.
const MIN_SEND_SHARDS: usize = 2;
const MAX_SEND_SHARDS: usize = 16;

/// Pick a sensible shard count from available CPU parallelism. N must be
/// small enough not to over-burn cores (each shard busy-spins) but large
/// enough to keep per-shard `(D/N) × t_datagram` work bounded.
fn compute_send_shards() -> usize {
    let par = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(8);
    (par / 4).clamp(MIN_SEND_SHARDS, MAX_SEND_SHARDS)
}

/// Per-batch latency trace shared between the coordinator and every shard
/// that received the batch. Created once per batch by the coordinator when
/// trace mode is on. Each shard does `fetch_sub(1, AcqRel)` on
/// `shard_remaining` after its `sendmmsg` returns; the shard whose decrement
/// brings the counter to 0 records `t_start.elapsed()` into the e2e metric
/// fields.
///
/// This is the canonical "recv → last shard's sendmmsg returned for THIS
/// batch" measurement. Older fields (`avg_total_us`, `avg_worker_send_us`)
/// only capture pieces of the pipeline; this is the full barrier.
pub struct BatchTrace {
    pub t_start: Instant,
    pub shard_remaining: AtomicU32,
}

impl BatchTrace {
    /// Construct a new trace with `shard_remaining` initialized to N (the
    /// number of shards we are about to dispatch to). The counter is set
    /// up-front so any shard that picks the batch up before the coordinator
    /// finishes its try_send loop still sees a sane initial value.
    pub fn new(t_start: Instant, num_shards: u32) -> Self {
        #[cfg(test)]
        BATCH_TRACE_ALLOCS.fetch_add(1, Ordering::Relaxed);
        Self {
            t_start,
            shard_remaining: AtomicU32::new(num_shards),
        }
    }
}

/// Test-only counter that increments on every `BatchTrace::new()`. Used by
/// `test_trace_off_zero_overhead_no_batch_trace_alloc` to assert that no
/// trace is allocated when the trace log level is off.
#[cfg(test)]
pub(crate) static BATCH_TRACE_ALLOCS: AtomicU64 = AtomicU64::new(0);

/// What a shard receives over its channel — the batch and an optional
/// per-batch trace. `None` when trace mode is off (zero allocation, the
/// shard skips the barrier block).
pub type ShardMsg = (Arc<PacketBatch>, Option<Arc<BatchTrace>>);

/// One connected UDP socket per destination served by a shard. The socket
/// is bound to `0.0.0.0:0` and `connect()`-ed to `addr`, so the kernel
/// caches the route lookup. Sent on via `sendmmsg(2)` with `msg_name = NULL`.
#[derive(Clone)]
pub struct ConnectedDest {
    pub addr: SocketAddr,
    pub socket: Arc<UdpSocket>,
}

/// Snapshot of the N shard channel senders, published once at startup.
/// Coordinators load this and dispatch each `Arc<PacketBatch>` (plus the
/// optional `BatchTrace`) to all N shards.
pub type ShardSenderList = Vec<crossbeam_channel::Sender<ShardMsg>>;

/// Handle held by the shard manager — owns the destination assignment
/// (mutated on reconcile), the per-destination connected-socket cache, the
/// channel sender, and the thread join.
pub struct ShardHandle {
    /// Currently-assigned destinations + their connected sockets. Updated
    /// by the manager on reconcile via `ArcSwap::store`; read by the shard
    /// thread on every batch via a lock-free `load()`.
    pub assignment: Arc<ArcSwap<Vec<ConnectedDest>>>,
    /// Manager-owned cache keyed by destination. Used by `reshard_assignments`
    /// to reuse sockets across reconciles (so destinations that stay in the
    /// set keep their existing connected `UdpSocket`, preserving the kernel
    /// route cache). The shard thread NEVER touches this map.
    pub socket_cache: HashMap<SocketAddr, Arc<UdpSocket>>,
    /// Channel sender for feeding batches to the shard.
    pub sender: crossbeam_channel::Sender<ShardMsg>,
    /// Join handle for the shard thread.
    pub join: JoinHandle<()>,
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
    _use_discovery_service: bool,
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

    // Published snapshot of the N shard channel senders. Filled in by the
    // shard manager once N shards have been spawned; never re-published
    // after that (N is fixed). Coordinators dispatch each `Arc<PacketBatch>`
    // to all N senders.
    let shard_senders: Arc<ArcSwap<ShardSenderList>> =
        Arc::new(ArcSwap::from_pointee(ShardSenderList::default()));

    // Spawn the shard manager. It spawns N busy-spinning send-shard threads
    // and periodically re-distributes `unioned_dest_sockets` across them.
    let shard_mgr_hdl = start_shard_manager_thread(
        unioned_dest_sockets.clone(),
        shard_senders.clone(),
        metrics.clone(),
        shutdown_receiver.clone(),
        exit.clone(),
    );
    thread_hdls.push(shard_mgr_hdl);

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
            let metrics = metrics.clone();
            let shutdown_receiver = shutdown_receiver.clone();
            let reconstruct_tx = reconstruct_tx.clone();
            let exit = exit.clone();
            let shard_senders = shard_senders.clone();

            let send_thread = Builder::new()
                .name(format!("ssPxyTx_{thread_id}"))
                .spawn(move || {
                    while !exit.load(Ordering::Relaxed) {
                        crossbeam_channel::select! {
                            // forward packets
                            recv(packet_receiver) -> maybe_packet_batch => {
                                let res = recv_from_channel_and_send_multiple_dest(
                                    maybe_packet_batch,
                                    &deduper,
                                    &shard_senders,
                                    should_reconstruct_shreds,
                                    &reconstruct_tx,
                                    debug_trace_shred,
                                    &metrics,
                                );

                                // If the channel is closed or error, break out
                                if res.is_err() {
                                    break;
                                }
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
        .into_iter()
        .chain(thread_hdls)
        .collect()
}

/// Spawn one busy-spinning send-shard thread. Returns a `ShardHandle`
/// holding the assignment ArcSwap, the manager-owned socket cache, the
/// channel sender, and the thread join.
///
/// Unlike the previous architecture the shard does **not** own a shared
/// sending socket. Sockets live per-destination in `ConnectedDest` entries
/// published via `assignment` (`ArcSwap`). The manager thread creates and
/// `connect()`-s sockets during `reshard_assignments` and keeps them in
/// `socket_cache` to reuse across reconciles.
pub fn spawn_send_shard(
    shard_id: usize,
    metrics: Arc<ShredMetrics>,
    exit: Arc<AtomicBool>,
) -> ShardHandle {
    let (tx, rx) = crossbeam_channel::bounded::<ShardMsg>(SHARD_CHANNEL_CAPACITY);
    let assignment: Arc<ArcSwap<Vec<ConnectedDest>>> =
        Arc::new(ArcSwap::from_pointee(Vec::new()));
    let assignment_for_thread = assignment.clone();
    let name = format!("ssPxyShard_{shard_id}");
    let join = Builder::new()
        .name(name)
        .spawn(move || run_send_shard(shard_id, assignment_for_thread, rx, metrics, exit))
        .expect("failed to spawn send-shard thread");
    ShardHandle {
        assignment,
        socket_cache: HashMap::new(),
        sender: tx,
        join,
    }
}

/// The body of a busy-spinning send-shard thread.
///
/// Each batch:
///   1. Load the current destination assignment (ArcSwap, lock-free). Every
///      `ConnectedDest` carries an already-`connect()`-ed `UdpSocket`.
///   2. For each destination, build a reused `Vec<&[u8]>` of P packet
///      slices and issue one `sendmmsg(2)` with `msg_name = NULL`.
///   3. Decrement the per-batch barrier counter (if `trace_on`); the shard
///      that drives it to 0 records the e2e elapsed time.
///   4. Clear per-dest scratch and loop.
///
/// One `sendmmsg` per destination is required because `sendmmsg(2)` takes
/// a single fd and our connected sockets are per-destination. The win is
/// that the kernel skips per-datagram route lookup (cached on connect()),
/// dropping `t_datagram` from ~4 µs to ~1 µs.
///
/// STRATEGY 1 (no parking) is preserved: the shard polls via `try_recv` +
/// `std::hint::spin_loop()`. Empty polls cost ~zero kernel work.
///
/// WARNING: each shard pins ~1 CPU core at ~100 %. With N shards that's N
/// cores burned steady-state. N is fixed at startup from
/// `available_parallelism()` — see `compute_send_shards`.
fn run_send_shard(
    shard_id: usize,
    assignment: Arc<ArcSwap<Vec<ConnectedDest>>>,
    rx: crossbeam_channel::Receiver<ShardMsg>,
    metrics: Arc<ShredMetrics>,
    exit: Arc<AtomicBool>,
) {
    // Per-destination scratch. Indexed in lock-step with the current
    // assignment. Sub-vec capacity is preserved across batches; we only
    // grow the outer Vec when the destination count grows.
    //
    // SAFETY: the `&'static [u8]` slices stored here borrow from the
    // `Arc<PacketBatch>` for the current iteration. Every sub-vec is
    // `clear()`-ed before the batch is dropped at the end of the iteration —
    // no transmuted reference outlives the batch.
    let mut per_dest_scratch: Vec<Vec<&'static [u8]>> = Vec::new();
    per_dest_scratch
        .reserve(SHARD_SCRATCH_INITIAL_CAPACITY.max(1));

    let trace_on = log_enabled!(Level::Trace);

    loop {
        match rx.try_recv() {
            Ok((batch, trace)) => {
                let t_send = trace_on.then(Instant::now);
                let batch_packet_count = batch.len();

                // Snapshot the current destination assignment. The Guard
                // outlives both the scratch fill and the send phase below.
                let dests = assignment.load();
                let n_dests = dests.len();

                // Resize per-dest scratch up to current dest count. Existing
                // sub-vecs keep their allocated capacity.
                if per_dest_scratch.len() < n_dests {
                    per_dest_scratch.resize_with(n_dests, Vec::new);
                }
                // Defensive clear in case a previous iteration left data
                // (it shouldn't — we clear before iteration end below).
                for sub in per_dest_scratch.iter_mut().take(n_dests) {
                    debug_assert!(sub.is_empty());
                    sub.clear();
                }

                // Fill: each packet goes into every destination's bucket.
                for pkt in batch.iter() {
                    if let Some(data) = pkt.data(..) {
                        // SAFETY: `data` borrows from `batch`, held for this
                        // iteration. Sub-vecs are cleared before iteration
                        // end — no transmuted ref escapes.
                        let data_static: &'static [u8] =
                            unsafe { std::mem::transmute(data) };
                        for sub in per_dest_scratch.iter_mut().take(n_dests) {
                            sub.push(data_static);
                        }
                    }
                }

                // Send: one `sendmmsg(2)` per connected destination.
                let mut total_sent: u64 = 0;
                let mut total_failed: u64 = 0;
                let mut first_err: Option<std::io::Error> = None;
                for (i, dest) in dests.iter().enumerate() {
                    let pkts = &per_dest_scratch[i];
                    if pkts.is_empty() {
                        continue;
                    }
                    match sendmmsg_connected(&dest.socket, pkts) {
                        Ok(sent) => total_sent += sent as u64,
                        Err(e) => {
                            total_failed += pkts.len() as u64;
                            if first_err.is_none() {
                                first_err = Some(e);
                            }
                        }
                    }
                }

                if total_sent > 0 {
                    metrics
                        .success_forward
                        .fetch_add(total_sent, Ordering::Relaxed);
                }
                if total_failed > 0 {
                    metrics
                        .fail_forward
                        .fetch_add(total_failed, Ordering::Relaxed);
                    if let Some(e) = first_err {
                        error!(
                            "shard {shard_id} send failures: {total_failed} \
                             packets across {n_dests} dests. First error: {e}"
                        );
                    }
                }

                // Per-shard send timing (existing `worker_send_us_*` metric).
                // Its semantics are now "sum of all per-dest sendmmsg in this
                // shard for this batch" — wider than before, but still the
                // right number for diagnosing per-shard send cost.
                if let Some(t) = t_send {
                    let send_us = t.elapsed().as_micros() as u64;
                    metrics.worker_batches.fetch_add(1, Ordering::Relaxed);
                    metrics
                        .worker_send_us_sum
                        .fetch_add(send_us, Ordering::Relaxed);
                    metrics
                        .worker_packets_sent
                        .fetch_add(batch_packet_count as u64, Ordering::Relaxed);
                    update_max_atomic(&metrics.worker_send_us_max, send_us);
                }

                // E2E barrier: if this batch carries a trace, decrement the
                // remaining-shard counter. The shard whose decrement brings
                // it to 0 is the last shard to finish sending for this batch
                // and records the full recv→send-done elapsed time.
                //
                // AcqRel ordering ensures the metric writes done by peer
                // shards on losing decrements are visible to the winning
                // shard's e2e_us read of t_start.elapsed().
                if let Some(t) = trace {
                    let prev = t.shard_remaining.fetch_sub(1, Ordering::AcqRel);
                    if prev == 1 {
                        let e2e_us = t.t_start.elapsed().as_micros() as u64;
                        metrics.e2e_batches.fetch_add(1, Ordering::Relaxed);
                        metrics
                            .e2e_us_sum
                            .fetch_add(e2e_us, Ordering::Relaxed);
                        update_max_atomic(&metrics.e2e_us_max, e2e_us);
                    }
                }

                // Clear scratch BEFORE dropping batch so the transmuted
                // 'static slices are gone before their backing storage is.
                for sub in per_dest_scratch.iter_mut().take(n_dests) {
                    sub.clear();
                }

                drop(batch);
            }
            Err(TryRecvError::Empty) => {
                if exit.load(Ordering::Relaxed) {
                    break;
                }
                std::hint::spin_loop();
            }
            Err(TryRecvError::Disconnected) => break,
        }
    }
    info!("Exiting send shard {shard_id}.");
}

/// `sendmmsg(2)` wrapper for a **connected** UDP socket. Each packet
/// becomes one `mmsghdr` with `msg_name = NULL` / `msg_namelen = 0` —
/// the kernel uses the socket's cached peer address (set via `connect()`).
/// Chunks at `UIO_MAXIOV` like `solana_streamer::batch_send_max_iov`.
///
/// Returns the number of packets the kernel reports as sent. On error,
/// returns the first I/O error encountered; subsequent packets are
/// dropped and counted as failures by the caller.
///
/// Non-Linux fallback uses `send(2)` per packet — kept for cross-platform
/// dev builds (production is Linux-only). The Linux path is the only one
/// that hits the optimized kernel route cache from `connect()`.
fn sendmmsg_connected(socket: &UdpSocket, packets: &[&[u8]]) -> std::io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }
    #[cfg(target_os = "linux")]
    {
        sendmmsg_connected_linux(socket, packets)
    }
    #[cfg(not(target_os = "linux"))]
    {
        sendmmsg_connected_fallback(socket, packets)
    }
}

#[cfg(target_os = "linux")]
fn sendmmsg_connected_linux(
    socket: &UdpSocket,
    packets: &[&[u8]],
) -> std::io::Result<usize> {
    let fd = socket.as_raw_fd();
    let mut total_sent: usize = 0;

    // libc::UIO_MAXIOV is the kernel cap on per-syscall mmsghdr count (1024
    // on Linux). For our P=1..few workloads we never chunk; the loop is for
    // safety only.
    let max_iov = libc::UIO_MAXIOV as usize;

    let mut first_err: Option<std::io::Error> = None;
    for chunk in packets.chunks(max_iov) {
        // Build parallel iovec[] and mmsghdr[] arrays. Per-message
        // msg_name=NULL — the kernel uses the connected peer.
        let mut iovecs: Vec<libc::iovec> = chunk
            .iter()
            .map(|pkt| libc::iovec {
                iov_base: pkt.as_ptr() as *mut libc::c_void,
                iov_len: pkt.len(),
            })
            .collect();

        // SAFETY: zero-init mmsghdr is valid (all-zero msghdr means
        // msg_name=NULL, msg_namelen=0, msg_control=NULL, msg_controllen=0,
        // msg_flags=0). We then fill iov fields below.
        let mut hdrs: Vec<libc::mmsghdr> = vec![
            unsafe { std::mem::zeroed::<libc::mmsghdr>() };
            chunk.len()
        ];
        for (i, hdr) in hdrs.iter_mut().enumerate() {
            hdr.msg_hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
            hdr.msg_hdr.msg_iovlen = 1;
            // msg_name / msg_namelen left at zero — connected socket path.
        }

        // sendmmsg can do a short send; loop until everything is consumed
        // or we hit a fatal error on a specific message.
        let mut pkts = &mut hdrs[..];
        while !pkts.is_empty() {
            let n = unsafe {
                libc::sendmmsg(fd, pkts.as_mut_ptr(), pkts.len() as u32, 0)
            };
            if n == -1 {
                if first_err.is_none() {
                    first_err = Some(std::io::Error::last_os_error());
                }
                // Skip the failing packet and retry the rest, mirroring
                // solana_streamer's sendmmsg_retry strategy.
                pkts = &mut pkts[1..];
            } else {
                total_sent += n as usize;
                pkts = &mut pkts[n as usize..];
            }
        }
    }

    if let Some(e) = first_err {
        Err(e)
    } else {
        Ok(total_sent)
    }
}

#[cfg(not(target_os = "linux"))]
fn sendmmsg_connected_fallback(
    socket: &UdpSocket,
    packets: &[&[u8]],
) -> std::io::Result<usize> {
    let mut sent = 0;
    let mut first_err: Option<std::io::Error> = None;
    for pkt in packets {
        match socket.send(pkt) {
            Ok(_) => sent += 1,
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    if let Some(e) = first_err {
        Err(e)
    } else {
        Ok(sent)
    }
}

/// Spawns the N busy-spinning send-shard threads ONCE at startup, then
/// loops on a tick: every `SHARD_RECONCILE_INTERVAL`, re-distributes the
/// current `unioned_dest_sockets` across the N shards (round-robin) via
/// each shard's per-thread `assignment` `ArcSwap`.
///
/// N is fixed for the lifetime of the process — see `compute_send_shards`.
/// Only the per-shard destination ASSIGNMENT changes when D changes.
fn start_shard_manager_thread(
    unioned_dest_sockets: Arc<ArcSwap<Vec<SocketAddr>>>,
    shard_senders: Arc<ArcSwap<ShardSenderList>>,
    metrics: Arc<ShredMetrics>,
    shutdown_receiver: Receiver<()>,
    exit: Arc<AtomicBool>,
) -> JoinHandle<()> {
    Builder::new()
        .name("ssPxyShardMgr".to_string())
        .spawn(move || {
            let available_cores = std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(0);
            let num_shards = compute_send_shards();
            info!(
                "Send-shard pool: spawning N={num_shards} busy-spinning send \
                 shards on a host with {available_cores} available cores \
                 (clamped between MIN={MIN_SEND_SHARDS} and MAX={MAX_SEND_SHARDS}). \
                 Each shard pins ~1 core at 100% — total expected steady-state \
                 spin burn: ~{num_shards} cores."
            );

            // Spawn N shard threads. The thread count is fixed for the
            // lifetime of the process; D changes are absorbed by re-sharding
            // the assignment.
            let mut shards: Vec<ShardHandle> = (0..num_shards)
                .map(|i| spawn_send_shard(i, metrics.clone(), exit.clone()))
                .collect();

            // Publish the senders snapshot once. It never changes again until
            // shutdown.
            let senders_snapshot: ShardSenderList =
                shards.iter().map(|s| s.sender.clone()).collect();
            shard_senders.store(Arc::new(senders_snapshot));

            // Initial assignment so shards have something to serve before the
            // first tick. `reshard_assignments` is the only writer to each
            // shard's `socket_cache` — we hold `&mut shards` for that.
            reshard_assignments(&unioned_dest_sockets, &mut shards, &metrics);

            let tick = crossbeam_channel::tick(SHARD_RECONCILE_INTERVAL);
            while !exit.load(Ordering::Relaxed) {
                crossbeam_channel::select! {
                    recv(tick) -> _ => {
                        reshard_assignments(
                            &unioned_dest_sockets,
                            &mut shards,
                            &metrics,
                        );
                    }
                    recv(shutdown_receiver) -> _ => break,
                }
            }

            // Shutdown: drop the published sender snapshot so coordinators
            // stop dispatching, then drop each shard's sender so the shard
            // thread sees `Disconnected` (its busy-spin loop breaks).
            shard_senders.store(Arc::new(ShardSenderList::default()));
            let join_handles: Vec<JoinHandle<()>> = shards
                .drain(..)
                .map(|s| {
                    drop(s.sender);
                    s.join
                })
                .collect();
            for (i, h) in join_handles.into_iter().enumerate() {
                if let Err(e) = h.join() {
                    warn!("send shard {i} join failed: {e:?}");
                }
            }
            info!("Exiting shard manager.");
        })
        .unwrap()
}

/// Re-distribute the current destination set across the fixed N shards
/// (round-robin) and refresh each shard's connected-socket cache. Sockets
/// for destinations that survive a reshard are **reused** (their cached
/// kernel route stays warm); new destinations get a fresh `bind() +
/// connect()`; removed destinations have their sockets dropped (closed).
///
/// Each shard's `ArcSwap<Vec<ConnectedDest>>` is replaced in one atomic
/// store — shard threads pick up the new slice on their next batch via a
/// lock-free `load()` and never touch the manager-owned `socket_cache`.
///
/// `worker_count` is updated to the destination count D (kept under the
/// historical field name for dashboard continuity).
fn reshard_assignments(
    unioned_dest_sockets: &ArcSwap<Vec<SocketAddr>>,
    shards: &mut [ShardHandle],
    metrics: &Arc<ShredMetrics>,
) {
    let desired = unioned_dest_sockets.load();
    let n = shards.len();

    // Round-robin: shard i gets dests[i], dests[i+n], dests[i+2n], …
    // Spreads heterogeneous destinations across shards better than
    // contiguous slicing.
    let mut buckets: Vec<Vec<SocketAddr>> = (0..n).map(|_| Vec::new()).collect();
    for (idx, dest) in desired.iter().enumerate() {
        buckets[idx % n].push(*dest);
    }

    for (shard, bucket) in shards.iter_mut().zip(buckets) {
        // Build the new (addr, socket) list, reusing existing sockets for
        // surviving destinations and creating fresh ones for new dests.
        // After this loop, anything left in `shard.socket_cache` is stale
        // and gets dropped (closing the FD).
        let mut new_assignment: Vec<ConnectedDest> = Vec::with_capacity(bucket.len());
        let mut next_cache: HashMap<SocketAddr, Arc<UdpSocket>> =
            HashMap::with_capacity(bucket.len());
        for addr in &bucket {
            // IPv4-only: the bind below is `0.0.0.0:0`, so v6 dests can't
            // be reached through this socket. Skip with a warn-once per
            // shard (kept simple via per-call check; rare on shred dests).
            if matches!(addr, SocketAddr::V6(_)) {
                warn!(
                    "skipping IPv6 destination {addr} during reshard \
                     (shard sockets are IPv4-only)"
                );
                continue;
            }
            let socket = match shard.socket_cache.remove(addr) {
                Some(s) => s, // reuse: kernel route cache stays warm
                None => match new_connected_socket(addr) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        warn!(
                            "failed to bind/connect new socket for {addr} \
                             during reshard: {e}. Skipping this dest."
                        );
                        continue;
                    }
                },
            };
            next_cache.insert(*addr, socket.clone());
            new_assignment.push(ConnectedDest {
                addr: *addr,
                socket,
            });
        }
        // Anything still in the old cache is now unreferenced — replacing
        // the HashMap drops them, which closes the FDs.
        shard.socket_cache = next_cache;
        shard.assignment.store(Arc::new(new_assignment));
    }

    metrics
        .worker_count
        .store(desired.len(), Ordering::Relaxed);
}

/// Bind a fresh ephemeral IPv4 UDP socket and `connect()` it to `dest`.
/// On Linux the `connect()` caches the route lookup and next-hop on the
/// socket, so subsequent `sendmmsg(2)` calls skip those steps — the
/// single biggest contributor to per-datagram in-kernel cost.
fn new_connected_socket(dest: &SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    ))?;
    sock.connect(dest)?;
    Ok(sock)
}

/// Lock-free monotonic max update.
fn update_max_atomic(cell: &AtomicU64, val: u64) {
    let mut prev = cell.load(Ordering::Relaxed);
    while val > prev {
        match cell.compare_exchange_weak(prev, val, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => prev = observed,
        }
    }
}

/// Receives a `PacketBatch` from a listener thread, deduplicates it, updates
/// per-source stats, then dispatches the batch (wrapped in `Arc`) to all
/// per-destination worker threads.
///
/// The actual UDP send happens in those worker threads in parallel — see
/// `run_dest_worker`. This function performs only channel sends in its
/// "fanout" phase, so latency is independent of the number of destinations.
#[allow(clippy::too_many_arguments)]
fn recv_from_channel_and_send_multiple_dest(
    maybe_packet_batch: Result<PacketBatch, RecvError>,
    deduper: &RwLock<Deduper<2, [u8]>>,
    shard_senders: &ArcSwap<ShardSenderList>,
    should_reconstruct_shreds: bool,
    reconstruct_tx: &crossbeam_channel::Sender<PacketBatch>,
    debug_trace_shred: bool,
    metrics: &ShredMetrics,
) -> Result<(), ShredstreamProxyError> {
    // All forward-perf instrumentation is gated on trace level: when off,
    // no Instant::now() calls and no atomic accumulator updates.
    let trace_on = log_enabled!(Level::Trace);
    let mark = || -> Option<Instant> { trace_on.then(Instant::now) };
    let elapsed_us = |t: Option<Instant>| -> u64 {
        t.map(|t| t.elapsed().as_micros() as u64).unwrap_or(0)
    };

    let t_batch_start = mark();
    let packet_batch = maybe_packet_batch.map_err(ShredstreamProxyError::RecvError)?;
    let trace_shred_received_time = SystemTime::now();
    let batch_packet_count = packet_batch.len();
    metrics
        .received
        .fetch_add(batch_packet_count as u64, Ordering::Relaxed);

    let t_before_reconstruct = mark();
    if should_reconstruct_shreds {
        let _ = reconstruct_tx.try_send(packet_batch.clone());
    }
    let reconstruct_clone_us = elapsed_us(t_before_reconstruct);

    let mut packet_batch_vec = vec![packet_batch];

    let t_before_dedup = mark();
    let num_deduped = solana_perf::deduper::dedup_packets_and_count_discards(
        &deduper.read().unwrap(),
        &mut packet_batch_vec,
    );
    let dedup_us = elapsed_us(t_before_dedup);
    metrics
        .duplicate
        .fetch_add(num_deduped, Ordering::Relaxed);

    // Per-source packet stats (discarded vs. not).
    let t_before_stats = mark();
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
    let stats_us = elapsed_us(t_before_stats);

    // Dispatch to per-destination worker threads. After this point all
    // workers share a single Arc<PacketBatch> — no clone of the underlying
    // packet data is needed. The Vec is drained so the inner PacketBatch
    // can be wrapped in Arc without copying.
    let packet_batch = packet_batch_vec
        .drain(..)
        .next()
        .expect("packet_batch_vec invariant: exactly one entry");
    let arc_batch = Arc::new(packet_batch);

    let t_before_fanout = mark();
    let senders_snapshot = shard_senders.load();
    // num_dest here means "fan-out targets the coordinator wakes per batch".
    // With Strategy 3 that's N shards, not D destinations — the actual
    // (packet × destination) UDP send count is tracked downstream via
    // success_forward / fail_forward in each shard thread.
    let num_dest = senders_snapshot.len() as u64;

    // Construct the per-batch e2e trace in trace mode. `shard_remaining` is
    // initialized to N up-front (so any shard that picks the batch up before
    // we finish the try_send loop already sees a sane counter). On try_send
    // failures the coordinator compensates by decrementing here — keeping
    // the invariant that exactly N decrements happen per trace.
    //
    // SAFETY of `t_batch_start.unwrap()`: gated on `trace_on`, which is the
    // same flag that made `mark()` return `Some` at the top of this fn.
    let trace: Option<Arc<BatchTrace>> = trace_on
        .then(|| Arc::new(BatchTrace::new(t_batch_start.unwrap(), num_dest as u32)));

    let mut dropped: u64 = 0;
    for sender in senders_snapshot.iter() {
        match sender.try_send((arc_batch.clone(), trace.clone())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                dropped += 1;
                // Compensate for the missing shard decrement. If this brings
                // the counter to 0 we ARE the last "writer" for this batch
                // and record the e2e elapsed ourselves.
                if let Some(t) = &trace {
                    let prev = t.shard_remaining.fetch_sub(1, Ordering::AcqRel);
                    if prev == 1 {
                        let e2e_us = t.t_start.elapsed().as_micros() as u64;
                        metrics.e2e_batches.fetch_add(1, Ordering::Relaxed);
                        metrics.e2e_us_sum.fetch_add(e2e_us, Ordering::Relaxed);
                        update_max_atomic(&metrics.e2e_us_max, e2e_us);
                    }
                }
            }
        }
    }
    // Edge case: N == 0 (no shards published yet). No shard will decrement;
    // the trace silently expires when its last Arc clone is dropped.
    if dropped > 0 {
        metrics
            .worker_dropped_batches
            .fetch_add(dropped, Ordering::Relaxed);
    }

    if trace_on {
        let fanout_dispatch_us = elapsed_us(t_before_fanout);
        let total_us = elapsed_us(t_batch_start);

        metrics.forward_batches.fetch_add(1, Ordering::Relaxed);
        metrics
            .forward_packets_in_batches
            .fetch_add(batch_packet_count as u64, Ordering::Relaxed);
        metrics
            .forward_dest_send_count
            .fetch_add(num_dest, Ordering::Relaxed);
        metrics
            .forward_total_us_sum
            .fetch_add(total_us, Ordering::Relaxed);
        metrics
            .forward_dedup_us_sum
            .fetch_add(dedup_us, Ordering::Relaxed);
        // Note: in the worker-based architecture, `forward_fanout_send_us`
        // measures only the dispatch cost (channel try_send * D), not the
        // actual UDP send. The UDP send latency is reported separately as
        // `worker_send_us_*`.
        metrics
            .forward_fanout_send_us_sum
            .fetch_add(fanout_dispatch_us, Ordering::Relaxed);
        metrics
            .forward_stats_us_sum
            .fetch_add(stats_us, Ordering::Relaxed);
        metrics
            .forward_reconstruct_clone_us_sum
            .fetch_add(reconstruct_clone_us, Ordering::Relaxed);
        update_max_atomic(&metrics.forward_total_us_max, total_us);
        update_max_atomic(&metrics.forward_fanout_send_us_max, fanout_dispatch_us);
    }

    // Count TraceShred shreds. Borrow the Arc'd batch directly.
    if debug_trace_shred {
        arc_batch
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

    // forwarding-perf metrics (per reporting interval; reset on each tick)
    /// Number of packet batches handled by the forwarder
    pub forward_batches: AtomicU64,
    /// Sum of packet counts across all batches (avg-packets-per-batch = this / forward_batches)
    pub forward_packets_in_batches: AtomicU64,
    /// Sum of destination-sends across all batches (fanout multiplier = this / forward_batches)
    pub forward_dest_send_count: AtomicU64,
    /// Sum of total per-batch handling time (microseconds)
    pub forward_total_us_sum: AtomicU64,
    /// Max per-batch handling time observed (microseconds)
    pub forward_total_us_max: AtomicU64,
    /// Sum of dedup time per batch (microseconds)
    pub forward_dedup_us_sum: AtomicU64,
    /// Sum of fanout-send time per batch (microseconds) — all destinations
    pub forward_fanout_send_us_sum: AtomicU64,
    /// Max fanout-send time observed (microseconds)
    pub forward_fanout_send_us_max: AtomicU64,
    /// Sum of per-packet stats-update time per batch (microseconds)
    pub forward_stats_us_sum: AtomicU64,
    /// Sum of reconstruct clone + try_send time per batch (microseconds)
    pub forward_reconstruct_clone_us_sum: AtomicU64,
    /// Sum of the slowest single-destination send per batch (microseconds).
    /// Legacy field — no longer populated in the worker-based architecture.
    pub forward_max_per_dest_us_sum: AtomicU64,
    /// Max single-destination send time observed (microseconds).
    /// Legacy field — no longer populated in the worker-based architecture.
    pub forward_per_dest_us_max: AtomicU64,

    // per-destination worker metrics (per reporting interval; reset on tick)
    /// Number of currently-active worker threads (one per destination).
    pub worker_count: AtomicUsize,
    /// Number of batches processed by all workers combined.
    pub worker_batches: AtomicU64,
    /// Sum of batch_send wall-clock per worker per batch (microseconds).
    pub worker_send_us_sum: AtomicU64,
    /// Max batch_send wall-clock observed in any worker (microseconds).
    pub worker_send_us_max: AtomicU64,
    /// Sum of packet counts processed by workers (for avg-per-worker calc).
    pub worker_packets_sent: AtomicU64,
    /// Number of times a dispatch was dropped because the worker's bounded
    /// channel was full or disconnected. Backpressure indicator.
    pub worker_dropped_batches: AtomicU64,

    // End-to-end barrier metrics (per reporting interval; reset on tick).
    // These are the canonical "recv → last shard's sendmmsg returned"
    // numbers. Older `forward_total_us_*` / `worker_send_us_*` are kept
    // for diagnostics but only measure pieces of the pipeline.
    /// Number of batches for which the e2e barrier completed (every shard
    /// that received the batch decremented the per-batch counter to zero).
    /// In steady state this equals `forward_batches`; if a coordinator
    /// dropped to ALL shards (rare), the trace expires without recording.
    pub e2e_batches: AtomicU64,
    /// Sum of per-batch e2e wall-clock (microseconds).
    pub e2e_us_sum: AtomicU64,
    /// Max single-batch e2e wall-clock observed (microseconds). Tail metric.
    pub e2e_us_max: AtomicU64,

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
            forward_batches: Default::default(),
            forward_packets_in_batches: Default::default(),
            forward_dest_send_count: Default::default(),
            forward_total_us_sum: Default::default(),
            forward_total_us_max: Default::default(),
            forward_dedup_us_sum: Default::default(),
            forward_fanout_send_us_sum: Default::default(),
            forward_fanout_send_us_max: Default::default(),
            forward_stats_us_sum: Default::default(),
            forward_reconstruct_clone_us_sum: Default::default(),
            forward_max_per_dest_us_sum: Default::default(),
            forward_per_dest_us_max: Default::default(),
            worker_count: AtomicUsize::new(0),
            worker_batches: Default::default(),
            worker_send_us_sum: Default::default(),
            worker_send_us_max: Default::default(),
            worker_packets_sent: Default::default(),
            worker_dropped_batches: Default::default(),
            e2e_batches: Default::default(),
            e2e_us_sum: Default::default(),
            e2e_us_max: Default::default(),
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

        // Forwarding perf: per-interval throughput + latency breakdown.
        // Only populated when RUST_LOG=trace is active; skip emission otherwise
        // so we don't flood Influx with zero rows.
        let batches = self.forward_batches.load(Ordering::Relaxed);
        if batches == 0 {
            return;
        }
        let packets = self.forward_packets_in_batches.load(Ordering::Relaxed);
        let dest_sends = self.forward_dest_send_count.load(Ordering::Relaxed);
        let total_us = self.forward_total_us_sum.load(Ordering::Relaxed);
        let dedup_us = self.forward_dedup_us_sum.load(Ordering::Relaxed);
        let fanout_us = self.forward_fanout_send_us_sum.load(Ordering::Relaxed);
        let stats_us = self.forward_stats_us_sum.load(Ordering::Relaxed);
        let reconstruct_us = self
            .forward_reconstruct_clone_us_sum
            .load(Ordering::Relaxed);
        let div = batches;
        let dropped = self.worker_dropped_batches.load(Ordering::Relaxed);

        // End-to-end barrier metrics. `e2e_batches` ≈ `forward_batches` in
        // steady state; divisor is the same when populated. If the e2e
        // barrier never completed for any batch in this interval (e.g.
        // every coordinator dispatch was dropped), emit zeros so the field
        // is still present in the datapoint and downstream parsers stay
        // stable.
        let e2e_batches = self.e2e_batches.load(Ordering::Relaxed);
        let (avg_end_to_end_us, max_end_to_end_us) = if e2e_batches > 0 {
            (
                (self.e2e_us_sum.load(Ordering::Relaxed) / e2e_batches) as i64,
                self.e2e_us_max.load(Ordering::Relaxed) as i64,
            )
        } else {
            (0i64, 0i64)
        };

        datapoint_info!(
            "shredstream_proxy-forwarding_perf",
            ("batches", batches as i64, i64),
            ("packets", packets as i64, i64),
            ("dest_sends", dest_sends as i64, i64),
            ("worker_count", self.worker_count.load(Ordering::Relaxed) as i64, i64),
            ("worker_dropped_batches", dropped as i64, i64),
            ("avg_packets_per_batch", (packets / div) as i64, i64),
            ("avg_dests_per_batch", (dest_sends / div) as i64, i64),
            ("avg_total_us", (total_us / div) as i64, i64),
            ("avg_dedup_us", (dedup_us / div) as i64, i64),
            ("avg_fanout_dispatch_us", (fanout_us / div) as i64, i64),
            ("avg_stats_us", (stats_us / div) as i64, i64),
            ("avg_reconstruct_clone_us", (reconstruct_us / div) as i64, i64),
            (
                "max_total_us",
                self.forward_total_us_max.load(Ordering::Relaxed) as i64,
                i64
            ),
            (
                "max_fanout_dispatch_us",
                self.forward_fanout_send_us_max.load(Ordering::Relaxed) as i64,
                i64
            ),
            // Canonical end-to-end barrier — see field docs on ShredMetrics.
            ("e2e_batches", e2e_batches as i64, i64),
            ("avg_end_to_end_us", avg_end_to_end_us, i64),
            ("max_end_to_end_us", max_end_to_end_us, i64),
        );

        // Worker-side metrics (per-destination send latency). These are the
        // numbers that should improve after optimizations #1/#2/#3.
        let worker_batches = self.worker_batches.load(Ordering::Relaxed);
        if worker_batches > 0 {
            let wdiv = worker_batches;
            let w_send_us = self.worker_send_us_sum.load(Ordering::Relaxed);
            let w_packets = self.worker_packets_sent.load(Ordering::Relaxed);
            datapoint_info!(
                "shredstream_proxy-worker_perf",
                ("worker_batches", worker_batches as i64, i64),
                ("worker_packets_sent", w_packets as i64, i64),
                ("avg_worker_send_us", (w_send_us / wdiv) as i64, i64),
                (
                    "max_worker_send_us",
                    self.worker_send_us_max.load(Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "avg_worker_packets_per_batch",
                    (w_packets / wdiv) as i64,
                    i64
                ),
            );
        }
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

        // reset forwarding-perf interval counters
        self.forward_batches.store(0, Ordering::Relaxed);
        self.forward_packets_in_batches.store(0, Ordering::Relaxed);
        self.forward_dest_send_count.store(0, Ordering::Relaxed);
        self.forward_total_us_sum.store(0, Ordering::Relaxed);
        self.forward_total_us_max.store(0, Ordering::Relaxed);
        self.forward_dedup_us_sum.store(0, Ordering::Relaxed);
        self.forward_fanout_send_us_sum.store(0, Ordering::Relaxed);
        self.forward_fanout_send_us_max.store(0, Ordering::Relaxed);
        self.forward_stats_us_sum.store(0, Ordering::Relaxed);
        self.forward_reconstruct_clone_us_sum
            .store(0, Ordering::Relaxed);
        self.forward_max_per_dest_us_sum
            .store(0, Ordering::Relaxed);
        self.forward_per_dest_us_max.store(0, Ordering::Relaxed);

        // worker-side counters
        self.worker_batches.store(0, Ordering::Relaxed);
        self.worker_send_us_sum.store(0, Ordering::Relaxed);
        self.worker_send_us_max.store(0, Ordering::Relaxed);
        self.worker_packets_sent.store(0, Ordering::Relaxed);
        self.worker_dropped_batches.store(0, Ordering::Relaxed);

        // e2e barrier counters
        self.e2e_batches.store(0, Ordering::Relaxed);
        self.e2e_us_sum.store(0, Ordering::Relaxed);
        self.e2e_us_max.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex, RwLock,
        },
        thread,
        thread::sleep,
        time::Duration,
    };

    use arc_swap::ArcSwap;
    use log::LevelFilter;
    use solana_perf::{
        deduper::Deduper,
        packet::{Meta, Packet, PacketBatch},
    };
    use solana_sdk::packet::{PacketFlags, PACKET_DATA_SIZE};

    use crate::forwarder::{
        new_connected_socket, recv_from_channel_and_send_multiple_dest, reshard_assignments,
        sendmmsg_connected, spawn_send_shard, ConnectedDest, ShardSenderList, ShredMetrics,
        BATCH_TRACE_ALLOCS,
    };

    /// Permissive logger installed once for the trace-mode tests.
    /// `log_enabled!(Level::Trace)` short-circuits to `false` whenever no
    /// logger is installed (the default `NoopLogger::enabled()` returns
    /// `false`). The test binary doesn't install one — so we provide a
    /// minimal logger that always reports enabled and discards records.
    struct AlwaysEnabledLogger;
    impl log::Log for AlwaysEnabledLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, _: &log::Record) {}
        fn flush(&self) {}
    }
    static ALWAYS_ENABLED_LOGGER: AlwaysEnabledLogger = AlwaysEnabledLogger;

    /// Serializes tests that mutate the process-global `log` crate max-level
    /// AND lazily installs the permissive test logger on first acquisition.
    /// Cargo runs `#[test]` items in parallel by default, and `log_enabled!`
    /// reads a shared atomic — tests that flip the level would race without
    /// this guard. `set_logger` may only be called once per process; we
    /// swallow the second-call error.
    fn log_level_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = log::set_logger(&ALWAYS_ENABLED_LOGGER);
        guard
    }

    fn listen_and_collect(listen_socket: UdpSocket, received_packets: Arc<Mutex<Vec<Vec<u8>>>>) {
        let mut buf = [0u8; PACKET_DATA_SIZE];
        loop {
            match listen_socket.recv(&mut buf) {
                Ok(_) => received_packets.lock().unwrap().push(Vec::from(buf)),
                Err(_) => break,
            }
        }
    }

    /// Bind a UDP listener on `127.0.0.1` at an OS-assigned port. Returns
    /// the bound socket and its concrete `local_addr()`. Used by the tests
    /// to avoid hard-coded ports which conflict under parallel `cargo test`.
    fn bind_listener() -> (UdpSocket, SocketAddr) {
        let s = UdpSocket::bind("127.0.0.1:0").expect("bind listener");
        let addr = s.local_addr().expect("local_addr");
        (s, addr)
    }

    /// Build a `ConnectedDest` whose socket is `connect()`-ed to `addr`.
    /// Mirrors what `reshard_assignments` would do for one destination.
    fn make_connected_dest(addr: SocketAddr) -> ConnectedDest {
        let sock = new_connected_socket(&addr).expect("bind + connect");
        ConnectedDest {
            addr,
            socket: Arc::new(sock),
        }
    }

    #[test]
    fn test_2shreds_3destinations() {
        // Engage trace mode so the coordinator builds a BatchTrace and the
        // shard runs the e2e barrier block. The lock keeps this test from
        // racing with other tests that toggle the log level.
        let _guard = log_level_lock();
        log::set_max_level(LevelFilter::Trace);

        let packet_batch = PacketBatch::new(vec![
            Packet::new(
                [1; PACKET_DATA_SIZE],
                Meta {
                    size: PACKET_DATA_SIZE,
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    port: 48289,
                    flags: PacketFlags::empty(),
                },
            ),
            Packet::new(
                [2; PACKET_DATA_SIZE],
                Meta {
                    size: PACKET_DATA_SIZE,
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    port: 9999,
                    flags: PacketFlags::empty(),
                },
            ),
        ]);
        let (packet_sender, packet_receiver) = crossbeam_channel::unbounded::<PacketBatch>();
        packet_sender.send(packet_batch).unwrap();

        // Bind 3 listeners on ephemeral ports so parallel test runs don't
        // collide on hard-coded port numbers.
        let listeners: Vec<(UdpSocket, SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>)> = (0..3)
            .map(|_| {
                let (s, a) = bind_listener();
                (s, a, Arc::new(Mutex::new(Vec::new())))
            })
            .collect();

        let dest_addrs: Vec<SocketAddr> = listeners.iter().map(|(_, a, _)| *a).collect();

        // Spawn listener threads.
        for (listen_socket, _, to_receive) in &listeners {
            let socket = listen_socket.try_clone().unwrap();
            let to_receive = to_receive.to_owned();
            thread::spawn(move || listen_and_collect(socket, to_receive));
        }

        // Spawn ONE send shard, populate its assignment with `ConnectedDest`s
        // pointing at the listeners, and publish the sender snapshot.
        let metrics = Arc::new(ShredMetrics::default());
        let exit = Arc::new(AtomicBool::new(false));
        let shard = spawn_send_shard(0, metrics.clone(), exit.clone());
        let connected: Vec<ConnectedDest> =
            dest_addrs.iter().copied().map(make_connected_dest).collect();
        shard.assignment.store(Arc::new(connected));

        let shard_senders: ShardSenderList = vec![shard.sender.clone()];
        let shard_senders = ArcSwap::from_pointee(shard_senders);

        let (reconstruct_tx, _reconstruct_rx) = crossbeam_channel::bounded(10_240);
        recv_from_channel_and_send_multiple_dest(
            packet_receiver.recv(),
            &Arc::new(RwLock::new(Deduper::<2, [u8]>::new(
                &mut rand::thread_rng(),
                crate::forwarder::DEDUPER_NUM_BITS,
            ))),
            &shard_senders,
            true,
            &reconstruct_tx,
            false,
            &metrics,
        )
        .unwrap();

        // Give the shard time to drain its channel and let the kernel
        // deliver to the listeners.
        sleep(Duration::from_millis(500));

        // Check each listener got both packets in order.
        for (_, _, results) in &listeners {
            let got = results.lock().unwrap();
            assert_eq!(got.len(), 2, "listener got wrong number of packets");
            assert!(got.iter().all(|p| p.len() == PACKET_DATA_SIZE));
            assert_eq!(got[0], [1; PACKET_DATA_SIZE]);
            assert_eq!(got[1], [2; PACKET_DATA_SIZE]);
        }
        let total: usize = listeners
            .iter()
            .map(|(_, _, r)| r.lock().unwrap().len())
            .sum();
        assert_eq!(total, 6, "expected 2 packets × 3 dests = 6");

        // E2E barrier metric: exactly one batch went through the pipeline,
        // and the single shard decremented the counter to 0 → recorded once.
        assert_eq!(
            metrics.e2e_batches.load(Ordering::Relaxed),
            1,
            "e2e barrier should fire exactly once per batch"
        );
        assert!(
            metrics.e2e_us_sum.load(Ordering::Relaxed) > 0,
            "e2e_us_sum should be > 0"
        );
        assert!(
            metrics.e2e_us_max.load(Ordering::Relaxed) > 0,
            "e2e_us_max should be > 0"
        );

        // Cleanly shut down the shard.
        exit.store(true, Ordering::Relaxed);
        drop(shard_senders);
        drop(shard.sender);
        shard.join.join().unwrap();
    }

    /// Verify that destinations surviving a reshard keep their existing
    /// `Arc<UdpSocket>` — i.e. the connected-socket cache is doing its job.
    /// This is the property that makes connect()'s kernel route cache stay
    /// warm across reconciles.
    #[test]
    fn test_connected_socket_reshard_reuses_existing() {
        let metrics = Arc::new(ShredMetrics::default());
        let exit = Arc::new(AtomicBool::new(false));
        let shard = spawn_send_shard(99, metrics.clone(), exit.clone());

        // Build the unioned_dest_sockets ArcSwap in the same shape the
        // shard manager would. The first reshard creates fresh sockets;
        // the second reshard tests reuse semantics.
        let (_listener_a, addr_a) = bind_listener();
        let (_listener_b, addr_b) = bind_listener();
        let (_listener_c, addr_c) = bind_listener();

        let unioned = ArcSwap::from_pointee(vec![addr_a, addr_b]);
        let mut shards = vec![shard];

        // First reshard — populates the cache.
        reshard_assignments(&unioned, &mut shards, &metrics);
        let assignment_1 = shards[0].assignment.load();
        assert_eq!(assignment_1.len(), 2, "should have 2 dests after first reshard");
        let old_b_socket = assignment_1
            .iter()
            .find(|d| d.addr == addr_b)
            .expect("B should be in first assignment")
            .socket
            .clone();
        let old_a_socket = assignment_1
            .iter()
            .find(|d| d.addr == addr_a)
            .expect("A should be in first assignment")
            .socket
            .clone();
        drop(assignment_1);

        // Drop addr_a, add addr_c. addr_b stays — its socket should survive
        // by Arc::ptr_eq.
        unioned.store(Arc::new(vec![addr_b, addr_c]));
        reshard_assignments(&unioned, &mut shards, &metrics);

        let assignment_2 = shards[0].assignment.load();
        assert_eq!(assignment_2.len(), 2, "should have 2 dests after second reshard");

        let new_b = assignment_2
            .iter()
            .find(|d| d.addr == addr_b)
            .expect("B should survive reshard")
            .socket
            .clone();
        assert!(
            Arc::ptr_eq(&old_b_socket, &new_b),
            "B's socket Arc should be reused across reshard"
        );

        // A's socket should NOT be reused (A is gone). We can't directly
        // assert "absence from cache" because the cache is private, but we
        // can check that no `ConnectedDest` in the new assignment carries
        // A's socket pointer (since A isn't in the new assignment at all).
        let any_uses_old_a = assignment_2
            .iter()
            .any(|d| Arc::ptr_eq(&d.socket, &old_a_socket));
        assert!(!any_uses_old_a, "A's old socket should have been dropped");
        drop(assignment_2);

        // Tear down.
        exit.store(true, Ordering::Relaxed);
        for s in shards.drain(..) {
            drop(s.sender);
            s.join.join().unwrap();
        }
    }

    /// Bind a listener, connect a sender to it, push 4 distinct payloads
    /// through `sendmmsg_connected`. Assert all 4 land on the listener side.
    /// Covers the Linux `sendmmsg(2)` path and the non-Linux fallback.
    #[test]
    fn test_sendmmsg_connected_delivers_all_packets() {
        let (listener, listener_addr) = bind_listener();
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let sender = new_connected_socket(&listener_addr).expect("bind+connect sender");

        // Distinct fixed-size payloads so we can tell them apart on recv.
        let payloads: Vec<Vec<u8>> =
            (1u8..=4).map(|i| vec![i; PACKET_DATA_SIZE]).collect();
        let pkt_refs: Vec<&[u8]> = payloads.iter().map(|v| v.as_slice()).collect();

        let sent = sendmmsg_connected(&sender, &pkt_refs).expect("sendmmsg_connected ok");
        assert_eq!(sent, 4, "should have sent all 4 packets");

        // Receive 4 packets, collect, then verify the SET matches (order is
        // not guaranteed across kernels though Linux is FIFO for single fd).
        let mut got: Vec<Vec<u8>> = Vec::with_capacity(4);
        for _ in 0..4 {
            let mut buf = [0u8; PACKET_DATA_SIZE];
            let n = listener.recv(&mut buf).expect("recv");
            assert_eq!(n, PACKET_DATA_SIZE);
            got.push(buf.to_vec());
        }
        for expected in &payloads {
            assert!(
                got.iter().any(|g| g == expected),
                "missing payload starting with byte {}",
                expected[0]
            );
        }
    }

    /// With trace OFF, the coordinator must not allocate a `BatchTrace`
    /// and the e2e metrics must stay at zero. Flipping trace ON should
    /// allocate exactly one trace and record one e2e datapoint.
    #[test]
    fn test_trace_off_zero_overhead_no_batch_trace_alloc() {
        let _guard = log_level_lock();
        // Use a separate listener+shard from the other tests to keep
        // metrics isolated.
        let (_listener, addr) = bind_listener();
        let metrics = Arc::new(ShredMetrics::default());
        let exit = Arc::new(AtomicBool::new(false));
        let shard = spawn_send_shard(7, metrics.clone(), exit.clone());
        shard
            .assignment
            .store(Arc::new(vec![make_connected_dest(addr)]));
        let shard_senders: ShardSenderList = vec![shard.sender.clone()];
        let shard_senders = ArcSwap::from_pointee(shard_senders);
        let deduper = Arc::new(RwLock::new(Deduper::<2, [u8]>::new(
            &mut rand::thread_rng(),
            crate::forwarder::DEDUPER_NUM_BITS,
        )));
        let (reconstruct_tx, _reconstruct_rx) = crossbeam_channel::bounded(10_240);

        let make_batch = || {
            PacketBatch::new(vec![Packet::new(
                [9; PACKET_DATA_SIZE],
                Meta {
                    size: PACKET_DATA_SIZE,
                    addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: 1234,
                    flags: PacketFlags::empty(),
                },
            )])
        };

        // ---- trace OFF: no allocations expected, no e2e increment.
        log::set_max_level(LevelFilter::Info);
        let allocs_before = BATCH_TRACE_ALLOCS.load(Ordering::Relaxed);

        let (tx_off, rx_off) = crossbeam_channel::unbounded::<PacketBatch>();
        tx_off.send(make_batch()).unwrap();
        recv_from_channel_and_send_multiple_dest(
            rx_off.recv(),
            &deduper,
            &shard_senders,
            true,
            &reconstruct_tx,
            false,
            &metrics,
        )
        .unwrap();
        sleep(Duration::from_millis(50));

        let allocs_after_off = BATCH_TRACE_ALLOCS.load(Ordering::Relaxed);
        assert_eq!(
            allocs_after_off, allocs_before,
            "trace OFF must not allocate any BatchTrace"
        );
        assert_eq!(
            metrics.e2e_batches.load(Ordering::Relaxed),
            0,
            "trace OFF must not record any e2e batches"
        );

        // ---- trace ON: exactly one alloc, exactly one e2e batch recorded.
        log::set_max_level(LevelFilter::Trace);

        // Fresh deduper to avoid the second identical batch being dropped.
        let deduper_on = Arc::new(RwLock::new(Deduper::<2, [u8]>::new(
            &mut rand::thread_rng(),
            crate::forwarder::DEDUPER_NUM_BITS,
        )));
        let (tx_on, rx_on) = crossbeam_channel::unbounded::<PacketBatch>();
        // Use a different payload so dedup doesn't accidentally drop.
        tx_on
            .send(PacketBatch::new(vec![Packet::new(
                [11; PACKET_DATA_SIZE],
                Meta {
                    size: PACKET_DATA_SIZE,
                    addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    port: 1234,
                    flags: PacketFlags::empty(),
                },
            )]))
            .unwrap();
        recv_from_channel_and_send_multiple_dest(
            rx_on.recv(),
            &deduper_on,
            &shard_senders,
            true,
            &reconstruct_tx,
            false,
            &metrics,
        )
        .unwrap();
        sleep(Duration::from_millis(100));

        let allocs_after_on = BATCH_TRACE_ALLOCS.load(Ordering::Relaxed);
        assert_eq!(
            allocs_after_on - allocs_after_off,
            1,
            "trace ON must allocate exactly one BatchTrace per batch"
        );
        assert_eq!(
            metrics.e2e_batches.load(Ordering::Relaxed),
            1,
            "trace ON must record exactly one e2e batch"
        );

        // Clean shutdown.
        exit.store(true, Ordering::Relaxed);
        drop(shard_senders);
        drop(shard.sender);
        shard.join.join().unwrap();
    }
}
