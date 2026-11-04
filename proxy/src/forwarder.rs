use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    thread::{Builder, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

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

/// Bounded capacity of each per-destination batch channel. When a worker
/// can't keep up, additional batches are *dropped for that destination only*
/// (counted in `worker_dropped_batches`). Fast destinations are unaffected.
const DEST_CHANNEL_CAPACITY: usize = 1024;
/// Initial scratch-buffer capacity for the per-destination send Vec.
/// Sized for typical batches; the Vec will grow on demand and stay grown.
const DEST_SCRATCH_INITIAL_CAPACITY: usize = 128;
/// How often the dest-manager reconciles workers against the current
/// `unioned_dest_sockets`.
const DEST_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// Per-batch latency trace shared between the coordinator and every worker
/// that received the batch. Created once per batch by the coordinator when
/// trace mode is on. Each worker does `fetch_sub(1, AcqRel)` on
/// `workers_remaining` after its `batch_send` returns; the worker whose
/// decrement brings the counter to 0 records `t_start.elapsed()` into the
/// e2e metric fields.
///
/// This is the canonical "recv → last worker's sendmmsg returned for THIS
/// batch" measurement. Older fields (`avg_total_us`, `avg_worker_send_us`)
/// only capture pieces of the pipeline; this is the full barrier.
pub struct BatchTrace {
    pub t_start: Instant,
    pub workers_remaining: AtomicU32,
}

impl BatchTrace {
    /// Construct a new trace with `workers_remaining` initialized to N (the
    /// number of workers we are about to dispatch to). The counter is set
    /// up-front so any worker that picks the batch up before the coordinator
    /// finishes its try_send loop still sees a sane initial value.
    pub fn new(t_start: Instant, num_workers: u32) -> Self {
        Self {
            t_start,
            workers_remaining: AtomicU32::new(num_workers),
        }
    }
}

/// What a worker receives over its channel — the batch and an optional
/// per-batch trace. `None` when trace mode is off (zero allocation, the
/// worker skips the barrier block).
pub type WorkerMsg = (Arc<PacketBatch>, Option<Arc<BatchTrace>>);

/// One channel per active destination. Coordinator threads load a snapshot
/// of this map and dispatch a `WorkerMsg` to each sender.
pub type DestSenderMap = HashMap<SocketAddr, crossbeam_channel::Sender<WorkerMsg>>;

/// Opt-in sender layout. The default (all off) is one worker thread per
/// destination.
#[derive(Clone, Debug, Default)]
pub struct SendConfig {
    /// Sender threads, each owning a share of the destinations (one
    /// `sendmmsg` per destination per batch); 0 = one worker per destination.
    pub shards: usize,
    /// CPU per shard, in shard order. A pinned shard busy-polls its queue
    /// instead of sleeping (one full core each).
    pub shard_cores: Vec<usize>,
    /// Unpinned shards keep polling their queue for this long (µs) after
    /// their last batch before sleeping, so in bursts they are never woken;
    /// 0 = sleep at once.
    pub shard_spin_us: u32,
    /// CPU for the listen threads.
    pub recv_core: Option<usize>,
    /// CPU for the dispatch thread (dedup + hand-off to the senders); pinned,
    /// it busy-polls the listen thread's channel instead of sleeping.
    pub dispatch_core: Option<usize>,
    /// `SO_BUSY_POLL` (µs) on the listen sockets; 0 = off.
    pub recv_busy_poll_us: u32,
    /// Receive buffer (bytes) of each listen socket, set with
    /// `SO_RCVBUFFORCE` (ignores `net.core.rmem_max`); 0 = system default.
    pub recv_buffer_bytes: usize,
    /// Bond (layer3+4 hash) whose ports the destinations should be spread
    /// over evenly, by choosing each destination's source port.
    pub balance_bond: Option<String>,
}

/// Source ports tried for `SendConfig::balance_bond` (the kernel's default
/// ephemeral range, so service ports below it are never taken).
const BALANCE_PORTS: std::ops::Range<u16> = 33_000..60_000;

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
    send_config: SendConfig,
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
    if send_config.recv_busy_poll_us > 0 {
        sockets
            .iter()
            .for_each(|s| set_busy_poll(s, send_config.recv_busy_poll_us));
    }
    if send_config.recv_buffer_bytes > 0 {
        sockets
            .iter()
            .for_each(|s| set_recv_buffer(s, send_config.recv_buffer_bytes));
    }
    let recv_core = send_config.recv_core;
    let dispatch_core = send_config.dispatch_core;

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

    // Shared snapshot of (dest -> channel-sender-to-worker). Coordinator
    // threads load this and dispatch each Arc<PacketBatch>. The dest-manager
    // thread (below) is the only writer; coordinators are readers.
    let dest_senders: Arc<ArcSwap<DestSenderMap>> =
        Arc::new(ArcSwap::from_pointee(DestSenderMap::default()));

    // Spawn the dest manager (or, with send shards, the shard manager). It
    // reconciles `dest_senders` against `unioned_dest_sockets` and owns the
    // sender join handles.
    let dest_mgr_hdl = if send_config.shards > 0 {
        start_shard_manager_thread(
            unioned_dest_sockets.clone(),
            dest_senders.clone(),
            send_config.clone(),
            metrics.clone(),
            shutdown_receiver.clone(),
            exit.clone(),
        )
    } else {
        start_dest_manager_thread(
            unioned_dest_sockets.clone(),
            dest_senders.clone(),
            metrics.clone(),
            shutdown_receiver.clone(),
            exit.clone(),
        )
    };
    thread_hdls.push(dest_mgr_hdl);

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
            if let Some(core) = recv_core {
                pin_thread(&listen_thread, core);
            }

            let deduper = deduper.clone();
            let metrics = metrics.clone();
            let shutdown_receiver = shutdown_receiver.clone();
            let reconstruct_tx = reconstruct_tx.clone();
            let exit = exit.clone();
            let dest_senders = dest_senders.clone();

            let send_thread = Builder::new()
                .name(format!("ssPxyTx_{thread_id}"))
                .spawn(move || {
                    if let Some(core) = dispatch_core {
                        // Pinned: busy-poll the channel (no wake-up per batch).
                        pin_current_thread(core);
                        while !exit.load(Ordering::Relaxed) {
                            match packet_receiver.try_recv() {
                                Ok(packet_batch) => {
                                    if recv_from_channel_and_send_multiple_dest(
                                        Ok(packet_batch),
                                        &deduper,
                                        &dest_senders,
                                        should_reconstruct_shreds,
                                        &reconstruct_tx,
                                        debug_trace_shred,
                                        &metrics,
                                    )
                                    .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(TryRecvError::Empty) => std::hint::spin_loop(),
                                Err(TryRecvError::Disconnected) => break,
                            }
                        }
                    } else {
                        while !exit.load(Ordering::Relaxed) {
                            crossbeam_channel::select! {
                                // forward packets
                                recv(packet_receiver) -> maybe_packet_batch => {
                                    let res = recv_from_channel_and_send_multiple_dest(
                                        maybe_packet_batch,
                                        &deduper,
                                        &dest_senders,
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

/// Spawn a per-destination worker thread.
///
/// The worker owns its own `UdpSocket` (avoiding contention on a shared send
/// buffer) and a reused scratch `Vec<(&'static [u8], &'static SocketAddr)>`
/// so the steady-state send loop performs zero heap allocations.
///
/// Each received `Arc<PacketBatch>` is sent in a single `batch_send` call,
/// which is `sendmmsg(2)` on Linux (one syscall for up to 1024 packets).
fn spawn_dest_worker(
    dest: SocketAddr,
    metrics: Arc<ShredMetrics>,
    exit: Arc<AtomicBool>,
) -> (crossbeam_channel::Sender<WorkerMsg>, JoinHandle<()>) {
    let (tx, rx) = crossbeam_channel::bounded::<WorkerMsg>(DEST_CHANNEL_CAPACITY);
    // Box the destination so its address is stable for the lifetime of the
    // thread — references into it can safely be transmuted to 'static.
    let dest_boxed: Box<SocketAddr> = Box::new(dest);
    let bind_addr = match dest {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let name = format!("ssPxyDst_{}_{}", dest.ip(), dest.port());
    let hdl = Builder::new()
        .name(name)
        .spawn(move || run_dest_worker(dest_boxed, bind_addr, rx, metrics, exit))
        .expect("failed to spawn dest worker thread");
    (tx, hdl)
}

/// The body of a per-destination worker thread.
fn run_dest_worker(
    dest_boxed: Box<SocketAddr>,
    bind_addr: SocketAddr,
    rx: crossbeam_channel::Receiver<WorkerMsg>,
    metrics: Arc<ShredMetrics>,
    exit: Arc<AtomicBool>,
) {
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            error!("dest worker for {} failed to bind: {e}", *dest_boxed);
            return;
        }
    };

    // Reused scratch: (&packet_data, &dest_addr). The 'static lifetime is a
    // *phantom* — see SAFETY notes at each push. We `clear()` before every
    // function exit, so no reference outlives its source.
    let mut scratch: Vec<(&'static [u8], &'static SocketAddr)> =
        Vec::with_capacity(DEST_SCRATCH_INITIAL_CAPACITY);

    // Stable pointer to the destination — Box keeps it pinned for the
    // lifetime of this thread.
    let dest_ref: &SocketAddr = &dest_boxed;
    // SAFETY: dest_ref lives as long as this thread; this transmute extends
    // its lifetime to 'static for storage purposes only. The Vec is cleared
    // before the function returns.
    let dest_static: &'static SocketAddr = unsafe { std::mem::transmute(dest_ref) };

    let trace_on = log_enabled!(Level::Trace);

    while !exit.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok((batch, trace)) => {
                debug_assert!(scratch.is_empty());
                let t_send = trace_on.then(Instant::now);
                let batch_packet_count = batch.len();

                for pkt in batch.iter() {
                    if let Some(data) = pkt.data(..) {
                        // SAFETY: `data` borrows from `batch`, which is held
                        // for the duration of this loop iteration. We clear
                        // `scratch` before this iteration ends, so the
                        // transmuted 'static reference never escapes.
                        let data_static: &'static [u8] = unsafe { std::mem::transmute(data) };
                        scratch.push((data_static, dest_static));
                    }
                }

                let to_send = scratch.len() as u64;
                match batch_send(&socket, &scratch) {
                    Ok(()) => {
                        metrics
                            .success_forward
                            .fetch_add(to_send, Ordering::Relaxed);
                    }
                    Err(SendPktsError::IoError(err, num_failed)) => {
                        metrics
                            .fail_forward
                            .fetch_add(num_failed as u64, Ordering::Relaxed);
                        metrics
                            .success_forward
                            .fetch_add(to_send.saturating_sub(num_failed as u64), Ordering::Relaxed);
                        error!(
                            "dest worker for {} failed batch of {to_send}: {num_failed} failed. Error: {err}",
                            *dest_boxed
                        );
                    }
                }
                scratch.clear();

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
                // remaining-worker counter. The worker whose decrement brings
                // it to 0 is the last to finish sending for this batch and
                // records the full recv→send-done elapsed time.
                //
                // AcqRel ordering ensures the e2e read of t_start.elapsed()
                // happens-after every peer worker's losing fetch_sub.
                if let Some(t) = trace {
                    let prev = t.workers_remaining.fetch_sub(1, Ordering::AcqRel);
                    if prev == 1 {
                        let e2e_us = t.t_start.elapsed().as_micros() as u64;
                        metrics.e2e_batches.fetch_add(1, Ordering::Relaxed);
                        metrics
                            .e2e_us_sum
                            .fetch_add(e2e_us, Ordering::Relaxed);
                        update_max_atomic(&metrics.e2e_us_max, e2e_us);
                    }
                }

                drop(batch);
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
    info!("Exiting dest worker for {}.", *dest_boxed);
    // scratch is dropped here — it's already empty.
}

/// Reconciles per-destination worker threads against the current set of
/// destinations published in `unioned_dest_sockets`. Spawns new workers when
/// destinations appear, drops senders when destinations are removed (which
/// causes the worker thread to exit on channel disconnect).
fn start_dest_manager_thread(
    unioned_dest_sockets: Arc<ArcSwap<Vec<SocketAddr>>>,
    dest_senders: Arc<ArcSwap<DestSenderMap>>,
    metrics: Arc<ShredMetrics>,
    shutdown_receiver: Receiver<()>,
    exit: Arc<AtomicBool>,
) -> JoinHandle<()> {
    Builder::new()
        .name("ssPxyDstMgr".to_string())
        .spawn(move || {
            let tick = crossbeam_channel::tick(DEST_RECONCILE_INTERVAL);
            // Owned handles & senders, kept in sync with the published map.
            // We hold senders here so they outlive any in-flight broadcast
            // until the worker has fully drained.
            let mut handles: HashMap<SocketAddr, JoinHandle<()>> = HashMap::new();
            let mut owned: DestSenderMap = DestSenderMap::default();

            // Run one reconciliation immediately so workers exist before the
            // first packet arrives.
            reconcile_dest_workers(
                &unioned_dest_sockets,
                &dest_senders,
                &mut owned,
                &mut handles,
                &metrics,
                &exit,
            );

            while !exit.load(Ordering::Relaxed) {
                crossbeam_channel::select! {
                    recv(tick) -> _ => {
                        reconcile_dest_workers(
                            &unioned_dest_sockets,
                            &dest_senders,
                            &mut owned,
                            &mut handles,
                            &metrics,
                            &exit,
                        );
                    }
                    recv(shutdown_receiver) -> _ => break,
                }
            }

            // Shutdown: drop all senders so workers see Disconnected and exit.
            drop(owned);
            dest_senders.store(Arc::new(DestSenderMap::default()));
            for (dest, h) in handles.drain() {
                if let Err(e) = h.join() {
                    warn!("dest worker {dest} join failed: {e:?}");
                }
            }
            info!("Exiting dest manager.");
        })
        .unwrap()
}

fn reconcile_dest_workers(
    unioned_dest_sockets: &ArcSwap<Vec<SocketAddr>>,
    dest_senders: &ArcSwap<DestSenderMap>,
    owned: &mut DestSenderMap,
    handles: &mut HashMap<SocketAddr, JoinHandle<()>>,
    metrics: &Arc<ShredMetrics>,
    exit: &Arc<AtomicBool>,
) {
    let desired = unioned_dest_sockets.load();
    let desired_set: HashSet<SocketAddr> = desired.iter().copied().collect();

    // Remove workers whose destination is gone.
    let to_remove: Vec<SocketAddr> = owned
        .keys()
        .filter(|d| !desired_set.contains(d))
        .copied()
        .collect();
    for dest in to_remove {
        owned.remove(&dest);
        // Don't join yet — the worker thread may still be draining. It will
        // exit on Disconnected; we'll join on shutdown.
        if let Some(h) = handles.remove(&dest) {
            // Detach: the JoinHandle is dropped, which is fine — Rust threads
            // continue running. The thread will see channel disconnect and exit.
            drop(h);
        }
        info!("dest worker removed: {dest}");
    }

    // Spawn workers for new destinations.
    for dest in desired_set.iter() {
        if !owned.contains_key(dest) {
            let (tx, hdl) = spawn_dest_worker(*dest, metrics.clone(), exit.clone());
            owned.insert(*dest, tx);
            handles.insert(*dest, hdl);
            info!("dest worker spawned: {dest}");
        }
    }

    // Publish a fresh snapshot to coordinators.
    dest_senders.store(Arc::new(owned.clone()));
    metrics
        .worker_count
        .store(owned.len(), Ordering::Relaxed);
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

/// A destination owned by a send shard. Each has its own socket, so its
/// source port can be chosen (see `SendConfig::balance_bond`).
struct ShardDest {
    addr: SocketAddr,
    socket: UdpSocket,
}

/// A shard's current destinations, replaced by the shard manager on change.
type ShardDests = Arc<ArcSwap<Vec<Arc<ShardDest>>>>;

/// Key of shard `i` in `DestSenderMap`; coordinators only use the values.
fn shard_key(i: usize) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), i as u16)
}

/// Spawns `config.shards` send shards once, then keeps their destinations in
/// sync with `unioned_dest_sockets` (and with the bond's ports going up or
/// down when balancing). Publishes one sender per shard to the coordinators.
fn start_shard_manager_thread(
    unioned_dest_sockets: Arc<ArcSwap<Vec<SocketAddr>>>,
    dest_senders: Arc<ArcSwap<DestSenderMap>>,
    config: SendConfig,
    metrics: Arc<ShredMetrics>,
    shutdown_receiver: Receiver<()>,
    exit: Arc<AtomicBool>,
) -> JoinHandle<()> {
    Builder::new()
        .name("ssPxyShardMgr".to_string())
        .spawn(move || {
            let mut owned = DestSenderMap::default();
            let mut handles = Vec::with_capacity(config.shards);
            let mut shard_dests: Vec<ShardDests> = Vec::with_capacity(config.shards);
            for i in 0..config.shards {
                let (tx, rx) = crossbeam_channel::bounded::<WorkerMsg>(DEST_CHANNEL_CAPACITY);
                let dests: ShardDests = Arc::new(ArcSwap::from_pointee(Vec::new()));
                let core = config.shard_cores.get(i).copied();
                let spin_for = Duration::from_micros(config.shard_spin_us.into());
                let (shard_dests_i, metrics, exit) = (dests.clone(), metrics.clone(), exit.clone());
                let hdl = Builder::new()
                    .name(format!("ssPxyShard_{i}"))
                    .spawn(move || {
                        run_send_shard(i, rx, shard_dests_i, core, spin_for, metrics, exit)
                    })
                    .expect("failed to spawn send shard");
                owned.insert(shard_key(i), tx);
                handles.push(hdl);
                shard_dests.push(dests);
            }
            info!(
                "send shards: {} (cores {:?}; pinned shards busy-poll; others spin {} us before sleeping)",
                config.shards, config.shard_cores, config.shard_spin_us
            );

            let tick = crossbeam_channel::tick(DEST_RECONCILE_INTERVAL);
            let mut current: Option<(Vec<SocketAddr>, Option<usize>)> = None;
            while !exit.load(Ordering::Relaxed) {
                let mut desired: Vec<SocketAddr> =
                    unioned_dest_sockets.load().iter().copied().collect();
                desired.sort();
                desired.dedup();
                let ports = config.balance_bond.as_deref().and_then(bond_ports);
                if current.as_ref() != Some(&(desired.clone(), ports)) {
                    if config.balance_bond.is_some() && ports.is_none() {
                        warn!(
                            "--balance-bond {:?}: not an 802.3ad/balance-xor bond with layer3+4 hash and 2+ ports up; not balancing",
                            config.balance_bond
                        );
                    }
                    reshard(&desired, &shard_dests, ports);
                    metrics.worker_count.store(desired.len(), Ordering::Relaxed);
                    if current.is_none() {
                        dest_senders.store(Arc::new(owned.clone()));
                    }
                    current = Some((desired, ports));
                }
                crossbeam_channel::select! {
                    recv(tick) -> _ => {}
                    recv(shutdown_receiver) -> _ => break,
                }
            }

            // Shutdown: drop all senders so shards see Disconnected and exit.
            drop(owned);
            dest_senders.store(Arc::new(DestSenderMap::default()));
            for (i, h) in handles.into_iter().enumerate() {
                if let Err(e) = h.join() {
                    warn!("send shard {i} join failed: {e:?}");
                }
            }
            info!("Exiting shard manager.");
        })
        .unwrap()
}

/// Assigns the destinations round-robin to the shards, each with a new
/// socket. With `bond_ports`, the n-th balanced destination gets a source
/// port that the bond's hash sends out on port n % bond_ports.
fn reshard(desired: &[SocketAddr], shard_dests: &[ShardDests], bond_ports: Option<usize>) {
    let n = shard_dests.len();
    let mut per_shard: Vec<Vec<Arc<ShardDest>>> = vec![Vec::new(); n];
    let mut slot = 0;
    for (k, addr) in desired.iter().enumerate() {
        let want = bond_ports.map(|p| (slot % p, p));
        match new_dest_socket(addr, want) {
            Ok((socket, balanced)) => {
                let sport = socket.local_addr().map(|a| a.port()).unwrap_or(0);
                if balanced {
                    info!("send shard {}: {addr} from port {sport}, bond port {}", k % n, slot % bond_ports.unwrap_or(1));
                    slot += 1;
                } else {
                    info!("send shard {}: {addr} from port {sport}", k % n);
                }
                per_shard[k % n].push(Arc::new(ShardDest { addr: *addr, socket }));
            }
            Err(e) => error!("send shard: no socket for {addr}, not sending to it: {e}"),
        }
    }
    for (dests, assigned) in shard_dests.iter().zip(per_shard) {
        dests.store(Arc::new(assigned));
    }
}

/// A socket for sending to `dest`. With `bond = Some((slot, ports))`, bound to
/// a source port that the bond's layer3+4 hash maps to port `slot` (IPv4,
/// non-loopback only); returns whether that worked.
fn new_dest_socket(
    dest: &SocketAddr,
    bond: Option<(usize, usize)>,
) -> std::io::Result<(UdpSocket, bool)> {
    let unspecified = match dest {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    if let (Some((slot, ports)), SocketAddr::V4(d)) = (bond, dest) {
        // connect() on a UDP socket only resolves the route (no packet sent):
        // it tells us the source address the kernel will use.
        let probe = UdpSocket::bind(SocketAddr::new(unspecified, 0))?;
        probe.connect(dest)?;
        if let IpAddr::V4(src) = probe.local_addr()?.ip() {
            if !src.is_loopback() {
                drop(probe);
                for sport in BALANCE_PORTS {
                    if bond_l34_hash(src, sport, *d.ip(), d.port()) as usize % ports != slot {
                        continue;
                    }
                    if let Ok(socket) = UdpSocket::bind(SocketAddr::new(unspecified, sport)) {
                        return Ok((socket, true));
                    }
                }
            }
        }
    }
    Ok((UdpSocket::bind(SocketAddr::new(unspecified, 0))?, false))
}

/// The bonding driver's layer3+4 transmit hash for IPv4 UDP on a
/// little-endian host (`bond_xmit_hash` / `bond_ip_hash`); the bond sends on
/// port `hash % ports up`. Verify on a server with
/// `fanout/scripts/bond-hash-check.py` before relying on it.
fn bond_l34_hash(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16) -> u32 {
    let [s0, s1] = sport.to_be_bytes();
    let [d0, d1] = dport.to_be_bytes();
    let mut h = u32::from_le_bytes([s0, s1, d0, d1]);
    h ^= u32::from_le_bytes(dst.octets()) ^ u32::from_le_bytes(src.octets());
    h ^= h >> 16;
    h ^= h >> 8;
    h >> 1
}

/// Ports up on `bond` if it spreads flows by layer3+4 hash over 2 or more.
fn bond_ports(bond: &str) -> Option<usize> {
    let read = |f: &str| std::fs::read_to_string(format!("/sys/class/net/{bond}/bonding/{f}")).ok();
    let mode = read("mode")?;
    if !(mode.starts_with("802.3ad") || mode.starts_with("balance-xor"))
        || !read("xmit_hash_policy")?.starts_with("layer3+4")
    {
        return None;
    }
    let up = read("slaves")?
        .split_whitespace()
        .filter(|s| {
            std::fs::read_to_string(format!("/sys/class/net/{s}/operstate"))
                .map(|o| o.trim() == "up")
                .unwrap_or(false)
        })
        .count();
    (up >= 2).then_some(up)
}

/// The body of a send shard: for every batch, one `batch_send` (`sendmmsg`)
/// per destination it owns. Pinned (`core`), it busy-polls its queue.
fn run_send_shard(
    id: usize,
    rx: crossbeam_channel::Receiver<WorkerMsg>,
    dests: ShardDests,
    core: Option<usize>,
    spin_for: Duration,
    metrics: Arc<ShredMetrics>,
    exit: Arc<AtomicBool>,
) {
    if let Some(core) = core {
        pin_current_thread(core);
    }
    let spin = core.is_some();
    let mut idle_since = Instant::now();
    let trace_on = log_enabled!(Level::Trace);
    let mut scratch: Vec<(&'static [u8], &'static SocketAddr)> =
        Vec::with_capacity(DEST_SCRATCH_INITIAL_CAPACITY);

    while !exit.load(Ordering::Relaxed) {
        let (batch, trace) = if spin {
            match rx.try_recv() {
                Ok(msg) => msg,
                Err(TryRecvError::Empty) => {
                    std::hint::spin_loop();
                    continue;
                }
                Err(TryRecvError::Disconnected) => break,
            }
        } else {
            // A polling receiver is not parked, so the dispatcher's send
            // needs no wake-up; only after `spin_for` idle does it sleep.
            match rx.try_recv() {
                Ok(msg) => msg,
                Err(TryRecvError::Empty) if idle_since.elapsed() < spin_for => {
                    std::hint::spin_loop();
                    continue;
                }
                Err(TryRecvError::Empty) => match rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(msg) => msg,
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                },
                Err(TryRecvError::Disconnected) => break,
            }
        };
        let t_send = trace_on.then(Instant::now);

        let snapshot = dests.load();
        for dest in snapshot.iter() {
            let addr: &SocketAddr = &dest.addr;
            // SAFETY: `snapshot` keeps `dest` alive past the `scratch.clear()`
            // below, so the 'static lifetime is a phantom that never escapes.
            let addr_static: &'static SocketAddr = unsafe { std::mem::transmute(addr) };
            for pkt in batch.iter() {
                if let Some(data) = pkt.data(..) {
                    // SAFETY: `batch` outlives this loop; `scratch` is cleared
                    // before the iteration ends.
                    let data_static: &'static [u8] = unsafe { std::mem::transmute(data) };
                    scratch.push((data_static, addr_static));
                }
            }
            let to_send = scratch.len() as u64;
            match batch_send(&dest.socket, &scratch) {
                Ok(()) => {
                    metrics
                        .success_forward
                        .fetch_add(to_send, Ordering::Relaxed);
                }
                Err(SendPktsError::IoError(err, num_failed)) => {
                    metrics
                        .fail_forward
                        .fetch_add(num_failed as u64, Ordering::Relaxed);
                    metrics
                        .success_forward
                        .fetch_add(to_send.saturating_sub(num_failed as u64), Ordering::Relaxed);
                    error!(
                        "send shard {id} to {addr} failed batch of {to_send}: {num_failed} failed. Error: {err}"
                    );
                }
            }
            scratch.clear();
        }
        drop(snapshot);

        if let Some(t) = t_send {
            let send_us = t.elapsed().as_micros() as u64;
            metrics.worker_batches.fetch_add(1, Ordering::Relaxed);
            metrics
                .worker_send_us_sum
                .fetch_add(send_us, Ordering::Relaxed);
            metrics
                .worker_packets_sent
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            update_max_atomic(&metrics.worker_send_us_max, send_us);
        }
        // E2E barrier, as in `run_dest_worker`: one decrement per shard.
        if let Some(t) = trace {
            let prev = t.workers_remaining.fetch_sub(1, Ordering::AcqRel);
            if prev == 1 {
                let e2e_us = t.t_start.elapsed().as_micros() as u64;
                metrics.e2e_batches.fetch_add(1, Ordering::Relaxed);
                metrics.e2e_us_sum.fetch_add(e2e_us, Ordering::Relaxed);
                update_max_atomic(&metrics.e2e_us_max, e2e_us);
            }
        }
        drop(batch);
        idle_since = Instant::now();
    }
    info!("Exiting send shard {id}.");
}

#[cfg(target_os = "linux")]
fn cpu_set(core: usize) -> libc::cpu_set_t {
    // SAFETY: cpu_set_t is a plain bit set; all zeroes is the empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a valid, exclusively borrowed cpu_set_t.
    unsafe { libc::CPU_SET(core, &mut set) };
    set
}

/// Pins the calling thread to `core`.
#[cfg(target_os = "linux")]
fn pin_current_thread(core: usize) {
    let set = cpu_set(core);
    // SAFETY: pid 0 means the calling thread; `set` is a valid cpu_set_t.
    let r = unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) };
    let name = std::thread::current().name().unwrap_or("?").to_string();
    if r == 0 {
        info!("pinned {name} to CPU {core}");
    } else {
        warn!("could not pin {name} to CPU {core}: {}", std::io::Error::last_os_error());
    }
}

/// Pins a running thread to `core`.
#[cfg(target_os = "linux")]
fn pin_thread(handle: &JoinHandle<()>, core: usize) {
    use std::os::unix::thread::JoinHandleExt;
    let set = cpu_set(core);
    // SAFETY: the thread behind `handle` has not been joined, so its pthread_t
    // is valid; `set` is a valid cpu_set_t.
    let r = unsafe {
        libc::pthread_setaffinity_np(
            handle.as_pthread_t(),
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        )
    };
    if r == 0 {
        info!("pinned {:?} to CPU {core}", handle.thread().name());
    } else {
        warn!(
            "could not pin {:?} to CPU {core}: {}",
            handle.thread().name(),
            std::io::Error::from_raw_os_error(r)
        );
    }
}

/// Sets `SO_BUSY_POLL`: blocking receives poll the NIC queue for up to
/// `usecs` before sleeping.
#[cfg(target_os = "linux")]
fn set_busy_poll(socket: &UdpSocket, usecs: u32) {
    use std::os::fd::AsRawFd;
    let v = usecs as libc::c_int;
    // SAFETY: valid fd, option value points to a c_int of the given size.
    let r = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL,
            &v as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        warn!("could not set SO_BUSY_POLL {usecs}: {}", std::io::Error::last_os_error());
    }
}

/// Sets the receive buffer to `bytes` with `SO_RCVBUFFORCE` (needs
/// CAP_NET_ADMIN; not capped by `net.core.rmem_max`).
#[cfg(target_os = "linux")]
fn set_recv_buffer(socket: &UdpSocket, bytes: usize) {
    use std::os::fd::AsRawFd;
    let v = bytes.min(libc::c_int::MAX as usize / 2) as libc::c_int;
    // SAFETY: valid fd, option value points to a c_int of the given size.
    let r = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &v as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r == 0 {
        info!("listen socket receive buffer {bytes} bytes");
    } else {
        warn!("could not set receive buffer {bytes}: {}", std::io::Error::last_os_error());
    }
}

/// Keeps the calling thread, and every thread it spawns afterwards, off
/// `cores` and their SMT siblings, so the threads pinned there have their
/// physical cores to themselves. Call before spawning anything.
#[cfg(target_os = "linux")]
pub fn keep_off_cores(cores: &[usize]) {
    let mut off: Vec<usize> = Vec::new();
    for &core in cores {
        off.push(core);
        // e.g. "14,30" or "14-15"
        let path = format!("/sys/devices/system/cpu/cpu{core}/topology/thread_siblings_list");
        for part in std::fs::read_to_string(path).unwrap_or_default().trim().split(',') {
            let mut ends = part.split('-').filter_map(|n| n.parse::<usize>().ok());
            if let Some(lo) = ends.next() {
                off.extend(lo..=ends.next().unwrap_or(lo));
            }
        }
    }
    off.sort_unstable();
    off.dedup();
    // SAFETY: cpu_set_t is a plain bit set; pid 0 is the calling thread.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::cpu_set_t>();
    if unsafe { libc::sched_getaffinity(0, size, &mut set) } != 0 {
        warn!("could not read CPU affinity: {}", std::io::Error::last_os_error());
        return;
    }
    for &core in &off {
        // SAFETY: `set` is a valid, exclusively borrowed cpu_set_t.
        unsafe { libc::CPU_CLR(core, &mut set) };
    }
    // SAFETY: as above.
    if unsafe { libc::CPU_COUNT(&set) } == 0 {
        warn!("not keeping threads off CPUs {off:?}: no CPU would be left");
        return;
    }
    // SAFETY: pid 0 means the calling thread; `set` is a valid cpu_set_t.
    if unsafe { libc::sched_setaffinity(0, size, &set) } == 0 {
        info!("other threads kept off CPUs {off:?}");
    } else {
        warn!("could not keep threads off CPUs {off:?}: {}", std::io::Error::last_os_error());
    }
}

#[cfg(not(target_os = "linux"))]
pub fn keep_off_cores(cores: &[usize]) {
    warn!("CPU pinning is Linux only; not keeping threads off CPUs {cores:?}");
}

#[cfg(not(target_os = "linux"))]
fn set_recv_buffer(_socket: &UdpSocket, bytes: usize) {
    warn!("SO_RCVBUFFORCE is Linux only; not setting {bytes}");
}

#[cfg(not(target_os = "linux"))]
fn pin_current_thread(core: usize) {
    warn!("CPU pinning is Linux only; not pinning to CPU {core}");
}

#[cfg(not(target_os = "linux"))]
fn pin_thread(_handle: &JoinHandle<()>, core: usize) {
    warn!("CPU pinning is Linux only; not pinning to CPU {core}");
}

#[cfg(not(target_os = "linux"))]
fn set_busy_poll(_socket: &UdpSocket, usecs: u32) {
    warn!("SO_BUSY_POLL is Linux only; not setting {usecs}");
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
    dest_senders: &ArcSwap<DestSenderMap>,
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
    let senders_snapshot = dest_senders.load();
    let num_dest = senders_snapshot.len() as u64;
    let mut dropped: u64 = 0;
    // Construct the per-batch e2e trace in trace mode. `workers_remaining`
    // is initialized to N up-front (so any worker that picks the batch up
    // before we finish the try_send loop already sees a sane counter). On
    // try_send failures the coordinator compensates by decrementing here —
    // preserving the invariant that exactly N decrements happen per trace.
    //
    // SAFETY of `t_batch_start.unwrap()`: gated on `trace_on`, which is the
    // same flag that made `mark()` return `Some` at the top of this fn.
    let trace: Option<Arc<BatchTrace>> = trace_on.then(|| {
        Arc::new(BatchTrace::new(
            t_batch_start.unwrap(),
            num_dest as u32,
        ))
    });

    for sender in senders_snapshot.values() {
        match sender.try_send((arc_batch.clone(), trace.clone())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                dropped += 1;
                // Compensate for the missing worker decrement. If this brings
                // the counter to 0 we ARE the last "writer" for this batch
                // and record the e2e elapsed ourselves.
                if let Some(t) = &trace {
                    let prev = t.workers_remaining.fetch_sub(1, Ordering::AcqRel);
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
    // Edge case: N == 0 (no workers published yet). No worker will decrement;
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
    // These are the canonical "recv → last worker's sendmmsg returned"
    // numbers. Older `forward_total_us_*` / `worker_send_us_*` are kept
    // for diagnostics but only measure pieces of the pipeline.
    /// Number of batches for which the e2e barrier completed (every worker
    /// that received the batch decremented the per-batch counter to zero).
    /// In steady state this equals `forward_batches`; if a coordinator
    /// dropped to ALL workers (rare), the trace expires without recording.
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
        str::FromStr,
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
        recv_from_channel_and_send_multiple_dest, spawn_dest_worker, DestSenderMap, ShredMetrics,
    };

    /// Permissive logger so `log_enabled!(Level::Trace)` returns true in the
    /// trace-gated metric paths. Without an installed logger the default
    /// NoopLogger reports `enabled() == false`, so the e2e barrier would
    /// never run and the metric assertions below would be vacuous.
    struct AlwaysEnabledLogger;
    impl log::Log for AlwaysEnabledLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, _: &log::Record) {}
        fn flush(&self) {}
    }
    static ALWAYS_ENABLED_LOGGER: AlwaysEnabledLogger = AlwaysEnabledLogger;

    /// Install the permissive logger once and raise the level to Trace so the
    /// e2e barrier path is exercised. `set_logger` may only succeed once per
    /// process; the error on subsequent calls is swallowed.
    fn enable_trace_metrics() {
        let _ = log::set_logger(&ALWAYS_ENABLED_LOGGER);
        log::set_max_level(LevelFilter::Trace);
    }

    fn listen_and_collect(listen_socket: UdpSocket, received_packets: Arc<Mutex<Vec<Vec<u8>>>>) {
        let mut buf = [0u8; PACKET_DATA_SIZE];
        loop {
            listen_socket.recv(&mut buf).unwrap();
            received_packets.lock().unwrap().push(Vec::from(buf));
        }
    }

    #[test]
    fn test_2shreds_3destinations() {
        // Engage trace mode so the coordinator builds a BatchTrace and the
        // workers run the e2e barrier block. Lets the assertions at the end
        // verify the e2e metric actually records.
        enable_trace_metrics();

        let packet_batch = PacketBatch::new(vec![
            Packet::new(
                [1; PACKET_DATA_SIZE],
                Meta {
                    size: PACKET_DATA_SIZE,
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    port: 48289, // received on random port
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

        let dest_socketaddrs = vec![
            SocketAddr::from_str("0.0.0.0:32881").unwrap(),
            SocketAddr::from_str("0.0.0.0:33881").unwrap(),
            SocketAddr::from_str("0.0.0.0:34881").unwrap(),
        ];

        let test_listeners = dest_socketaddrs
            .iter()
            .map(|socketaddr| {
                (
                    UdpSocket::bind(socketaddr).unwrap(),
                    *socketaddr,
                    // store results in vec of packet, where packet is Vec<u8>
                    Arc::new(Mutex::new(vec![])),
                )
            })
            .collect::<Vec<_>>();

        // spawn listeners
        test_listeners
            .iter()
            .for_each(|(listen_socket, _socketaddr, to_receive)| {
                let socket = listen_socket.try_clone().unwrap();
                let to_receive = to_receive.to_owned();
                thread::spawn(move || listen_and_collect(socket, to_receive));
            });

        // Spawn one worker per destination and build the dest_senders snapshot
        // the same way the dest manager would in production.
        let metrics = Arc::new(ShredMetrics::default());
        let exit = Arc::new(AtomicBool::new(false));
        let mut map = DestSenderMap::default();
        let mut worker_handles = Vec::new();
        for dest in &dest_socketaddrs {
            let (tx, hdl) = spawn_dest_worker(*dest, metrics.clone(), exit.clone());
            map.insert(*dest, tx);
            worker_handles.push(hdl);
        }
        let dest_senders = ArcSwap::from_pointee(map);

        let (reconstruct_tx, _reconstruct_rx) = crossbeam_channel::bounded(10_240);
        recv_from_channel_and_send_multiple_dest(
            packet_receiver.recv(),
            &Arc::new(RwLock::new(Deduper::<2, [u8]>::new(
                &mut rand::thread_rng(),
                crate::forwarder::DEDUPER_NUM_BITS,
            ))),
            &dest_senders,
            true,
            &reconstruct_tx,
            false,
            &metrics,
        )
        .unwrap();

        // allow packets to be received
        sleep(Duration::from_millis(500));

        let received = test_listeners
            .iter()
            .map(|(_, _, results)| results.clone())
            .collect::<Vec<_>>();

        // check results
        for received in received.iter() {
            let received = received.lock().unwrap();
            assert_eq!(received.len(), 2);
            assert!(received
                .iter()
                .all(|packet| packet.len() == PACKET_DATA_SIZE));
            assert_eq!(received[0], [1; PACKET_DATA_SIZE]);
            assert_eq!(received[1], [2; PACKET_DATA_SIZE]);
        }

        assert_eq!(
            received
                .iter()
                .fold(0, |acc, elem| elem.lock().unwrap().len() + acc),
            6
        );

        // E2E barrier metric: exactly one batch traversed the pipeline, so
        // the barrier must have fired exactly once (the last of the 3 workers
        // to finish recorded it), with a non-zero elapsed time.
        assert_eq!(
            metrics.e2e_batches.load(Ordering::Relaxed),
            1,
            "e2e barrier should fire exactly once per batch under trace"
        );
        assert!(
            metrics.e2e_us_sum.load(Ordering::Relaxed) > 0,
            "e2e_us_sum should be > 0"
        );
        assert!(
            metrics.e2e_us_max.load(Ordering::Relaxed) > 0,
            "e2e_us_max should be > 0"
        );

        // Signal workers to exit and join.
        exit.store(true, Ordering::Relaxed);
        // Drop senders so workers see Disconnected if they're between recv timeouts.
        drop(dest_senders);
        for h in worker_handles {
            h.join().unwrap();
        }
    }
}
