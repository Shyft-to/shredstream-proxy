//! Single-producer, multi-consumer broadcast ring.
//!
//! The receive thread publishes each unique packet once; every sender thread
//! reads every packet through its own cursor. Nothing blocks or sleeps: if the
//! slowest sender is a whole ring behind, the producer drops the packet and
//! reports it, rather than stalling the receive path.

use std::{
    cell::UnsafeCell,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// Largest packet the ring stores. Shreds are at most 1232 bytes.
pub const MAX_PACKET: usize = 1536;

/// Keeps hot atomics on their own cache lines so the producer and each
/// consumer do not invalidate each other's lines on every update.
#[repr(align(128))]
struct Padded<T>(T);

struct Slot {
    len: UnsafeCell<u16>,
    data: UnsafeCell<[u8; MAX_PACKET]>,
}

pub struct Ring {
    slots: Box<[Slot]>,
    mask: u64,
    /// Sequence number of the next packet to be published.
    head: Padded<AtomicU64>,
    /// Per consumer: sequence number of the next packet it will read.
    tails: Box<[Padded<AtomicU64>]>,
}

// SAFETY: a slot is written only by the single producer, and only once every
// consumer has moved past it (checked against `tails`). Consumers read a slot
// only after the producer's Release store of `head` covering it.
unsafe impl Sync for Ring {}
unsafe impl Send for Ring {}

/// Creates a ring with `slots` entries (rounded up to a power of two) and
/// returns its producer and `consumers` consumers.
pub fn broadcast(slots: usize, consumers: usize) -> (Producer, Vec<Consumer>) {
    let slots = slots.max(2).next_power_of_two();
    let ring = Arc::new(Ring {
        slots: (0..slots)
            .map(|_| Slot {
                len: UnsafeCell::new(0),
                data: UnsafeCell::new([0; MAX_PACKET]),
            })
            .collect(),
        mask: slots as u64 - 1,
        head: Padded(AtomicU64::new(0)),
        tails: (0..consumers).map(|_| Padded(AtomicU64::new(0))).collect(),
    });
    let consumers = (0..consumers)
        .map(|id| Consumer {
            ring: ring.clone(),
            id,
            next: 0,
        })
        .collect();
    let producer = Producer {
        ring,
        next: 0,
        min_tail: 0,
    };
    (producer, consumers)
}

impl Ring {
    fn capacity(&self) -> u64 {
        self.mask + 1
    }

    fn min_tail(&self) -> u64 {
        self.tails
            .iter()
            .map(|t| t.0.load(Ordering::Acquire))
            .min()
            .unwrap_or(u64::MAX)
    }
}

pub struct Producer {
    ring: Arc<Ring>,
    next: u64,
    /// Cached slowest consumer position, refreshed only when the ring looks full.
    min_tail: u64,
}

impl Producer {
    /// Copies `data` into the next slot. Not visible to consumers until
    /// [`flush`](Self::flush). Returns false (packet dropped) if the slowest
    /// consumer is a full ring behind, or the packet is too large.
    pub fn publish(&mut self, data: &[u8]) -> bool {
        if data.len() > MAX_PACKET {
            return false;
        }
        let seq = self.next;
        if seq - self.min_tail >= self.ring.capacity() {
            self.min_tail = self.ring.min_tail();
            if seq - self.min_tail >= self.ring.capacity() {
                return false;
            }
        }
        let slot = &self.ring.slots[(seq & self.ring.mask) as usize];
        // SAFETY: every consumer is past `seq - capacity`, so none reads this slot.
        unsafe {
            (*slot.data.get())[..data.len()].copy_from_slice(data);
            *slot.len.get() = data.len() as u16;
        }
        self.next = seq + 1;
        true
    }

    /// Makes every published packet visible to the consumers.
    pub fn flush(&self) {
        self.ring.head.0.store(self.next, Ordering::Release);
    }
}

pub struct Consumer {
    ring: Arc<Ring>,
    id: usize,
    next: u64,
}

impl Consumer {
    /// Number of packets published but not yet consumed by this consumer.
    pub fn available(&self) -> u64 {
        self.ring.head.0.load(Ordering::Acquire) - self.next
    }

    /// The `i`-th unconsumed packet (`i < available()`). Valid until
    /// [`advance`](Self::advance).
    pub fn packet(&self, i: u64) -> &[u8] {
        let slot = &self.ring.slots[((self.next + i) & self.ring.mask) as usize];
        // SAFETY: published (covered by the Acquire load of `head` in
        // `available`) and not reusable until this consumer advances past it.
        unsafe { &(*slot.data.get())[..*slot.len.get() as usize] }
    }

    /// Marks `n` packets as consumed, releasing their slots to the producer.
    pub fn advance(&mut self, n: u64) {
        self.next += n;
        self.ring.tails[self.id]
            .0
            .store(self.next, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_consumer_sees_every_packet_in_order() {
        const N: u64 = 200_000;
        let (mut producer, consumers) = broadcast(64, 3);
        let readers: Vec<_> = consumers
            .into_iter()
            .map(|mut c| {
                std::thread::spawn(move || {
                    let mut expected = 0u64;
                    while expected < N {
                        let n = c.available();
                        for i in 0..n {
                            let p = c.packet(i);
                            assert_eq!(u64::from_le_bytes(p[..8].try_into().unwrap()), expected);
                            assert_eq!(p.len(), 8 + (expected % 100) as usize);
                            expected += 1;
                        }
                        c.advance(n);
                    }
                })
            })
            .collect();

        let mut seq = 0u64;
        let mut buf = vec![0u8; 108];
        while seq < N {
            let len = 8 + (seq % 100) as usize;
            buf[..8].copy_from_slice(&seq.to_le_bytes());
            if producer.publish(&buf[..len]) {
                seq += 1;
            }
            producer.flush();
        }
        for r in readers {
            r.join().unwrap();
        }
    }

    #[test]
    fn full_ring_drops_instead_of_overwriting() {
        let (mut producer, mut consumers) = broadcast(4, 1);
        for i in 0..4u8 {
            assert!(producer.publish(&[i]));
        }
        assert!(
            !producer.publish(&[9]),
            "ring is full; slowest consumer has read nothing"
        );
        producer.flush();
        let c = &mut consumers[0];
        assert_eq!(c.packet(0), &[0]);
        c.advance(1);
        assert!(producer.publish(&[4]));
        producer.flush();
        assert_eq!(c.available(), 4);
        assert_eq!(c.packet(3), &[4]);
    }

    #[test]
    fn oversized_packet_is_rejected() {
        let (mut producer, _consumers) = broadcast(4, 1);
        assert!(!producer.publish(&[0u8; MAX_PACKET + 1]));
    }
}
