//! Exact duplicate filter over a sliding window of recent packets.
//!
//! Keeps 64-bit hashes of the full packet in two generations. When the
//! current generation is full, it becomes the previous one and the old
//! previous one is cleared and reused, so steady state never allocates.
//! Unlike a Bloom filter, it never drops a new packet as a false duplicate
//! (barring a 64-bit hash collision).

use std::{
    collections::HashSet,
    hash::{BuildHasherDefault, Hasher},
};

/// The keys are already hashes; hashing them again would be wasted work.
#[derive(Default)]
struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {
        unreachable!("only u64 keys are hashed");
    }
    fn write_u64(&mut self, v: u64) {
        self.0 = v;
    }
}

type HashSet64 = HashSet<u64, BuildHasherDefault<IdentityHasher>>;

pub struct Deduper {
    current: HashSet64,
    previous: HashSet64,
    generation_size: usize,
    hasher: ahash::RandomState,
}

impl Deduper {
    /// Remembers between `generation_size` and `2 * generation_size` of the
    /// most recent unique packets.
    pub fn new(generation_size: usize) -> Self {
        let generation_size = generation_size.max(1);
        Self {
            current: HashSet64::with_capacity_and_hasher(generation_size, Default::default()),
            previous: HashSet64::with_capacity_and_hasher(generation_size, Default::default()),
            generation_size,
            hasher: ahash::RandomState::new(),
        }
    }

    /// True the first time a packet is seen within the window.
    pub fn is_new(&mut self, packet: &[u8]) -> bool {
        let h = self.hasher.hash_one(packet);
        if self.previous.contains(&h) || !self.current.insert(h) {
            return false;
        }
        if self.current.len() >= self.generation_size {
            std::mem::swap(&mut self.current, &mut self.previous);
            self.current.clear();
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_duplicates() {
        let mut d = Deduper::new(100);
        assert!(d.is_new(b"shred-1"));
        assert!(d.is_new(b"shred-2"));
        assert!(!d.is_new(b"shred-1"));
        assert!(!d.is_new(b"shred-2"));
    }

    #[test]
    fn remembers_at_least_one_generation() {
        let mut d = Deduper::new(10);
        for i in 0..25u32 {
            assert!(d.is_new(&i.to_le_bytes()));
        }
        // The last 10 are always remembered, whatever the rotation phase.
        for i in 15..25u32 {
            assert!(
                !d.is_new(&i.to_le_bytes()),
                "{i} should still be a duplicate"
            );
        }
        // Old ones age out.
        assert!(d.is_new(&0u32.to_le_bytes()));
    }
}
