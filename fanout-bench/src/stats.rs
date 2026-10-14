//! Latency distribution summaries (nearest-rank percentiles).

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
pub struct Summary {
    pub count: usize,
    pub mean_us: f64,
    pub p50_us: f64,
    pub p90_us: f64,
    pub p99_us: f64,
    pub p999_us: f64,
    pub max_us: f64,
}

/// Summarizes nanosecond samples into microsecond percentiles. Sorts `ns`.
pub fn summarize(ns: &mut [u64]) -> Summary {
    if ns.is_empty() {
        return Summary::default();
    }
    ns.sort_unstable();
    let n = ns.len();
    let q = |p: f64| {
        let rank = ((p * n as f64).ceil() as usize).clamp(1, n);
        ns[rank - 1] as f64 / 1_000.0
    };
    let sum: u128 = ns.iter().map(|&v| v as u128).sum();
    Summary {
        count: n,
        mean_us: sum as f64 / n as f64 / 1_000.0,
        p50_us: q(0.50),
        p90_us: q(0.90),
        p99_us: q(0.99),
        p999_us: q(0.999),
        max_us: ns[n - 1] as f64 / 1_000.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_percentiles() {
        let mut v: Vec<u64> = (1..=1000).map(|i| i * 1_000).collect();
        let s = summarize(&mut v);
        assert_eq!(s.count, 1000);
        assert_eq!(s.p50_us, 500.0);
        assert_eq!(s.p99_us, 990.0);
        assert_eq!(s.p999_us, 999.0);
        assert_eq!(s.max_us, 1000.0);
    }

    #[test]
    fn empty_is_default() {
        assert_eq!(summarize(&mut []).count, 0);
    }
}
