use std::time::Duration;

use serde::Serialize;

/// Nearest-rank percentile over an ascending slice; None when empty.
pub fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    Some(sorted[rank.min(sorted.len()) - 1])
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Summary {
    pub n: usize,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub p99: Option<f64>,
    pub max: Option<f64>,
}

pub fn summarize(samples: &mut [f64]) -> Summary {
    samples.sort_by(|a, b| a.total_cmp(b));
    Summary {
        n: samples.len(),
        p50: percentile(samples, 50.0),
        p95: percentile(samples, 95.0),
        p99: percentile(samples, 99.0),
        max: samples.last().copied(),
    }
}

/// Emits `rate * elapsed` events in total, however irregularly it is polled.
pub struct Pacer {
    rate: u64,
    emitted: u64,
}

impl Pacer {
    pub fn new(rate_per_sec: u64) -> Self {
        Self {
            rate: rate_per_sec,
            emitted: 0,
        }
    }

    pub fn due(&mut self, elapsed: Duration) -> u64 {
        let target = (self.rate as u128 * elapsed.as_millis() / 1000) as u64;
        let n = target.saturating_sub(self.emitted);
        self.emitted += n;
        n
    }
}

/// utime + stime (clock ticks) from /proc/<pid>/stat. Parses after the LAST
/// ')' because comm may contain spaces and parentheses.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only the Linux agent bench reads /proc
pub fn parse_proc_stat_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // rest starts at field 3 (state); utime is field 14, stime 15.
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    Some(utime + stime)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only the Linux agent bench reads /proc
pub fn parse_vm_rss_kib(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// One machine-readable result line (printed as JSON).
#[derive(Debug, Serialize)]
pub struct Record {
    pub bench: String,
    pub params: serde_json::Value,
    pub metrics: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn percentile_of_empty_is_none_not_a_panic() {
        assert_eq!(percentile(&[], 50.0), None);
        assert_eq!(summarize(&mut []).p99, None);
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let mut v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let s = summarize(&mut v);
        assert_eq!(s.p50, Some(50.0));
        assert_eq!(s.p95, Some(95.0));
        assert_eq!(s.p99, Some(99.0));
        assert_eq!(s.max, Some(100.0));
    }

    #[test]
    fn pacer_tracks_rate_times_elapsed_without_drift() {
        let mut p = Pacer::new(1000);
        let mut total = 0;
        for ms in 1..=1000 {
            total += p.due(Duration::from_millis(ms));
        }
        assert_eq!(total, 1000);
        assert_eq!(p.due(Duration::from_millis(1000)), 0);
    }

    #[test]
    fn proc_stat_ticks_survive_a_comm_with_spaces_and_parens() {
        // Fields after the last ')': state=3, ... utime=14, stime=15 (1-based in proc(5)).
        let stat =
            "4242 (osiris (a) b) S 1 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 9 0 100 0 0";
        assert_eq!(parse_proc_stat_ticks(stat), Some(300));
    }

    #[test]
    fn vm_rss_is_read_in_kib() {
        let status = "Name:\tosiris-agent\nVmPeak:\t  90000 kB\nVmRSS:\t   12345 kB\n";
        assert_eq!(parse_vm_rss_kib(status), Some(12345));
        assert_eq!(parse_vm_rss_kib("Name:\tx\n"), None);
    }
}
