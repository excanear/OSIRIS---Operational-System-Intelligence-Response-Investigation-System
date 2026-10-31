//! OS-neutral table of kernel UDP sends to port 53, joined with captured
//! query packets so each packet is attributed to the process that sent it.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use crate::tracker::Attribution;

const LOOKBACK_NS: u64 = 2_000_000_000;
const SLACK_NS: u64 = 5_000_000;
const TTL_NS: u64 = 10_000_000_000;
const QUEUE_MAX: usize = 8;
const CAPACITY: usize = 16_384;

/// Join key: local port plus the canonical remote endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SendKey {
    pub lport: u16,
    pub raddr: IpAddr,
    pub rport: u16,
}

impl SendKey {
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            lport: local.port(),
            raddr: remote.ip().to_canonical(),
            rport: remote.port(),
        }
    }
}

/// One kernel-reported send.
#[derive(Debug, Clone)]
pub struct KernelSend {
    pub key: SendKey,
    pub laddr: IpAddr,
    pub sent_wall_ns: u64,
    pub owner: Attribution,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SendTableCounters {
    pub inserted: u64,
    pub consumed: u64,
    pub evicted: u64,
    pub expired: u64,
}

#[derive(Debug)]
struct Entry {
    seq: u64,
    laddr: IpAddr,
    sent_wall_ns: u64,
    owner: Attribution,
}

#[derive(Debug, Default)]
pub struct SendTable {
    map: HashMap<SendKey, VecDeque<Entry>>,
    order: VecDeque<(u64, SendKey)>,
    next_seq: u64,
    len: usize,
    counters: SendTableCounters,
}

fn locals_compatible(entry: IpAddr, packet: IpAddr) -> bool {
    let (e, p) = (entry.to_canonical(), packet.to_canonical());
    e.is_unspecified() || p.is_unspecified() || e == p
}

impl SendTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, send: KernelSend) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let queue = self.map.entry(send.key).or_default();
        if queue.len() >= QUEUE_MAX && queue.pop_front().is_some() {
            self.len = self.len.saturating_sub(1);
            self.counters.evicted += 1;
        }
        queue.push_back(Entry {
            seq,
            laddr: send.laddr,
            sent_wall_ns: send.sent_wall_ns,
            owner: send.owner,
        });
        self.order.push_back((seq, send.key));
        self.len += 1;
        self.counters.inserted += 1;
        while self.len > CAPACITY {
            if !self.evict_oldest() {
                break;
            }
        }
        self.compact_order();
    }

    /// Drops the globally oldest live entry; false when none is found.
    fn evict_oldest(&mut self) -> bool {
        while let Some((seq, key)) = self.order.pop_front() {
            let Some(queue) = self.map.get_mut(&key) else {
                continue;
            };
            let Some(pos) = queue.iter().position(|e| e.seq == seq) else {
                continue;
            };
            queue.remove(pos);
            if queue.is_empty() {
                self.map.remove(&key);
            }
            self.len = self.len.saturating_sub(1);
            self.counters.evicted += 1;
            return true;
        }
        false
    }

    /// Bounds the order list when stale slots (consumed or expired entries)
    /// accumulate faster than eviction pops them.
    fn compact_order(&mut self) {
        if self.order.len() <= CAPACITY * 2 {
            return;
        }
        let map = &self.map;
        self.order.retain(|(seq, key)| {
            map.get(key)
                .is_some_and(|q| q.iter().any(|e| e.seq == *seq))
        });
    }

    pub fn take(
        &mut self,
        key: &SendKey,
        laddr: IpAddr,
        packet_wall_ns: u64,
    ) -> Option<Attribution> {
        let lo = packet_wall_ns.saturating_sub(LOOKBACK_NS);
        let hi = packet_wall_ns.saturating_add(SLACK_NS);
        let queue = self.map.get_mut(key)?;
        let before = queue.len();
        queue.retain(|e| e.sent_wall_ns >= lo);
        let dropped = before - queue.len();
        self.len = self.len.saturating_sub(dropped);
        self.counters.expired += dropped as u64;
        let pos = queue
            .iter()
            .position(|e| e.sent_wall_ns <= hi && locals_compatible(e.laddr, laddr));
        let taken = pos.and_then(|p| queue.remove(p));
        if queue.is_empty() {
            self.map.remove(key);
        }
        let entry = taken?;
        self.len = self.len.saturating_sub(1);
        self.counters.consumed += 1;
        Some(entry.owner)
    }

    pub fn expire(&mut self, now_wall_ns: u64) {
        let cutoff = now_wall_ns.saturating_sub(TTL_NS);
        let mut removed = 0usize;
        self.map.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|e| e.sent_wall_ns >= cutoff);
            removed += before - queue.len();
            !queue.is_empty()
        });
        self.len = self.len.saturating_sub(removed);
        self.counters.expired += removed as u64;
        self.compact_order();
    }

    pub fn counters(&self) -> SendTableCounters {
        self.counters
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Locks the shared table, recovering from a poisoned lock.
pub fn lock_table(table: &SharedSendTable) -> std::sync::MutexGuard<'_, SendTable> {
    table.lock().unwrap_or_else(|e| e.into_inner())
}

pub type SharedSendTable = Arc<Mutex<SendTable>>;

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;
    const MS: u64 = 1_000_000;
    const T: u64 = 100 * S;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn owner(pid: u32) -> Attribution {
        Attribution {
            pid: Some(pid),
            uid: 1000,
            exe_path: format!("/bin/p{pid}"),
            comm: format!("p{pid}"),
        }
    }
    fn key() -> SendKey {
        SendKey::new(sa("10.0.0.5:40000"), sa("10.0.0.1:53"))
    }
    fn send(k: SendKey, laddr: &str, t: u64, pid: u32) -> KernelSend {
        KernelSend {
            key: k,
            laddr: ip(laddr),
            sent_wall_ns: t,
            owner: owner(pid),
        }
    }
    fn pid_of(a: Option<Attribution>) -> Option<u32> {
        a.and_then(|a| a.pid)
    }

    #[test]
    fn exact_match_consumes_once() {
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.5", T, 1));
        assert_eq!(pid_of(t.take(&key(), ip("10.0.0.5"), T + MS)), Some(1));
        assert!(t.take(&key(), ip("10.0.0.5"), T + MS).is_none());
        assert_eq!(t.counters().consumed, 1);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn window_bounds() {
        let l = ip("10.0.0.5");
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.5", T, 1));
        assert!(t.take(&key(), l, T + 2 * S + 1).is_none());
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.5", T, 1));
        assert!(t.take(&key(), l, T + 2 * S).is_some());
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.5", T + 6 * MS, 1));
        assert!(t.take(&key(), l, T).is_none());
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.5", T + 5 * MS, 1));
        assert!(t.take(&key(), l, T).is_some());
    }

    #[test]
    fn port_reuse_never_misattributes() {
        let ta = T;
        let tb = T + 100 * MS;
        let l = ip("10.0.0.5");
        // A then B inserted; A's packet is looked up first.
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.5", ta, 1));
        t.insert(send(key(), "10.0.0.5", tb, 2));
        assert_eq!(pid_of(t.take(&key(), l, ta + MS)), Some(1));
        assert_eq!(pid_of(t.take(&key(), l, tb + MS)), Some(2));
        // B's packet is looked up first: the oldest match in window is A.
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.5", ta, 1));
        t.insert(send(key(), "10.0.0.5", tb, 2));
        assert_eq!(pid_of(t.take(&key(), l, tb + MS)), Some(1));
        assert_eq!(pid_of(t.take(&key(), l, tb + MS)), Some(2));
        // A's record is missing: A's packet gets nothing, never B.
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.5", tb, 2));
        assert!(t.take(&key(), l, ta + MS).is_none());
        assert_eq!(pid_of(t.take(&key(), l, tb + MS)), Some(2));
    }

    #[test]
    fn retransmission_consumes_one_entry_each() {
        let l = ip("10.0.0.5");
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.5", T, 7));
        t.insert(send(key(), "10.0.0.5", T + S, 7));
        assert_eq!(pid_of(t.take(&key(), l, T + MS)), Some(7));
        assert_eq!(pid_of(t.take(&key(), l, T + S + MS)), Some(7));
        assert!(t.take(&key(), l, T + S + 2 * MS).is_none());
    }

    #[test]
    fn wildcard_local_matches_any() {
        let mut t = SendTable::new();
        t.insert(send(key(), "0.0.0.0", T, 1));
        assert!(t.take(&key(), ip("10.0.0.5"), T + MS).is_some());
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.6", T, 1));
        assert!(t.take(&key(), ip("10.0.0.5"), T + MS).is_none());
        // A wildcard on the packet side also matches.
        assert!(t.take(&key(), ip("0.0.0.0"), T + MS).is_some());
    }

    #[test]
    fn ipv4_mapped_normalised() {
        let mut t = SendTable::new();
        let k = SendKey::new(sa("[::ffff:10.0.0.5]:40000"), sa("[::ffff:127.0.0.53]:53"));
        t.insert(send(k, "::ffff:10.0.0.5", T, 1));
        let k2 = SendKey::new(sa("10.0.0.5:40000"), sa("127.0.0.53:53"));
        assert!(t.take(&k2, ip("10.0.0.5"), T + MS).is_some());
    }

    #[test]
    fn queue_and_capacity_limits() {
        let l = ip("10.0.0.5");
        let mut t = SendTable::new();
        for i in 0..9u64 {
            t.insert(send(key(), "10.0.0.5", T + i * MS, i as u32));
        }
        assert_eq!(t.len(), 8);
        assert_eq!(t.counters().evicted, 1);
        assert_eq!(pid_of(t.take(&key(), l, T + 10 * MS)), Some(1));

        let mut t = SendTable::new();
        for i in 0..16_385u64 {
            let remote = SocketAddr::new(IpAddr::from([10, 1, (i >> 8) as u8, i as u8]), 53);
            let k = SendKey::new(sa("10.0.0.5:40000"), remote);
            t.insert(send(k, "10.0.0.5", T + i, i as u32));
        }
        assert_eq!(t.len(), 16_384);
        assert_eq!(t.counters().evicted, 1);
        let k0 = SendKey::new(sa("10.0.0.5:40000"), sa("10.1.0.0:53"));
        assert!(t.take(&k0, l, T + MS).is_none());
        let k1 = SendKey::new(sa("10.0.0.5:40000"), sa("10.1.0.1:53"));
        assert!(t.take(&k1, l, T + MS).is_some());
    }

    #[test]
    fn expire_drops_old() {
        let mut t = SendTable::new();
        t.insert(send(key(), "10.0.0.5", T, 1));
        t.expire(T + 10 * S);
        assert_eq!(t.len(), 1);
        t.expire(T + 10 * S + 1);
        assert_eq!(t.len(), 0);
        assert_eq!(t.counters().expired, 1);
    }
}
