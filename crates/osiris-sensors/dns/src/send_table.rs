//! OS-neutral table of kernel UDP sends to port 53, joined with captured
//! query packets so each packet is attributed to the process that sent it.

use std::collections::{BTreeMap, HashMap, VecDeque};
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
    /// Claims dropped because the claim table was full.
    pub claims_dropped: u64,
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
    /// Packets that missed and still wait for their entry, per key.
    claims: HashMap<SendKey, Vec<Claim>>,
    /// Live claims in creation order: id -> key.
    claim_keys: BTreeMap<u64, SendKey>,
    next_claim: u64,
}

/// Opaque handle for a packet that missed its kernel send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClaimId(u64);

#[derive(Debug, Clone, Copy)]
struct Claim {
    id: u64,
    laddr: IpAddr,
    packet_wall_ns: u64,
}

fn locals_compatible(entry: IpAddr, packet: IpAddr) -> bool {
    let (e, p) = (entry.to_canonical(), packet.to_canonical());
    e.is_unspecified() || p.is_unspecified() || e == p
}

/// True when `entry` is inside the window of a packet at `packet_wall_ns`
/// and the local addresses agree.
fn eligible(entry: &Entry, laddr: IpAddr, packet_wall_ns: u64) -> bool {
    entry.sent_wall_ns >= packet_wall_ns.saturating_sub(LOOKBACK_NS)
        && entry.sent_wall_ns <= packet_wall_ns.saturating_add(SLACK_NS)
        && locals_compatible(entry.laddr, laddr)
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

    /// Joins a new packet with the oldest eligible entry that no older live
    /// claim on the key could take.
    pub fn take(
        &mut self,
        key: &SendKey,
        laddr: IpAddr,
        packet_wall_ns: u64,
    ) -> Option<Attribution> {
        // A new packet ranks after every claim with the same timestamp.
        self.take_ranked(key, laddr, packet_wall_ns, (packet_wall_ns, u64::MAX))
    }

    /// Takes for a packet of rank `(ts, claim id)`: claims ranked before it
    /// first reserve, in rank order, the oldest entries they could take.
    fn take_ranked(
        &mut self,
        key: &SendKey,
        laddr: IpAddr,
        packet_wall_ns: u64,
        rank: (u64, u64),
    ) -> Option<Attribution> {
        let claims: &[Claim] = self.claims.get(key).map_or(&[], Vec::as_slice);
        // Keep what any live claim on the key could still take.
        let cutoff = claims
            .iter()
            .map(|c| c.packet_wall_ns.saturating_sub(LOOKBACK_NS))
            .fold(packet_wall_ns.saturating_sub(LOOKBACK_NS), u64::min);
        let queue = self.map.get_mut(key)?;
        let before = queue.len();
        queue.retain(|e| e.sent_wall_ns >= cutoff);
        let dropped = before - queue.len();
        self.len = self.len.saturating_sub(dropped);
        self.counters.expired += dropped as u64;
        let mut older: Vec<&Claim> = claims
            .iter()
            .filter(|c| (c.packet_wall_ns, c.id) < rank)
            .collect();
        older.sort_by_key(|c| (c.packet_wall_ns, c.id));
        let mut reserved = vec![false; queue.len()];
        for c in older {
            let slot = (0..queue.len())
                .find(|&i| !reserved[i] && eligible(&queue[i], c.laddr, c.packet_wall_ns));
            if let Some(i) = slot {
                reserved[i] = true;
            }
        }
        let pos =
            (0..queue.len()).find(|&i| !reserved[i] && eligible(&queue[i], laddr, packet_wall_ns));
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
        self.claims.retain(|_, list| {
            list.retain(|c| c.packet_wall_ns >= cutoff);
            !list.is_empty()
        });
        let claims = &self.claims;
        self.claim_keys.retain(|id, key| {
            claims
                .get(key)
                .is_some_and(|list| list.iter().any(|c| c.id == *id))
        });
    }

    /// Registers a packet that found no entry, so newer packets on the same
    /// key cannot take the entry it is still waiting for.
    pub fn claim(&mut self, key: SendKey, laddr: IpAddr, packet_wall_ns: u64) -> ClaimId {
        let id = self.next_claim;
        self.next_claim += 1;
        self.claims.entry(key).or_default().push(Claim {
            id,
            laddr,
            packet_wall_ns,
        });
        self.claim_keys.insert(id, key);
        while self.claim_keys.len() > CAPACITY {
            let Some((old, k)) = self.claim_keys.pop_first() else {
                break;
            };
            self.detach_claim(old, k);
            self.counters.claims_dropped += 1;
        }
        ClaimId(id)
    }

    /// Retries the join for a claimed packet. Only claims older than this
    /// one have priority over it; on a hit the claim is removed.
    pub fn take_claimed(
        &mut self,
        claim: ClaimId,
        key: &SendKey,
        laddr: IpAddr,
        packet_wall_ns: u64,
    ) -> Option<Attribution> {
        let hit = self.take_ranked(key, laddr, packet_wall_ns, (packet_wall_ns, claim.0));
        if hit.is_some() {
            self.release(claim);
        }
        hit
    }

    /// Drops a claim whose packet will no longer be joined.
    pub fn release(&mut self, claim: ClaimId) {
        if let Some(key) = self.claim_keys.remove(&claim.0) {
            self.detach_claim(claim.0, key);
        }
    }

    fn detach_claim(&mut self, id: u64, key: SendKey) {
        if let Some(list) = self.claims.get_mut(&key) {
            list.retain(|c| c.id != id);
            if list.is_empty() {
                self.claims.remove(&key);
            }
        }
    }

    /// Number of live claims.
    pub fn claims_len(&self) -> usize {
        self.claim_keys.len()
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

    // ---- claims: older unresolved packets keep priority ----

    #[test]
    fn claim_keeps_older_entry_from_newer_packet() {
        // A's packet misses, A's and B's records arrive, then B's packet.
        let l = ip("10.0.0.5");
        let (ta, tb) = (T, T + 100 * MS);
        let mut t = SendTable::new();
        let a = t.claim(key(), l, ta + MS);
        t.insert(send(key(), "10.0.0.5", ta, 1));
        t.insert(send(key(), "10.0.0.5", tb, 2));
        assert_eq!(pid_of(t.take(&key(), l, tb + MS)), Some(2));
        assert_eq!(pid_of(t.take_claimed(a, &key(), l, ta + MS)), Some(1));
        assert_eq!(t.claims_len(), 0);
        assert!(t.is_empty());
    }

    #[test]
    fn newer_packet_before_its_record_misses_then_gets_own() {
        let l = ip("10.0.0.5");
        let (ta, tb) = (T, T + 100 * MS);
        let mut t = SendTable::new();
        let a = t.claim(key(), l, ta + MS);
        t.insert(send(key(), "10.0.0.5", ta, 1));
        // B's packet arrives before B's record: it must not get A's entry.
        assert!(t.take(&key(), l, tb + MS).is_none());
        let b = t.claim(key(), l, tb + MS);
        t.insert(send(key(), "10.0.0.5", tb, 2));
        assert_eq!(pid_of(t.take_claimed(b, &key(), l, tb + MS)), Some(2));
        assert_eq!(pid_of(t.take_claimed(a, &key(), l, ta + MS)), Some(1));
        assert_eq!(t.claims_len(), 0);
    }

    #[test]
    fn lost_record_claim_does_not_block_entry_outside_its_window() {
        let l = ip("10.0.0.5");
        let (ta, tb) = (T, T + 100 * MS);
        let mut t = SendTable::new();
        let a = t.claim(key(), l, ta + MS);
        // A's record is lost; B's send is after A's window.
        t.insert(send(key(), "10.0.0.5", tb, 2));
        assert_eq!(pid_of(t.take(&key(), l, tb + MS)), Some(2));
        assert!(t.take_claimed(a, &key(), l, ta + MS).is_none());
        assert_eq!(t.claims_len(), 1);
    }

    #[test]
    fn releasing_a_claim_unblocks_the_entry() {
        let l = ip("10.0.0.5");
        let mut t = SendTable::new();
        let a = t.claim(key(), l, T + MS);
        t.insert(send(key(), "10.0.0.5", T, 1));
        assert!(t.take(&key(), l, T + 2 * MS).is_none());
        t.release(a);
        assert_eq!(t.claims_len(), 0);
        assert_eq!(pid_of(t.take(&key(), l, T + 2 * MS)), Some(1));
    }

    #[test]
    fn claim_ties_break_by_claim_order() {
        let l = ip("10.0.0.5");
        let mut t = SendTable::new();
        let a = t.claim(key(), l, T + MS);
        let b = t.claim(key(), l, T + MS);
        t.insert(send(key(), "10.0.0.5", T, 1));
        t.insert(send(key(), "10.0.0.5", T + MS / 2, 2));
        // B resolves first but A, the older claim, owns the oldest entry.
        assert_eq!(pid_of(t.take_claimed(b, &key(), l, T + MS)), Some(2));
        assert_eq!(pid_of(t.take_claimed(a, &key(), l, T + MS)), Some(1));
    }

    #[test]
    fn claims_on_other_keys_or_locals_do_not_block() {
        let l = ip("10.0.0.5");
        let other = SendKey::new(sa("10.0.0.5:40001"), sa("10.0.0.1:53"));
        let mut t = SendTable::new();
        t.claim(other, l, T + MS);
        t.claim(key(), ip("10.0.0.6"), T + MS);
        t.insert(send(key(), "10.0.0.5", T, 1));
        assert_eq!(pid_of(t.take(&key(), l, T + 2 * MS)), Some(1));
    }

    #[test]
    fn claim_keeps_entries_below_newer_lookback() {
        // B's lookup 2 s after A's send must not discard what A's claim can take.
        let l = ip("10.0.0.5");
        let mut t = SendTable::new();
        let a = t.claim(key(), l, T + MS);
        t.insert(send(key(), "10.0.0.5", T, 1));
        assert!(t.take(&key(), l, T + 3 * S).is_none());
        assert_eq!(pid_of(t.take_claimed(a, &key(), l, T + MS)), Some(1));
    }

    #[test]
    fn claims_expire_with_ttl_and_are_capped() {
        let l = ip("10.0.0.5");
        let mut t = SendTable::new();
        t.claim(key(), l, T + MS);
        assert_eq!(t.claims_len(), 1);
        t.expire(T + MS + 10 * S);
        assert_eq!(t.claims_len(), 1);
        t.expire(T + MS + 10 * S + 1);
        assert_eq!(t.claims_len(), 0);

        // Cap: the oldest claim is dropped first.
        let mut t = SendTable::new();
        let first = t.claim(key(), l, T + MS);
        for i in 0..CAPACITY as u64 {
            let remote = SocketAddr::new(IpAddr::from([10, 2, (i >> 8) as u8, i as u8]), 53);
            t.claim(SendKey::new(sa("10.0.0.5:40000"), remote), l, T + MS);
        }
        assert_eq!(t.claims_len(), CAPACITY);
        assert_eq!(t.counters().claims_dropped, 1);
        t.insert(send(key(), "10.0.0.5", T, 1));
        // A dropped claim's own retry still joins; nothing older blocks it.
        assert_eq!(pid_of(t.take_claimed(first, &key(), l, T + MS)), Some(1));
        assert_eq!(t.claims_len(), CAPACITY);
    }
}
