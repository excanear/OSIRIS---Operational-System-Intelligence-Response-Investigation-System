//! DNS transaction tracker: pairs a query with its response (or a timeout)
//! and yields exactly one closed transaction per query. Time is always
//! passed in so behaviour is deterministic; the pending table is bounded.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use osiris_sensor_api::{DnsEventRaw, RawEventSource};

use crate::send_table::{ClaimId, SendKey};
use crate::wire::{qtype_mnemonic, DnsMessage};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

/// Identity of one transaction: client endpoint, server address, DNS id.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct TxKey {
    pub client: SocketAddr,
    pub server: IpAddr,
    pub id: u16,
}

/// Who asked; `Default` is unattributed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attribution {
    pub pid: Option<u32>,
    pub uid: u32,
    pub exe_path: String,
    pub comm: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrackerCounters {
    pub timeouts: u64,
    pub unmatched_responses: u64,
    pub overflow_evictions: u64,
    pub duplicates: u64,
}

/// Kernel join still owed by a transaction whose query packet found no
/// kernel send (eBPF mode). Re-tried when the transaction closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingAttribution {
    pub key: SendKey,
    pub laddr: IpAddr,
    /// The query packet's wall-clock timestamp: the join's reference time.
    pub packet_ts_ns: u64,
    /// The packet's claim in the send table, released when the join is
    /// given up.
    pub claim: ClaimId,
}

/// Why a transaction closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseKind {
    Response,
    Timeout,
    Evicted,
}

/// A closed transaction: its event plus what the engine needs to finish
/// attributing it.
#[derive(Debug, Clone)]
pub struct Closed {
    pub event: DnsEventRaw,
    pub kind: CloseKind,
    /// The query's client endpoint (the `/proc` lookup key).
    pub client: SocketAddr,
    pub pending: Option<PendingAttribution>,
}

struct Pending {
    seq: u64,
    deadline: Instant,
    client: SocketAddr,
    query: String,
    qtype: String,
    attribution: Attribution,
    pending: Option<PendingAttribution>,
    timestamp_ns: u64,
}

impl Pending {
    fn close(self, kind: CloseKind, response_ips: Vec<String>, ttl: Option<u32>) -> Closed {
        Closed {
            event: DnsEventRaw {
                query: self.query,
                qtype: self.qtype,
                response_ips,
                ttl,
                pid: self.attribution.pid,
                uid: self.attribution.uid,
                exe_path: self.attribution.exe_path,
                comm: self.attribution.comm,
                timestamp_ns: self.timestamp_ns,
                source: RawEventSource::Packet,
            },
            kind,
            client: self.client,
            pending: self.pending,
        }
    }
}

pub struct Tracker {
    timeout: Duration,
    capacity: usize,
    pending: HashMap<TxKey, Pending>,
    /// Insertion order: seq -> key.
    order: BTreeMap<u64, TxKey>,
    next_seq: u64,
    counters: TrackerCounters,
}

impl Tracker {
    pub fn new(timeout: Duration, capacity: usize) -> Self {
        Self {
            timeout,
            capacity: capacity.max(1),
            pending: HashMap::new(),
            order: BTreeMap::new(),
            next_seq: 0,
            counters: TrackerCounters::default(),
        }
    }

    pub fn counters(&self) -> TrackerCounters {
        self.counters
    }

    /// True when a transaction with `key` is already pending (a retransmit).
    pub fn contains(&self, key: &TxKey) -> bool {
        self.pending.contains_key(key)
    }

    /// Gives a transaction still pending attribution its owner and returns
    /// the join it no longer owes. None when the transaction is unknown or
    /// not pending attribution.
    pub fn resolve_pending(
        &mut self,
        key: &TxKey,
        attribution: Attribution,
    ) -> Option<PendingAttribution> {
        let p = self.pending.get_mut(key)?;
        let owed = p.pending.take()?;
        p.attribution = attribution;
        Some(owed)
    }

    /// Register a query. When the table is full the oldest pending
    /// transaction is evicted and returned, to be emitted as a timeout.
    /// `pending` is set when the kernel join must be retried at close.
    pub fn on_query(
        &mut self,
        key: TxKey,
        msg: &DnsMessage,
        attribution: Attribution,
        pending: Option<PendingAttribution>,
        timestamp_ns: u64,
        now: Instant,
    ) -> Option<Closed> {
        let q = msg.question.as_ref()?;
        if self.pending.contains_key(&key) {
            self.counters.duplicates += 1;
            return None;
        }
        let mut evicted = None;
        if self.pending.len() >= self.capacity {
            if let Some((_, oldest)) = self.order.pop_first() {
                if let Some(p) = self.pending.remove(&oldest) {
                    self.counters.overflow_evictions += 1;
                    evicted = Some(p.close(CloseKind::Evicted, Vec::new(), None));
                }
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.order.insert(seq, key);
        self.pending.insert(
            key,
            Pending {
                seq,
                deadline: now + self.timeout,
                client: key.client,
                query: q.name.clone(),
                qtype: qtype_mnemonic(q.qtype),
                attribution,
                pending,
                timestamp_ns,
            },
        );
        evicted
    }

    /// Number of transactions currently pending (always <= capacity).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn on_response(&mut self, key: TxKey, msg: &DnsMessage) -> Option<Closed> {
        let Some(p) = self.pending.remove(&key) else {
            self.counters.unmatched_responses += 1;
            return None;
        };
        self.order.remove(&p.seq);
        let mut ips = Vec::new();
        let mut ttl: Option<u32> = None;
        for a in &msg.answers {
            if a.rtype != TYPE_A && a.rtype != TYPE_AAAA {
                continue;
            }
            if let Some(addr) = a.addr {
                ips.push(addr.to_string());
                ttl = Some(ttl.map_or(a.ttl, |t| t.min(a.ttl)));
            }
        }
        Some(p.close(CloseKind::Response, ips, ttl))
    }

    /// Close every pending transaction now, oldest first, as a timeout
    /// (shutdown). The timeout counter is not bumped: none actually timed out.
    pub fn drain_all(&mut self) -> Vec<Closed> {
        let order = std::mem::take(&mut self.order);
        let mut out: Vec<Closed> = order
            .into_values()
            .filter_map(|key| self.pending.remove(&key))
            .map(|p| p.close(CloseKind::Timeout, Vec::new(), None))
            .collect();
        // `order` and `pending` always agree; this is only defensive.
        out.extend(
            self.pending
                .drain()
                .map(|(_, p)| p.close(CloseKind::Timeout, Vec::new(), None)),
        );
        out
    }

    /// Close every pending transaction whose deadline has passed as a
    /// timeout (empty ips, no ttl). Deadlines are monotonic in insertion
    /// order, so scanning stops at the first entry not yet due.
    pub fn expire(&mut self, now: Instant) -> Vec<Closed> {
        let mut out = Vec::new();
        while let Some(entry) = self.order.first_entry() {
            let key = *entry.get();
            let due = self.pending.get(&key).is_none_or(|p| p.deadline <= now);
            if !due {
                break;
            }
            entry.remove();
            if let Some(p) = self.pending.remove(&key) {
                self.counters.timeouts += 1;
                out.push(p.close(CloseKind::Timeout, Vec::new(), None));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Answer, Question};

    fn key(port: u16, id: u16) -> TxKey {
        TxKey {
            client: format!("10.0.0.2:{port}").parse().unwrap(),
            server: "10.0.0.1".parse().unwrap(),
            id,
        }
    }

    fn query(name: &str) -> DnsMessage {
        DnsMessage {
            id: 1,
            is_response: false,
            rcode: 0,
            question: Some(Question {
                name: name.into(),
                qtype: 1,
            }),
            answers: vec![],
        }
    }

    fn response(rcode: u8, answers: Vec<Answer>) -> DnsMessage {
        DnsMessage {
            id: 1,
            is_response: true,
            rcode,
            question: None,
            answers,
        }
    }

    fn a(ip: &str, ttl: u32) -> Answer {
        Answer {
            rtype: 1,
            ttl,
            addr: Some(ip.parse().unwrap()),
        }
    }

    fn attr() -> Attribution {
        Attribution {
            pid: Some(42),
            uid: 1000,
            exe_path: "/usr/bin/curl".into(),
            comm: "curl".into(),
        }
    }

    #[test]
    fn query_then_response_emits_one_event() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        let now = Instant::now();
        t.on_query(key(1000, 1), &query("example.com"), attr(), None, 77, now);
        let ev = t
            .on_response(
                key(1000, 1),
                &response(0, vec![a("1.2.3.4", 300), a("1.2.3.5", 60)]),
            )
            .unwrap()
            .event;
        assert_eq!(ev.query, "example.com");
        assert_eq!(ev.qtype, "A");
        assert_eq!(ev.response_ips, vec!["1.2.3.4", "1.2.3.5"]);
        assert_eq!(ev.ttl, Some(60));
        assert_eq!(ev.pid, Some(42));
        assert_eq!(ev.timestamp_ns, 77);
        assert!(matches!(ev.source, RawEventSource::Packet));
        assert!(t.expire(now + Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn timeout_after_5s_emits_empty() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        let now = Instant::now();
        t.on_query(key(1000, 1), &query("example.com"), attr(), None, 1, now);
        assert!(t.expire(now + Duration::from_secs(4)).is_empty());
        let evs = t.expire(now + Duration::from_secs(5));
        assert_eq!(evs.len(), 1);
        assert!(evs[0].event.response_ips.is_empty());
        assert_eq!(evs[0].event.ttl, None);
        assert_eq!(t.counters().timeouts, 1);
    }

    #[test]
    fn unmatched_response_counted_and_dropped() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        assert!(t.on_response(key(1, 9), &response(0, vec![])).is_none());
        assert_eq!(t.counters().unmatched_responses, 1);
    }

    #[test]
    fn retransmit_keeps_single_transaction() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        let now = Instant::now();
        t.on_query(key(1000, 1), &query("example.com"), attr(), None, 1, now);
        t.on_query(key(1000, 1), &query("example.com"), attr(), None, 2, now);
        assert_eq!(t.counters().duplicates, 1);
        let ev = t
            .on_response(key(1000, 1), &response(0, vec![a("1.2.3.4", 5)]))
            .unwrap()
            .event;
        assert_eq!(ev.timestamp_ns, 1);
        assert!(t.expire(now + Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn cname_only_response_completes_immediately() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        t.on_query(key(1, 1), &query("x.com"), attr(), None, 1, Instant::now());
        let cname = Answer {
            rtype: 5,
            ttl: 30,
            addr: None,
        };
        let ev = t
            .on_response(key(1, 1), &response(0, vec![cname]))
            .unwrap()
            .event;
        assert!(ev.response_ips.is_empty());
        assert_eq!(ev.ttl, None);
    }

    #[test]
    fn nxdomain_completes_immediately() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        t.on_query(key(1, 1), &query("x.com"), attr(), None, 1, Instant::now());
        let ev = t
            .on_response(key(1, 1), &response(3, vec![]))
            .unwrap()
            .event;
        assert!(ev.response_ips.is_empty());
        assert_eq!(ev.ttl, None);
    }

    #[test]
    fn same_id_different_port_are_distinct() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        let now = Instant::now();
        t.on_query(key(1000, 1), &query("a.com"), attr(), None, 1, now);
        t.on_query(key(1001, 1), &query("b.com"), attr(), None, 2, now);
        assert_eq!(t.counters().duplicates, 0);
        let ev = t
            .on_response(key(1001, 1), &response(0, vec![]))
            .unwrap()
            .event;
        assert_eq!(ev.query, "b.com");
        let ev = t
            .on_response(key(1000, 1), &response(0, vec![]))
            .unwrap()
            .event;
        assert_eq!(ev.query, "a.com");
    }

    #[test]
    fn overflow_evicts_oldest_as_timeout() {
        let mut t = Tracker::new(Duration::from_secs(5), 2);
        let now = Instant::now();
        t.on_query(key(1, 1), &query("a.com"), attr(), None, 1, now);
        t.on_query(key(2, 1), &query("b.com"), attr(), None, 2, now);
        let ev = t
            .on_query(key(3, 1), &query("c.com"), attr(), None, 3, now)
            .unwrap()
            .event;
        assert_eq!(t.counters().overflow_evictions, 1);
        assert_eq!(ev.query, "a.com");
        assert!(ev.response_ips.is_empty());
        assert_eq!(ev.ttl, None);
        assert!(t.expire(now).is_empty());
        assert!(t.on_response(key(1, 1), &response(0, vec![])).is_none());
    }

    #[test]
    fn flood_keeps_memory_bounded() {
        let mut t = Tracker::new(Duration::from_secs(5), 4);
        let now = Instant::now();
        let mut evicted = 0;
        for i in 0..10_000u32 {
            let k = TxKey {
                server: format!("10.1.{}.{}", (i >> 8) & 255, i & 255)
                    .parse()
                    .unwrap(),
                ..key(1000, 1)
            };
            if t.on_query(k, &query("x.com"), attr(), None, 1, now)
                .is_some()
            {
                evicted += 1;
            }
            assert!(t.pending_len() <= 4);
        }
        assert_eq!(evicted, 9_996);
        assert_eq!(t.counters().overflow_evictions, 9_996);
        assert_eq!(t.pending_len(), 4);
    }

    #[test]
    fn query_without_question_ignored() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        let now = Instant::now();
        let mut m = query("x.com");
        m.question = None;
        t.on_query(key(1, 1), &m, attr(), None, 1, now);
        assert!(t.expire(now + Duration::from_secs(60)).is_empty());
        assert!(t.on_response(key(1, 1), &response(0, vec![])).is_none());
    }

    fn pending_attr() -> PendingAttribution {
        PendingAttribution {
            key: SendKey::new(key(1000, 1).client, "10.0.0.1:53".parse().unwrap()),
            laddr: "10.0.0.2".parse().unwrap(),
            packet_ts_ns: 9,
            claim: crate::send_table::SendTable::new().claim(
                SendKey::new(key(1000, 1).client, "10.0.0.1:53".parse().unwrap()),
                "10.0.0.2".parse().unwrap(),
                9,
            ),
        }
    }

    #[test]
    fn closed_carries_kind_client_and_pending() {
        let mut t = Tracker::new(Duration::from_secs(5), 1);
        let now = Instant::now();
        let p = pending_attr();
        t.on_query(
            key(1000, 1),
            &query("a.com"),
            Attribution::default(),
            Some(p),
            9,
            now,
        );
        let c = t
            .on_query(key(1001, 1), &query("b.com"), attr(), None, 10, now)
            .unwrap();
        assert_eq!(c.kind, CloseKind::Evicted);
        assert_eq!(c.client, key(1000, 1).client);
        assert_eq!(c.pending, Some(p));
        let c = t.on_response(key(1001, 1), &response(0, vec![])).unwrap();
        assert_eq!((c.kind, c.pending), (CloseKind::Response, None));
        t.on_query(key(1002, 1), &query("c.com"), attr(), None, 11, now);
        let evs = t.expire(now + Duration::from_secs(5));
        assert_eq!(evs[0].kind, CloseKind::Timeout);
    }

    #[test]
    fn resolve_pending_sets_owner_once() {
        let mut t = Tracker::new(Duration::from_secs(5), 4);
        let now = Instant::now();
        assert!(t.resolve_pending(&key(1000, 1), attr()).is_none());
        t.on_query(
            key(1000, 1),
            &query("a.com"),
            Attribution::default(),
            Some(pending_attr()),
            1,
            now,
        );
        assert!(t.contains(&key(1000, 1)));
        assert_eq!(
            t.resolve_pending(&key(1000, 1), attr()),
            Some(pending_attr())
        );
        assert!(t
            .resolve_pending(&key(1000, 1), Attribution::default())
            .is_none());
        let c = t.on_response(key(1000, 1), &response(0, vec![])).unwrap();
        assert_eq!(c.pending, None);
        assert_eq!(c.event.pid, Some(42));
    }
}
