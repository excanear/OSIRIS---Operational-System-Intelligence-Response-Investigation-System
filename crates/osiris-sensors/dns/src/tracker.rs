//! DNS transaction tracker: pairs a query with its response (or a timeout)
//! and yields exactly one `DnsEventRaw` per transaction. Time is always passed
//! in so behaviour is deterministic; the pending table is bounded.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use osiris_sensor_api::{DnsEventRaw, RawEventSource};

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

struct Pending {
    seq: u64,
    deadline: Instant,
    query: String,
    qtype: String,
    attribution: Attribution,
    timestamp_ns: u64,
}

impl Pending {
    fn into_event(self, response_ips: Vec<String>, ttl: Option<u32>) -> DnsEventRaw {
        DnsEventRaw {
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
    /// Evicted transactions, emitted as timeouts by the next `expire`.
    evicted: Vec<DnsEventRaw>,
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
            evicted: Vec::new(),
            counters: TrackerCounters::default(),
        }
    }

    pub fn counters(&self) -> TrackerCounters {
        self.counters
    }

    pub fn on_query(
        &mut self,
        key: TxKey,
        msg: &DnsMessage,
        attribution: Attribution,
        timestamp_ns: u64,
        now: Instant,
    ) {
        let Some(q) = &msg.question else { return };
        if self.pending.contains_key(&key) {
            self.counters.duplicates += 1;
            return;
        }
        if self.pending.len() >= self.capacity {
            if let Some((_, oldest)) = self.order.pop_first() {
                if let Some(p) = self.pending.remove(&oldest) {
                    self.counters.overflow_evictions += 1;
                    self.evicted.push(p.into_event(Vec::new(), None));
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
                query: q.name.clone(),
                qtype: qtype_mnemonic(q.qtype),
                attribution,
                timestamp_ns,
            },
        );
    }

    pub fn on_response(&mut self, key: TxKey, msg: &DnsMessage) -> Option<DnsEventRaw> {
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
        Some(p.into_event(ips, ttl))
    }

    /// Emit overflow-evicted transactions plus every pending one whose
    /// deadline has passed, all as timeouts (empty ips, no ttl).
    pub fn expire(&mut self, now: Instant) -> Vec<DnsEventRaw> {
        let mut out = std::mem::take(&mut self.evicted);
        let due: Vec<u64> = self
            .order
            .iter()
            .filter(|(_, k)| self.pending.get(k).is_some_and(|p| p.deadline <= now))
            .map(|(s, _)| *s)
            .collect();
        for seq in due {
            if let Some(key) = self.order.remove(&seq) {
                if let Some(p) = self.pending.remove(&key) {
                    self.counters.timeouts += 1;
                    out.push(p.into_event(Vec::new(), None));
                }
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
        t.on_query(key(1000, 1), &query("example.com"), attr(), 77, now);
        let ev = t
            .on_response(
                key(1000, 1),
                &response(0, vec![a("1.2.3.4", 300), a("1.2.3.5", 60)]),
            )
            .unwrap();
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
        t.on_query(key(1000, 1), &query("example.com"), attr(), 1, now);
        assert!(t.expire(now + Duration::from_secs(4)).is_empty());
        let evs = t.expire(now + Duration::from_secs(5));
        assert_eq!(evs.len(), 1);
        assert!(evs[0].response_ips.is_empty());
        assert_eq!(evs[0].ttl, None);
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
        t.on_query(key(1000, 1), &query("example.com"), attr(), 1, now);
        t.on_query(key(1000, 1), &query("example.com"), attr(), 2, now);
        assert_eq!(t.counters().duplicates, 1);
        let ev = t
            .on_response(key(1000, 1), &response(0, vec![a("1.2.3.4", 5)]))
            .unwrap();
        assert_eq!(ev.timestamp_ns, 1);
        assert!(t.expire(now + Duration::from_secs(60)).is_empty());
    }

    #[test]
    fn cname_only_response_completes_immediately() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        t.on_query(key(1, 1), &query("x.com"), attr(), 1, Instant::now());
        let cname = Answer {
            rtype: 5,
            ttl: 30,
            addr: None,
        };
        let ev = t.on_response(key(1, 1), &response(0, vec![cname])).unwrap();
        assert!(ev.response_ips.is_empty());
        assert_eq!(ev.ttl, None);
    }

    #[test]
    fn nxdomain_completes_immediately() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        t.on_query(key(1, 1), &query("x.com"), attr(), 1, Instant::now());
        let ev = t.on_response(key(1, 1), &response(3, vec![])).unwrap();
        assert!(ev.response_ips.is_empty());
        assert_eq!(ev.ttl, None);
    }

    #[test]
    fn same_id_different_port_are_distinct() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        let now = Instant::now();
        t.on_query(key(1000, 1), &query("a.com"), attr(), 1, now);
        t.on_query(key(1001, 1), &query("b.com"), attr(), 2, now);
        assert_eq!(t.counters().duplicates, 0);
        let ev = t.on_response(key(1001, 1), &response(0, vec![])).unwrap();
        assert_eq!(ev.query, "b.com");
        let ev = t.on_response(key(1000, 1), &response(0, vec![])).unwrap();
        assert_eq!(ev.query, "a.com");
    }

    #[test]
    fn overflow_evicts_oldest_as_timeout() {
        let mut t = Tracker::new(Duration::from_secs(5), 2);
        let now = Instant::now();
        t.on_query(key(1, 1), &query("a.com"), attr(), 1, now);
        t.on_query(key(2, 1), &query("b.com"), attr(), 2, now);
        t.on_query(key(3, 1), &query("c.com"), attr(), 3, now);
        assert_eq!(t.counters().overflow_evictions, 1);
        let evs = t.expire(now);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].query, "a.com");
        assert!(evs[0].response_ips.is_empty());
        assert_eq!(evs[0].ttl, None);
        assert!(t.on_response(key(1, 1), &response(0, vec![])).is_none());
    }

    #[test]
    fn query_without_question_ignored() {
        let mut t = Tracker::new(Duration::from_secs(5), 16);
        let now = Instant::now();
        let mut m = query("x.com");
        m.question = None;
        t.on_query(key(1, 1), &m, attr(), 1, now);
        assert!(t.expire(now + Duration::from_secs(60)).is_empty());
        assert!(t.on_response(key(1, 1), &response(0, vec![])).is_none());
    }
}
