//! OS-neutral packet-to-event engine: raw L3 packets in, `RawEvent::Dns` out.
//!
//! Composes frame decoding, DNS wire parsing, the transaction tracker and
//! process attribution. The Linux capture loop owns I/O and calls
//! [`Engine::on_packet`] per packet and [`Engine::tick`] periodically.
//!
//! Attribution has two modes. In [`AttributionMode::Procfs`] the query's
//! owner is looked up in `/proc` when the query packet is seen (11a). In
//! [`AttributionMode::Kernel`] the query packet is joined with the kernel's
//! record of the send ([`SendTable`]) and `/proc` is never read. Packet and
//! record race, so a miss at query time claims its place in the table (newer
//! packets on the key cannot take what it may still join) and is retried
//! when the transaction closes, and a response that still misses is held for
//! [`ATTRIBUTION_GRACE`], re-checked on every tick, before it is emitted
//! unattributed. [`Engine::latch_procfs`] switches to `/proc` for good.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use osiris_sensor_api::{DnsEventRaw, RawEvent};

use crate::attribution::Attributor;
use crate::frame::{classify, decode_l3, Direction};
use crate::send_table::{lock_table, ClaimId, SendKey, SharedSendTable};
use crate::tracker::{
    Attribution, CloseKind, Closed, PendingAttribution, Tracker, TrackerCounters, TxKey,
};
use crate::wire::parse_message;

/// How long a query waits for its response before a timeout event.
pub const TX_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum number of simultaneously pending transactions.
pub const MAX_PENDING: usize = 4096;
/// How long a response that closed an unattributed transaction waits for a
/// late kernel record (GC 9).
pub const ATTRIBUTION_GRACE: Duration = Duration::from_millis(250);
/// Minimum spacing between expiry scans of the kernel send table.
pub const SEND_EXPIRE_INTERVAL: Duration = Duration::from_secs(1);

/// Current wall-clock time in ns since the Unix epoch.
pub fn wall_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Where query owners come from.
pub enum AttributionMode {
    /// Join packets with kernel-reported sends; never read `/proc`.
    Kernel(SharedSendTable),
    /// Look the owner up in `/proc` at query time.
    Procfs,
}

/// Snapshot of engine counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineMetrics {
    pub packets: u64,
    pub parse_errors: u64,
    /// Packets whose QR bit contradicted the port-derived direction.
    pub direction_mismatches: u64,
    pub emitted: u64,
    /// `attributed_kernel + attributed_procfs`.
    pub attributed: u64,
    pub unattributed: u64,
    pub tracker: TrackerCounters,
    /// Transactions attributed from a kernel send record.
    pub attributed_kernel: u64,
    /// Transactions attributed by a `/proc` lookup.
    pub attributed_procfs: u64,
    /// Kernel attributions found only when the transaction closed.
    pub attribution_late: u64,
    /// Responses held waiting for a late kernel record (cumulative).
    pub held: u64,
    /// Packets without a kernel receive timestamp (processing time used).
    pub timestamp_fallbacks: u64,
}

/// A closed, still-unattributed response waiting for its kernel record.
struct Held {
    event: DnsEventRaw,
    client: SocketAddr,
    pending: PendingAttribution,
    deadline: Instant,
}

/// Outcome of retrying attribution for a closed transaction.
enum Resolved {
    /// Final attribution (counters already updated).
    Done(Attribution),
    /// Kernel mode, no record yet.
    Miss,
}

pub struct Engine {
    attributor: Attributor,
    mode: AttributionMode,
    tracker: Tracker,
    held: VecDeque<Held>,
    held_capacity: usize,
    /// When old kernel sends were last expired.
    last_expire: Option<Instant>,
    /// The kernel table kept after [`Engine::latch_procfs`], only so claims
    /// of transactions still pending can be released.
    latched_table: Option<SharedSendTable>,
    packets: u64,
    parse_errors: u64,
    direction_mismatches: u64,
    emitted: u64,
    attributed_kernel: u64,
    attributed_procfs: u64,
    attribution_late: u64,
    unattributed: u64,
    held_total: u64,
    timestamp_fallbacks: u64,
}

fn apply(event: &mut DnsEventRaw, a: Attribution) {
    event.pid = a.pid;
    event.uid = a.uid;
    event.exe_path = a.exe_path;
    event.comm = a.comm;
}

impl Engine {
    pub fn new(
        attributor: Attributor,
        mode: AttributionMode,
        timeout: Duration,
        capacity: usize,
    ) -> Self {
        Self {
            attributor,
            mode,
            tracker: Tracker::new(timeout, capacity),
            held: VecDeque::new(),
            held_capacity: capacity.max(1),
            last_expire: None,
            latched_table: None,
            packets: 0,
            parse_errors: 0,
            direction_mismatches: 0,
            emitted: 0,
            attributed_kernel: 0,
            attributed_procfs: 0,
            attribution_late: 0,
            unattributed: 0,
            held_total: 0,
            timestamp_fallbacks: 0,
        }
    }

    pub fn metrics(&self) -> EngineMetrics {
        EngineMetrics {
            packets: self.packets,
            parse_errors: self.parse_errors,
            direction_mismatches: self.direction_mismatches,
            emitted: self.emitted,
            attributed: self.attributed_kernel + self.attributed_procfs,
            unattributed: self.unattributed,
            tracker: self.tracker.counters(),
            attributed_kernel: self.attributed_kernel,
            attributed_procfs: self.attributed_procfs,
            attribution_late: self.attribution_late,
            held: self.held_total,
            timestamp_fallbacks: self.timestamp_fallbacks,
        }
    }

    /// Counts a packet that carried no kernel receive timestamp.
    pub fn record_timestamp_fallback(&mut self) {
        self.timestamp_fallbacks += 1;
    }

    /// One-way switch to `/proc` attribution (GC 10/12): later queries are
    /// looked up in `/proc`, and transactions still pending attribution get
    /// a `/proc` lookup when they close (held ones on the next tick).
    pub fn latch_procfs(&mut self) {
        if let AttributionMode::Kernel(table) =
            std::mem::replace(&mut self.mode, AttributionMode::Procfs)
        {
            self.latched_table = Some(table);
        }
    }

    /// The table holding claims: the kernel one, or the latched one.
    fn claim_table(&self) -> Option<&SharedSendTable> {
        match &self.mode {
            AttributionMode::Kernel(table) => Some(table),
            AttributionMode::Procfs => self.latched_table.as_ref(),
        }
    }

    /// Drops the claim of a transaction whose owner was settled another way
    /// (a `/proc` lookup after the latch).
    fn release_claim(&self, claim: ClaimId) {
        if let Some(table) = self.claim_table() {
            lock_table(table).release(claim);
        }
    }

    /// Gives up on a claim whose transaction is emitted unattributed (or
    /// not tracked at all). Its send still happened, so the claim stays as a
    /// tombstone that consumes the late record instead of letting a newer
    /// packet on a reused port take it.
    fn abandon_claim(&self, claim: ClaimId) {
        if let Some(table) = self.claim_table() {
            lock_table(table).abandon(claim);
        }
    }

    /// Process one raw L3 packet. Never panics on malformed input.
    ///
    /// `local_origin` is true when the packet was sent by this host (the
    /// capture loop sets it from `sll_pkttype == PACKET_OUTGOING`, or when it
    /// arrived on the loopback interface). Queries from remote clients are
    /// never attributed: their source port says nothing about local sockets.
    ///
    /// `timestamp_ns` is the packet's wall-clock time: the kernel receive
    /// timestamp when present, else the processing time.
    pub fn on_packet(
        &mut self,
        l3: &[u8],
        local_origin: bool,
        timestamp_ns: u64,
        now: Instant,
    ) -> Vec<RawEvent> {
        self.packets += 1;
        let Some(dg) = decode_l3(l3) else {
            return Vec::new();
        };
        let Some(mut direction) = classify(&dg) else {
            return Vec::new();
        };
        let Ok(msg) = parse_message(dg.payload) else {
            self.parse_errors += 1;
            return Vec::new();
        };
        // 53->53 is ambiguous by ports alone; the QR bit decides.
        if dg.src.port() == 53 && dg.dst.port() == 53 {
            direction = if msg.is_response {
                Direction::Response
            } else {
                Direction::Query
            };
        }
        let mut raw: Vec<DnsEventRaw> = Vec::new();
        match direction {
            Direction::Query => {
                if msg.is_response {
                    self.direction_mismatches += 1;
                    return Vec::new();
                }
                let key = TxKey {
                    client: dg.src,
                    server: dg.dst.ip(),
                    id: msg.id,
                };
                let (attribution, pending) = if !local_origin {
                    self.unattributed += 1;
                    (Attribution::default(), None)
                } else {
                    self.attribute_query(key, dg.dst, timestamp_ns, now)
                };
                let claim = pending.map(|p| p.claim);
                if let Some(closed) =
                    self.tracker
                        .on_query(key, &msg, attribution, pending, timestamp_ns, now)
                {
                    self.close(closed, now, &mut raw);
                }
                // A query the tracker did not keep (no question) is never
                // joined, but its send happened: tombstone its claim.
                if let Some(claim) = claim {
                    if !self.tracker.contains(&key) {
                        self.abandon_claim(claim);
                    }
                }
            }
            Direction::Response => {
                if !msg.is_response {
                    self.direction_mismatches += 1;
                    return Vec::new();
                }
                let key = TxKey {
                    client: dg.dst,
                    server: dg.src.ip(),
                    id: msg.id,
                };
                if let Some(closed) = self.tracker.on_response(key, &msg) {
                    self.close(closed, now, &mut raw);
                }
            }
        }
        self.wrap(raw)
    }

    /// Attribution of a local query packet at query time: the owner, plus
    /// the kernel join still owed when the kernel record has not arrived.
    fn attribute_query(
        &mut self,
        key: TxKey,
        server: SocketAddr,
        timestamp_ns: u64,
        now: Instant,
    ) -> (Attribution, Option<PendingAttribution>) {
        let table = match &self.mode {
            AttributionMode::Procfs => {
                let a = self.attributor.lookup(key.client, now);
                self.count_procfs(&a);
                return (a, None);
            }
            AttributionMode::Kernel(table) => table,
        };
        let send_key = SendKey::new(key.client, server);
        let laddr = key.client.ip();
        if self.tracker.contains(&key) {
            // Retransmit: it consumes its own record (if any) and may
            // complete a transaction whose first record was lost. It makes
            // no claim. The tracker counts the duplicate and keeps the
            // first packet. The lock is held only for the lookup itself.
            let hit = lock_table(table).take(&send_key, laddr, timestamp_ns);
            if let Some(a) = hit {
                if let Some(owed) = self.tracker.resolve_pending(&key, a) {
                    self.attributed_kernel += 1;
                    // The original send's entry must not stay stealable:
                    // consume it now, or tombstone the claim for it.
                    let mut t = lock_table(table);
                    let own = t.take_claimed(owed.claim, &owed.key, owed.laddr, owed.packet_ts_ns);
                    if own.is_none() {
                        t.abandon(owed.claim);
                    }
                }
            }
            return (Attribution::default(), None);
        }
        // A miss claims the packet's place, so a newer packet on a reused
        // port cannot take the record this one still waits for.
        let joined = {
            let mut t = lock_table(table);
            t.take(&send_key, laddr, timestamp_ns)
                .ok_or_else(|| t.claim(send_key, laddr, timestamp_ns))
        };
        match joined {
            Ok(a) => {
                self.attributed_kernel += 1;
                (a, None)
            }
            Err(claim) => (
                Attribution::default(),
                Some(PendingAttribution {
                    key: send_key,
                    laddr,
                    packet_ts_ns: timestamp_ns,
                    claim,
                }),
            ),
        }
    }

    fn count_procfs(&mut self, a: &Attribution) {
        if a.pid.is_some() {
            self.attributed_procfs += 1;
        } else {
            self.unattributed += 1;
        }
    }

    /// Retries attribution for a transaction that closed pending it.
    fn resolve(
        &mut self,
        pending: &PendingAttribution,
        client: SocketAddr,
        now: Instant,
    ) -> Resolved {
        match &self.mode {
            AttributionMode::Kernel(table) => {
                let hit = lock_table(table).take_claimed(
                    pending.claim,
                    &pending.key,
                    pending.laddr,
                    pending.packet_ts_ns,
                );
                match hit {
                    Some(a) => {
                        self.attributed_kernel += 1;
                        self.attribution_late += 1;
                        Resolved::Done(a)
                    }
                    None => Resolved::Miss,
                }
            }
            AttributionMode::Procfs => {
                self.release_claim(pending.claim);
                let a = self.attributor.lookup(client, now);
                self.count_procfs(&a);
                Resolved::Done(a)
            }
        }
    }

    /// Finishes a closed transaction: emits it, or holds a response whose
    /// kernel record has not arrived yet.
    fn close(&mut self, closed: Closed, now: Instant, out: &mut Vec<DnsEventRaw>) {
        let Closed {
            mut event,
            kind,
            client,
            pending,
        } = closed;
        let Some(pending) = pending else {
            out.push(event);
            return;
        };
        match self.resolve(&pending, client, now) {
            Resolved::Done(a) => {
                apply(&mut event, a);
                out.push(event);
            }
            Resolved::Miss if kind == CloseKind::Response => {
                if self.held.len() >= self.held_capacity {
                    if let Some(oldest) = self.held.pop_front() {
                        self.abandon_claim(oldest.pending.claim);
                        self.unattributed += 1;
                        out.push(oldest.event);
                    }
                }
                self.held_total += 1;
                self.held.push_back(Held {
                    event,
                    client,
                    pending,
                    deadline: now + ATTRIBUTION_GRACE,
                });
            }
            Resolved::Miss => {
                // Timeouts and evictions are re-checked once (GC 9).
                self.abandon_claim(pending.claim);
                self.unattributed += 1;
                out.push(event);
            }
        }
    }

    /// Emit timeouts, re-check held responses (emitting them on a hit or
    /// once their grace has passed) and expire old kernel sends.
    pub fn tick(&mut self, now: Instant) -> Vec<RawEvent> {
        let mut raw = Vec::new();
        for closed in self.tracker.expire(now) {
            self.close(closed, now, &mut raw);
        }
        let held = std::mem::take(&mut self.held);
        for mut h in held {
            match self.resolve(&h.pending, h.client, now) {
                Resolved::Done(a) => {
                    apply(&mut h.event, a);
                    raw.push(h.event);
                }
                Resolved::Miss if h.deadline > now => self.held.push_back(h),
                Resolved::Miss => {
                    self.abandon_claim(h.pending.claim);
                    self.unattributed += 1;
                    raw.push(h.event);
                }
            }
        }
        self.expire_sends(now);
        self.wrap(raw)
    }

    /// Expires old kernel sends at most once per [`SEND_EXPIRE_INTERVAL`]:
    /// the expiry is a full scan under the lock the reader thread shares.
    fn expire_sends(&mut self, now: Instant) {
        let AttributionMode::Kernel(table) = &self.mode else {
            return;
        };
        let due = self
            .last_expire
            .is_none_or(|t| now.saturating_duration_since(t) >= SEND_EXPIRE_INTERVAL);
        if !due {
            return;
        }
        let wall = wall_ns();
        lock_table(table).expire(wall);
        self.last_expire = Some(now);
    }

    /// Shutdown flush: closes every pending transaction (as a timeout,
    /// with one final attribution attempt) and every held response (one
    /// final re-check), so nothing is lost on cancel. Each is emitted once.
    pub fn drain(&mut self, now: Instant) -> Vec<RawEvent> {
        let mut raw = Vec::new();
        for closed in self.tracker.drain_all() {
            self.close(closed, now, &mut raw);
        }
        for mut h in std::mem::take(&mut self.held) {
            match self.resolve(&h.pending, h.client, now) {
                Resolved::Done(a) => apply(&mut h.event, a),
                Resolved::Miss => {
                    self.abandon_claim(h.pending.claim);
                    self.unattributed += 1;
                }
            }
            raw.push(h.event);
        }
        self.wrap(raw)
    }

    fn wrap(&mut self, raw: Vec<DnsEventRaw>) -> Vec<RawEvent> {
        self.emitted += raw.len() as u64;
        raw.into_iter().map(RawEvent::Dns).collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::send_table::{KernelSend, SendTable};
    use std::net::{Ipv6Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    fn engine() -> (Engine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::new(
            Attributor::new(dir.path().to_path_buf()),
            AttributionMode::Procfs,
            TX_TIMEOUT,
            16,
        );
        (e, dir)
    }

    fn dns(id: u16, flags: u16, name: &str, qtype: u16, answer: Option<(u16, &[u8])>) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&flags.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes());
        b.extend_from_slice(&[0; 4]);
        for l in name.split('.') {
            b.push(l.len() as u8);
            b.extend_from_slice(l.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        if let Some((t, data)) = answer {
            b.extend_from_slice(&[0xc0, 0x0c]);
            b.extend_from_slice(&t.to_be_bytes());
            b.extend_from_slice(&1u16.to_be_bytes());
            b.extend_from_slice(&300u32.to_be_bytes());
            b.extend_from_slice(&(data.len() as u16).to_be_bytes());
            b.extend_from_slice(data);
        }
        b
    }

    fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = Vec::new();
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(payload);
        u
    }

    fn v4(src: [u8; 4], dst: [u8; 4], seg: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + seg.len()) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p.extend_from_slice(seg);
        p
    }

    fn v6(src: Ipv6Addr, dst: Ipv6Addr, seg: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(seg.len() as u16).to_be_bytes());
        p[6] = 17;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p.extend_from_slice(seg);
        p
    }

    pub(crate) fn only_dns(mut evs: Vec<RawEvent>) -> DnsEventRaw {
        assert_eq!(evs.len(), 1, "{evs:?}");
        match evs.remove(0) {
            RawEvent::Dns(d) => d,
            other => panic!("not dns: {other:?}"),
        }
    }

    #[test]
    fn query_response_packets_emit_dns_event() {
        let (mut e, _d) = engine();
        let now = Instant::now();
        let q = v4(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            &udp(41000, 53, &dns(7, 0x0100, "example.com", 1, None)),
        );
        let r = v4(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &udp(
                53,
                41000,
                &dns(7, 0x8180, "example.com", 1, Some((1, &[93, 184, 216, 34]))),
            ),
        );
        assert!(e.on_packet(&q, true, 111, now).is_empty());
        let ev = only_dns(e.on_packet(&r, true, 222, now));
        assert_eq!(ev.query, "example.com");
        assert_eq!(ev.qtype, "A");
        assert_eq!(ev.response_ips, vec!["93.184.216.34"]);
        assert_eq!(ev.ttl, Some(300));
        assert_eq!(ev.timestamp_ns, 111);
        let m = e.metrics();
        assert_eq!((m.packets, m.emitted, m.parse_errors), (2, 1, 0));
        assert_eq!((m.attributed, m.unattributed), (0, 1));
    }

    #[test]
    fn ipv6_pair_emits() {
        let (mut e, _d) = engine();
        let now = Instant::now();
        let c = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let s = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let ans = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        let q = v6(
            c,
            s,
            &udp(42000, 53, &dns(9, 0x0100, "v6.example.org", 28, None)),
        );
        let r = v6(
            s,
            c,
            &udp(
                53,
                42000,
                &dns(9, 0x8180, "v6.example.org", 28, Some((28, &ans))),
            ),
        );
        e.on_packet(&q, true, 1, now);
        let ev = only_dns(e.on_packet(&r, true, 2, now));
        assert_eq!(ev.qtype, "AAAA");
        assert_eq!(ev.response_ips, vec!["2001:db8::1"]);
    }

    #[test]
    fn garbage_packet_counts_parse_error() {
        let (mut e, _d) = engine();
        let now = Instant::now();
        let bad = v4([10, 0, 0, 2], [10, 0, 0, 1], &udp(41000, 53, &[1, 2, 3]));
        assert!(e.on_packet(&bad, true, 1, now).is_empty());
        assert_eq!(e.metrics().parse_errors, 1);
        // Non-IP garbage is ignored silently.
        assert!(e.on_packet(&[0xff; 7], true, 1, now).is_empty());
        assert_eq!(e.metrics().parse_errors, 1);
        assert_eq!(e.metrics().packets, 2);
    }

    #[test]
    fn non_dns_udp_ignored_without_error() {
        let (mut e, _d) = engine();
        let p = v4([10, 0, 0, 2], [10, 0, 0, 1], &udp(1234, 5678, &[1, 2, 3]));
        assert!(e.on_packet(&p, true, 1, Instant::now()).is_empty());
        assert_eq!(e.metrics().parse_errors, 0);
        assert_eq!(e.metrics().unattributed, 0);
    }

    #[test]
    fn tick_emits_timeouts() {
        let (mut e, _d) = engine();
        let now = Instant::now();
        let q = v4(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            &udp(41000, 53, &dns(7, 0x0100, "slow.example.com", 1, None)),
        );
        e.on_packet(&q, true, 5, now);
        assert!(e.tick(now + Duration::from_secs(1)).is_empty());
        let ev = only_dns(e.tick(now + TX_TIMEOUT + Duration::from_millis(1)));
        assert_eq!(ev.query, "slow.example.com");
        assert!(ev.response_ips.is_empty());
        assert_eq!(ev.ttl, None);
        assert_eq!(e.metrics().tracker.timeouts, 1);
        assert_eq!(e.metrics().emitted, 1);
    }

    #[test]
    fn remote_query_is_not_attributed() {
        let hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
";
        let row = "  1: 00000000:A028 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 4242 2 0000000000000000 0
";
        let dir = tempfile::tempdir().unwrap();
        let net = dir.path().join("net");
        std::fs::create_dir_all(&net).unwrap();
        std::fs::write(net.join("udp"), format!("{hdr}{row}")).unwrap();
        std::fs::write(net.join("udp6"), hdr).unwrap();
        let mut e = Engine::new(
            Attributor::new(dir.path().to_path_buf()),
            AttributionMode::Procfs,
            TX_TIMEOUT,
            16,
        );
        let now = Instant::now();
        let q = |id: u16| {
            v4(
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                &udp(41000, 53, &dns(id, 0x0100, "r.example.com", 1, None)),
            )
        };
        e.on_packet(&q(1), false, 1, now);
        e.on_packet(&q(2), true, 2, now);
        let evs = e.tick(now + TX_TIMEOUT + Duration::from_millis(1));
        assert_eq!(evs.len(), 2);
        let uids: Vec<u32> = evs
            .into_iter()
            .map(|ev| match ev {
                RawEvent::Dns(d) => {
                    assert_eq!(d.pid, None);
                    d.uid
                }
                other => panic!("{other:?}"),
            })
            .collect();
        // Remote: default attribution (uid 0). Local: the table row was used.
        assert_eq!(uids, vec![0, 1000]);
    }

    #[test]
    fn port53_to_port53_query_then_response_emits() {
        let (mut e, _d) = engine();
        let now = Instant::now();
        let q = v4(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            &udp(53, 53, &dns(5, 0x0100, "rr.example.com", 1, None)),
        );
        let r = v4(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &udp(
                53,
                53,
                &dns(5, 0x8180, "rr.example.com", 1, Some((1, &[1, 2, 3, 4]))),
            ),
        );
        assert!(e.on_packet(&q, false, 1, now).is_empty());
        let ev = only_dns(e.on_packet(&r, false, 2, now));
        assert_eq!(ev.query, "rr.example.com");
        assert_eq!(ev.response_ips, vec!["1.2.3.4"]);
        assert_eq!(e.metrics().direction_mismatches, 0);
    }

    #[test]
    fn qr_direction_mismatch_is_counted() {
        let (mut e, _d) = engine();
        let now = Instant::now();
        let p = v4(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            &udp(41000, 53, &dns(5, 0x8180, "x.example.com", 1, None)),
        );
        assert!(e.on_packet(&p, true, 1, now).is_empty());
        assert_eq!(e.metrics().direction_mismatches, 1);
    }

    #[test]
    fn evicted_transaction_is_emitted() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::new(
            Attributor::new(dir.path().to_path_buf()),
            AttributionMode::Procfs,
            TX_TIMEOUT,
            1,
        );
        let now = Instant::now();
        let mk = |id: u16, name: &str| {
            v4(
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                &udp(41000, 53, &dns(id, 0x0100, name, 1, None)),
            )
        };
        assert!(e
            .on_packet(&mk(1, "a.example.com"), true, 1, now)
            .is_empty());
        let ev = only_dns(e.on_packet(&mk(2, "b.example.com"), true, 2, now));
        assert_eq!(ev.query, "a.example.com");
        assert!(ev.response_ips.is_empty());
    }

    // ---- Kernel attribution mode -------------------------------------

    const CLIENT: [u8; 4] = [10, 0, 0, 2];
    const SERVER: [u8; 4] = [10, 0, 0, 1];
    const CPORT: u16 = 41000;
    const MS: u64 = 1_000_000;

    /// A proc root whose `/proc/net/udp` has a row for the client socket
    /// (uid 1000, inode 4242); `with_row == false` leaves the tables empty.
    fn proc_fixture(with_row: bool) -> tempfile::TempDir {
        let hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n";
        let row = "  1: 0200000A:A028 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 4242 2 0000000000000000 0\n";
        let dir = tempfile::tempdir().unwrap();
        let net = dir.path().join("net");
        std::fs::create_dir_all(&net).unwrap();
        let udp = if with_row {
            format!("{hdr}{row}")
        } else {
            hdr.to_string()
        };
        std::fs::write(net.join("udp"), udp).unwrap();
        std::fs::write(net.join("udp6"), hdr).unwrap();
        // fd -> socket inode; best effort (symlinks may be unavailable).
        let fd = dir.path().join("300").join("fd");
        std::fs::create_dir_all(&fd).unwrap();
        std::fs::write(dir.path().join("300").join("comm"), "resolver\n").unwrap();
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink("socket:[4242]", fd.join("3"));
        dir
    }

    pub(crate) fn kernel_engine(with_row: bool) -> (Engine, SharedSendTable, tempfile::TempDir) {
        let dir = proc_fixture(with_row);
        let table: SharedSendTable = Arc::new(Mutex::new(SendTable::new()));
        let e = Engine::new(
            Attributor::new(dir.path().to_path_buf()),
            AttributionMode::Kernel(table.clone()),
            TX_TIMEOUT,
            16,
        );
        (e, table, dir)
    }

    fn client_addr() -> SocketAddr {
        SocketAddr::from((CLIENT, CPORT))
    }

    fn server_addr() -> SocketAddr {
        SocketAddr::from((SERVER, 53))
    }

    fn owner() -> Attribution {
        Attribution {
            pid: Some(777),
            uid: 1001,
            exe_path: "/usr/bin/dig".into(),
            comm: "dig".into(),
        }
    }

    fn insert_send(table: &SharedSendTable, sent_wall_ns: u64) {
        insert_send_as(table, sent_wall_ns, owner());
    }

    fn insert_send_as(table: &SharedSendTable, sent_wall_ns: u64, owner: Attribution) {
        lock_table(table).insert(KernelSend {
            key: SendKey::new(client_addr(), server_addr()),
            laddr: client_addr().ip(),
            sent_wall_ns,
            owner,
        });
    }

    fn other_owner() -> Attribution {
        Attribution {
            pid: Some(888),
            uid: 1002,
            exe_path: "/usr/bin/host".into(),
            comm: "host".into(),
        }
    }

    fn pids(evs: &[RawEvent]) -> Vec<Option<u32>> {
        evs.iter()
            .map(|ev| match ev {
                RawEvent::Dns(d) => d.pid,
                other => panic!("{other:?}"),
            })
            .collect()
    }

    #[test]
    fn reused_port_keeps_older_pending_owner() {
        // A's query packet beats A's record; A closes the port, B reuses it
        // for the same resolver; A's then B's records land; B's packet.
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        assert!(e.on_packet(&kq(1), true, base + MS, now).is_empty());
        insert_send(&table, base);
        insert_send_as(&table, base + 100 * MS, other_owner());
        assert!(e.on_packet(&kq(2), true, base + 101 * MS, now).is_empty());
        let b = only_dns(e.on_packet(&kr(2), true, base + 102 * MS, now));
        assert_eq!(b.pid, Some(888));
        let a = only_dns(e.on_packet(&kr(1), true, base + 103 * MS, now));
        assert_eq!(a.pid, Some(777));
        assert!(lock_table(&table).is_empty());
        assert_eq!(lock_table(&table).claims_len(), 0);
        assert_eq!(e.metrics().held, 0);
    }

    #[test]
    fn reused_port_newer_packet_waits_for_its_own_record() {
        // As above, but B's packet also beats B's record. A's response
        // arrives last; nothing may ever carry the other's pid.
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        e.on_packet(&kq(1), true, base + MS, now);
        insert_send(&table, base);
        e.on_packet(&kq(2), true, base + 101 * MS, now);
        assert!(e.on_packet(&kr(2), true, base + 102 * MS, now).is_empty());
        insert_send_as(&table, base + 100 * MS, other_owner());
        let b = only_dns(e.tick(now + Duration::from_millis(10)));
        assert_eq!(b.pid, Some(888));
        let a = only_dns(e.on_packet(&kr(1), true, base + 103 * MS, now));
        assert_eq!(a.pid, Some(777));
        assert_eq!(lock_table(&table).claims_len(), 0);
    }

    #[test]
    fn given_up_transactions_tombstone_their_claims() {
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        // Held response past its grace; timeout miss; drain miss. Each
        // give-up keeps its claim as a tombstone.
        e.on_packet(&kq(1), true, base, now);
        assert!(e.on_packet(&kr(1), true, base + MS, now).is_empty());
        e.on_packet(&kq(2), true, base + 2 * MS, now);
        assert_eq!(lock_table(&table).claims_len(), 2);
        assert_eq!(pids(&e.tick(now + Duration::from_millis(251))), vec![None]);
        assert_eq!(
            pids(&e.tick(now + TX_TIMEOUT + Duration::from_millis(1))),
            vec![None]
        );
        e.on_packet(&kq(3), true, base + 3 * MS, now);
        assert!(e.on_packet(&kr(3), true, base + 4 * MS, now).is_empty());
        e.on_packet(&kq(4), true, base + 5 * MS, now);
        assert_eq!(e.drain(now).len(), 2);
        assert_eq!(lock_table(&table).claims_len(), 4);
        // One late record: the oldest tombstone consumes it silently.
        insert_send(&table, base);
        assert!(lock_table(&table).is_empty());
        assert_eq!(lock_table(&table).claims_len(), 3);
        assert_eq!(lock_table(&table).counters().tombstone_consumed, 1);
    }

    #[test]
    fn late_record_after_give_up_is_not_stolen() {
        // A's response is held 250 ms without A's record; the engine gives
        // up. A's record then lands; B reuses the port within 2 s.
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        e.on_packet(&kq(1), true, base + MS, now);
        assert!(e.on_packet(&kr(1), true, base + 2 * MS, now).is_empty());
        let a = only_dns(e.tick(now + Duration::from_millis(251)));
        assert_eq!(a.pid, None);
        insert_send(&table, base);
        insert_send_as(&table, base + 300 * MS, other_owner());
        e.on_packet(&kq(2), true, base + 301 * MS, now);
        let b = only_dns(e.on_packet(&kr(2), true, base + 302 * MS, now));
        assert_eq!(b.pid, Some(888));
    }

    #[test]
    fn late_record_after_give_up_before_newer_record() {
        // As above, but B's packet also beats B's record.
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        e.on_packet(&kq(1), true, base + MS, now);
        assert!(e.on_packet(&kr(1), true, base + 2 * MS, now).is_empty());
        only_dns(e.tick(now + Duration::from_millis(251)));
        insert_send(&table, base);
        e.on_packet(&kq(2), true, base + 301 * MS, now);
        assert!(e.on_packet(&kr(2), true, base + 302 * MS, now).is_empty());
        let later = now + Duration::from_millis(260);
        let b = only_dns(e.tick(later + Duration::from_millis(251)));
        assert_ne!(b.pid, Some(777));
        assert_eq!(b.pid, None);
    }

    #[test]
    fn retransmit_consumes_original_entry() {
        // Original packet missed; both records land; the retransmit takes
        // its own and the original's entry is consumed too.
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        e.on_packet(&kq(1), true, base + MS, now);
        insert_send(&table, base);
        insert_send(&table, base + 1000 * MS);
        e.on_packet(&kq(1), true, base + 1001 * MS, now);
        assert!(lock_table(&table).is_empty());
        assert_eq!(lock_table(&table).claims_len(), 0);
        let ev = only_dns(e.on_packet(&kr(1), true, base + 1002 * MS, now));
        assert_eq!(ev.pid, Some(777));
        assert_eq!(e.metrics().attributed_kernel, 1);
    }

    #[test]
    fn retransmit_tombstones_and_latch_releases() {
        let (mut e, table, _d) = kernel_engine(true);
        let now = Instant::now();
        let base = wall_ns();
        // Original record lost: the retransmit resolves the transaction and
        // the original's claim stays as a tombstone for its late record.
        e.on_packet(&kq(1), true, base, now);
        insert_send(&table, base + 10 * MS);
        e.on_packet(&kq(1), true, base + 11 * MS, now);
        assert_eq!(lock_table(&table).claims_len(), 1);
        e.on_packet(&kq(2), true, base + 20 * MS, now);
        assert_eq!(lock_table(&table).claims_len(), 2);
        e.latch_procfs();
        let ev = only_dns(e.on_packet(&kr(2), true, base + 21 * MS, now));
        assert_eq!(ev.uid, 1000);
        assert_eq!(lock_table(&table).claims_len(), 1);
    }

    #[test]
    fn held_overflow_tombstones_claim() {
        let dir = proc_fixture(false);
        let table: SharedSendTable = Arc::new(Mutex::new(SendTable::new()));
        let mut e = Engine::new(
            Attributor::new(dir.path().to_path_buf()),
            AttributionMode::Kernel(table.clone()),
            TX_TIMEOUT,
            1,
        );
        let now = Instant::now();
        let base = wall_ns();
        e.on_packet(&kq(1), true, base, now);
        assert!(e.on_packet(&kr(1), true, base, now).is_empty());
        e.on_packet(&kq(2), true, base, now);
        assert_eq!(e.on_packet(&kr(2), true, base, now).len(), 1);
        // The forced-out claim is a tombstone; the held one is live.
        assert_eq!(lock_table(&table).claims_len(), 2);
    }

    pub(crate) fn kq(id: u16) -> Vec<u8> {
        v4(
            CLIENT,
            SERVER,
            &udp(CPORT, 53, &dns(id, 0x0100, "k.example.com", 1, None)),
        )
    }

    pub(crate) fn kr(id: u16) -> Vec<u8> {
        v4(
            SERVER,
            CLIENT,
            &udp(
                53,
                CPORT,
                &dns(id, 0x8180, "k.example.com", 1, Some((1, &[1, 2, 3, 4]))),
            ),
        )
    }

    #[test]
    fn kernel_mode_attributes_from_table() {
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        insert_send(&table, base);
        assert!(e.on_packet(&kq(1), true, base + MS, now).is_empty());
        let ev = only_dns(e.on_packet(&kr(1), true, base + 2 * MS, now));
        assert_eq!(ev.pid, Some(777));
        assert_eq!(ev.uid, 1001);
        assert_eq!(ev.exe_path, "/usr/bin/dig");
        assert_eq!(ev.comm, "dig");
        assert_eq!(ev.timestamp_ns, base + MS);
        let m = e.metrics();
        assert_eq!(m.attributed_kernel, 1);
        assert_eq!(m.attributed_procfs, 0);
        assert_eq!(m.attributed, 1);
        assert_eq!((m.attribution_late, m.unattributed, m.held), (0, 0, 0));
        assert!(lock_table(&table).is_empty());
    }

    #[test]
    fn kernel_mode_never_reads_proc() {
        let (mut e, _table, _d) = kernel_engine(true);
        let now = Instant::now();
        let base = wall_ns();
        e.on_packet(&kq(1), true, base, now);
        assert!(e.on_packet(&kr(1), true, base + MS, now).is_empty());
        assert_eq!(e.metrics().held, 1);
        let ev = only_dns(e.tick(now + Duration::from_millis(251)));
        // The /proc row (uid 1000) was never consulted.
        assert_eq!(ev.pid, None);
        assert_eq!(ev.uid, 0);
        let m = e.metrics();
        assert_eq!((m.unattributed, m.attributed), (1, 0));
    }

    #[test]
    fn late_record_attributes_held_response() {
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        assert!(e.on_packet(&kq(1), true, base + MS, now).is_empty());
        assert!(e.on_packet(&kr(1), true, base + 2 * MS, now).is_empty());
        insert_send(&table, base);
        let ev = only_dns(e.tick(now + Duration::from_millis(100)));
        assert_eq!(ev.pid, Some(777));
        assert_eq!(ev.response_ips, vec!["1.2.3.4"]);
        let m = e.metrics();
        assert_eq!((m.attribution_late, m.attributed_kernel), (1, 1));
        assert_eq!((m.unattributed, m.held, m.emitted), (0, 1, 1));
        assert!(e.tick(now + Duration::from_secs(1)).is_empty());
    }

    #[test]
    fn held_response_emits_unattributed_after_grace() {
        let (mut e, _table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        e.on_packet(&kq(1), true, base, now);
        assert!(e.on_packet(&kr(1), true, base + MS, now).is_empty());
        assert!(e.tick(now + Duration::from_millis(249)).is_empty());
        let ev = only_dns(e.tick(now + Duration::from_millis(251)));
        assert_eq!(ev.pid, None);
        assert_eq!(ev.response_ips, vec!["1.2.3.4"]);
        assert_eq!(e.metrics().unattributed, 1);
        assert!(e.tick(now + Duration::from_secs(1)).is_empty());
    }

    #[test]
    fn timeout_close_rechecks_table() {
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        e.on_packet(&kq(1), true, base + MS, now);
        insert_send(&table, base);
        let ev = only_dns(e.tick(now + TX_TIMEOUT + Duration::from_millis(1)));
        assert_eq!(ev.pid, Some(777));
        assert!(ev.response_ips.is_empty());
        let m = e.metrics();
        assert_eq!((m.attribution_late, m.attributed_kernel), (1, 1));
        assert_eq!((m.tracker.timeouts, m.held), (1, 0));
    }

    #[test]
    fn timeout_close_miss_emits_without_hold() {
        let (mut e, _table, _d) = kernel_engine(false);
        let now = Instant::now();
        e.on_packet(&kq(1), true, wall_ns(), now);
        let ev = only_dns(e.tick(now + TX_TIMEOUT + Duration::from_millis(1)));
        assert_eq!(ev.pid, None);
        let m = e.metrics();
        assert_eq!((m.unattributed, m.held), (1, 0));
    }

    #[test]
    fn retransmit_hit_attributes_pending_transaction() {
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        // First packet's record is lost; the retransmit's record is present.
        e.on_packet(&kq(1), true, base, now);
        insert_send(&table, base + 10 * MS);
        e.on_packet(&kq(1), true, base + 11 * MS, now);
        let ev = only_dns(e.on_packet(&kr(1), true, base + 12 * MS, now));
        assert_eq!(ev.pid, Some(777));
        assert_eq!(ev.timestamp_ns, base);
        let m = e.metrics();
        assert_eq!((m.attributed_kernel, m.unattributed), (1, 0));
        assert_eq!(m.tracker.duplicates, 1);
    }

    #[test]
    fn remote_query_in_kernel_mode_is_unattributed_without_hold() {
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        insert_send(&table, base);
        e.on_packet(&kq(1), false, base + MS, now);
        let ev = only_dns(e.on_packet(&kr(1), false, base + 2 * MS, now));
        assert_eq!(ev.pid, None);
        let m = e.metrics();
        assert_eq!((m.unattributed, m.held, m.attributed), (1, 0, 0));
        // The kernel send was not consumed by a remote packet.
        assert_eq!(lock_table(&table).len(), 1);
    }

    #[test]
    fn latch_switches_to_procfs() {
        let (mut e, _table, _d) = kernel_engine(true);
        let now = Instant::now();
        let base = wall_ns();
        e.on_packet(&kq(1), true, base, now);
        e.latch_procfs();
        let ev = only_dns(e.on_packet(&kr(1), true, base + MS, now));
        // uid 1000 comes from the /proc/net/udp fixture.
        assert_eq!(ev.uid, 1000);
        assert_eq!(e.metrics().held, 0);
        // A new query also uses /proc.
        e.on_packet(&kq(2), true, base + 2 * MS, now);
        let ev = only_dns(e.on_packet(&kr(2), true, base + 3 * MS, now));
        assert_eq!(ev.uid, 1000);
    }

    #[test]
    fn latch_resolves_held_response_via_procfs() {
        let (mut e, _table, _d) = kernel_engine(true);
        let now = Instant::now();
        let base = wall_ns();
        e.on_packet(&kq(1), true, base, now);
        assert!(e.on_packet(&kr(1), true, base + MS, now).is_empty());
        e.latch_procfs();
        let ev = only_dns(e.tick(now + Duration::from_millis(10)));
        assert_eq!(ev.uid, 1000);
    }

    #[test]
    fn tick_expires_send_table() {
        let (mut e, table, _d) = kernel_engine(false);
        insert_send(&table, wall_ns().saturating_sub(11_000 * MS));
        assert_eq!(lock_table(&table).len(), 1);
        e.tick(Instant::now());
        assert!(lock_table(&table).is_empty());
    }

    #[test]
    fn drain_emits_held_and_pending_once() {
        let (mut e, table, _d) = kernel_engine(false);
        let now = Instant::now();
        let base = wall_ns();
        // Transaction 1: response held (no record). Transaction 2: query
        // still pending, whose record arrives before the drain.
        e.on_packet(&kq(1), true, base, now);
        assert!(e.on_packet(&kr(1), true, base + MS, now).is_empty());
        e.on_packet(&kq(2), true, base + 3 * MS, now);
        insert_send(&table, base + 2 * MS);
        let evs = e.drain(now + Duration::from_millis(10));
        assert_eq!(evs.len(), 2, "{evs:?}");
        let pids: Vec<Option<u32>> = evs
            .iter()
            .map(|ev| match ev {
                RawEvent::Dns(d) => d.pid,
                other => panic!("{other:?}"),
            })
            .collect();
        assert!(
            pids.contains(&None) && pids.contains(&Some(777)),
            "{pids:?}"
        );
        let m = e.metrics();
        assert_eq!((m.emitted, m.unattributed, m.attributed_kernel), (2, 1, 1));
        assert!(e.tick(now + Duration::from_secs(10)).is_empty());
        assert!(e.drain(now + Duration::from_secs(10)).is_empty());
    }

    #[test]
    fn expire_is_throttled() {
        let (mut e, table, _d) = kernel_engine(false);
        let old = || wall_ns().saturating_sub(11_000 * MS);
        let now = Instant::now();
        insert_send(&table, old());
        e.tick(now);
        assert!(lock_table(&table).is_empty());
        insert_send(&table, old());
        e.tick(now + Duration::from_millis(100));
        assert_eq!(lock_table(&table).len(), 1);
        e.tick(now + Duration::from_millis(1000));
        assert!(lock_table(&table).is_empty());
        assert_eq!(lock_table(&table).counters().expired, 2);
    }

    #[test]
    fn held_queue_is_bounded() {
        let dir = proc_fixture(false);
        let table: SharedSendTable = Arc::new(Mutex::new(SendTable::new()));
        let mut e = Engine::new(
            Attributor::new(dir.path().to_path_buf()),
            AttributionMode::Kernel(table),
            TX_TIMEOUT,
            2,
        );
        let now = Instant::now();
        let base = wall_ns();
        let mut emitted = 0;
        for id in 0..5u16 {
            e.on_packet(&kq(id), true, base, now);
            emitted += e.on_packet(&kr(id), true, base, now).len();
        }
        // Capacity 2: three were forced out unattributed, two still held.
        assert_eq!(emitted, 3);
        assert_eq!(e.tick(now + Duration::from_secs(1)).len(), 2);
        assert_eq!(e.metrics().unattributed, 5);
    }
}
