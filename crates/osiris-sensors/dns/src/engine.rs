//! OS-neutral packet-to-event engine: raw L3 packets in, `RawEvent::Dns` out.
//!
//! Composes frame decoding, DNS wire parsing, the transaction tracker and
//! process attribution. The Linux capture loop owns I/O and calls
//! [`Engine::on_packet`] per packet and [`Engine::tick`] periodically.

use std::time::{Duration, Instant};

use osiris_sensor_api::{DnsEventRaw, RawEvent};

use crate::attribution::Attributor;
use crate::frame::{classify, decode_l3, Direction};
use crate::tracker::{Attribution, Tracker, TrackerCounters, TxKey};
use crate::wire::parse_message;

/// How long a query waits for its response before a timeout event.
pub const TX_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum number of simultaneously pending transactions.
pub const MAX_PENDING: usize = 4096;

/// Snapshot of engine counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineMetrics {
    pub packets: u64,
    pub parse_errors: u64,
    pub emitted: u64,
    pub attributed: u64,
    pub unattributed: u64,
    pub tracker: TrackerCounters,
}

pub struct Engine {
    attributor: Attributor,
    tracker: Tracker,
    packets: u64,
    parse_errors: u64,
    emitted: u64,
    attributed: u64,
    unattributed: u64,
}

impl Engine {
    pub fn new(attributor: Attributor, timeout: Duration, capacity: usize) -> Self {
        Self {
            attributor,
            tracker: Tracker::new(timeout, capacity),
            packets: 0,
            parse_errors: 0,
            emitted: 0,
            attributed: 0,
            unattributed: 0,
        }
    }

    pub fn metrics(&self) -> EngineMetrics {
        EngineMetrics {
            packets: self.packets,
            parse_errors: self.parse_errors,
            emitted: self.emitted,
            attributed: self.attributed,
            unattributed: self.unattributed,
            tracker: self.tracker.counters(),
        }
    }

    /// Process one raw L3 packet. Never panics on malformed input.
    ///
    /// `local_origin` is true when the packet was sent by this host (the
    /// capture loop sets it from `sll_pkttype == PACKET_OUTGOING`, or when it
    /// arrived on the loopback interface). Queries from remote clients are
    /// never attributed: their source port says nothing about local sockets.
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
        let Some(direction) = classify(&dg) else {
            return Vec::new();
        };
        let Ok(msg) = parse_message(dg.payload) else {
            self.parse_errors += 1;
            return Vec::new();
        };
        let mut raw: Vec<DnsEventRaw> = Vec::new();
        match direction {
            Direction::Query => {
                if msg.is_response {
                    return Vec::new();
                }
                let key = TxKey {
                    client: dg.src,
                    server: dg.dst.ip(),
                    id: msg.id,
                };
                let attribution = if local_origin {
                    self.attributor.lookup(dg.src, now)
                } else {
                    Attribution::default()
                };
                if attribution.pid.is_some() {
                    self.attributed += 1;
                } else {
                    self.unattributed += 1;
                }
                raw.extend(
                    self.tracker
                        .on_query(key, &msg, attribution, timestamp_ns, now),
                );
            }
            Direction::Response => {
                if !msg.is_response {
                    return Vec::new();
                }
                let key = TxKey {
                    client: dg.dst,
                    server: dg.src.ip(),
                    id: msg.id,
                };
                raw.extend(self.tracker.on_response(key, &msg));
            }
        }
        self.wrap(raw)
    }

    /// Emit timeouts for transactions whose deadline has passed.
    pub fn tick(&mut self, now: Instant) -> Vec<RawEvent> {
        let raw = self.tracker.expire(now);
        self.wrap(raw)
    }

    fn wrap(&mut self, raw: Vec<DnsEventRaw>) -> Vec<RawEvent> {
        self.emitted += raw.len() as u64;
        raw.into_iter().map(RawEvent::Dns).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn engine() -> (Engine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let e = Engine::new(Attributor::new(dir.path().to_path_buf()), TX_TIMEOUT, 16);
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

    fn only_dns(mut evs: Vec<RawEvent>) -> DnsEventRaw {
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
        let mut e = Engine::new(Attributor::new(dir.path().to_path_buf()), TX_TIMEOUT, 16);
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
    fn evicted_transaction_is_emitted() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::new(Attributor::new(dir.path().to_path_buf()), TX_TIMEOUT, 1);
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
}
