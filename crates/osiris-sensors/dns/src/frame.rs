//! L3/UDP frame decoding.
//!
//! Input is an IP packet as `AF_PACKET` `SOCK_DGRAM` delivers it: the buffer
//! starts at the IPv4/IPv6 header (the link-layer header is already stripped).
//! All reads are bounds-checked; malformed or unsupported packets yield `None`.
//! Fragmented IPv4 and IPv6 packets with extension headers are skipped by
//! design (fragmented DNS is not inspected).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const PROTO_UDP: u8 = 17;
const UDP_HEADER_LEN: usize = 8;
const DNS_PORT: u16 = 53;

/// A decoded UDP datagram borrowing its payload from the capture buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: &'a [u8],
}

/// Whether a DNS-port datagram is a query or a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Query,
    Response,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

/// Decode an IPv4 or IPv6 packet carrying UDP. Returns `None` for anything
/// else (non-UDP, fragments, IPv6 extension headers, truncated/malformed).
pub fn decode_l3(buf: &[u8]) -> Option<UdpDatagram<'_>> {
    match buf.first()? >> 4 {
        4 => decode_v4(buf),
        6 => decode_v6(buf),
        _ => None,
    }
}

fn decode_v4(buf: &[u8]) -> Option<UdpDatagram<'_>> {
    let hdr = usize::from(buf.first()? & 0x0f) * 4;
    if hdr < 20 || buf.len() < hdr {
        return None;
    }
    let total = usize::from(be16(buf, 2)?);
    if total < hdr {
        return None;
    }
    // Fragment offset != 0 or More-Fragments set: skip.
    if be16(buf, 6)? & 0x3fff != 0 {
        return None;
    }
    if *buf.get(9)? != PROTO_UDP {
        return None;
    }
    let src = Ipv4Addr::new(*buf.get(12)?, *buf.get(13)?, *buf.get(14)?, *buf.get(15)?);
    let dst = Ipv4Addr::new(*buf.get(16)?, *buf.get(17)?, *buf.get(18)?, *buf.get(19)?);
    let end = total.min(buf.len());
    decode_udp(buf.get(hdr..end)?, IpAddr::V4(src), IpAddr::V4(dst))
}

fn decode_v6(buf: &[u8]) -> Option<UdpDatagram<'_>> {
    const HDR: usize = 40;
    if buf.len() < HDR {
        return None;
    }
    // Only UDP directly after the fixed header; extension headers are skipped.
    if buf[6] != PROTO_UDP {
        return None;
    }
    let plen = usize::from(be16(buf, 4)?);
    let mut s = [0u8; 16];
    s.copy_from_slice(buf.get(8..24)?);
    let mut d = [0u8; 16];
    d.copy_from_slice(buf.get(24..40)?);
    let end = HDR.saturating_add(plen).min(buf.len());
    decode_udp(
        buf.get(HDR..end)?,
        IpAddr::V6(Ipv6Addr::from(s)),
        IpAddr::V6(Ipv6Addr::from(d)),
    )
}

fn decode_udp(seg: &[u8], src: IpAddr, dst: IpAddr) -> Option<UdpDatagram<'_>> {
    let sport = be16(seg, 0)?;
    let dport = be16(seg, 2)?;
    let len = usize::from(be16(seg, 4)?);
    if len < UDP_HEADER_LEN {
        return None;
    }
    let payload = seg.get(UDP_HEADER_LEN..len)?;
    Some(UdpDatagram {
        src: SocketAddr::new(src, sport),
        dst: SocketAddr::new(dst, dport),
        payload,
    })
}

/// Source port 53 is a response (even 53->53); destination 53 otherwise a query.
pub fn classify(d: &UdpDatagram) -> Option<Direction> {
    if d.src.port() == DNS_PORT {
        Some(Direction::Response)
    } else if d.dst.port() == DNS_PORT {
        Some(Direction::Query)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = Vec::new();
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(payload);
        u
    }

    fn v4(ihl: u8, frag: u16, proto: u8, seg: &[u8]) -> Vec<u8> {
        let hdr = usize::from(ihl) * 4;
        let mut p = vec![0u8; hdr];
        p[0] = 0x40 | ihl;
        p[2..4].copy_from_slice(&((hdr + seg.len()) as u16).to_be_bytes());
        p[6..8].copy_from_slice(&frag.to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p.extend_from_slice(seg);
        p
    }

    fn v6(next: u8, seg: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(seg.len() as u16).to_be_bytes());
        p[6] = next;
        p[7] = 64;
        p[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        p[24..40].copy_from_slice(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets());
        p.extend_from_slice(seg);
        p
    }

    #[test]
    fn ipv4_udp_decodes() {
        for ihl in [5u8, 6] {
            let pkt = v4(ihl, 0, 17, &udp(40000, 53, b"hello"));
            let d = decode_l3(&pkt).expect("decodes");
            assert_eq!(d.src, "10.0.0.1:40000".parse().unwrap());
            assert_eq!(d.dst, "10.0.0.2:53".parse().unwrap());
            assert_eq!(d.payload, b"hello");
        }
    }

    #[test]
    fn ipv4_ignores_trailing_padding() {
        let mut pkt = v4(5, 0, 17, &udp(1, 53, b"abc"));
        pkt.extend_from_slice(&[0xff; 6]);
        assert_eq!(decode_l3(&pkt).unwrap().payload, b"abc");
    }

    #[test]
    fn ipv6_udp_decodes() {
        let pkt = v6(17, &udp(53, 50000, b"resp"));
        let d = decode_l3(&pkt).expect("decodes");
        assert_eq!(d.src, "[::1]:53".parse().unwrap());
        assert_eq!(d.dst, "[fe80::1]:50000".parse().unwrap());
        assert_eq!(d.payload, b"resp");
    }

    #[test]
    fn ipv4_non_first_fragment_ignored() {
        let pkt = v4(5, 0x0001, 17, &udp(1, 53, b"x"));
        assert!(decode_l3(&pkt).is_none());
    }

    #[test]
    fn ipv4_more_fragments_first_fragment_ignored() {
        let pkt = v4(5, 0x2000, 17, &udp(1, 53, b"x"));
        assert!(decode_l3(&pkt).is_none());
    }

    #[test]
    fn ipv6_extension_header_ignored() {
        let pkt = v6(0, &udp(1, 53, b"x"));
        assert!(decode_l3(&pkt).is_none());
    }

    #[test]
    fn non_udp_ignored() {
        assert!(decode_l3(&v4(5, 0, 6, &udp(1, 53, b"x"))).is_none());
        assert!(decode_l3(&v6(6, &udp(1, 53, b"x"))).is_none());
    }

    #[test]
    fn udp_length_beyond_buffer_ignored() {
        let mut seg = udp(1, 53, b"abcd");
        seg[4..6].copy_from_slice(&200u16.to_be_bytes());
        assert!(decode_l3(&v4(5, 0, 17, &seg)).is_none());
        assert!(decode_l3(&v6(17, &seg)).is_none());
        // Truncated buffer with IP total length beyond it.
        let mut pkt = v4(5, 0, 17, &udp(1, 53, b"abcd"));
        pkt.truncate(pkt.len() - 2);
        assert!(decode_l3(&pkt).is_none());
    }

    #[test]
    fn garbage_never_panics() {
        assert!(decode_l3(&[]).is_none());
        assert!(decode_l3(&[0x45]).is_none());
        assert!(decode_l3(&[0x60; 10]).is_none());
        assert!(decode_l3(&[0x4f; 30]).is_none());
        let mut bad = v4(5, 0, 17, &udp(1, 53, b""));
        bad[2..4].copy_from_slice(&3u16.to_be_bytes());
        assert!(decode_l3(&bad).is_none());
        let mut short_udp = v4(5, 0, 17, &udp(1, 53, b""));
        short_udp[24..26].copy_from_slice(&4u16.to_be_bytes());
        assert!(decode_l3(&short_udp).is_none());
    }

    fn dg(sport: u16, dport: u16) -> UdpDatagram<'static> {
        UdpDatagram {
            src: SocketAddr::from(([1, 1, 1, 1], sport)),
            dst: SocketAddr::from(([2, 2, 2, 2], dport)),
            payload: &[],
        }
    }

    #[test]
    fn classify_query_and_response() {
        assert_eq!(classify(&dg(40000, 53)), Some(Direction::Query));
        assert_eq!(classify(&dg(53, 40000)), Some(Direction::Response));
        assert_eq!(classify(&dg(1000, 2000)), None);
    }

    #[test]
    fn classify_53_to_53_is_response() {
        assert_eq!(classify(&dg(53, 53)), Some(Direction::Response));
    }
}
