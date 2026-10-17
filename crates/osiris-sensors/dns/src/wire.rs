//! Panic-free, bounded DNS wire-format parser (RFC 1035).
//!
//! Operates on untrusted packet bytes. Limits: names <= 255 bytes on the wire,
//! labels <= 63, <= 16 compression jumps, <= 64 answer RRs inspected. Only the
//! first question is retained; any further questions are skipped.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const HEADER_LEN: usize = 12;
const MAX_NAME_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;
const MAX_JUMPS: usize = 16;
const MAX_ANSWERS: usize = 64;

/// A parsed DNS message (header, first question, inspected answers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub rcode: u8,
    pub question: Option<Question>,
    pub answers: Vec<Answer>,
}

/// The first question of a message. `name` is lower-cased, no trailing dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
}

/// One answer RR. `addr` is set for A / AAAA records only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub rtype: u16,
    pub ttl: u32,
    pub addr: Option<IpAddr>,
}

/// Why a buffer could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended before a complete field.
    Truncated,
    /// Invalid label type or label longer than 63 bytes.
    BadName,
    /// Name longer than 255 bytes on the wire.
    NameTooLong,
    /// Compression pointers exceeded the jump limit (likely a loop).
    TooManyJumps,
}

/// Parse a DNS message. Never panics; all reads are bounds-checked.
pub fn parse_message(buf: &[u8]) -> Result<DnsMessage, WireError> {
    if buf.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = HEADER_LEN;
    let mut question = None;
    for i in 0..qdcount {
        let (name, next) = read_name(buf, pos)?;
        let qtype = read_u16(buf, next)?;
        read_u16(buf, next + 2)?; // qclass
        pos = next + 4;
        if i == 0 {
            question = Some(Question { name, qtype });
        }
    }

    let mut answers = Vec::new();
    for _ in 0..ancount.min(MAX_ANSWERS) {
        let (_, next) = read_name(buf, pos)?;
        let rtype = read_u16(buf, next)?;
        let ttl = read_u32(buf, next + 4)?;
        let rdlen = read_u16(buf, next + 8)? as usize;
        let start = next + 10;
        let end = start.checked_add(rdlen).ok_or(WireError::Truncated)?;
        let rdata = buf.get(start..end).ok_or(WireError::Truncated)?;
        let addr = match (rtype, rdata.len()) {
            (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (28, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                Some(IpAddr::V6(Ipv6Addr::from(o)))
            }
            _ => None,
        };
        answers.push(Answer { rtype, ttl, addr });
        pos = end;
    }

    Ok(DnsMessage {
        id,
        is_response: flags & 0x8000 != 0,
        rcode: (flags & 0x000f) as u8,
        question,
        answers,
    })
}

fn read_u16(buf: &[u8], pos: usize) -> Result<u16, WireError> {
    let end = pos.checked_add(2).ok_or(WireError::Truncated)?;
    let b = buf.get(pos..end).ok_or(WireError::Truncated)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32(buf: &[u8], pos: usize) -> Result<u32, WireError> {
    let end = pos.checked_add(4).ok_or(WireError::Truncated)?;
    let b = buf.get(pos..end).ok_or(WireError::Truncated)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a (possibly compressed) name at `start`. Returns the lower-cased
/// dotted name and the position just after the name's in-place encoding.
fn read_name(buf: &[u8], start: usize) -> Result<(String, usize), WireError> {
    let mut name = String::new();
    let mut pos = start;
    let mut after: Option<usize> = None;
    let mut jumps = 0usize;
    let mut wire_len = 1usize; // terminating root byte
    loop {
        let len = *buf.get(pos).ok_or(WireError::Truncated)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    pos += 1;
                    break;
                }
                let l = len as usize;
                if l > MAX_LABEL_LEN {
                    return Err(WireError::BadName);
                }
                wire_len += l + 1;
                if wire_len > MAX_NAME_LEN {
                    return Err(WireError::NameTooLong);
                }
                let label = buf.get(pos + 1..pos + 1 + l).ok_or(WireError::Truncated)?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
                pos += 1 + l;
            }
            0xc0 => {
                let lo = *buf.get(pos + 1).ok_or(WireError::Truncated)?;
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err(WireError::TooManyJumps);
                }
                if after.is_none() {
                    after = Some(pos + 2);
                }
                pos = (((len & 0x3f) as usize) << 8) | lo as usize;
            }
            _ => return Err(WireError::BadName),
        }
    }
    Ok((name, after.unwrap_or(pos)))
}

/// Mnemonic for a query type, or `TYPE<n>` when unknown.
pub fn qtype_mnemonic(qtype: u16) -> String {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        n => return format!("TYPE{n}"),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(id: u16, flags: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut v = Vec::new();
        for x in [id, flags, qd, an, 0, 0] {
            v.extend_from_slice(&x.to_be_bytes());
        }
        v
    }

    fn name(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in s.split('.') {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    fn question(s: &str, qtype: u16) -> Vec<u8> {
        let mut v = name(s);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v
    }

    /// RR whose owner name is a compression pointer to offset 12.
    fn rr(rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut v = vec![0xc0, 0x0c];
        v.extend_from_slice(&rtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        v.extend_from_slice(rdata);
        v
    }

    #[test]
    fn parses_a_query() {
        let mut p = header(0x1234, 0x0100, 1, 0);
        p.extend(question("example.com", 1));
        let m = parse_message(&p).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(!m.is_response);
        assert_eq!(m.rcode, 0);
        assert_eq!(
            m.question,
            Some(Question {
                name: "example.com".into(),
                qtype: 1
            })
        );
        assert!(m.answers.is_empty());
    }

    #[test]
    fn parses_a_response_with_two_a_records() {
        let mut p = header(7, 0x8180, 1, 2);
        p.extend(question("example.com", 1));
        p.extend(rr(1, 300, &[93, 184, 216, 34]));
        p.extend(rr(1, 60, &[1, 2, 3, 4]));
        let m = parse_message(&p).unwrap();
        assert!(m.is_response);
        assert_eq!(m.answers.len(), 2);
        assert_eq!(m.answers[0].addr, Some("93.184.216.34".parse().unwrap()));
        assert_eq!(m.answers[0].ttl, 300);
        assert_eq!(m.answers[1].addr, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(m.answers[1].ttl, 60);
    }

    #[test]
    fn parses_aaaa_answer() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut p = header(1, 0x8180, 1, 1);
        p.extend(question("example.com", 28));
        p.extend(rr(28, 120, &ip.octets()));
        let m = parse_message(&p).unwrap();
        assert_eq!(m.answers[0].rtype, 28);
        assert_eq!(m.answers[0].addr, Some(IpAddr::V6(ip)));
    }

    #[test]
    fn cname_chain_then_a() {
        let mut p = header(1, 0x8180, 1, 2);
        p.extend(question("www.example.com", 1));
        p.extend(rr(5, 30, &name("edge.example.net")));
        p.extend(rr(1, 20, &[10, 0, 0, 9]));
        let m = parse_message(&p).unwrap();
        assert_eq!(m.answers.len(), 2);
        assert_eq!(m.answers[0].rtype, 5);
        assert_eq!(m.answers[0].addr, None);
        assert_eq!(m.answers[1].addr, Some("10.0.0.9".parse().unwrap()));
    }

    #[test]
    fn nxdomain_rcode_3_no_answers() {
        let mut p = header(1, 0x8183, 1, 0);
        p.extend(question("nope.example.com", 1));
        let m = parse_message(&p).unwrap();
        assert_eq!(m.rcode, 3);
        assert!(m.answers.is_empty());
    }

    #[test]
    fn compressed_name_pointer() {
        // Second question's name is a pointer to the first.
        let mut p = header(1, 0x0100, 2, 0);
        p.extend(question("a.example.com", 1));
        p.extend([0xc0, 0x0c, 0, 28, 0, 1]);
        let m = parse_message(&p).unwrap();
        assert_eq!(m.question.unwrap().name, "a.example.com");

        // A name that is a label followed by a pointer to a later suffix.
        let mut p = header(1, 0x0100, 1, 0);
        p.extend([3, b'w', b'w', b'w', 0xc0, 22]); // offsets 12..18
        p.extend([0, 1, 0, 1]); // qtype/qclass, offsets 18..22
        p.extend(name("example.com")); // suffix at offset 22
        let m = parse_message(&p).unwrap();
        assert_eq!(m.question.unwrap().name, "www.example.com");
    }

    #[test]
    fn compression_loop_is_error() {
        let mut p = header(1, 0x0100, 1, 0);
        p.extend([0xc0, 0x0c, 0, 1, 0, 1]); // points at itself
        assert_eq!(parse_message(&p), Err(WireError::TooManyJumps));
    }

    #[test]
    fn name_over_255_is_error() {
        let mut p = header(1, 0x0100, 1, 0);
        for _ in 0..5 {
            p.push(63);
            p.extend([b'a'; 63]);
        }
        p.push(0);
        p.extend([0, 1, 0, 1]);
        assert_eq!(parse_message(&p), Err(WireError::NameTooLong));
    }

    #[test]
    fn label_over_63_is_error() {
        let mut p = header(1, 0x0100, 1, 0);
        p.push(64);
        p.extend([b'a'; 64]);
        p.push(0);
        p.extend([0, 1, 0, 1]);
        assert_eq!(parse_message(&p), Err(WireError::BadName));
    }

    #[test]
    fn truncated_header_is_error() {
        assert_eq!(parse_message(&[0; 11]), Err(WireError::Truncated));
        assert_eq!(parse_message(&[]), Err(WireError::Truncated));
    }

    #[test]
    fn answer_count_lies_is_error_or_partial() {
        let mut p = header(1, 0x8180, 1, 50);
        p.extend(question("example.com", 1));
        p.extend(rr(1, 10, &[1, 1, 1, 1]));
        assert_eq!(parse_message(&p), Err(WireError::Truncated));
    }

    #[test]
    fn qtype_mnemonics() {
        assert_eq!(qtype_mnemonic(1), "A");
        assert_eq!(qtype_mnemonic(28), "AAAA");
        assert_eq!(qtype_mnemonic(65), "HTTPS");
        assert_eq!(qtype_mnemonic(255), "ANY");
        assert_eq!(qtype_mnemonic(999), "TYPE999");
    }

    #[test]
    fn uppercase_name_is_lowercased() {
        let mut p = header(1, 0x0100, 1, 0);
        p.extend(question("ExAmPlE.COM", 1));
        assert_eq!(
            parse_message(&p).unwrap().question.unwrap().name,
            "example.com"
        );
    }
}
