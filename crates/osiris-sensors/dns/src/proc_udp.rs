//! Parser for `/proc/net/udp` and `/proc/net/udp6`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// One parsed row: the socket's local address, owner uid and inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpRow {
    pub local: SocketAddr,
    pub uid: u32,
    pub inode: u64,
}

/// Decodes `hex` (`N * 2` chars) into bytes where each 32-bit word was
/// printed as a native-endian (little-endian) integer, so the bytes of
/// every 4-byte word are reversed.
fn decode_words<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for word in 0..N / 4 {
        for b in 0..4 {
            let at = (word * 4 + b) * 2;
            out[word * 4 + (3 - b)] = u8::from_str_radix(&hex[at..at + 2], 16).ok()?;
        }
    }
    Some(out)
}

fn parse_local(field: &str, v6: bool) -> Option<SocketAddr> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if v6 {
        IpAddr::V6(Ipv6Addr::from(decode_words::<16>(ip_hex)?))
    } else {
        IpAddr::V4(Ipv4Addr::from(decode_words::<4>(ip_hex)?))
    };
    Some(SocketAddr::new(ip, port))
}

/// Parses a `/proc/net/udp` (`v6 == false`) or `udp6` table. The header and
/// malformed lines are skipped, never panicked on.
pub fn parse_udp_table(text: &str, v6: bool) -> Vec<UdpRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                return None;
            }
            Some(UdpRow {
                local: parse_local(fields[1], v6)?,
                uid: fields[7].parse().ok()?,
                inode: fields[9].parse().ok()?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HDR: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n";

    #[test]
    fn parses_udp_v4_row() {
        let text = format!(
            "{HDR}  12: 0100007F:A028 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 55555 2 0000000000000000 0\n"
        );
        let rows = parse_udp_table(&text, false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local, "127.0.0.1:41000".parse().unwrap());
        assert_eq!(rows[0].uid, 1000);
        assert_eq!(rows[0].inode, 55555);
    }

    #[test]
    fn parses_udp_v6_row() {
        let text = format!(
            "{HDR}   3: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   100        0 777 2 0000000000000000 0\n   4: 0000000000000000FFFF00000100007F:A028 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 888 2 0000000000000000 0\n"
        );
        let rows = parse_udp_table(&text, true);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].local, "[::1]:53".parse().unwrap());
        assert_eq!(rows[0].uid, 100);
        assert_eq!(rows[0].inode, 777);
        assert_eq!(rows[1].local, "[::ffff:127.0.0.1]:41000".parse().unwrap());
    }

    #[test]
    fn malformed_lines_skipped() {
        let text = format!(
            "{HDR}garbage\n 1: ZZZZZZZZ:0035 x 07 a b c 0 0 1 2\n 2: 0100007F:00 x 07 a b c 0 0 notnum 2\n  5: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9 2 0 0\n"
        );
        let rows = parse_udp_table(&text, false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].inode, 9);
        assert!(parse_udp_table("", true).is_empty());
    }
}
