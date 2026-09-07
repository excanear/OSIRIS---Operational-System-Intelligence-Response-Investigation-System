/// The `/proc/net/tcp` state value for ESTABLISHED (Linux's
/// `net/tcp_states.h`). This phase reports every row's raw state and lets
/// the caller (`NetworkPoller`) decide what to act on, so a later phase
/// reading LISTEN (0x0A) does not need a second parser.
pub const TCP_ESTABLISHED: u8 = 0x01;

/// One parsed row of `/proc/net/tcp`. IPv4 only (Phase 3 plan Global
/// Constraints #2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRow {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

/// Decodes `/proc/net/tcp`'s `AABBCCDD` hex IPv4 encoding: four hex-byte
/// pairs in reversed order (the kernel prints the 32-bit address as a
/// native-endian integer on little-endian x86/ARM) — `0100007F` decodes to
/// `127.0.0.1`, not `1.0.0.127`.
fn parse_ipv4_hex(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for i in 0..4 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]))
}

/// Decodes one `ADDR:PORT` field (e.g. `0100007F:0050`). The port half is
/// big-endian hex, no byte reversal needed.
fn parse_addr_port(field: &str) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    let ip = parse_ipv4_hex(ip_hex)?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((ip, port))
}

/// Parses a full `/proc/net/tcp`-format table. Malformed lines are
/// skipped, never panicked on.
pub fn parse_tcp_table(text: &str) -> Vec<TcpRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                return None;
            }
            let (local_addr, local_port) = parse_addr_port(fields[1])?;
            let (remote_addr, remote_port) = parse_addr_port(fields[2])?;
            let state = u8::from_str_radix(fields[3], 16).ok()?;
            let uid: u32 = fields[7].parse().ok()?;
            let inode: u64 = fields[9].parse().ok()?;
            Some(TcpRow {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                uid,
                inode,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0500000A:C738 32671BCB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0
   2: 00000000:0016 6400A8C0:C000 01 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_every_data_row_and_skips_the_header() {
        let rows = parse_tcp_table(SAMPLE);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn decodes_the_reversed_hex_ipv4_address_and_big_endian_port() {
        let rows = parse_tcp_table(SAMPLE);
        let outbound = &rows[0];
        assert_eq!(outbound.local_addr, "10.0.0.5");
        assert_eq!(outbound.local_port, 51000);
        assert_eq!(outbound.remote_addr, "203.27.103.50");
        assert_eq!(outbound.remote_port, 443);
        assert_eq!(outbound.state, TCP_ESTABLISHED);
        assert_eq!(outbound.uid, 1000);
        assert_eq!(outbound.inode, 12345);
    }

    #[test]
    fn reports_a_listen_rows_state_without_filtering_it() {
        let rows = parse_tcp_table(SAMPLE);
        assert_eq!(rows[1].state, 0x0A);
        assert_eq!(rows[1].local_port, 22);
    }

    #[test]
    fn a_second_established_row_on_a_well_known_local_port_parses_too() {
        let rows = parse_tcp_table(SAMPLE);
        assert_eq!(rows[2].state, TCP_ESTABLISHED);
        assert_eq!(rows[2].local_port, 22);
        assert_eq!(rows[2].inode, 33333);
    }

    #[test]
    fn malformed_lines_are_skipped_not_panicked_on() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: not-hex:XX also-not-hex:YY ZZ 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
";
        assert_eq!(parse_tcp_table(text).len(), 0);
    }

    #[test]
    fn a_table_with_only_a_header_yields_no_rows() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        assert_eq!(parse_tcp_table(text).len(), 0);
    }
}
