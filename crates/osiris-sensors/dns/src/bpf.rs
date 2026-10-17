//! Classic BPF socket filter admitting only UDP port-53 traffic.
//!
//! OS-neutral data so the program is unit-tested on every host; the Linux
//! capture module converts it to `libc::sock_filter` and attaches it with
//! `SO_ATTACH_FILTER`. On an `AF_PACKET`/`SOCK_DGRAM` socket the data seen
//! by the filter starts at the L3 header, so the EtherType comes from the
//! `SKF_AD_PROTOCOL` ancillary load rather than from a link-layer header.

/// One classic BPF instruction (layout of `struct sock_filter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// Opcode fields, values from linux/bpf_common.h.
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MSH: u16 = 0xa0;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;

// Ancillary load offsets, values from linux/filter.h.
pub const SKF_AD_OFF: i32 = -0x1000;
pub const SKF_AD_PROTOCOL: i32 = 0;

/// EtherTypes (linux/if_ether.h), as returned host-order by the ancillary load.
pub const ETH_P_IP: u32 = 0x0800;
pub const ETH_P_IPV6: u32 = 0x86dd;
const IPPROTO_UDP: u32 = 17;
const DNS_PORT: u32 = 53;

/// Filter verdict for an accepted packet: keep up to 64 KiB of it.
pub const ACCEPT: u32 = 0xffff;
/// Filter verdict for a dropped packet.
pub const DROP: u32 = 0;

const fn stmt(code: u16, k: u32) -> Insn {
    Insn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code, jt, jf, k }
}

/// Relative jump offset from instruction `from` to instruction `to`.
const fn to(from: usize, to: usize) -> u8 {
    (to - from - 1) as u8
}

const JEQ: u16 = BPF_JMP | BPF_JEQ | BPF_K;
const L_V6: usize = 11;
const L_ACCEPT: usize = 18;
const L_DROP: usize = 19;

/// IPv4/UDP (first fragment only) or IPv6/UDP (next header 17) with source
/// or destination port 53. Anything else is dropped in the kernel.
pub const DNS_FILTER: [Insn; 20] = [
    // 0: A = EtherType (ancillary SKF_AD_PROTOCOL, host order).
    stmt(
        BPF_LD | BPF_H | BPF_ABS,
        (SKF_AD_OFF + SKF_AD_PROTOCOL) as u32,
    ),
    // 1: IPv4? else try IPv6.
    jump(JEQ, ETH_P_IP, to(1, 2), to(1, L_V6)),
    // 2: A = IPv4 protocol byte.
    stmt(BPF_LD | BPF_B | BPF_ABS, 9),
    // 3: UDP? else drop.
    jump(JEQ, IPPROTO_UDP, to(3, 4), to(3, L_DROP)),
    // 4: A = flags + fragment offset.
    stmt(BPF_LD | BPF_H | BPF_ABS, 6),
    // 5: non-first fragment (offset != 0)? drop: it carries no UDP header.
    jump(BPF_JMP | BPF_JSET | BPF_K, 0x1fff, to(5, L_DROP), to(5, 6)),
    // 6: X = 4 * IHL (IPv4 header length).
    stmt(BPF_LDX | BPF_B | BPF_MSH, 0),
    // 7: A = UDP source port.
    stmt(BPF_LD | BPF_H | BPF_IND, 0),
    // 8: source port 53? accept.
    jump(JEQ, DNS_PORT, to(8, L_ACCEPT), to(8, 9)),
    // 9: A = UDP destination port.
    stmt(BPF_LD | BPF_H | BPF_IND, 2),
    // 10: destination port 53? accept, else drop.
    jump(JEQ, DNS_PORT, to(10, L_ACCEPT), to(10, L_DROP)),
    // 11 (L_V6): A still holds the EtherType. IPv6? else drop.
    jump(JEQ, ETH_P_IPV6, to(11, 12), to(11, L_DROP)),
    // 12: A = IPv6 next header (extension headers are not followed).
    stmt(BPF_LD | BPF_B | BPF_ABS, 6),
    // 13: UDP? else drop.
    jump(JEQ, IPPROTO_UDP, to(13, 14), to(13, L_DROP)),
    // 14: A = UDP source port (fixed 40-byte IPv6 header).
    stmt(BPF_LD | BPF_H | BPF_ABS, 40),
    // 15: source port 53? accept.
    jump(JEQ, DNS_PORT, to(15, L_ACCEPT), to(15, 16)),
    // 16: A = UDP destination port.
    stmt(BPF_LD | BPF_H | BPF_ABS, 42),
    // 17: destination port 53? accept, else drop.
    jump(JEQ, DNS_PORT, to(17, L_ACCEPT), to(17, L_DROP)),
    // 18 (L_ACCEPT): keep the packet.
    stmt(BPF_RET | BPF_K, ACCEPT),
    // 19 (L_DROP): drop the packet.
    stmt(BPF_RET | BPF_K, DROP),
];

#[cfg(test)]
mod tests {
    use super::*;

    const AD_PROTOCOL: u32 = (SKF_AD_OFF + SKF_AD_PROTOCOL) as u32;

    /// Minimal interpreter for the opcodes `DNS_FILTER` uses, with kernel
    /// semantics: an out-of-bounds load drops the packet.
    fn run(prog: &[Insn], pkt: &[u8], ethertype: u16) -> u32 {
        let load = |off: usize, size: usize| -> Option<u32> {
            let b = pkt.get(off..off.checked_add(size)?)?;
            Some(b.iter().fold(0u32, |acc, &x| (acc << 8) | u32::from(x)))
        };
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        while let Some(i) = prog.get(pc) {
            pc += 1;
            let size = if i.code & 0x18 == BPF_B { 1 } else { 2 };
            let class = i.code & 0x07;
            let mode = i.code & 0xe0;
            if i.code == BPF_LD | BPF_H | BPF_ABS && i.k == AD_PROTOCOL {
                a = u32::from(ethertype);
            } else if class == BPF_LD && (mode == BPF_ABS || mode == BPF_IND) {
                let base = if mode == BPF_IND { x } else { 0 };
                match load((base + i.k) as usize, size) {
                    Some(v) => a = v,
                    None => return 0,
                }
            } else if i.code == BPF_LDX | BPF_B | BPF_MSH {
                match load(i.k as usize, 1) {
                    Some(v) => x = 4 * (v & 0xf),
                    None => return 0,
                }
            } else if i.code == JEQ {
                pc += usize::from(if a == i.k { i.jt } else { i.jf });
            } else if i.code == BPF_JMP | BPF_JSET | BPF_K {
                pc += usize::from(if a & i.k != 0 { i.jt } else { i.jf });
            } else if i.code == BPF_RET | BPF_K {
                return i.k;
            } else {
                panic!("unexpected opcode {:#x}", i.code);
            }
        }
        panic!("fell off the end of the program");
    }

    fn v4(proto: u8, ihl: u8, frag: u16, sport: u16, dport: u16) -> Vec<u8> {
        let hl = usize::from(ihl) * 4;
        let mut p = vec![0u8; hl + 8];
        p[0] = 0x40 | ihl;
        p[6..8].copy_from_slice(&frag.to_be_bytes());
        p[9] = proto;
        p[hl..hl + 2].copy_from_slice(&sport.to_be_bytes());
        p[hl + 2..hl + 4].copy_from_slice(&dport.to_be_bytes());
        p
    }

    fn v6(next: u8, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0] = 0x60;
        p[6] = next;
        p[40..42].copy_from_slice(&sport.to_be_bytes());
        p[42..44].copy_from_slice(&dport.to_be_bytes());
        p
    }

    const IP: u16 = ETH_P_IP as u16;
    const IP6: u16 = ETH_P_IPV6 as u16;

    #[test]
    fn jumps_stay_in_bounds_and_program_ends_in_return() {
        let n = DNS_FILTER.len();
        assert!(n <= 64);
        for (i, ins) in DNS_FILTER.iter().enumerate() {
            if ins.code & 0x07 == BPF_JMP {
                assert!(i + 1 + usize::from(ins.jt) < n, "jt of {i}");
                assert!(i + 1 + usize::from(ins.jf) < n, "jf of {i}");
            }
        }
        assert_eq!(DNS_FILTER[n - 1].code & 0x07, BPF_RET);
    }

    #[test]
    fn ipv4_udp_port_53_accepted_either_direction() {
        assert_eq!(run(&DNS_FILTER, &v4(17, 5, 0, 41000, 53), IP), ACCEPT);
        assert_eq!(run(&DNS_FILTER, &v4(17, 5, 0, 53, 41000), IP), ACCEPT);
        // IP options: the UDP header is located via IHL.
        assert_eq!(run(&DNS_FILTER, &v4(17, 6, 0, 41000, 53), IP), ACCEPT);
        // DF flag set, offset 0: still a first fragment.
        assert_eq!(run(&DNS_FILTER, &v4(17, 5, 0x4000, 41000, 53), IP), ACCEPT);
    }

    #[test]
    fn ipv4_non_dns_dropped() {
        assert_eq!(run(&DNS_FILTER, &v4(17, 5, 0, 41000, 443), IP), DROP);
        assert_eq!(run(&DNS_FILTER, &v4(6, 5, 0, 41000, 53), IP), DROP);
        // Non-first fragment whose payload happens to look like port 53.
        assert_eq!(run(&DNS_FILTER, &v4(17, 5, 0x0001, 41000, 53), IP), DROP);
        // Truncated before the destination port.
        assert_eq!(run(&DNS_FILTER, &v4(17, 5, 0, 41000, 53)[..22], IP), DROP);
    }

    #[test]
    fn ipv6_udp_port_53_accepted_and_others_dropped() {
        assert_eq!(run(&DNS_FILTER, &v6(17, 42000, 53), IP6), ACCEPT);
        assert_eq!(run(&DNS_FILTER, &v6(17, 53, 42000), IP6), ACCEPT);
        assert_eq!(run(&DNS_FILTER, &v6(17, 42000, 80), IP6), DROP);
        // Hop-by-hop extension header: not followed.
        assert_eq!(run(&DNS_FILTER, &v6(0, 42000, 53), IP6), DROP);
    }

    #[test]
    fn other_ethertypes_dropped() {
        assert_eq!(run(&DNS_FILTER, &v4(17, 5, 0, 41000, 53), 0x0806), DROP);
        assert_eq!(run(&DNS_FILTER, &v6(17, 42000, 53), IP), DROP);
    }
}
