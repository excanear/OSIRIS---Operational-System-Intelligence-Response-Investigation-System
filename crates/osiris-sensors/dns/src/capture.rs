//! Linux `AF_PACKET` capture: socket setup and one-packet receive.
//!
//! The socket is created with protocol 0 (it receives nothing), gets the
//! [`crate::bpf::DNS_FILTER`] program and a receive timeout, and only then
//! is bound with `htons(ETH_P_ALL)` — so no unfiltered packet is ever
//! queued between `socket(2)` and `SO_ATTACH_FILTER`. The descriptor is an
//! [`OwnedFd`], closed on every path when dropped.

use std::ffi::CString;
use std::fmt;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use crate::bpf::DNS_FILTER;

/// Receive timeout: bounds how long cancellation and engine ticks wait.
pub(crate) const RECV_TIMEOUT: Duration = Duration::from_millis(500);
/// Receive buffer size; the filter accepts at most 0xffff bytes.
pub(crate) const RECV_BUF: usize = 65536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CaptureError {
    Os { op: &'static str, errno: i32 },
    NoInterface(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os { op, errno } => write!(f, "AF_PACKET {op} failed: errno {errno}"),
            Self::NoInterface(name) => write!(f, "capture interface {name:?} not found"),
        }
    }
}

/// Result of one receive call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recv {
    /// `len` bytes of L3 packet are in the buffer.
    Packet { len: usize, local_origin: bool },
    /// Duplicate loopback copy; ignore.
    Skip,
    /// No packet within [`RECV_TIMEOUT`] (or interrupted).
    Timeout,
    /// Socket error (errno).
    Error(i32),
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn os_err(op: &'static str) -> CaptureError {
    CaptureError::Os { op, errno: errno() }
}

fn new_socket() -> Result<OwnedFd, i32> {
    // SAFETY: socket(2) takes no pointers; constant arguments.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(errno());
    }
    // SAFETY: `fd` is a freshly created, valid descriptor owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Capability probe: open and immediately close an `AF_PACKET` socket.
pub(crate) fn probe() -> Result<(), i32> {
    new_socket().map(drop)
}

/// The filter program in kernel layout.
pub(crate) fn sock_filters() -> Vec<libc::sock_filter> {
    DNS_FILTER
        .iter()
        .map(|i| libc::sock_filter {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        })
        .collect()
}

fn ifindex(name: &str) -> Option<i32> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string for the duration of the call.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    i32::try_from(idx).ok().filter(|&i| i != 0)
}

fn setsockopt<T>(fd: &OwnedFd, name: libc::c_int, value: &T) -> Result<(), ()> {
    // SAFETY: `value` is a valid, initialised `T` that outlives the call and
    // the length passed is exactly its size; the kernel copies it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            name,
            (value as *const T).cast(),
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// Decide what to do with a received packet (Ruling R4). On loopback every
/// packet is seen twice (outgoing then incoming): the outgoing copy is
/// skipped and the incoming one is still local-origin. Elsewhere, only
/// `PACKET_OUTGOING` packets were sent by this host. `None` = skip.
pub(crate) fn disposition(pkttype: u8, ifindex: i32, lo_ifindex: Option<i32>) -> Option<bool> {
    let on_lo = lo_ifindex == Some(ifindex);
    let outgoing = pkttype == libc::PACKET_OUTGOING;
    if on_lo && outgoing {
        None
    } else {
        Some(outgoing || on_lo)
    }
}

pub(crate) struct Capture {
    fd: OwnedFd,
    lo_ifindex: Option<i32>,
}

impl Capture {
    /// Open, filter and bind the capture socket; `interface` `None` = all.
    pub(crate) fn open(interface: Option<&str>) -> Result<Self, CaptureError> {
        let bind_index = match interface {
            Some(name) => ifindex(name).ok_or_else(|| CaptureError::NoInterface(name.into()))?,
            None => 0,
        };
        let fd = new_socket().map_err(|errno| CaptureError::Os {
            op: "socket",
            errno,
        })?;

        let mut prog = sock_filters();
        let fprog = libc::sock_fprog {
            len: prog.len() as libc::c_ushort,
            filter: prog.as_mut_ptr(),
        };
        setsockopt(&fd, libc::SO_ATTACH_FILTER, &fprog).map_err(|_| os_err("SO_ATTACH_FILTER"))?;

        let tv = libc::timeval {
            tv_sec: RECV_TIMEOUT.as_secs() as libc::time_t,
            tv_usec: RECV_TIMEOUT.subsec_micros() as libc::suseconds_t,
        };
        setsockopt(&fd, libc::SO_RCVTIMEO, &tv).map_err(|_| os_err("SO_RCVTIMEO"))?;

        // SAFETY: `sockaddr_ll` is a plain C struct for which all-zero is valid.
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as libc::c_ushort;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = bind_index;
        // SAFETY: `sll` is a valid `sockaddr_ll` and the length is its size.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&sll as *const libc::sockaddr_ll).cast(),
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(os_err("bind"));
        }

        Ok(Self {
            fd,
            lo_ifindex: ifindex("lo"),
        })
    }

    /// Receive one packet into `buf`, blocking at most [`RECV_TIMEOUT`].
    pub(crate) fn recv(&self, buf: &mut [u8]) -> Recv {
        // SAFETY: `sockaddr_ll` is a plain C struct for which all-zero is valid.
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        let mut alen = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // SAFETY: `buf`, `sll` and `alen` are valid and writable for the
        // lengths passed, for the whole duration of the call.
        let n = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&mut sll as *mut libc::sockaddr_ll).cast(),
                &mut alen,
            )
        };
        if n < 0 {
            let e = errno();
            return if e == libc::EAGAIN || e == libc::EWOULDBLOCK || e == libc::EINTR {
                Recv::Timeout
            } else {
                Recv::Error(e)
            };
        }
        let len = usize::try_from(n).unwrap_or(0).min(buf.len());
        match disposition(sll.sll_pkttype, sll.sll_ifindex, self.lo_ifindex) {
            Some(local_origin) => Recv::Packet { len, local_origin },
            None => Recv::Skip,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf;

    #[test]
    fn cbpf_program_is_well_formed() {
        let prog = sock_filters();
        assert!(!prog.is_empty() && prog.len() <= 64);
        let last = prog[prog.len() - 1];
        assert_eq!(u32::from(last.code) & 0x07, libc::BPF_RET);
        // The first instruction is the ancillary protocol load.
        assert_eq!(prog[0].k, (libc::SKF_AD_OFF + libc::SKF_AD_PROTOCOL) as u32);
        for (i, ins) in prog.iter().enumerate() {
            if u32::from(ins.code) & 0x07 == libc::BPF_JMP {
                assert!(i + 1 + usize::from(ins.jt) < prog.len());
                assert!(i + 1 + usize::from(ins.jf) < prog.len());
            }
        }
    }

    #[test]
    fn local_bpf_constants_match_libc() {
        let pairs: [(u16, u32); 12] = [
            (bpf::BPF_LD, libc::BPF_LD),
            (bpf::BPF_LDX, libc::BPF_LDX),
            (bpf::BPF_JMP, libc::BPF_JMP),
            (bpf::BPF_RET, libc::BPF_RET),
            (bpf::BPF_H, libc::BPF_H),
            (bpf::BPF_B, libc::BPF_B),
            (bpf::BPF_ABS, libc::BPF_ABS),
            (bpf::BPF_IND, libc::BPF_IND),
            (bpf::BPF_MSH, libc::BPF_MSH),
            (bpf::BPF_JEQ, libc::BPF_JEQ),
            (bpf::BPF_JSET, libc::BPF_JSET),
            (bpf::BPF_K, libc::BPF_K),
        ];
        for (local, sys) in pairs {
            assert_eq!(u32::from(local), sys);
        }
        assert_eq!(bpf::SKF_AD_OFF, libc::SKF_AD_OFF);
        assert_eq!(bpf::SKF_AD_PROTOCOL, libc::SKF_AD_PROTOCOL);
        assert_eq!(bpf::ETH_P_IP, libc::ETH_P_IP as u32);
        assert_eq!(bpf::ETH_P_IPV6, libc::ETH_P_IPV6 as u32);
    }

    #[test]
    fn loopback_outgoing_copy_is_skipped() {
        let lo = Some(1);
        // lo: outgoing copy skipped, incoming copy kept as local-origin.
        assert_eq!(disposition(libc::PACKET_OUTGOING, 1, lo), None);
        assert_eq!(disposition(libc::PACKET_HOST, 1, lo), Some(true));
        // Other interfaces: outgoing is local, incoming is not.
        assert_eq!(disposition(libc::PACKET_OUTGOING, 2, lo), Some(true));
        assert_eq!(disposition(libc::PACKET_HOST, 2, lo), Some(false));
        // Unknown loopback index: nothing is skipped.
        assert_eq!(disposition(libc::PACKET_OUTGOING, 1, None), Some(true));
    }
}
