//! Real-kernel load of `dns.bpf.o` (Linux, root, `$OSIRIS_BPF_DIR`).
//!
//! Ignored by default: the real-Linux workflow runs it as root with
//! `--include-ignored --test-threads=1` after `tools/real-linux/setup.sh`
//! has built the objects into `$OSIRIS_BPF_DIR`; the unprivileged
//! unit-test step skips it by name. It proves the verifier accepts both
//! kprobes, that they attach, that a UDP send to port 53 is reported once
//! per family with its tuple, sender and network namespace, that a send to
//! another port is not, and that the agent's own sends are emitted although
//! SELF_TGID is set to this process.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use osiris_ebpf::{decode_dns, spawn_reader, DnsSendEvent, LoadedObject, DNS_OBJECT};
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(5);
/// 12 bytes: the size of a DNS header (the payload is never parsed here).
const PAYLOAD: [u8; 12] = *b"osiris-dns-t";

/// `name=count` (or `name=n/a`) for each verified-instruction count.
fn insn_list(counts: &[(String, Option<u32>)]) -> String {
    counts
        .iter()
        .map(|(name, n)| match n {
            Some(n) => format!("{name}={n}"),
            None => format!("{name}=n/a"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The initial pid namespace's fixed inode (PROC_PID_INIT_INO, 0xEFFFFFFC).
const INIT_PID_NS_INO: u64 = 0xEFFF_FFFC;

/// True when this process's pids are the kernel's root-namespace pids (the
/// ones BPF reports): one `NSpid:` field, and the pid namespace is the
/// initial one. NSpid alone is not enough: under WSL2 the distro runs in a
/// child pid namespace with its own /proc mount, where NSpid shows a
/// single field, so the inode check is what keeps the test valid there.
fn in_root_pid_namespace() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    let one_level = status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))
        .is_some_and(|rest| rest.split_whitespace().count() == 1);
    let pidns = std::fs::metadata("/proc/self/ns/pid")
        .expect("stat /proc/self/ns/pid")
        .ino();
    one_level && pidns == INIT_PID_NS_INO
}

#[test]
#[ignore = "needs root, a BPF-capable kernel and $OSIRIS_BPF_DIR (real-Linux workflow)"]
fn dns_object_loads_and_reports_a_send() {
    // SAFETY: geteuid() takes no arguments and cannot fail.
    assert_eq!(unsafe { libc::geteuid() }, 0, "must run as root");
    let bpf_dir = PathBuf::from(
        std::env::var_os("OSIRIS_BPF_DIR")
            .expect("OSIRIS_BPF_DIR is unset: build the objects with tools/ebpf/build.sh"),
    );
    let pid = std::process::id();
    // SELF_TGID = this process: the program must ignore it.
    let obj = match LoadedObject::load(&bpf_dir, &DNS_OBJECT, pid) {
        Ok(obj) => obj,
        Err(e) => {
            // Display keeps the verifier log's line breaks.
            eprintln!("{e}");
            panic!("loading dns.bpf.o failed (error above)");
        }
    };
    println!(
        "osiris-ebpf: dns verified insns: {}",
        insn_list(&obj.verified_instruction_counts())
    );

    let (tx, rx) = mpsc::channel::<DnsSendEvent>();
    let cancel = CancellationToken::new();
    let reader = spawn_reader(obj, decode_dns, cancel.clone(), move |r| {
        if let Ok(ev) = r {
            let _ = tx.send(ev);
        }
    })
    .expect("spawn reader");

    let v4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind 127.0.0.1:0");
    let v4_port = v4.local_addr().expect("v4 local addr").port();
    let v4_dns = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let v4_other = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353);
    let v6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind [::1]:0");
    let v6_port = v6.local_addr().expect("v6 local addr").port();
    let v6_dns = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);
    // Nothing need listen: the sends complete (an ICMP unreachable is not
    // reported on an unconnected socket) and the kprobes fire on entry.
    v4.send_to(&PAYLOAD, v4_other)
        .expect("send to 127.0.0.1:5353");
    v4.send_to(&PAYLOAD, v4_dns).expect("send to 127.0.0.1:53");
    v6.send_to(&PAYLOAD, v6_dns).expect("send to [::1]:53");

    let is_v4 = |e: &DnsSendEvent| e.local.port() == v4_port && e.remote == v4_dns;
    let is_v6 = |e: &DnsSendEvent| e.local.port() == v6_port && e.remote == v6_dns;
    let mut seen: Vec<DnsSendEvent> = Vec::new();
    let deadline = Instant::now() + WAIT;
    while !(seen.iter().any(is_v4) && seen.iter().any(is_v6)) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(ev) => seen.push(ev),
            Err(_) => break,
        }
    }
    // A straggler for 5353 would arrive in order, before the port-53 one;
    // give one a moment anyway.
    let grace = Instant::now() + Duration::from_millis(300);
    while let Ok(ev) = rx.recv_timeout(grace.saturating_duration_since(Instant::now())) {
        seen.push(ev);
    }
    cancel.cancel();
    let joined = reader.join();
    assert!(
        matches!(joined, Ok(Ok(()))),
        "reader ended badly: {joined:?}"
    );

    let mine: Vec<&DnsSendEvent> = seen
        .iter()
        .filter(|e| e.local.port() == v4_port || e.local.port() == v6_port)
        .collect();
    let v4_events: Vec<&&DnsSendEvent> = mine.iter().filter(|e| is_v4(e)).collect();
    let v6_events: Vec<&&DnsSendEvent> = mine.iter().filter(|e| is_v6(e)).collect();
    assert_eq!(
        v4_events.len(),
        1,
        "one v4 send to :53; this test's: {mine:?}"
    );
    assert_eq!(
        v6_events.len(),
        1,
        "one v6 send to :53; this test's: {mine:?}"
    );
    let other: Vec<&DnsSendEvent> = seen.iter().filter(|e| e.remote.port() != 53).collect();
    assert!(other.is_empty(), "only port 53 is reported: {other:?}");
    let (ev4, ev6) = (*v4_events[0], *v6_events[0]);
    println!("osiris-ebpf: dns v4 send: {ev4:?}");
    println!("osiris-ebpf: dns v6 send: {ev6:?}");

    assert_eq!(
        ev4.local,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), v4_port)
    );
    assert_eq!(
        ev6.local,
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), v6_port)
    );

    let netns = std::fs::metadata("/proc/self/ns/net")
        .expect("stat /proc/self/ns/net")
        .ino();
    let exe_ino = std::fs::metadata(std::env::current_exe().expect("current exe"))
        .expect("stat current exe")
        .ino();
    // SAFETY: getuid() takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let root_pidns = in_root_pid_namespace();
    for ev in [ev4, ev6] {
        assert_eq!(u64::from(ev.netns_ino), netns, "netns inode: {ev:?}");
        assert_eq!(ev.uid, uid, "{ev:?}");
        assert_eq!(ev.exe.map(|x| x.ino), Some(exe_ino), "exe inode: {ev:?}");
        // The group leader's comm: the test binary's name (load_dns-<hash>,
        // cut to 15 bytes), not the test thread's.
        assert!(ev.comm.starts_with("load_dns"), "group-leader comm: {ev:?}");
        assert_ne!(ev.tid, 0, "{ev:?}");
        if root_pidns {
            assert_eq!(ev.pid, pid, "sender tgid: {ev:?}");
        }
    }
    if !root_pidns {
        println!("osiris-ebpf: dns pid not asserted (child pid namespace)");
    }
}
