//! DNS sensor bench: UDP sends on `lo` to port 5300 and to port 53, with a
//! listener on each, with and without the agent running (eBPF DNS
//! attribution, Phase 11b-4). The kprobes on `udp_sendmsg`/`udpv6_sendmsg`
//! run on every UDP send on the host, so the overhead of interest is the
//! port-5300 (non-53) slowdown the agent causes; port 53 adds the ring-buffer
//! record and the packet capture.
use crate::stats::Record;

#[cfg(not(target_os = "linux"))]
pub fn run(sends: u64) -> Record {
    Record {
        bench: "dns_send".into(),
        params: serde_json::json!({"sends": sends}),
        metrics: serde_json::json!({"skipped": "linux only"}),
    }
}

#[cfg(target_os = "linux")]
pub fn run(sends: u64) -> Record {
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use osiris_real_linux_tests::stack::{AgentOptions, Stack, StackOptions};

    use crate::stats::{parse_proc_stat_ticks, summarize};

    /// A well-formed DNS A query, so the port-53 sends take the sensor's
    /// real parse path. Same bytes to both ports.
    fn query(id: u16, i: u64) -> Vec<u8> {
        let mut q = Vec::with_capacity(64);
        for w in [id, 0x0100, 1, 0, 0, 0] {
            q.extend_from_slice(&w.to_be_bytes());
        }
        for label in [format!("b{i}"), "osiris-bench".into(), "xyz".into()] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]);
        q
    }

    /// Drains a port on `127.0.0.1` until told to stop, so no send hits a
    /// closed port (ICMP unreachable) and nothing is answered.
    struct Listener {
        stop: Arc<AtomicBool>,
        received: Arc<AtomicU64>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Listener {
        fn start(port: u16) -> Self {
            let sock = UdpSocket::bind(("127.0.0.1", port))
                .unwrap_or_else(|e| panic!("bind 127.0.0.1:{port}: {e}"));
            sock.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let received = Arc::new(AtomicU64::new(0));
            let (s, r) = (stop.clone(), received.clone());
            let thread = std::thread::spawn(move || {
                let mut buf = [0u8; 512];
                while !s.load(Ordering::Relaxed) {
                    if sock.recv_from(&mut buf).is_ok() {
                        r.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
            Self {
                stop,
                received,
                thread: Some(thread),
            }
        }
        fn received(&self) -> u64 {
            self.received.load(Ordering::Relaxed)
        }
    }
    impl Drop for Listener {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    // `sends` sendto calls from one socket, each timed; ids and names vary
    // per send. Received counts what the listener saw in the loop (drops on
    // a full receive buffer are not the agent's cost).
    fn one_loop(port: u16, listener: &Listener, sends: u64) -> serde_json::Value {
        let sock = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let before = listener.received();
        let mut lat_us = Vec::with_capacity(sends as usize);
        let mut errors = 0u64;
        let start = Instant::now();
        for i in 0..sends {
            let q = query((i & 0xffff) as u16, i);
            let t = Instant::now();
            if sock.send_to(&q, ("127.0.0.1", port)).is_err() {
                errors += 1;
            }
            lat_us.push(t.elapsed().as_secs_f64() * 1e6);
        }
        let total = start.elapsed();
        std::thread::sleep(Duration::from_millis(300)); // let the listener drain
        serde_json::json!({
            "total_ms": total.as_secs_f64() * 1e3,
            "sends_per_sec": sends as f64 / total.as_secs_f64(),
            "send_us": summarize(&mut lat_us),
            "send_errors": errors,
            "received": listener.received() - before,
        })
    }

    fn both(l5300: &Listener, l53: &Listener, sends: u64) -> serde_json::Value {
        let _ = one_loop(5300, l5300, 500); // warm up
        serde_json::json!({
            "port_5300": one_loop(5300, l5300, sends),
            "port_53": one_loop(53, l53, sends),
        })
    }

    let l5300 = Listener::start(5300);
    let l53 = Listener::start(53);
    let without_agent = both(&l5300, &l53, sends);

    let persist = tempfile::tempdir().unwrap();
    let stack = Stack::start(StackOptions {
        agent: Some(AgentOptions {
            audit_log: "/var/log/audit/audit.log".into(),
            persistence_dirs: vec![persist.path().to_path_buf()],
            ebpf_object_dir: osiris_real_linux_tests::render::bpf_dir_from_env(),
            extra_fs_watch: vec![],
        }),
        ..Default::default()
    });
    let pid = stack.agent_pid().unwrap();
    let ticks = || -> Option<u64> {
        parse_proc_stat_ticks(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
    };
    std::thread::sleep(Duration::from_secs(5)); // let startup settle
    let status_before = stack.agent_status();
    let t0 = ticks();
    let with_agent = both(&l5300, &l53, sends);
    let t1 = ticks();
    let agent_cpu_s = match (t0, t1) {
        (Some(a), Some(b)) => Some((b - a) as f64 / 100.0),
        _ => None,
    };
    std::thread::sleep(Duration::from_secs(3)); // let the sensor count the burst
    let status_after = stack.agent_status();
    drop(stack);

    let rate = |v: &serde_json::Value, port: &str| v[port]["sends_per_sec"].as_f64();
    let overhead_pct = |port: &str| -> Option<f64> {
        let (a, b) = (rate(&without_agent, port)?, rate(&with_agent, port)?);
        Some((a / b - 1.0) * 100.0)
    };
    let summary = serde_json::json!({
        "port_5300_overhead_pct": overhead_pct("port_5300"),
        "port_53_overhead_pct": overhead_pct("port_53"),
    });
    eprintln!("osiris-bench: dns_send summary: {summary}");

    Record {
        bench: "dns_send".into(),
        params: serde_json::json!({"sends": sends, "ports": [5300, 53], "iface": "lo"}),
        metrics: serde_json::json!({
            "without_agent": without_agent,
            "with_agent": with_agent,
            "overhead": summary,
            "agent_cpu_seconds_during_loops": agent_cpu_s,
            "agent_status_before": status_before,
            "agent_status_after": status_after,
        }),
    }
}
