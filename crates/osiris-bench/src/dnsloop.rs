//! DNS sensor bench: UDP sends on `lo` to port 5300 and to port 53, with a
//! listener on each, under four configurations (Phase 11b-4):
//!
//! - A: no agent;
//! - B: the full agent (DNS on eBPF attribution);
//! - C: the full agent with `dns.bpf.o*` removed from a copy of its object
//!   dir, so DNS runs AF_PACKET + `/proc` attribution and no kprobes;
//! - D: the full agent without `dns_capture`, so no DNS sensor at all.
//!
//! B vs C is the kprobe cost of 11b-4, C vs D the AF_PACKET capture (and,
//! on port 53, `/proc` attribution) cost of 11a, D vs A the rest of the
//! agent. Each configuration runs [`ROUNDS`] times, interleaved (the order
//! rotates per round), and the summary reports medians over the rounds.
//!
//! The port-53 loop is an unanswered 10 000-query flood. After it the DNS
//! sensor's status is sampled every second for [`TIMELINE`], so the
//! tracker's overflow behaviour and the drop counters are reported, not
//! hidden.
use crate::stats::Record;

/// Interleaved repetitions of each configuration.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ROUNDS: usize = 5;

#[cfg(not(target_os = "linux"))]
pub fn run(sends: u64) -> Record {
    Record {
        bench: "dns_send".into(),
        params: serde_json::json!({"sends": sends, "rounds": ROUNDS}),
        metrics: serde_json::json!({"skipped": "linux only"}),
    }
}

#[cfg(target_os = "linux")]
pub fn run(sends: u64) -> Record {
    use std::net::UdpSocket;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use serde_json::{json, Value};

    use osiris_real_linux_tests::stack::{AgentOptions, Stack, StackOptions};

    use crate::stats::{parse_proc_stat_ticks, summarize};

    /// Status samples after the loops: past the 5 s transaction timeout, so
    /// unanswered queries have closed.
    const TIMELINE: Duration = Duration::from_secs(10);

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

    /// Drains a port on `127.0.0.1` until dropped, so no send hits a closed
    /// port (ICMP unreachable) and nothing is answered.
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
    // per send. Received counts what the listener saw (drops on a full
    // receive buffer are not the agent's cost).
    fn one_loop(port: u16, listener: &Listener, sends: u64) -> Value {
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
        json!({
            "total_ms": total.as_secs_f64() * 1e3,
            "sends_per_sec": sends as f64 / total.as_secs_f64(),
            "send_us": summarize(&mut lat_us),
            "send_errors": errors,
            "received": listener.received() - before,
        })
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Config {
        NoAgent,
        Full,
        NoDnsObject,
        NoDnsSensor,
    }
    impl Config {
        const ALL: [Config; 4] = [
            Config::NoAgent,
            Config::Full,
            Config::NoDnsObject,
            Config::NoDnsSensor,
        ];
        fn label(self) -> &'static str {
            match self {
                Config::NoAgent => "A_no_agent",
                Config::Full => "B_full_agent",
                Config::NoDnsObject => "C_no_dns_object",
                Config::NoDnsSensor => "D_no_dns_sensor",
            }
        }
    }

    /// The `dns` entry of the agent's `/status`, trimmed to what the
    /// bench reports; `null` when the agent runs no DNS sensor.
    fn dns_entry(stack: &Stack) -> Value {
        let status = stack.agent_status();
        let Some(e) = status["sensors"]
            .as_array()
            .and_then(|a| a.iter().find(|h| h["name"] == json!("dns")))
        else {
            return Value::Null;
        };
        json!({
            "state": e["state"],
            "flags": e["capability_flags"],
            "emitted": e["events_emitted_total"],
            "dropped": e["events_dropped_total"],
            "last_error": e["last_error"],
        })
    }

    struct Ctx<'a> {
        l5300: &'a Listener,
        l53: &'a Listener,
        sends: u64,
        bpf: Option<PathBuf>,
        bpf_no_dns: Option<PathBuf>,
    }

    fn run_config(cfg: Config, ctx: &Ctx) -> Value {
        let loops = |ctx: &Ctx| -> (Value, Value) {
            let _ = one_loop(5300, ctx.l5300, 500); // warm up
                                                    // Port 5300 first, so the unanswered port-53 flood cannot
                                                    // weigh on it.
            let p5300 = one_loop(5300, ctx.l5300, ctx.sends);
            let p53 = one_loop(53, ctx.l53, ctx.sends);
            (p5300, p53)
        };
        if cfg == Config::NoAgent {
            let (p5300, p53) = loops(ctx);
            return json!({"port_5300": p5300, "port_53": p53});
        }
        let object_dir = match cfg {
            Config::NoDnsObject => ctx.bpf_no_dns.clone(),
            _ => ctx.bpf.clone(),
        };
        let persist = tempfile::tempdir().unwrap();
        let stack = Stack::start(StackOptions {
            agent: Some(AgentOptions {
                audit_log: "/var/log/audit/audit.log".into(),
                persistence_dirs: vec![persist.path().to_path_buf()],
                ebpf_object_dir: object_dir,
                extra_fs_watch: vec![],
                no_dns_capture: cfg == Config::NoDnsSensor,
            }),
            ..Default::default()
        });
        let pid = stack.agent_pid().unwrap();
        let ticks = || -> Option<u64> {
            parse_proc_stat_ticks(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
        };
        std::thread::sleep(Duration::from_secs(5)); // let startup settle
        let dns_before = dns_entry(&stack);
        let t0 = ticks();
        let (p5300, p53) = loops(ctx);
        let t1 = ticks();
        let agent_cpu_s = match (t0, t1) {
            (Some(a), Some(b)) => Some((b - a) as f64 / 100.0),
            _ => None,
        };
        let start = Instant::now();
        let mut timeline = Vec::new();
        while start.elapsed() < TIMELINE {
            std::thread::sleep(Duration::from_secs(1));
            let mut e = dns_entry(&stack);
            if e.is_null() {
                break;
            }
            e["t_s"] = json!(start.elapsed().as_secs());
            timeline.push(e);
        }
        drop(stack);
        json!({
            "port_5300": p5300,
            "port_53": p53,
            "agent_cpu_seconds_during_loops": agent_cpu_s,
            "dns_before": dns_before,
            "dns_after_flood": timeline,
        })
    }

    /// A copy of `good` without `dns.bpf.o*` (the real-Linux tests'
    /// broken-copy pattern).
    fn copy_without_dns(good: &Path, into: &Path) {
        for entry in std::fs::read_dir(good).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("dns.bpf.o") {
                continue;
            }
            if entry.file_type().unwrap().is_file() {
                std::fs::copy(entry.path(), into.join(&name)).unwrap();
            }
        }
    }

    fn median(mut v: Vec<f64>) -> Option<f64> {
        if v.is_empty() {
            return None;
        }
        v.sort_by(|a, b| a.total_cmp(b));
        let n = v.len();
        Some(if n % 2 == 1 {
            v[n / 2]
        } else {
            (v[n / 2 - 1] + v[n / 2]) / 2.0
        })
    }

    let bpf = osiris_real_linux_tests::render::bpf_dir_from_env();
    if bpf.is_none() {
        eprintln!(
            "osiris-bench: dns_send: OSIRIS_BPF_DIR is unset, so B and C both run \
             without eBPF; the B-vs-C (11b-4 kprobe) pair is skipped"
        );
    }
    // Declared before any stack so it outlives every agent reading it.
    let no_dns_dir = tempfile::Builder::new()
        .prefix("osiris-bpf-nodns-")
        .tempdir()
        .unwrap();
    if let Some(good) = &bpf {
        copy_without_dns(good, no_dns_dir.path());
    }
    let l5300 = Listener::start(5300);
    let l53 = Listener::start(53);
    let ctx = Ctx {
        l5300: &l5300,
        l53: &l53,
        sends,
        bpf: bpf.clone(),
        bpf_no_dns: bpf.as_ref().map(|_| no_dns_dir.path().to_path_buf()),
    };

    // rounds[config label] = one result per round, in round order.
    let mut rounds: serde_json::Map<String, Value> = Config::ALL
        .iter()
        .map(|c| (c.label().to_string(), json!([])))
        .collect();
    for r in 0..ROUNDS {
        for k in 0..Config::ALL.len() {
            let cfg = Config::ALL[(r + k) % Config::ALL.len()];
            let mut res = run_config(cfg, &ctx);
            res["round"] = json!(r);
            rounds[cfg.label()].as_array_mut().unwrap().push(res);
        }
    }

    // Medians per configuration and port.
    let pick = |label: &str, port: &str, f: &dyn Fn(&Value) -> Option<f64>| {
        median(
            rounds[label]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|r| f(&r[port]))
                .collect(),
        )
    };
    let mut medians = serde_json::Map::new();
    for c in Config::ALL {
        let mut per_port = serde_json::Map::new();
        for port in ["port_5300", "port_53"] {
            per_port.insert(
                port.into(),
                json!({
                    "sends_per_sec": pick(c.label(), port, &|v| v["sends_per_sec"].as_f64()),
                    "p50_us": pick(c.label(), port, &|v| v["send_us"]["p50"].as_f64()),
                    "p99_us": pick(c.label(), port, &|v| v["send_us"]["p99"].as_f64()),
                }),
            );
        }
        medians.insert(c.label().into(), Value::Object(per_port));
    }

    // Overhead of `with` over `base`: time per send, from median rates.
    let pair = |with: Config, base: Config| -> Value {
        let mut out = serde_json::Map::new();
        for port in ["port_5300", "port_53"] {
            let m = |c: Config, k: &str| medians[c.label()][port][k].as_f64();
            let pct = match (m(base, "sends_per_sec"), m(with, "sends_per_sec")) {
                (Some(b), Some(w)) if w > 0.0 => Some((b / w - 1.0) * 100.0),
                _ => None,
            };
            let d50 = match (m(with, "p50_us"), m(base, "p50_us")) {
                (Some(w), Some(b)) => Some(w - b),
                _ => None,
            };
            out.insert(
                port.into(),
                json!({"overhead_pct": pct, "p50_delta_us": d50}),
            );
        }
        Value::Object(out)
    };
    // Without objects B and C are the same configuration.
    let kprobes = if bpf.is_some() {
        pair(Config::Full, Config::NoDnsObject)
    } else {
        json!({"skipped": "OSIRIS_BPF_DIR unset: B and C both run without eBPF"})
    };
    let pairs = json!({
        "agent_total_B_vs_A": pair(Config::Full, Config::NoAgent),
        "dns_kprobes_11b4_B_vs_C": kprobes,
        "dns_af_packet_11a_C_vs_D": pair(Config::NoDnsObject, Config::NoDnsSensor),
        "rest_of_agent_D_vs_A": pair(Config::NoDnsSensor, Config::NoAgent),
    });
    eprintln!(
        "osiris-bench: dns_send medians: {}",
        Value::Object(medians.clone())
    );
    eprintln!("osiris-bench: dns_send overhead: {pairs}");

    Record {
        bench: "dns_send".into(),
        params: json!({
            "sends": sends,
            "ports": [5300, 53],
            "iface": "lo",
            "rounds": ROUNDS,
            "bpf_dir": bpf,
        }),
        metrics: json!({
            "medians": medians,
            "overhead": pairs,
            "rounds": rounds,
        }),
    }
}
