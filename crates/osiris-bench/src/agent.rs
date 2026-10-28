//! Agent bench: real agent on real auditd, real exec load, /proc sampling.
use crate::stats::Record;

#[cfg(not(target_os = "linux"))]
pub fn run(rate: u64, duration_s: u64) -> Record {
    Record {
        bench: "agent".into(),
        params: serde_json::json!({"rate": rate, "duration_s": duration_s}),
        metrics: serde_json::json!({"skipped": "linux only"}),
    }
}

#[cfg(target_os = "linux")]
pub fn run(rate: u64, duration_s: u64) -> Record {
    use std::time::{Duration, Instant};

    use osiris_real_linux_tests::stack::{AgentOptions, Stack, StackOptions};

    use crate::stats::{parse_proc_stat_ticks, parse_vm_rss_kib, summarize, Pacer};

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
    let tick_hz = 100.0; // USER_HZ on Linux x86_64/arm64
    let read = || -> Option<(u64, u64)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        Some((parse_proc_stat_ticks(&stat)?, parse_vm_rss_kib(&status)?))
    };
    std::thread::sleep(Duration::from_secs(5)); // let startup settle
    let mut pacer = Pacer::new(rate);
    let start = Instant::now();
    let end = Duration::from_secs(duration_s);
    // Sampling runs on its own fixed 1 s tick, so a saturated spawn loop cannot skew it.
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (mut max_behind, mut spawned) = (0u64, 0u64);
    let (cpu, rss, read_failures, spawned_elapsed) = std::thread::scope(|scope| {
        let sampler = scope.spawn(|| {
            let (mut cpu, mut rss, mut failures) = (vec![], vec![], 0u64);
            let (mut prev_ticks, _) = read().expect("agent /proc readable");
            let mut prev_at = Instant::now();
            let mut tick = 1u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let due = start + Duration::from_secs(tick);
                while Instant::now() < due && !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                tick += 1;
                match read() {
                    Some((ticks, kib)) => {
                        let secs = prev_at.elapsed().as_secs_f64();
                        cpu.push((ticks - prev_ticks) as f64 / tick_hz / secs * 100.0);
                        rss.push(kib as f64 / 1024.0);
                        prev_ticks = ticks;
                        prev_at = Instant::now();
                    }
                    None => failures += 1, // agent gone: visible in the record
                }
            }
            (cpu, rss, failures)
        });
        let mut children = vec![];
        while start.elapsed() < end {
            max_behind = max_behind.max(pacer.behind(start.elapsed()));
            for _ in 0..pacer.due(start.elapsed()) {
                if let Ok(c) = std::process::Command::new("/bin/true").spawn() {
                    children.push(c);
                    spawned += 1;
                }
            }
            children.retain_mut(|c| !matches!(c.try_wait(), Ok(Some(_))));
            if pacer.behind(start.elapsed()) == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let elapsed = start.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let out = sampler.join().expect("sampler thread");
        for mut c in children {
            let _ = c.wait();
        }
        (out.0, out.1, out.2, elapsed)
    });
    let achieved = spawned as f64 / spawned_elapsed.as_secs_f64();
    let saturated = max_behind > pacer.slice();
    Record {
        bench: "agent".into(),
        params: serde_json::json!({"rate": rate, "duration_s": duration_s}),
        metrics: serde_json::json!({
            "target_exec_per_sec": rate,
            "achieved_exec_per_sec": achieved,
            "saturated": saturated,
            "max_behind_events": max_behind,
            "sample_read_failures": read_failures,
            "cpu_pct_one_core": summarize(&mut { cpu }),
            "rss_mib": summarize(&mut { rss }),
        }),
    }
}
