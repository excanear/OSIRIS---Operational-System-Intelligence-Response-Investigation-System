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
    let (mut prev_ticks, _) = read().expect("agent /proc readable");
    let mut next_sample = Duration::from_secs(1);
    let (mut cpu, mut rss) = (vec![], vec![]);
    let mut spawned = 0u64;
    let mut children = vec![];
    while start.elapsed() < end {
        for _ in 0..pacer.due(start.elapsed()) {
            if let Ok(c) = std::process::Command::new("/bin/true").spawn() {
                children.push(c);
                spawned += 1;
            }
        }
        children.retain_mut(|c| !matches!(c.try_wait(), Ok(Some(_))));
        if start.elapsed() >= next_sample {
            if let Some((ticks, kib)) = read() {
                cpu.push((ticks - prev_ticks) as f64 / tick_hz * 100.0); // % of one core over 1 s
                rss.push(kib as f64 / 1024.0);
                prev_ticks = ticks;
            }
            next_sample += Duration::from_secs(1);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let achieved = spawned as f64 / start.elapsed().as_secs_f64();
    for mut c in children {
        let _ = c.wait();
    }
    Record {
        bench: "agent".into(),
        params: serde_json::json!({"rate": rate, "duration_s": duration_s}),
        metrics: serde_json::json!({"achieved_exec_per_sec": achieved,
            "cpu_pct_one_core": summarize(&mut cpu), "rss_mib": summarize(&mut rss)}),
    }
}
