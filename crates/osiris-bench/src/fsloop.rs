//! Filesystem sensor bench: a create/write/delete loop in a watched and an
//! unwatched directory, with and without the agent running (eBPF filesystem
//! backend, Phase 11b-3). The overhead of interest is the unwatched-dir
//! slowdown the agent causes: every file operation on the host hits the hooks,
//! watched or not.
use crate::stats::Record;

#[cfg(not(target_os = "linux"))]
pub fn run(iterations: u64) -> Record {
    Record {
        bench: "fs_loop".into(),
        params: serde_json::json!({"iterations": iterations}),
        metrics: serde_json::json!({"skipped": "linux only"}),
    }
}

#[cfg(target_os = "linux")]
pub fn run(iterations: u64) -> Record {
    use std::io::Write;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use osiris_real_linux_tests::stack::{AgentOptions, Stack, StackOptions};

    use crate::stats::{parse_proc_stat_ticks, summarize};

    // One create + 4 KiB write + delete per iteration, timed individually.
    fn one_loop(dir: &Path, iterations: u64) -> serde_json::Value {
        let payload = [0x5au8; 4096];
        let mut lat_us = Vec::with_capacity(iterations as usize);
        let start = Instant::now();
        for i in 0..iterations {
            let path = dir.join(format!("f{i}"));
            let t = Instant::now();
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(&payload).expect("write");
            drop(f);
            std::fs::remove_file(&path).expect("delete");
            lat_us.push(t.elapsed().as_secs_f64() * 1e6);
        }
        let total = start.elapsed();
        serde_json::json!({
            "total_ms": total.as_secs_f64() * 1e3,
            "iterations_per_sec": iterations as f64 / total.as_secs_f64(),
            "iteration_us": summarize(&mut lat_us),
        })
    }

    // Neither dir is under the global audit rules (/tmp/osiris-p10, /var/www,
    // /etc/systemd/system), so the "without agent" baseline carries no audit cost.
    let tag = std::process::id();
    let watched = std::path::PathBuf::from(format!("/tmp/osiris-fsbench-watched-{tag}"));
    let unwatched = std::path::PathBuf::from(format!("/var/tmp/osiris-fsbench-unwatched-{tag}"));
    std::fs::create_dir_all(&watched).unwrap();
    std::fs::create_dir_all(&unwatched).unwrap();

    let _ = one_loop(&unwatched, 500); // warm the page/dentry caches
    let without_agent = serde_json::json!({
        "watched_dir": one_loop(&watched, iterations),
        "unwatched_dir": one_loop(&unwatched, iterations),
    });

    let persist = tempfile::tempdir().unwrap();
    let stack = Stack::start(StackOptions {
        agent: Some(AgentOptions {
            audit_log: "/var/log/audit/audit.log".into(),
            persistence_dirs: vec![persist.path().to_path_buf()],
            ebpf_object_dir: osiris_real_linux_tests::render::bpf_dir_from_env(),
            extra_fs_watch: vec![watched.clone()],
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
    let _ = one_loop(&unwatched, 500);
    let with_agent_watched = one_loop(&watched, iterations);
    let with_agent_unwatched = one_loop(&unwatched, iterations);
    let t1 = ticks();
    let agent_cpu_s = match (t0, t1) {
        (Some(a), Some(b)) => Some((b - a) as f64 / 100.0),
        _ => None,
    };
    let status_after = stack.agent_status();
    drop(stack);
    let _ = std::fs::remove_dir_all(&watched);
    let _ = std::fs::remove_dir_all(&unwatched);

    Record {
        bench: "fs_loop".into(),
        params: serde_json::json!({"iterations": iterations, "payload_bytes": 4096}),
        metrics: serde_json::json!({
            "without_agent": without_agent,
            "with_agent": {
                "watched_dir": with_agent_watched,
                "unwatched_dir": with_agent_unwatched,
            },
            "agent_cpu_seconds_during_loops": agent_cpu_s,
            "agent_status_before": status_before,
            "agent_status_after": status_after,
        }),
    }
}
