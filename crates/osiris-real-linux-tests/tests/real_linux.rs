//! Phase 10 real-Linux scenarios. Run via `tools/real-linux/run.sh` as root
//! on a host prepared by `tools/real-linux/setup.sh`.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use osiris_real_linux_tests::json::{contains_str, has_kv};
use osiris_real_linux_tests::stack::{AgentOptions, Stack, StackOptions};
use serde_json::json;

const DEADLINE: Duration = Duration::from_secs(45);
const WATCH_ROOT: &str = "/tmp/osiris-p10";

fn marker() -> String {
    format!("osirisp10{}", uuid::Uuid::new_v4().simple())
}

/// Event and alert timestamps are nanoseconds since the epoch.
fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn sh(script: &str) {
    let st = Command::new("/bin/bash")
        .arg("-c")
        .arg(script)
        .status()
        .unwrap();
    assert!(st.success(), "script failed: {script}");
}

/// One stack per test: agent on the real audit log, persistence watch on a
/// per-test dir under WATCH_ROOT.
fn stack(persist: &Path) -> Stack {
    std::fs::create_dir_all(persist).unwrap();
    Stack::start(StackOptions {
        agent: Some(AgentOptions {
            audit_log: PathBuf::from("/var/log/audit/audit.log"),
            persistence_dirs: vec![persist.to_path_buf()],
        }),
        ..Default::default()
    })
}

fn events(
    stack: &Stack,
    event_type: &str,
    since: u128,
    done: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    stack.wait_for(
        &format!("/api/v1/events?event_type={event_type}&since={since}&limit=1000"),
        DEADLINE,
        done,
    )
}

/// Removes paths even when an assertion panics.
struct Cleanup(Vec<String>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for c in &self.0 {
            let _ = Command::new("/bin/bash").arg("-c").arg(c).status();
        }
    }
}

#[test]
#[ignore]
fn exec_is_observed() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let t0 = now_ns();
    sh(&format!("/bin/sh -c 'true {m}'"));
    events(&s, "PROCESS_EXEC", t0, |v| contains_str(v, &m));
}

#[test]
#[ignore]
fn file_lifecycle_is_observed() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(format!("{m}-p")));
    let a = format!("{WATCH_ROOT}/{m}.txt");
    let b = format!("{WATCH_ROOT}/{m}.renamed");
    let _c = Cleanup(vec![format!("rm -f {a} {b}")]);
    let t0 = now_ns();
    sh(&format!(
        "echo hi > {a} && echo more >> {a} && mv {a} {b} && rm {b}"
    ));
    events(&s, "FILE_CREATE", t0, |v| contains_str(v, &a));
    events(&s, "FILE_WRITE", t0, |v| {
        contains_str(v, &a) || contains_str(v, &b)
    });
    events(&s, "FILE_RENAME", t0, |v| contains_str(v, &b));
    events(&s, "FILE_DELETE", t0, |v| contains_str(v, &b));
}

#[test]
#[ignore]
fn network_connect_is_observed() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accept = std::thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(8));
        drop(conn);
    });
    let t0 = now_ns();
    // Held open well past one /proc/net/tcp poll interval.
    sh(&format!(
        "exec 3<>/dev/tcp/127.0.0.1/{port}; sleep 6; exec 3<&-"
    ));
    events(&s, "NETWORK_CONNECT", t0, |v| {
        has_kv(v, "dst_port", &json!(port))
    });
    accept.join().unwrap();
}

#[test]
#[ignore]
fn sudo_is_observed() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let t0 = now_ns();
    sh(&format!("sudo -u nobody /bin/sh -c 'true {m}'"));
    events(&s, "PRIVILEGE_SUDO", t0, |v| contains_str(v, &m));
}

#[test]
#[ignore]
fn systemd_unit_start_is_observed() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let unit = format!("osiris-{m}");
    let _c = Cleanup(vec![format!(
        "systemctl reset-failed {unit}.service 2>/dev/null; true"
    )]);
    let t0 = now_ns();
    sh(&format!("systemd-run --unit {unit} --wait /bin/true"));
    events(&s, "SERVICE_START", t0, |v| contains_str(v, &unit));
}

#[test]
#[ignore]
fn persistence_write_is_observed() {
    let m = marker();
    let dir = Path::new(WATCH_ROOT).join(format!("{m}-units"));
    let s = stack(&dir);
    let unit = dir.join(format!("{m}.service"));
    let t0 = now_ns();
    std::fs::write(&unit, "[Service]\nExecStart=/bin/true\n").unwrap();
    events(&s, "PERSISTENCE_CREATED", t0, |v| contains_str(v, &m));
}

#[test]
#[ignore]
fn web_root_drop_raises_an_alert() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let path = format!("/var/www/{m}.php");
    let _c = Cleanup(vec![format!("rm -f {path}")]);
    let t0 = now_ns();
    sh(&format!(
        "/bin/bash -c 'echo \"<?php system($_GET[c]); ?>\" > {path}'"
    ));
    s.wait_for(
        &format!("/api/v1/alerts?rule_id=shell_wrote_file_to_web_root&since={t0}"),
        DEADLINE,
        |v| contains_str(v, &m),
    );
}

#[test]
#[ignore]
fn agent_reports_real_host_facts_and_healthy_sensors() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    let host = s.host_id().unwrap().to_string();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let hosts = s.wait_for("/api/v1/hosts", DEADLINE, |v| contains_str(v, &host));
    assert!(
        contains_str(&hosts, kernel.trim()),
        "kernel missing: {hosts}"
    );
    assert!(
        !has_kv(&hosts, "distro", &json!("unknown")),
        "distro unknown: {hosts}"
    );
    let health = events(&s, "AGENT_HEALTH", 0, |v| {
        v.as_array().is_some_and(|a| !a.is_empty())
    });
    // Names are each sensor's `Sensor::name()` (the process sensor is "process_exec").
    for sensor in [
        "process_exec",
        "filesystem",
        "network",
        "identity",
        "systemd",
        "persistence",
    ] {
        assert!(
            contains_str(&health, sensor),
            "sensor {sensor} absent from AGENT_HEALTH: {health}"
        );
    }
    assert!(
        !contains_str(&health, "FAILED"),
        "a sensor reports FAILED: {health}"
    );
}
