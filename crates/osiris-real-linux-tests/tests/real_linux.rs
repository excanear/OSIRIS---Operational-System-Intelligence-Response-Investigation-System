//! Phase 10 real-Linux scenarios. Run via `tools/real-linux/run.sh` as root
//! on a host prepared by `tools/real-linux/setup.sh`.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use osiris_real_linux_tests::json::{contains_str, has_kv, ids_containing, objects_with};
use osiris_real_linux_tests::render::bpf_dir_from_env;
use osiris_real_linux_tests::stack::{AgentOptions, Stack, StackOptions};
use serde_json::{json, Value};

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

/// Bound on one scenario's shell action (global constraint #5: every wait
/// is bounded); coreutils `timeout` kills it and exits 124.
const SH_TIMEOUT_SECS: &str = "60";

fn sh(script: &str) {
    let st = Command::new("timeout")
        .args(["--kill-after=5", SH_TIMEOUT_SECS, "/bin/bash", "-c", script])
        .status()
        .unwrap();
    assert!(
        st.success(),
        "script failed ({st}; 124 = timed out after {SH_TIMEOUT_SECS}s): {script}"
    );
}

/// One stack per test: agent on the real audit log, persistence watch on a
/// per-test dir under WATCH_ROOT, and the process sensor on eBPF whenever
/// `$OSIRIS_BPF_DIR` names a built object dir (the workflow always sets it).
fn stack(persist: &Path) -> Stack {
    stack_with_bpf(persist, bpf_dir_from_env())
}

fn stack_with_bpf(persist: &Path, ebpf_object_dir: Option<PathBuf>) -> Stack {
    std::fs::create_dir_all(persist).unwrap();
    Stack::start(StackOptions {
        agent: Some(AgentOptions {
            audit_log: PathBuf::from("/var/log/audit/audit.log"),
            persistence_dirs: vec![persist.to_path_buf()],
            ebpf_object_dir,
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
    // Baseline is taken at sensor start (before Stack::start returns); rescans
    // run every 30s and the interval is not configurable. A systemd unit file
    // is reported as SERVICE_CREATE (PERSISTENCE_CREATED is for non-unit
    // checkpoints). Deadline = scan interval + 15s.
    s.wait_for(
        &format!("/api/v1/events?event_type=SERVICE_CREATE&since={t0}&limit=1000"),
        Duration::from_secs(30 + 15),
        |v| contains_str(v, &m),
    );
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
    // Alerts cite events by id only: find the marker's FILE_CREATE first,
    // then the alert whose evidence names it.
    let created = events(&s, "FILE_CREATE", t0, |v| contains_str(v, &path));
    let ids = ids_containing(&created, "event_id", &path);
    assert!(!ids.is_empty(), "no FILE_CREATE event_id for {path}");
    s.wait_for(
        &format!("/api/v1/alerts?rule_id=shell_wrote_file_to_web_root&since={t0}"),
        DEADLINE,
        |v| ids.iter().any(|id| contains_str(v, id)),
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

/// Phase 11a: a curl lookup of a unique `.xyz` name is seen by the passive
/// DNS sensor (AF_PACKET), attributed to curl, and raises the suspicious-TLD
/// alert. The query goes to the host resolver (systemd-resolved's stub on
/// Ubuntu); the name never resolves, which is fine — the query is the event.
#[test]
#[ignore]
fn dns_query_is_observed_and_alerts() {
    let m = marker();
    let s = stack(&Path::new(WATCH_ROOT).join(&m));
    // The sensor reports itself in the AGENT_HEALTH heartbeat (5s cadence):
    // an unprivileged or broken capture shows up here, not as silence.
    let health = events(&s, "AGENT_HEALTH", 0, |v| {
        !objects_with(v, "sensor_name", &json!("dns")).is_empty()
    });
    let dns_health = objects_with(&health, "sensor_name", &json!("dns"));
    assert!(
        dns_health
            .iter()
            .any(|h| h["state"]["state"] == json!("HEALTHY")),
        "dns sensor never HEALTHY in AGENT_HEALTH: {health}"
    );
    assert!(
        !dns_health
            .iter()
            .any(|h| h["state"]["state"] == json!("FAILED")),
        "dns sensor reports FAILED: {health}"
    );

    let name = format!("{m}.xyz");
    let t0 = now_ns();
    sh(&format!("curl -s -m 5 http://{name}/ || true"));
    let by_curl = |v: &serde_json::Value| -> Vec<String> {
        objects_with(v, "event_type", &json!("DNS_QUERY"))
            .into_iter()
            .filter(|e| e["dns"]["query"] == json!(name))
            .filter(|e| {
                e["process"]["exe_path"]
                    .as_str()
                    .is_some_and(|p| p.ends_with("curl"))
            })
            .filter_map(|e| e["event_id"].as_str().map(str::to_string))
            .collect()
    };
    let queries = events(&s, "DNS_QUERY", t0, |v| !by_curl(v).is_empty());
    let ids = by_curl(&queries);
    // Alerts cite events by id only (see web_root_drop_raises_an_alert).
    s.wait_for(
        &format!("/api/v1/alerts?rule_id=dns_query_to_suspicious_tld&since={t0}"),
        DEADLINE,
        |v| ids.iter().any(|id| contains_str(v, id)),
    );
}

// ---- Phase 11b-1: the eBPF process backend ----

const EBPF_PROVIDER: &str = "process_exec_sensor/ebpf";

/// The built object dir the eBPF scenarios need (`setup.sh` builds it when
/// `OSIRIS_BPF_DIR` is set; the real-Linux workflow always sets it).
fn required_bpf_dir() -> PathBuf {
    bpf_dir_from_env().expect(
        "OSIRIS_BPF_DIR is unset: run tools/real-linux/setup.sh with OSIRIS_BPF_DIR \
         to build the BPF object, and run the suite with it set",
    )
}

/// eBPF timestamps are boot time plus a wall-clock offset computed once at
/// sensor start; query from a little before `t0` so a few ms of offset skew
/// can never hide an event (markers and pids keep the match exact).
fn since_before(t0: u128) -> u128 {
    t0.saturating_sub(5_000_000_000)
}

/// Waits until AGENT_HEALTH reports the process sensor in `state`, and
/// returns every `process_exec` entry seen.
fn process_health_reaches(s: &Stack, state: &str) -> Vec<Value> {
    let health = events(s, "AGENT_HEALTH", 0, |v| {
        objects_with(v, "sensor_name", &json!("process_exec"))
            .iter()
            .any(|h| h["state"]["state"] == json!(state))
    });
    objects_with(&health, "sensor_name", &json!("process_exec"))
        .into_iter()
        .cloned()
        .collect()
}

/// The agent's full `process_exec` health (capability flags, last error),
/// from its local status endpoint, once it has left STARTING. Echoed with
/// an `osiris-ebpf:` prefix so the workflow can surface it as an annotation.
fn process_status(s: &Stack) -> Value {
    let pick = |v: &Value| -> Option<Value> {
        v["sensors"]
            .as_array()?
            .iter()
            .find(|h| h["name"] == json!("process_exec") && h["state"] != json!("STARTING"))
            .cloned()
    };
    let status = s.wait_agent_status(DEADLINE, |v| pick(v).is_some());
    let entry = pick(&status).unwrap();
    eprintln!("osiris-ebpf: process_exec status: {entry}");
    entry
}

fn has_flag(health: &Value, flag: &str) -> bool {
    health["capability_flags"]
        .as_array()
        .is_some_and(|a| a.contains(&json!(flag)))
}

/// With a built object on a BTF kernel, the process sensor runs on eBPF:
/// HEALTHY in the heartbeat, capability flag `ebpf` on the agent.
#[test]
#[ignore]
fn process_sensor_uses_ebpf() {
    let m = marker();
    let s = stack_with_bpf(&Path::new(WATCH_ROOT).join(&m), Some(required_bpf_dir()));
    let health = process_health_reaches(&s, "HEALTHY");
    assert!(
        !health
            .iter()
            .any(|h| h["state"]["state"] != json!("HEALTHY")),
        "process_exec not steadily HEALTHY in AGENT_HEALTH: {health:?}"
    );
    let status = process_status(&s);
    assert_eq!(status["state"], json!("HEALTHY"), "status: {status}");
    assert!(
        has_flag(&status, "ebpf"),
        "no `ebpf` capability flag: {status}"
    );
    assert!(
        !has_flag(&status, "audit_fallback"),
        "eBPF active yet `audit_fallback` set: {status}"
    );
}

/// `sh -c 'exit 7' <marker>` spawned by this test: its exec arrives from the
/// eBPF backend with the marker in argv, this process as parent, uid 0 and
/// `/bin/sh` (or its resolved target) as exe; its exit joins the same
/// process_key and carries exit code 7.
#[test]
#[ignore]
fn exec_and_exit_are_observed_via_ebpf() {
    let m = marker();
    let s = stack_with_bpf(&Path::new(WATCH_ROOT).join(&m), Some(required_bpf_dir()));
    let t0 = now_ns();
    // The marker is `$0` of the -c script, so it sits in argv.
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 7", &m])
        .spawn()
        .unwrap();
    let pid = child.id();
    // `exit 7` is a builtin: the shell ends at once, so this wait is bounded.
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(7), "sh exit status: {status}");

    let since = since_before(t0);
    let execs_of = |v: &Value| -> Vec<Value> {
        objects_with(v, "event_type", &json!("PROCESS_EXEC"))
            .into_iter()
            .filter(|e| e["provider"] == json!(EBPF_PROVIDER))
            .filter(|e| e["process"]["pid"] == json!(pid))
            .filter(|e| contains_str(&e["process"]["cmdline"], &m))
            .cloned()
            .collect()
    };
    let execs = events(&s, "PROCESS_EXEC", since, |v| !execs_of(v).is_empty());
    let exec = execs_of(&execs).remove(0);
    assert_eq!(exec["source"], json!("EBPF"), "exec: {exec}");
    assert_eq!(
        exec["event_data"]["ppid"],
        json!(std::process::id()),
        "ppid is not the spawning test process: {exec}"
    );
    assert_eq!(exec["event_data"]["uid"], json!(0), "uid: {exec}");
    // The right exe: the resolved `/proc/<pid>/exe` (the target of the
    // `/bin/sh` symlink chain) when the reader saw the process alive with
    // the same comm, else the execve filename itself.
    let sh_target = std::fs::canonicalize("/bin/sh").unwrap();
    let allowed = [
        "/bin/sh".to_string(),
        sh_target.to_string_lossy().into_owned(),
    ];
    assert!(
        allowed
            .iter()
            .any(|a| exec["process"]["exe_path"] == json!(a)),
        "exe_path is not one of {allowed:?}: {exec}"
    );
    let key = exec["process"]["process_key"].clone();
    assert!(key.is_string(), "exec has no process_key: {exec}");

    let exits_of = |v: &Value| -> Vec<Value> {
        objects_with(v, "event_type", &json!("PROCESS_EXIT"))
            .into_iter()
            .filter(|e| e["process"]["process_key"] == key)
            .cloned()
            .collect()
    };
    let exits = events(&s, "PROCESS_EXIT", since, |v| !exits_of(v).is_empty());
    let exit = exits_of(&exits).remove(0);
    assert_eq!(exit["provider"], json!(EBPF_PROVIDER), "exit: {exit}");
    assert_eq!(exit["event_data"]["exit_code"], json!(7), "exit: {exit}");
    assert_eq!(exit["process"]["pid"], json!(pid), "exit: {exit}");
}

/// A copy of the object dir whose sidecar digest is altered fails the
/// integrity check: the sensor falls back to audit (DEGRADED with the
/// reason, capability flag `audit_fallback`) and audit-backed execs still
/// arrive.
#[test]
#[ignore]
fn corrupted_object_falls_back_to_audit() {
    let m = marker();
    let good = required_bpf_dir();
    // Declared before the stack so it outlives the agent reading it.
    let bad = tempfile::Builder::new()
        .prefix("osiris-bpf-corrupt-")
        .tempdir()
        .unwrap();
    std::fs::copy(good.join("process.bpf.o"), bad.path().join("process.bpf.o")).unwrap();
    std::fs::write(
        bad.path().join("process.bpf.o.sha256"),
        format!("{}  process.bpf.o\n", "0".repeat(64)),
    )
    .unwrap();
    let s = stack_with_bpf(
        &Path::new(WATCH_ROOT).join(&m),
        Some(bad.path().to_path_buf()),
    );

    let health = process_health_reaches(&s, "DEGRADED");
    let degraded: Vec<&Value> = health
        .iter()
        .filter(|h| h["state"]["state"] == json!("DEGRADED"))
        .collect();
    assert!(
        degraded.iter().all(|h| h["state"]["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("integrity"))),
        "DEGRADED without the integrity reason: {health:?}"
    );
    let status = process_status(&s);
    assert_eq!(status["state"], json!("DEGRADED"), "status: {status}");
    assert!(
        has_flag(&status, "audit_fallback"),
        "no `audit_fallback` capability flag: {status}"
    );
    assert!(
        !has_flag(&status, "ebpf"),
        "fell back yet `ebpf` set: {status}"
    );

    let t0 = now_ns();
    sh(&format!("/bin/sh -c 'true {m}'"));
    events(&s, "PROCESS_EXEC", t0, |v| {
        objects_with(v, "event_type", &json!("PROCESS_EXEC"))
            .iter()
            .any(|e| e["provider"] == json!("process_exec_sensor/audit") && contains_str(e, &m))
    });
}
