use std::sync::Arc;
use std::time::Duration;

use osiris_agent::{Agent, AgentConfig};
use osiris_api::build_router;
use osiris_detect::DetectionEngine;
use osiris_schema::HostRef;
use osiris_server::run_ingestion_loop;
use osiris_storage::{QueryPlan, Storage};
use osiris_storage_sqlite::SqliteStorage;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Exercises ARCHITECTURE.md §26's worked trace, narrowed to the
/// process/exec portion per Phase 1's exit criterion (§29): a synthetic
/// sshd -> bash -> curl exec chain flows through the real Agent (Sensor ->
/// Pipeline -> Bus -> spool file), the real Server (spool tailer ->
/// SqliteStorage), and the real HTTP API — parent_process resolution
/// survives the whole path, verified both in-process and over real HTTP,
/// plus a real subprocess invocation of the `osiris` CLI binary.
// Multi-thread runtime: step 3 below blocks this test's thread on a
// synchronous `std::process::Command::output()` call while the spawned
// axum server task (step 2) must keep being polled on another OS thread to
// answer that subprocess's HTTP request — a current-thread runtime would
// starve the server task and the CLI's request would stall until it errors.
#[tokio::test(flavor = "multi_thread")]
async fn synthetic_exec_chain_flows_end_to_end_through_agent_server_and_api() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("spool.ndjson");
    let db_path = dir.path().join("events.db");

    let host = HostRef {
        host_id: Uuid::new_v4(),
        hostname: "e2e-test-host".to_string(),
        distro: "test".to_string(),
        kernel_version: "test".to_string(),
        cloud: None,
    };

    let agent_config = AgentConfig {
        audit_log_path: None,
        fs_audit_log_path: None,
        network_proc_root: None,
        enable_synthetic: true,
        synthetic_scenario: None,
        spool_path: spool_path.to_string_lossy().to_string(),
        status_addr: "127.0.0.1:0".to_string(),
    };
    let agent = Agent::start(agent_config, host, "e2e-boot".to_string())
        .await
        .unwrap();

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(&db_path).unwrap());
    let ingestion_cancellation = CancellationToken::new();
    tokio::spawn(run_ingestion_loop(
        spool_path.clone(),
        storage.clone(),
        Arc::new(DetectionEngine::new(vec![])),
        Duration::from_millis(50),
        ingestion_cancellation.clone(),
    ));

    // Give the synthetic sensor (3 events, 10ms apart) and the ingestion
    // loop (50ms poll) time to complete the whole path.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    agent.shutdown().await;
    ingestion_cancellation.cancel();

    // 1. Storage directly: all three events landed, with parent_process
    //    correctly resolved end-to-end (the Enrich stage's ProcessResolver
    //    survived Sensor -> Pipeline -> Bus -> spool file -> Server ->
    //    SqliteStorage).
    let events = storage.query(&QueryPlan::new()).unwrap();
    assert_eq!(events.len(), 3, "expected sshd, bash, curl");

    let curl = events
        .iter()
        .find(|e| e.process.as_ref().unwrap().exe_path == "/usr/bin/curl")
        .expect("curl event must be present");
    let bash = events
        .iter()
        .find(|e| e.process.as_ref().unwrap().exe_path == "/bin/bash")
        .expect("bash event must be present");
    assert_eq!(
        curl.parent_process.as_ref().unwrap().process_key,
        bash.process.as_ref().unwrap().process_key,
        "curl's parent_process must resolve to bash's process_key"
    );

    // 2. The real HTTP API, bound to a real TCP listener: the same chain
    //    is queryable over the wire, not just in-process.
    let app = build_router(storage.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let health: serde_json::Value = client
        .get(format!("http://{}/api/v1/health", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["event_count"], 3);

    let events_body: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/events?event_type=PROCESS_EXEC",
            addr
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(events_body.as_array().unwrap().len(), 3);

    let bash_key = bash.process.as_ref().unwrap().process_key.as_hex();
    let detail: serde_json::Value = client
        .get(format!("http://{}/api/v1/processes/{}", addr, bash_key))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        detail["children"].as_array().unwrap().len(),
        1,
        "bash's process tree must show curl as its one child"
    );

    // 3. The real CLI binary, invoked as a subprocess against the real
    //    running server (ARCHITECTURE.md §94's "CLI/API integration").
    let cli_binary = cli_binary_path();
    let output = std::process::Command::new(&cli_binary)
        .args(["--server", &format!("http://{}", addr), "--format", "json", "events"])
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "failed to run the osiris CLI binary at {}: {} — did Task 9's `cargo build -p osiris-cli` run first?",
                cli_binary.display(),
                e
            )
        });
    assert!(
        output.status.success(),
        "osiris events exited non-zero: {:?}",
        output
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("CLI stdout must be valid JSON in --format json mode");
    assert_eq!(parsed.as_array().unwrap().len(), 3);
}

/// Phase 2's full vertical slice: the web-shell-drop scenario (sshd -> bash
/// -> curl, then curl stages a payload under a temp name, writes it, renames
/// it into the web root, and bash makes an unrelated benign write) flows
/// through the real Agent, Server (spool tailer -> SqliteStorage ->
/// DetectionEngine -> alert persistence), and HTTP API. Verifies plan
/// Global Constraint #13 (Timeline interleaving), the PROCESS_KEY_PROVISIONAL
/// absence Task 3 promised Task 9 would check, the shipped detection rule
/// firing against real ingested events, and the File Story endpoint's
/// cross-rename identity join (Global Constraint #11) over real HTTP.
#[tokio::test(flavor = "multi_thread")]
async fn web_shell_drop_scenario_flows_end_to_end_and_triggers_detection() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("spool.ndjson");
    let db_path = dir.path().join("events.db");

    let host = HostRef {
        host_id: Uuid::new_v4(),
        hostname: "e2e-test-host".to_string(),
        distro: "test".to_string(),
        kernel_version: "test".to_string(),
        cloud: None,
    };

    let agent_config = AgentConfig {
        audit_log_path: None,
        fs_audit_log_path: None,
        network_proc_root: None,
        enable_synthetic: true,
        synthetic_scenario: Some("web_shell_drop".to_string()),
        spool_path: spool_path.to_string_lossy().to_string(),
        status_addr: "127.0.0.1:0".to_string(),
    };
    let agent = Agent::start(agent_config, host, "e2e-boot".to_string())
        .await
        .unwrap();

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(&db_path).unwrap());

    // Load the real shipped rule the same way osiris-server's main.rs does —
    // this proves the actual file this phase ships, not a hand-written
    // equivalent (Task 7's forward-reference to this test).
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
    let detection_engine = Arc::new(DetectionEngine::load_from_dir(&rules_dir).unwrap());
    assert!(
        detection_engine.rule_count() >= 1,
        "the shipped config/rules/ directory must contain at least the web-root rule"
    );

    let ingestion_cancellation = CancellationToken::new();
    tokio::spawn(run_ingestion_loop(
        spool_path.clone(),
        storage.clone(),
        detection_engine,
        Duration::from_millis(50),
        ingestion_cancellation.clone(),
    ));

    // 7-event scenario, 10ms apart (see generator::scenarios) plus a 50ms
    // ingestion poll interval: give it comfortably more than both Phase 1's
    // exec-chain test's 1000ms budget accounted for, since this scenario has
    // more than double the events.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    agent.shutdown().await;
    ingestion_cancellation.cancel();

    // 1. Storage directly: all 7 events landed (3 exec + 4 file).
    let events = storage.query(&QueryPlan::new()).unwrap();
    assert_eq!(events.len(), 7, "expected sshd, bash, curl, and 4 file events");

    // 2. PROCESS_KEY_PROVISIONAL must be absent from every file event: curl
    //    (pid 300) and bash (pid 200) both already executed earlier in this
    //    same scenario, so ProcessResolver must have resolved their real
    //    process_key rather than falling back to a provisional tag.
    let file_events: Vec<_> = events
        .iter()
        .filter(|e| e.file.is_some())
        .collect();
    assert_eq!(file_events.len(), 4, "expected create, write, rename, benign-write");
    for event in &file_events {
        assert!(
            !event.tags.iter().any(|t| t == "PROCESS_KEY_PROVISIONAL"),
            "file event for {:?} must not carry PROCESS_KEY_PROVISIONAL — its actor pid \
             already executed earlier in the scenario",
            event.file.as_ref().map(|f| &f.path)
        );
    }

    // 3. Timeline: GET /api/v1/events?since=&until= interleaves file and
    //    process events correctly in (timestamp, event_id) order (Global
    //    Constraint #13). Use the full scenario's time range.
    let app = build_router(storage.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let min_ts = events.iter().map(|e| e.timestamp).min().unwrap();
    let max_ts = events.iter().map(|e| e.timestamp).max().unwrap();
    let timeline: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/events?since={}&until={}",
            addr,
            min_ts - 1,
            max_ts + 1
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let timeline_events = timeline.as_array().unwrap();
    assert_eq!(timeline_events.len(), 7);
    // Content-level ordering assertion, not just a count: timestamps must be
    // non-decreasing across the whole response.
    let timestamps: Vec<u64> = timeline_events
        .iter()
        .map(|e| e["timestamp"].as_u64().unwrap())
        .collect();
    let mut sorted = timestamps.clone();
    sorted.sort();
    assert_eq!(timestamps, sorted, "events must come back in timestamp order");
    // File and process categories must both be present in this one ordered
    // response — proving interleaving, not two separately-sorted lists.
    let categories: std::collections::HashSet<_> = timeline_events
        .iter()
        .map(|e| e["category"].as_str().unwrap().to_string())
        .collect();
    assert!(categories.contains("PROCESS") && categories.contains("FILE"));

    // 4. The shipped detection rule fired: GET /api/v1/alerts must show the
    //    web-root rule, citing the temp-path create/write (both under
    //    /var/www/html/ per generator::scenarios::WEB_SHELL_TEMP_PATH).
    let alerts: serde_json::Value = client
        .get(format!("http://{}/api/v1/alerts", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alerts_array = alerts.as_array().unwrap();
    assert!(
        !alerts_array.is_empty(),
        "the shipped shell_wrote_file_to_web_root rule must have fired on curl's \
         create/write into /var/www/html/.shell.php.tmp"
    );
    assert!(alerts_array
        .iter()
        .all(|a| a["rule_id"].as_str().unwrap() == "shell_wrote_file_to_web_root"));
    // Every alert must carry non-empty reasons (§11.2's structural
    // guarantee) — assert on content, not just presence.
    for alert in alerts_array {
        let reasons = alert["reasons"].as_array().unwrap();
        assert!(!reasons.is_empty());
        assert!(reasons.iter().all(|r| !r.as_str().unwrap().trim().is_empty()));
    }

    // 5. File Story over real HTTP: querying by the FINAL path
    //    (/var/www/html/shell.php, which only the rename event carries)
    //    must still surface the create/write events at the TEMP path,
    //    because they share one file identity (Global Constraint #6/#11) —
    //    this is the cross-rename join, proven here over the wire, not just
    //    in Task 8's handler-level unit tests.
    let final_path = "/var/www/html/shell.php";
    let story: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/files/story?path={}",
            addr,
            urlencoding_lite(final_path)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let story_events = story["events"].as_array().unwrap();
    // create + write (temp path) + rename (final path) = 3 events sharing
    // the staged file's identity. The benign notes write has a different
    // inode and must NOT appear.
    assert_eq!(
        story_events.len(),
        3,
        "File Story for the final path must include the temp-path create/write via \
         identity, plus the rename event itself"
    );
    let story_paths: std::collections::HashSet<_> = story_events
        .iter()
        .map(|e| e["file"]["path"].as_str().unwrap().to_string())
        .collect();
    assert!(story_paths.contains("/var/www/html/.shell.php.tmp"));
    assert!(story_paths.contains(final_path));
    let story_alerts = story["alerts"].as_array().unwrap();
    assert!(
        !story_alerts.is_empty(),
        "the File Story must attach the alert(s) whose evidence cites one of these events"
    );

    // 6. The real CLI binary still works against this richer dataset
    //    (regression check — Phase 1's CLI/API integration must not have
    //    broken by adding file events and alerts to the mix).
    let cli_binary = cli_binary_path();
    let output = std::process::Command::new(&cli_binary)
        .args(["--server", &format!("http://{}", addr), "--format", "json", "events"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 7);
}

/// Minimal ad-hoc percent-encoding for the one query-string value this test
/// needs to send (a `/`-containing path) — not a general URL encoder.
/// `reqwest` does not percent-encode a raw string interpolated into a
/// `format!`-built URL, and this test has no encoding crate dependency
/// already in scope, so this keeps the test self-contained rather than
/// adding a new dependency for one call site.
fn urlencoding_lite(s: &str) -> String {
    s.replace('/', "%2F")
}

/// Locates the already-built `osiris` CLI binary next to this test
/// binary's own build output, without depending on `assert_cmd`. Requires
/// Task 9's `cargo build -p osiris-cli` (or an earlier `cargo test -p
/// osiris-cli`) to have run first in the same target directory — true both
/// for the per-task build/test steps already done and for any subsequent
/// `cargo test --workspace`.
fn cli_binary_path() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // this test binary's own file name
    if path.ends_with("deps") {
        path.pop();
    }
    path.push(format!("osiris{}", std::env::consts::EXE_SUFFIX));
    path
}
