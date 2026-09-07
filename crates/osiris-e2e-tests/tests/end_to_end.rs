use std::sync::Arc;
use std::time::Duration;

use osiris_agent::{Agent, AgentConfig};
use osiris_api::build_router;
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
