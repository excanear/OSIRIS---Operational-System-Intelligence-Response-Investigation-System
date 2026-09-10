use std::sync::Arc;
use std::time::Duration;

use osiris_agent::{Agent, AgentConfig};
use osiris_api::build_router;
use osiris_detect::DetectionEngine;
use osiris_schema::{Category, EntityRef, EventType, HostRef, Relation};
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
        identity_audit_log_path: None,
        systemd_audit_log_path: None,
        persistence_watch_paths: vec![],
        container_cgroup_roots: vec![],
        proc_root: None,
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
        identity_audit_log_path: None,
        systemd_audit_log_path: None,
        persistence_watch_paths: vec![],
        container_cgroup_roots: vec![],
        proc_root: None,
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

/// Phase 3's full vertical slice: the network-beacon scenario (sshd -> bash
/// -> curl, then curl resolves a suspicious-TLD domain and connects to the
/// resolved address before the connection closes) flows through the real
/// Agent, Server (ingest + detection + storage), and HTTP API. Verifies
/// Timeline interleaving of the DNS/Network categories, PROCESS_KEY_PROVISIONAL
/// absence, the shipped DNS rule firing on a real ingested event, and
/// Network Story's domain-to-connection join (and its disclosed
/// IP-form asymmetry) over real HTTP.
#[tokio::test(flavor = "multi_thread")]
async fn network_beacon_scenario_flows_end_to_end_and_triggers_detection() {
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
        identity_audit_log_path: None,
        systemd_audit_log_path: None,
        persistence_watch_paths: vec![],
        container_cgroup_roots: vec![],
        proc_root: None,
        enable_synthetic: true,
        synthetic_scenario: Some("network_beacon".to_string()),
        spool_path: spool_path.to_string_lossy().to_string(),
        status_addr: "127.0.0.1:0".to_string(),
    };
    let agent = Agent::start(agent_config, host, "e2e-boot".to_string())
        .await
        .unwrap();

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(&db_path).unwrap());

    // The real shipped rules directory — now two rules (Phase 2's web-root
    // rule plus Phase 3's DNS rule) loaded the same way osiris-server's
    // main.rs does.
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
    let detection_engine = Arc::new(DetectionEngine::load_from_dir(&rules_dir).unwrap());
    assert!(detection_engine.rule_count() >= 2);

    let ingestion_cancellation = CancellationToken::new();
    tokio::spawn(run_ingestion_loop(
        spool_path.clone(),
        storage.clone(),
        detection_engine,
        Duration::from_millis(50),
        ingestion_cancellation.clone(),
    ));

    // 6-event scenario, 1ms apart, plus a 50ms ingestion poll interval —
    // comfortably generous, matching Phase 2's precedent budget for a
    // similarly-sized scenario.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    agent.shutdown().await;
    ingestion_cancellation.cancel();

    // 1. Storage directly: all 6 events landed (3 exec + 1 DNS + 2 network).
    let events = storage.query(&QueryPlan::new()).unwrap();
    assert_eq!(events.len(), 6, "expected sshd, bash, curl, 1 DNS query, connect, close");

    // 2. PROCESS_KEY_PROVISIONAL must be absent from the DNS and network
    //    events: curl (pid 300) already executed earlier in this same
    //    scenario, so ProcessResolver must have resolved its real
    //    process_key.
    let non_process_events: Vec<_> = events
        .iter()
        .filter(|e| e.dns.is_some() || e.network.is_some())
        .collect();
    assert_eq!(non_process_events.len(), 3, "1 DNS + 2 network events");
    for event in &non_process_events {
        assert!(
            !event.tags.iter().any(|t| t == "PROCESS_KEY_PROVISIONAL"),
            "event {:?} must not carry PROCESS_KEY_PROVISIONAL — curl already executed earlier",
            event.event_id
        );
    }

    // 2b. Global Constraint #8's actual Entity Graph edges: this is checked
    //     directly on `event.relationships` (populated once at enrichment,
    //     ARCHITECTURE.md §9.4), not inferred from the Network Story join
    //     below (which proves Global Constraint #9's separate string-match
    //     logic and would pass even if these edges did not exist at all).
    let connect_event = events
        .iter()
        .find(|e| e.event_type == EventType::NetworkConnect)
        .expect("NETWORK_CONNECT event must be present");
    let connect_to_edges: Vec<_> = connect_event
        .relationships
        .iter()
        .filter(|r| r.relation == Relation::ConnectedTo)
        .collect();
    assert_eq!(
        connect_to_edges.len(),
        1,
        "NETWORK_CONNECT must carry exactly one CONNECTED_TO edge"
    );
    match &connect_to_edges[0].to {
        EntityRef::Ip { addr } => assert_eq!(addr, "203.0.113.50"),
        other => panic!("CONNECTED_TO edge must target an Ip entity, got {:?}", other),
    }

    let close_event = events
        .iter()
        .find(|e| e.event_type == EventType::NetworkClose)
        .expect("NETWORK_CLOSE event must be present");
    assert!(
        !close_event
            .relationships
            .iter()
            .any(|r| r.relation == Relation::ConnectedTo),
        "NETWORK_CLOSE must NOT carry a CONNECTED_TO edge — it would duplicate the one \
         already attached to NETWORK_CONNECT"
    );

    let dns_event = events
        .iter()
        .find(|e| e.event_type == EventType::DnsQuery)
        .expect("DNS_QUERY event must be present");
    let resolved_to_edges: Vec<_> = dns_event
        .relationships
        .iter()
        .filter(|r| r.relation == Relation::ResolvedTo)
        .collect();
    assert_eq!(
        resolved_to_edges.len(),
        1,
        "DNS_QUERY must carry exactly one RESOLVED_TO edge (one resolved IP)"
    );
    match (&resolved_to_edges[0].from, &resolved_to_edges[0].to) {
        (EntityRef::Domain { name }, EntityRef::Ip { addr }) => {
            assert_eq!(name, "cdn-assets.xyz");
            assert_eq!(addr, "203.0.113.50");
        }
        other => panic!("RESOLVED_TO edge must be Domain -> Ip, got {:?}", other),
    }

    // 3. Timeline: both DNS and NETWORK categories appear, correctly
    //    time-ordered alongside PROCESS, in one GET /api/v1/events response.
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
    assert_eq!(timeline_events.len(), 6);
    let timestamps: Vec<u64> = timeline_events
        .iter()
        .map(|e| e["timestamp"].as_u64().unwrap())
        .collect();
    let mut sorted = timestamps.clone();
    sorted.sort();
    assert_eq!(timestamps, sorted, "events must come back in timestamp order");
    let categories: std::collections::HashSet<_> = timeline_events
        .iter()
        .map(|e| e["category"].as_str().unwrap().to_string())
        .collect();
    assert!(categories.contains("PROCESS") && categories.contains("DNS") && categories.contains("NETWORK"));

    // 4. The shipped DNS rule fired: GET /api/v1/alerts must show
    //    dns_query_to_suspicious_tld, citing the DNS_QUERY event.
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
        "the shipped dns_query_to_suspicious_tld rule must have fired on curl's query to \
         cdn-assets.xyz"
    );
    assert!(alerts_array
        .iter()
        .all(|a| a["rule_id"].as_str().unwrap() == "dns_query_to_suspicious_tld"));
    for alert in alerts_array {
        let reasons = alert["reasons"].as_array().unwrap();
        assert!(!reasons.is_empty());
        assert!(reasons.iter().all(|r| !r.as_str().unwrap().trim().is_empty()));
    }

    // 5. Network Story by domain: the DNS event plus both network events
    //    that touch its resolved address (cdn-assets.xyz -> 203.0.113.50),
    //    proving Global Constraint #9's domain-form join (dns.response_ips
    //    string-matched against network_addr), over real HTTP. This is
    //    independent of the Entity Graph edges themselves — those are
    //    proven directly on `event.relationships` in step 2b above.
    let story: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/network/story?domain=cdn-assets.xyz",
            addr
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let story_events = story["events"].as_array().unwrap();
    assert_eq!(
        story_events.len(),
        3,
        "domain-form Network Story must include the DNS query plus both network events \
         touching its resolved address"
    );
    let story_categories: std::collections::HashSet<_> = story_events
        .iter()
        .map(|e| e["category"].as_str().unwrap().to_string())
        .collect();
    assert!(story_categories.contains("DNS") && story_categories.contains("NETWORK"));
    let story_alerts = story["alerts"].as_array().unwrap();
    assert!(!story_alerts.is_empty());

    // 6. Network Story by IP alone: only the two network events — the
    //    disclosed asymmetry from Global Constraint #9 (no reverse
    //    DNS-answer lookup from an IP alone).
    let ip_story: serde_json::Value = client
        .get(format!(
            "http://{}/api/v1/network/story?ip=203.0.113.50",
            addr
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ip_story_events = ip_story["events"].as_array().unwrap();
    assert_eq!(
        ip_story_events.len(),
        2,
        "IP-form Network Story must NOT include the resolving DNS event — Global \
         Constraint #9's disclosed asymmetry"
    );
    assert!(ip_story_events
        .iter()
        .all(|e| e["category"].as_str().unwrap() == "NETWORK"));

    // 7. The real CLI binary still works against this richer dataset
    //    (regression check).
    let cli_binary = cli_binary_path();
    let output = std::process::Command::new(&cli_binary)
        .args(["--server", &format!("http://{}", addr), "--format", "json", "events"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 6);
}

/// Phase 4a's full vertical slice, and ARCHITECTURE.md §26's worked trace
/// from its true first step: sshd accepts a remote connection, audit
/// records the login, a shell runs inside that session, sudo escalates it
/// to root, and the escalated process writes root's authorized_keys and
/// calls out to a remote address — all through the real Agent (Sensor →
/// Pipeline → Bus → spool), the real Server (spool tailer → SqliteStorage →
/// DetectionEngine → alert persistence) and the real HTTP API.
///
/// Verifies, in order: every event landed; the session propagated from the
/// login down the whole process tree into the privilege, file and network
/// events (plan Global Constraint #5); both §9.4 entity edges are present
/// on exactly the right events and absent everywhere else (Global
/// Constraint #8), asserted on `event.relationships` directly rather than
/// inferred from the Story join; USER_REF_PARTIAL is applied only where
/// auditd genuinely cannot report gid/euid/egid (Global Constraint #6);
/// the shipped escalation rule fired and the other two did not; and the
/// Identity Story returns the full multi-category chain over real HTTP.
#[tokio::test(flavor = "multi_thread")]
async fn ssh_sudo_escalation_flows_end_to_end_and_triggers_detection() {
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
        identity_audit_log_path: None,
        systemd_audit_log_path: None,
        persistence_watch_paths: vec![],
        container_cgroup_roots: vec![],
        proc_root: None,
        enable_synthetic: true,
        synthetic_scenario: Some("ssh_sudo_escalation".to_string()),
        spool_path: spool_path.to_string_lossy().to_string(),
        status_addr: "127.0.0.1:0".to_string(),
    };
    let agent = Agent::start(agent_config, host, "e2e-boot".to_string())
        .await
        .unwrap();

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(&db_path).unwrap());

    // The real shipped rules directory — now three rules, loaded exactly
    // the way osiris-server's main.rs loads them.
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
    let detection_engine = Arc::new(DetectionEngine::load_from_dir(&rules_dir).unwrap());
    assert!(detection_engine.rule_count() >= 3);

    let ingestion_cancellation = CancellationToken::new();
    tokio::spawn(run_ingestion_loop(
        spool_path.clone(),
        storage.clone(),
        detection_engine,
        Duration::from_millis(50),
        ingestion_cancellation.clone(),
    ));

    // 9-event scenario, 1ms apart, plus a 50ms ingestion poll interval —
    // the same generous budget Phase 2 and Phase 3 used for comparable
    // scenario sizes.
    tokio::time::sleep(Duration::from_millis(1400)).await;
    agent.shutdown().await;
    ingestion_cancellation.cancel();

    // 1. Storage directly: all 9 events landed, across all five categories.
    let events = storage.query(&QueryPlan::new()).unwrap();
    assert_eq!(
        events.len(),
        9,
        "expected sshd/bash/sudo execs, login, sudo, uid change, file write, connect, logout"
    );

    // 2. Session propagation (Global Constraint #5): every event after the
    //    login carries the SSH session — including the file and network
    //    events, which is what makes the chain multi-category under one id.
    //    The sshd exec that preceded the login does NOT, and must not be
    //    retro-attributed.
    let sshd_exec = events
        .iter()
        .find(|e| {
            e.event_type == EventType::ProcessExec
                && e.process.as_ref().map(|p| p.pid) == Some(100)
        })
        .expect("the sshd exec must be present");
    assert!(
        sshd_exec.session.is_none(),
        "the exec that preceded the login must not be retro-attributed to it"
    );

    for event in &events {
        // Skip the pre-login exec checked above.
        if event.event_id == sshd_exec.event_id {
            continue;
        }
        let session = event
            .session
            .as_ref()
            .unwrap_or_else(|| panic!("{:?} must carry the session", event.event_type));
        assert_eq!(session.session_id, "3");
        assert_eq!(
            session.remote_addr.as_deref(),
            Some("198.51.100.10"),
            "{:?} must carry the login's remote address, not just its id",
            event.event_type
        );
        assert_eq!(session.auth_method.as_deref(), Some("sshd"));
    }

    // 3. The two §9.4 entity edges (Global Constraint #8), asserted on
    //    event.relationships directly — a Story join would pass even if
    //    these did not exist.
    let bash_exec = events
        .iter()
        .find(|e| {
            e.event_type == EventType::ProcessExec
                && e.process.as_ref().map(|p| p.pid) == Some(200)
        })
        .expect("the bash exec must be present");
    let triggered: Vec<_> = bash_exec
        .relationships
        .iter()
        .filter(|r| r.relation == Relation::TriggeredBySession)
        .collect();
    assert_eq!(
        triggered.len(),
        1,
        "a PROCESS_EXEC inside a session must carry exactly one TRIGGERED_BY_SESSION edge"
    );
    match (&triggered[0].from, &triggered[0].to) {
        (EntityRef::Process { process_key }, EntityRef::Session { session_id }) => {
            assert_eq!(*process_key, bash_exec.process.as_ref().unwrap().process_key);
            assert_eq!(session_id, "3");
        }
        other => panic!("TRIGGERED_BY_SESSION must be Process -> Session, got {:?}", other),
    }

    let escalation = events
        .iter()
        .find(|e| e.event_type == EventType::PrivilegeUidChange)
        .expect("the PRIVILEGE_UID_CHANGE event must be present");
    let executed_as: Vec<_> = escalation
        .relationships
        .iter()
        .filter(|r| r.relation == Relation::ExecutedAs)
        .collect();
    assert_eq!(
        executed_as.len(),
        1,
        "a real uid transition must carry exactly one EXECUTED_AS edge"
    );
    match &executed_as[0].to {
        EntityRef::User { uid, .. } => assert_eq!(*uid, 0, "the edge must target root"),
        other => panic!("EXECUTED_AS must target a User entity, got {:?}", other),
    }

    // ...and nowhere else. The sudo event names no target account (Global
    // Constraint #9), so it mints no EXECUTED_AS; the file and network
    // events carry the session but not a duplicate TRIGGERED_BY_SESSION.
    let sudo_event = events
        .iter()
        .find(|e| e.event_type == EventType::PrivilegeSudo)
        .expect("the PRIVILEGE_SUDO event must be present");
    assert!(
        sudo_event
            .relationships
            .iter()
            .all(|r| r.relation != Relation::ExecutedAs),
        "a USER_CMD-derived sudo event must not invent a target account"
    );
    for event in events.iter().filter(|e| {
        matches!(
            e.event_type,
            EventType::FileWrite | EventType::NetworkConnect | EventType::PrivilegeUidChange
        )
    }) {
        assert!(
            event
                .relationships
                .iter()
                .all(|r| r.relation != Relation::TriggeredBySession),
            "TRIGGERED_BY_SESSION belongs on PROCESS_EXEC only — repeating it on \
             every later event of a session writes one fact hundreds of times"
        );
    }

    // 4. Provenance tags (Global Constraints #4/#6): the sudo event is
    //    tagged partial because USER_CMD reports no gid/euid/egid; the
    //    SYSCALL-derived escalation is NOT, because it reports them for
    //    real. Both name the one Identity sensor in `provider`.
    assert!(
        sudo_event.tags.iter().any(|t| t == "USER_REF_PARTIAL"),
        "a USER_CMD-derived event must be tagged partial, not silently mirrored"
    );
    assert!(
        !escalation.tags.iter().any(|t| t == "USER_REF_PARTIAL"),
        "a SYSCALL-derived event reports gid/euid/egid for real and must not be tagged"
    );
    for event in [sudo_event, escalation] {
        assert!(
            event.provider.starts_with("identity_sensor/"),
            "§4.3 has no Privilege sensor row: privilege events name the Identity \
            sensor in `provider` (got {:?})",
            event.provider
        );
    }
    assert!(
        !events.iter().any(|e| e.tags.iter().any(|t| t == "INVALID")),
        "no event in this scenario may fail validation"
    );

    // 5. Storage's own new filters work on real ingested rows (Task 4).
    let mut plan = QueryPlan::new();
    plan.session_id = Some("3".to_string());
    assert_eq!(
        storage.query(&plan).unwrap().len(),
        8,
        "every event except the pre-login sshd exec belongs to session 3"
    );

    // 6. Over real HTTP: Timeline interleaving of all five categories.
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
    assert_eq!(timeline_events.len(), 9);
    let timestamps: Vec<u64> = timeline_events
        .iter()
        .map(|e| e["timestamp"].as_u64().unwrap())
        .collect();
    let mut sorted = timestamps.clone();
    sorted.sort();
    assert_eq!(timestamps, sorted, "events must come back in timestamp order");
    let categories: std::collections::HashSet<_> = timeline_events
        .iter()
        .map(|e| e["category"].as_str().unwrap().to_string())
        .collect();
    for expected in ["IDENTITY", "PROCESS", "PRIVILEGE", "FILE", "NETWORK"] {
        assert!(
            categories.contains(expected),
            "§29's Phase 4 line requires a genuinely multi-category chain; missing {expected}"
        );
    }

    // 7. The shipped escalation rule fired — and only it. The file write
    //    is to /root/.ssh, not /var/www, and the connection is to a bare IP
    //    with no DNS query, so Phase 2's and Phase 3's rules must stay
    //    silent on this scenario.
    let alerts: serde_json::Value = client
        .get(format!("http://{}/api/v1/alerts", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alerts_array = alerts.as_array().unwrap();
    assert_eq!(
        alerts_array.len(),
        1,
        "exactly one alert: the escalation rule, not the web-root or DNS rules"
    );
    assert_eq!(
        alerts_array[0]["rule_id"].as_str().unwrap(),
        "privilege_escalation_to_root_in_remote_session"
    );
    let reasons = alerts_array[0]["reasons"].as_array().unwrap();
    assert_eq!(reasons.len(), 3);
    assert!(reasons.iter().all(|r| !r.as_str().unwrap().trim().is_empty()));
    // §11.1: the alert cites the exact rule revision that fired.
    assert_eq!(
        alerts_array[0]["rule_content_hash"].as_str().unwrap().len(),
        64
    );
    // ...and it cites the escalation event as its evidence.
    let evidence: Vec<&str> = alerts_array[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(evidence.contains(&escalation.event_id.to_string().as_str()));

    // 8. Identity Story by session over real HTTP: the whole
    //    identity->process->privilege->file->network chain plus the citing
    //    alert, in one response (Global Constraint #10's session form).
    let story: serde_json::Value = client
        .get(format!("http://{}/api/v1/identity/story?session_id=3", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let story_events = story["events"].as_array().unwrap();
    assert_eq!(
        story_events.len(),
        8,
        "the session story must contain every event of the session"
    );
    let story_categories: std::collections::HashSet<_> = story_events
        .iter()
        .map(|e| e["category"].as_str().unwrap().to_string())
        .collect();
    for expected in ["IDENTITY", "PROCESS", "PRIVILEGE", "FILE", "NETWORK"] {
        assert!(story_categories.contains(expected), "story missing {expected}");
    }
    assert_eq!(story["alerts"].as_array().unwrap().len(), 1);

    // 9. Identity Story by uid: Global Constraint #10's disclosed
    //    asymmetry — the uid form does not fan out to the whole session.
    //    `user` is only populated on Identity/Privilege events today (see
    //    `normalize.rs`'s `normalize_network_event`, which never sets it),
    //    and of this scenario's Identity/Privilege events only the login
    //    and logout carry uid 0 — sshd authenticates as root for both. The
    //    sudo and uid-change Privilege events carry uid 1000 (the actor,
    //    alice, not the euid=0 she escalated to), and the file/network
    //    events carry no `user` at all. So exactly 2 events come back.
    let uid_story: serde_json::Value = client
        .get(format!("http://{}/api/v1/identity/story?uid=0", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let uid_story_events = uid_story["events"].as_array().unwrap();
    assert_eq!(
        uid_story_events.len(),
        2,
        "the uid form must NOT expand to every event in the sessions that user opened \
         — Global Constraint #10's disclosed asymmetry — and must return exactly the \
         login and logout, the only two events that carry uid 0"
    );
    assert!(uid_story_events
        .iter()
        .all(|e| e["user"]["uid"].as_u64() == Some(0)));

    // 10. The real CLI binary still works against this richer dataset
    //     (regression check, unchanged from Phase 2/3).
    let cli_binary = cli_binary_path();
    let output = std::process::Command::new(&cli_binary)
        .args(["--server", &format!("http://{}", addr), "--format", "json", "events"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 9);
}

/// Phase 4b's flagship trace: continuing the same SSH-login-then-sudo-to-
/// root escalation `ssh_sudo_escalation_flows_end_to_end_and_triggers_detection`
/// proves, the same attacker now installs a backdoor systemd unit file
/// (observed by Persistence Monitor's periodic scan-and-diff — unattributed,
/// no pid triggered it) and starts it (observed by the audit-backed Systemd
/// sensor, whose record's own `ses=` carries the SSH session directly) — all
/// through the real Agent, Server, and HTTP API.
///
/// Verifies, in order: all 9 events landed across the four categories this
/// trace touches; the `SERVICE_CREATE` event carries no session (Global
/// Constraint #3 — the scanner is not triggered by a process) while the
/// `SERVICE_START` event's directly-observed session is enriched to the full
/// record (proof that Task 1's fix and this phase's direct-observation
/// normalize combine correctly); `SERVICE_START` carries zero relationship
/// edges (Global Constraint #3's "no fabricated actor" ruling, asserted as
/// an absence check the way Phase 4a's own final review required); both the
/// new systemd rule and Phase 4a's escalation rule fired — and only those
/// two; and the new Systemd Story endpoint returns exactly the two
/// `backdoor.service`-named events plus the one alert that cites either of
/// them as evidence.
#[tokio::test(flavor = "multi_thread")]
async fn persistence_via_systemd_service_scenario_flows_end_to_end_and_triggers_detection() {
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
        identity_audit_log_path: None,
        systemd_audit_log_path: None,
        persistence_watch_paths: vec![],
        container_cgroup_roots: vec![],
        proc_root: None,
        enable_synthetic: true,
        synthetic_scenario: Some("persistence_via_systemd_service".to_string()),
        spool_path: spool_path.to_string_lossy().to_string(),
        status_addr: "127.0.0.1:0".to_string(),
    };
    let agent = Agent::start(agent_config, host, "e2e-boot".to_string())
        .await
        .unwrap();

    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::open(&db_path).unwrap());

    // The real shipped rules directory — now four rules.
    let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/rules");
    let detection_engine = Arc::new(DetectionEngine::load_from_dir(&rules_dir).unwrap());
    assert!(detection_engine.rule_count() >= 4);

    let ingestion_cancellation = CancellationToken::new();
    tokio::spawn(run_ingestion_loop(
        spool_path.clone(),
        storage.clone(),
        detection_engine,
        Duration::from_millis(50),
        ingestion_cancellation.clone(),
    ));

    // 9-event scenario, same generous budget as the ssh_sudo_escalation e2e.
    tokio::time::sleep(Duration::from_millis(1400)).await;
    agent.shutdown().await;
    ingestion_cancellation.cancel();

    // 1. Storage directly: all 9 events landed, across exactly four
    //    categories (no FILE, no NETWORK, no generic PERSISTENCE — this
    //    scenario's one checkpoint is a SystemdUnit, which Global Constraint
    //    #1 routes entirely into SYSTEMD).
    let events = storage.query(&QueryPlan::new()).unwrap();
    assert_eq!(
        events.len(),
        9,
        "expected sshd/bash/sudo execs, login, sudo, uid change, unit-file create, service start, logout"
    );
    // `Category` derives neither `Hash` nor `Ord` (schema-frozen, Global
    // Constraint #6 — not something this phase may add just for a test), so
    // this checks membership directly rather than building a `HashSet`.
    assert!(
        events
            .iter()
            .all(|e| matches!(
                e.category,
                Category::Process | Category::Identity | Category::Privilege | Category::Systemd
            )),
        "no FILE/NETWORK/PERSISTENCE event exists in this scenario"
    );
    for expected in [
        Category::Process,
        Category::Identity,
        Category::Privilege,
        Category::Systemd,
    ] {
        assert!(
            events.iter().any(|e| e.category == expected),
            "expected at least one {expected:?} event"
        );
    }

    // 2. The two SYSTEMD-category events, told apart by event_type: the
    //    Persistence-Monitor-observed unit-file creation, and the
    //    audit-observed service start.
    let unit_create = events
        .iter()
        .find(|e| e.event_type == EventType::ServiceCreate)
        .expect("the SERVICE_CREATE event must be present");
    let service_start = events
        .iter()
        .find(|e| e.event_type == EventType::ServiceStart)
        .expect("the SERVICE_START event must be present");
    assert_eq!(unit_create.service.as_ref().unwrap().unit_name, "backdoor.service");
    assert_eq!(service_start.service.as_ref().unwrap().unit_name, "backdoor.service");

    // 3. Session propagation (Global Constraint #3's disclosed asymmetry):
    //    SERVICE_CREATE carries none at all (the scanner has no process to
    //    attribute it to); SERVICE_START carries the SSH session, enriched
    //    to the full record — proof Task 1's fix and this phase's direct
    //    observation combine correctly, not just in the pipeline unit test.
    assert!(
        unit_create.session.is_none(),
        "a Persistence-Monitor-observed event must carry no session — it was never triggered by a process"
    );
    let start_session = service_start
        .session
        .as_ref()
        .expect("SERVICE_START's own ses= must be observed and preserved");
    assert_eq!(start_session.session_id, "3");
    assert_eq!(
        start_session.remote_addr.as_deref(),
        Some("198.51.100.10"),
        "the observed session id must be enriched to the full record, not left minimal"
    );
    assert_eq!(start_session.auth_method.as_deref(), Some("sshd"));

    let sshd_exec = events
        .iter()
        .find(|e| {
            e.event_type == EventType::ProcessExec
                && e.process.as_ref().map(|p| p.pid) == Some(100)
        })
        .expect("the sshd exec must be present");
    assert!(
        sshd_exec.session.is_none(),
        "the exec that preceded the login must not be retro-attributed to it"
    );

    for event in &events {
        if event.event_id == sshd_exec.event_id || event.event_id == unit_create.event_id {
            continue;
        }
        let session = event
            .session
            .as_ref()
            .unwrap_or_else(|| panic!("{:?} must carry the session", event.event_type));
        assert_eq!(session.session_id, "3");
    }

    // 4. Global Constraint #3: no entity-graph edges for either SYSTEMD
    //    event this phase adds — asserted as an absence, on
    //    event.relationships directly, not inferred from a Story join.
    assert!(
        service_start.relationships.is_empty(),
        "a SERVICE_START event must carry zero relationship edges — systemd's own \
         pid=1 is not an attacker-controlled process to graph an edge from"
    );
    assert!(
        unit_create.relationships.is_empty(),
        "a SERVICE_CREATE event must carry zero relationship edges — the scanner \
         observed a path on disk, not a process's action"
    );

    // ...while the pre-existing edges from Phase 4a's own escalation step
    // are still present, exactly as ssh_sudo_escalation's own e2e proved —
    // this phase changes nothing about them.
    let escalation = events
        .iter()
        .find(|e| e.event_type == EventType::PrivilegeUidChange)
        .expect("the PRIVILEGE_UID_CHANGE event must be present");
    assert_eq!(
        escalation
            .relationships
            .iter()
            .filter(|r| r.relation == Relation::ExecutedAs)
            .count(),
        1
    );

    // 5. Storage's new unit_name filter works on real ingested rows (Task 7).
    let mut plan = QueryPlan::new();
    plan.unit_name = Some("backdoor.service".to_string());
    assert_eq!(
        storage.query(&plan).unwrap().len(),
        2,
        "both the create and the start belong to backdoor.service"
    );

    // 6. Over real HTTP: both alerts fired, and only those two.
    let app = build_router(storage.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let alerts: serde_json::Value = client
        .get(format!("http://{}/api/v1/alerts", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let alerts_array = alerts.as_array().unwrap();
    assert_eq!(
        alerts_array.len(),
        2,
        "exactly two alerts: the new systemd rule and Phase 4a's escalation rule \
         — the same attacker continuing the same session, not cross-firing"
    );
    let rule_ids: std::collections::HashSet<_> = alerts_array
        .iter()
        .map(|a| a["rule_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        rule_ids,
        std::collections::HashSet::from([
            "systemd_service_started_in_remote_session".to_string(),
            "privilege_escalation_to_root_in_remote_session".to_string(),
        ]),
        "the Phase 2/3 rules must stay silent — this scenario has no FILE_WRITE/DNS_QUERY event"
    );
    for alert in alerts_array {
        let reasons = alert["reasons"].as_array().unwrap();
        assert!(!reasons.is_empty());
        assert!(reasons.iter().all(|r| !r.as_str().unwrap().trim().is_empty()));
        assert_eq!(alert["rule_content_hash"].as_str().unwrap().len(), 64);
    }

    // 7. The new Systemd Story endpoint (Task 10) over real HTTP: exactly
    //    the two backdoor.service events, plus the one alert that cites
    //    either of them as evidence (the escalation alert's evidence is the
    //    PRIVILEGE_UID_CHANGE event, which this unit-scoped story does not
    //    include).
    let story: serde_json::Value = client
        .get(format!("http://{}/api/v1/systemd/story?unit_name=backdoor.service", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let story_events = story["events"].as_array().unwrap();
    assert_eq!(story_events.len(), 2);
    let story_event_types: std::collections::HashSet<_> = story_events
        .iter()
        .map(|e| e["event_type"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        story_event_types,
        std::collections::HashSet::from([
            "SERVICE_CREATE".to_string(),
            "SERVICE_START".to_string(),
        ])
    );
    let story_alerts = story["alerts"].as_array().unwrap();
    assert_eq!(
        story_alerts.len(),
        1,
        "only the systemd rule's alert cites a backdoor.service event as evidence"
    );
    assert_eq!(
        story_alerts[0]["rule_id"].as_str().unwrap(),
        "systemd_service_started_in_remote_session"
    );

    // 8. The real CLI binary still works against this richer dataset
    //    (regression check, unchanged from Phase 2/3/4a).
    let cli_binary = cli_binary_path();
    let output = std::process::Command::new(&cli_binary)
        .args(["--server", &format!("http://{}", addr), "--format", "json", "events"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 9);
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
