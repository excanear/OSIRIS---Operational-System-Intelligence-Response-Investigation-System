//! Phase 12a: the real `osiris-server` binary with a file NDJSON exporter.
//! Server-only stack, so it runs on any OS; it is `#[ignore]` like the crate's
//! other tests because it needs built binaries (`cargo build --release -p
//! osiris-server`, or point `OSIRIS_BIN_DIR` at another profile's directory).
//!
//! Run: `cargo test -p osiris-real-linux-tests --test exporters_binary -- --ignored`

use std::io::Write;
use std::time::{Duration, Instant};

use osiris_real_linux_tests::seed::scenario_lines;
use osiris_real_linux_tests::stack::{Stack, StackOptions};
use serde_json::Value;

const DEADLINE: Duration = Duration::from_secs(10);

/// Forward slashes keep a Windows path valid inside a single-quoted YAML scalar.
fn yaml_path(p: &std::path::Path) -> String {
    p.display().to_string().replace('\\', "/")
}

#[test]
#[ignore = "needs built osiris-server binary"]
fn a_spool_event_reaches_the_file_exporter_and_the_status_endpoint() {
    let out_dir = tempfile::tempdir().unwrap();
    let export_path = out_dir.path().join("export.ndjson");
    let stack = Stack::start(StackOptions {
        exporters_yaml: Some(format!(
            "  - name: file-out\n    kind: file\n    path: '{}'\n    format: ndjson\n    flush_interval_ms: 200\n",
            yaml_path(&export_path)
        )),
        ..Default::default()
    });

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let line = scenario_lines(now_ns).remove(0);
    let event_id = serde_json::from_str::<Value>(&line).unwrap()["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut spool = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(stack.spool_path())
        .unwrap();
    writeln!(spool, "{line}").unwrap();
    spool.flush().unwrap();

    let end = Instant::now() + DEADLINE;
    loop {
        let text = std::fs::read_to_string(&export_path).unwrap_or_default();
        if text.lines().any(|l| l.contains(&event_id)) {
            let exported: Value =
                serde_json::from_str(text.lines().find(|l| l.contains(&event_id)).unwrap())
                    .unwrap();
            assert_eq!(exported["record_type"], "event");
            assert_eq!(exported["event_id"], event_id);
            break;
        }
        assert!(
            Instant::now() < end,
            "event {event_id} never reached {}\n{}",
            export_path.display(),
            stack.logs_tail()
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let status = stack.wait_for("/api/v1/exporters", DEADLINE, |v| {
        v["exporters"][0]["sent_records"].as_u64().unwrap_or(0) >= 1
    });
    let row = &status["exporters"][0];
    assert_eq!(row["name"], "file-out");
    assert_eq!(row["kind"], "file");
    assert_eq!(row["state"], "OK", "status: {status}");
}
