//! Replays `tests/fixtures/*.hex` through the engine and compares against the
//! companion `*.expected.json`.
//!
//! Fixture format: one hex-encoded L3 packet per line (blank lines and `#`
//! comments ignored); expected JSON: `{"query", "qtype", "response_ips"}` for
//! the single event the packets must produce.
//!
//! A `# local_origin=true|false` comment line sets the `local_origin` flag
//! passed for the file's packets (default true).

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use osiris_sensor_api::RawEvent;
use osiris_sensors_dns::attribution::Attributor;
use osiris_sensors_dns::engine::{Engine, MAX_PENDING, TX_TIMEOUT};

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn replays_fixture_files() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut count = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("hex") {
            continue;
        }
        let expected_path = path.with_extension("expected.json");
        let expected: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&expected_path).unwrap()).unwrap();

        let proc_root = tempfile::tempdir().unwrap();
        let mut engine = Engine::new(
            Attributor::new(proc_root.path().to_path_buf()),
            TX_TIMEOUT,
            MAX_PENDING,
        );
        let now = Instant::now();
        let mut events = Vec::new();
        let mut local_origin = true;
        for line in fs::read_to_string(&path).unwrap().lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("# local_origin=") {
                local_origin = v.trim() == "true";
                continue;
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            events.extend(engine.on_packet(&unhex(line), local_origin, 1, now));
        }
        assert_eq!(events.len(), 1, "{}: {events:?}", path.display());
        let RawEvent::Dns(d) = &events[0] else {
            panic!("{}: not a dns event", path.display());
        };
        assert_eq!(
            d.query,
            expected["query"].as_str().unwrap(),
            "{}",
            path.display()
        );
        assert_eq!(
            d.qtype,
            expected["qtype"].as_str().unwrap(),
            "{}",
            path.display()
        );
        let want: Vec<String> = expected["response_ips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(d.response_ips, want, "{}", path.display());
        count += 1;
    }
    assert!(count >= 3, "expected at least 3 fixtures, found {count}");
}
