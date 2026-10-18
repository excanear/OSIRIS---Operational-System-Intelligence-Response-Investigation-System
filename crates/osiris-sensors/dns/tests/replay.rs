//! Replays `tests/fixtures/*.hex` through the engine and compares against the
//! companion `*.expected.json`.
//!
//! Fixture format: one hex-encoded L3 packet per line (blank lines and `#`
//! comments ignored); expected JSON: `{"query", "qtype", "response_ips"}` for
//! the single event the packets must produce, or an array of such objects
//! for the events they must produce, in emit order.
//!
//! A `# local_origin=true|false` comment line sets the `local_origin` flag
//! passed for the packets that follow it (default true), so a capture that
//! mixes sent and received packets can be replayed as the sensor saw it.
//! No process attribution in replay (empty proc root), so it is not compared.

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
        let expected = match expected {
            serde_json::Value::Array(all) => all,
            one => vec![one],
        };

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
        assert_eq!(
            events.len(),
            expected.len(),
            "{}: {events:?}",
            path.display()
        );
        for (i, (event, want)) in events.iter().zip(&expected).enumerate() {
            let RawEvent::Dns(d) = event else {
                panic!("{} #{i}: not a dns event", path.display());
            };
            assert_eq!(
                d.query,
                want["query"].as_str().unwrap(),
                "{} #{i}",
                path.display()
            );
            assert_eq!(
                d.qtype,
                want["qtype"].as_str().unwrap(),
                "{} #{i}",
                path.display()
            );
            let ips: Vec<String> = want["response_ips"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            assert_eq!(d.response_ips, ips, "{} #{i}", path.display());
        }
        let m = engine.metrics();
        assert_eq!(m.parse_errors, 0, "{}: parse errors", path.display());
        assert_eq!(
            m.direction_mismatches,
            0,
            "{}: direction mismatches",
            path.display()
        );
        assert_eq!(
            m.tracker.unmatched_responses,
            0,
            "{}: unmatched responses",
            path.display()
        );
        count += 1;
    }
    assert!(count >= 4, "expected at least 4 fixtures, found {count}");
}
