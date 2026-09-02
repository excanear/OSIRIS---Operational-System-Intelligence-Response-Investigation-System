use std::time::{SystemTime, UNIX_EPOCH};

use osiris_config::HostIdentity;
use osiris_generator::exec_chain_scenario;
use osiris_pipeline::Pipeline;
use osiris_schema::HostRef;
use osiris_sensor_api::RawEvent;

/// Standalone dev/test tool (ARCHITECTURE.md §15): constructs real
/// CanonicalEvents by pushing a canned scenario through the real
/// Pipeline (Task 2), then prints each as JSON to stdout — exercises
/// production normalize/enrich/validate/prioritize code, not a parallel
/// simulation.
fn main() {
    let host_id = HostIdentity::load_or_create(&std::env::temp_dir().join("osiris-generator-host-id"))
        .unwrap_or_else(|_| uuid::Uuid::new_v4());
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".to_string());
    let host = HostRef {
        host_id,
        hostname,
        distro: "generator".to_string(),
        kernel_version: "n/a".to_string(),
        cloud: None,
    };

    let base_ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut pipeline = Pipeline::new(host, "synthetic-boot".to_string());

    for raw in exec_chain_scenario(base_ts_ns) {
        let result = pipeline.process(RawEvent::ProcessExec(raw));
        match serde_json::to_string(&result.event) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("failed to serialize event: {e}"),
        }
    }
}
