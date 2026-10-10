use std::time::Instant;

use osiris_pipeline::Pipeline;
use osiris_schema::HostRef;
use osiris_sensor_api::RawEvent;
use uuid::Uuid;

use crate::stats::Record;

pub fn new_pipeline() -> Pipeline {
    let host = HostRef {
        host_id: Uuid::new_v4(),
        hostname: "bench-host".to_string(),
        distro: "test".to_string(),
        kernel_version: "test".to_string(),
        cloud: None,
    };
    Pipeline::new(host, "bench-boot".to_string())
}

/// Cycles through the generator scenarios; `i` is the base timestamp.
pub fn scenario(i: u64) -> Vec<RawEvent> {
    match i % 5 {
        0 => osiris_generator::exec_chain_scenario(i),
        1 => osiris_generator::web_shell_drop_scenario(i),
        2 => osiris_generator::network_beacon_scenario(i),
        3 => osiris_generator::ssh_sudo_escalation_scenario(i),
        _ => osiris_generator::persistence_via_systemd_service_scenario(i),
    }
}

pub fn run(events: u64) -> Record {
    let mut pipeline = new_pipeline();
    let mut processed = 0u64;
    let mut i = 0u64;
    let start = Instant::now();
    while processed < events {
        for raw in scenario(i) {
            std::hint::black_box(pipeline.process(raw));
            processed += 1;
        }
        i += 1;
    }
    let elapsed = start.elapsed();
    Record {
        bench: "pipeline".to_string(),
        params: serde_json::json!({ "events": events }),
        metrics: serde_json::json!({
            "events_processed": processed,
            "events_per_sec": processed as f64 / elapsed.as_secs_f64(),
            "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        }),
    }
}
