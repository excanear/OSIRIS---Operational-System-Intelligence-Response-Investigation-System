use std::time::{SystemTime, UNIX_EPOCH};

use osiris_config::HostIdentity;
use osiris_generator::{exec_chain_scenario, web_shell_drop_scenario};
use osiris_pipeline::Pipeline;
use osiris_schema::HostRef;

/// Standalone dev/test tool (ARCHITECTURE.md §15): constructs real
/// CanonicalEvents by pushing a canned scenario through the real
/// Pipeline (Task 2), then prints each as JSON to stdout — exercises
/// production normalize/enrich/validate/prioritize code, not a parallel
/// simulation.
fn main() {
    let host_id =
        HostIdentity::load_or_create(&std::env::temp_dir().join("osiris-generator-host-id"))
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

    // `osiris-generator [exec_chain|web_shell_drop]`, defaulting to the
    // Phase 1 exec chain so existing usage is unchanged.
    let scenario_name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "exec_chain".to_string());
    let scenario = match scenario_name.as_str() {
        "web_shell_drop" => web_shell_drop_scenario(base_ts_ns),
        "exec_chain" => exec_chain_scenario(base_ts_ns),
        other => {
            eprintln!("unknown scenario '{other}'; expected exec_chain or web_shell_drop");
            std::process::exit(1);
        }
    };

    for raw in scenario {
        let result = pipeline.process(raw);
        match serde_json::to_string(&result.event) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("failed to serialize event: {e}"),
        }
    }
}
