use std::path::PathBuf;
use std::str::FromStr;

use osiris_agent::{Agent, AgentConfig};
use osiris_config::HostIdentity;
use osiris_schema::HostRef;

#[tokio::main]
async fn main() {
    osiris_selftelemetry::init_logging("info");

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/osiris/agent.yaml"));
    let config = match AgentConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config at {}: {}", config_path.display(), e);
            std::process::exit(1);
        }
    };

    let host_id = HostIdentity::load_or_create(&PathBuf::from("/etc/osiris/host_id"))
        .unwrap_or_else(|_| uuid::Uuid::new_v4());
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".to_string());
    let host = HostRef {
        host_id,
        hostname,
        distro: "unknown".to_string(),
        kernel_version: "unknown".to_string(),
        cloud: None,
    };

    let status_addr = match std::net::SocketAddr::from_str(&config.status_addr) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("invalid status_addr '{}': {}", config.status_addr, e);
            std::process::exit(1);
        }
    };

    let agent = match Agent::start(config, host, "boot-unset".to_string()).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("failed to start agent: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = agent.serve_status(status_addr).await {
        eprintln!("status endpoint stopped: {}", e);
    }
}
