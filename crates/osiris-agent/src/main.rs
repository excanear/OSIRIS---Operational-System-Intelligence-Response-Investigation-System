use std::path::PathBuf;
use std::str::FromStr;

use osiris_agent::{Agent, AgentConfig};
use osiris_config::HostIdentity;
use osiris_schema::HostRef;

/// Reads the kernel-assigned boot id (unique per boot, stable for the
/// life of the boot) so `ProcessKey::new(host_id, boot_id, pid, start_time)`
/// can actually disambiguate identical pid+start_time pairs across reboots
/// (finding 4). Only Linux exposes this path; on any other platform (this
/// environment is Windows/dev, where this fallback path is what actually
/// executes) a clearly-named sentinel is returned instead of a silent
/// magic string, with the failure logged so it's observable.
fn read_boot_id() -> String {
    match std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        Ok(contents) => {
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                tracing::warn!(
                    "/proc/sys/kernel/random/boot_id was empty; falling back to \"boot-unknown\" — \
                     process_key disambiguation across reboots is degraded"
                );
                "boot-unknown".to_string()
            } else {
                trimmed.to_string()
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to read /proc/sys/kernel/random/boot_id; falling back to \"boot-unknown\" — \
                 process_key disambiguation across reboots is degraded"
            );
            "boot-unknown".to_string()
        }
    }
}

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
        .unwrap_or_else(|e| {
            tracing::error!(
                error = %e,
                "failed to load or create persistent host identity; minting a fresh one — \
                 host_id will not be stable across restarts until this is fixed"
            );
            uuid::Uuid::new_v4()
        });
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

    let boot_id = read_boot_id();

    let agent = match Agent::start(config, host, boot_id).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Finding 4: the boot id must never be a silent, always-the-same
    /// magic string. Where `/proc/sys/kernel/random/boot_id` is readable
    /// (real Linux, including CI), `read_boot_id` must return its actual
    /// (non-empty) contents; where it isn't (this dev environment is
    /// Windows), it must fall back to the honestly-named "boot-unknown"
    /// sentinel — never the old "boot-unset" placeholder, and never a
    /// silent empty string, on either path.
    #[test]
    fn never_returns_the_old_silent_placeholder_or_an_empty_string() {
        let boot_id = read_boot_id();
        assert_ne!(boot_id, "boot-unset");
        assert!(!boot_id.is_empty());

        let real_boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        match real_boot_id {
            Some(expected) => assert_eq!(
                boot_id, expected,
                "boot_id file was readable — must return its real contents"
            ),
            None => assert_eq!(
                boot_id, "boot-unknown",
                "boot_id file was not readable — must fall back to the named sentinel"
            ),
        }
    }
}
