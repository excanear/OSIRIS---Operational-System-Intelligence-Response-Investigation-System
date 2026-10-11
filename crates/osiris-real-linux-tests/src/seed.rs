//! Generator scenarios rendered as server spool lines (what an Agent would
//! have shipped), for seeding a Console stack.
use osiris_generator::{
    container_deploy_in_remote_session_scenario, exec_chain_scenario, network_beacon_scenario,
    network_download_then_write_scenario, persistence_via_systemd_service_scenario,
    ssh_sudo_escalation_scenario, web_shell_drop_scenario,
};
use osiris_schema::HostRef;

pub fn scenario_lines(base_ts_ns: u64) -> Vec<String> {
    let host = HostRef {
        host_id: uuid::Uuid::new_v4(),
        hostname: "seeded-host".into(),
        distro: "Seeded Linux".into(),
        kernel_version: "6.0.0-seed".into(),
        cloud: None,
    };
    let mut pipeline = osiris_pipeline::Pipeline::new(host, "seed-boot".into());
    let scenarios: [fn(u64) -> Vec<osiris_sensor_api::RawEvent>; 7] = [
        exec_chain_scenario,
        web_shell_drop_scenario,
        network_beacon_scenario,
        network_download_then_write_scenario,
        ssh_sudo_escalation_scenario,
        persistence_via_systemd_service_scenario,
        container_deploy_in_remote_session_scenario,
    ];
    let mut out = vec![];
    for (i, s) in scenarios.iter().enumerate() {
        for raw in s(base_ts_ns + i as u64 * 10_000_000_000) {
            out.push(serde_json::to_string(&pipeline.process(raw).event).unwrap());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scenario_contributes_parseable_events() {
        let lines = scenario_lines(1_700_000_000_000_000_000);
        assert!(lines.len() >= 7 * 3);
        for l in &lines {
            let ev: osiris_schema::CanonicalEvent = serde_json::from_str(l).unwrap();
            assert!(ev.timestamp >= 1_700_000_000_000_000_000);
        }
        let all = lines.join("\n");
        assert!(all.contains(osiris_generator::WEB_SHELL_FINAL_PATH));
        assert!(all.contains(osiris_generator::BACKDOOR_UNIT_NAME));
    }
}
