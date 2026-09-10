pub mod scenarios;
pub mod sensor;

pub use scenarios::{
    container_deploy_in_remote_session_scenario, exec_chain_scenario, network_beacon_scenario,
    network_download_then_write_scenario, persistence_via_systemd_service_scenario,
    ssh_sudo_escalation_scenario, web_shell_drop_scenario, BACKDOOR_UNIT_NAME,
    BACKDOOR_UNIT_PATH, BEACON_DOMAIN, BEACON_IP, BENIGN_NOTES_PATH,
    DEPLOYED_CONTAINER_CGROUP_PATH, DEPLOYED_CONTAINER_ID, DOWNLOAD_C2_IP, DOWNLOAD_PAYLOAD_PATH,
    ESCALATION_C2_IP, ROOT_KEYS_PATH, SSH_REMOTE_ADDR, SSH_SESSION_ID, WEB_SHELL_DEVICE_ID,
    WEB_SHELL_FINAL_PATH, WEB_SHELL_INODE, WEB_SHELL_TEMP_PATH,
};
pub use sensor::SyntheticSensor;
