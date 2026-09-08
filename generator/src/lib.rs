pub mod scenarios;
pub mod sensor;

pub use scenarios::{
    exec_chain_scenario, network_beacon_scenario, ssh_sudo_escalation_scenario,
    web_shell_drop_scenario, BEACON_DOMAIN, BEACON_IP, BENIGN_NOTES_PATH, ESCALATION_C2_IP,
    ROOT_KEYS_PATH, SSH_REMOTE_ADDR, SSH_SESSION_ID, WEB_SHELL_DEVICE_ID, WEB_SHELL_FINAL_PATH,
    WEB_SHELL_INODE, WEB_SHELL_TEMP_PATH,
};
pub use sensor::SyntheticSensor;
