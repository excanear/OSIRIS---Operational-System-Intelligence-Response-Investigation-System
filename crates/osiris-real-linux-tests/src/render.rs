//! Renders server.yaml / agent.yaml for the production binaries. File names
//! inside `dir` are fixed; `stack.rs` writes the PKI/keys at the same names.
use std::path::{Path, PathBuf};

fn q(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', "''"))
}

fn f(dir: &Path, name: &str) -> String {
    // Forward slash join keeps Windows paths readable and valid.
    q(Path::new(&format!("{}/{}", dir.display(), name)))
}

pub struct ServerYaml {
    pub dir: PathBuf,
    pub api_port: u16,
    pub agent_port: u16,
    pub control_port: u16,
    pub rules_dir: PathBuf,
    pub risk_weights: PathBuf,
    pub dev_cors: bool,
}

impl ServerYaml {
    pub fn render(&self) -> String {
        let d = &self.dir;
        format!(
            "db_path: {db}\nspool_path: {spool}\nlisten_addr: '127.0.0.1:{api}'\n\
             rules_dir: {rules}\nrisk_weights_path: {risk}\n\
             baseline_db_path: {baseline}\nincidents_db_path: {inc}\nevidence_db_path: {ev}\n\
             links_db_path: {links}\ninvestigate_audit_log_path: {inv}\n\
             users_db_path: {users}\ntenants_db_path: {tenants}\nhosts_db_path: {hosts}\n\
             dev_cors: {cors}\n\
             agent_listener:\n  listen_addr: '127.0.0.1:{agent}'\n  cert: {scert}\n  key: {skey}\n  client_ca: {ca}\n\
             control:\n  listen_addr: '127.0.0.1:{control}'\n  cert: {scert}\n  key: {skey}\n  client_ca: {ca}\n  command_signing_key: {sign}\n",
            db = f(d, "events.db"),
            spool = f(d, "server-spool.ndjson"),
            api = self.api_port,
            rules = q(&self.rules_dir),
            risk = q(&self.risk_weights),
            baseline = f(d, "baseline.db"),
            inc = f(d, "incidents.db"),
            ev = f(d, "evidence.db"),
            links = f(d, "links.db"),
            inv = f(d, "investigate-audit.log"),
            users = f(d, "users.db"),
            tenants = f(d, "tenants.db"),
            hosts = f(d, "hosts.db"),
            cors = self.dev_cors,
            agent = self.agent_port,
            control = self.control_port,
            scert = f(d, "pki/server.pem"),
            skey = f(d, "pki/server.key"),
            ca = f(d, "pki/ca.pem"),
            sign = f(d, "keys/command.key"),
        )
    }
}

pub struct AgentYaml {
    pub dir: PathBuf,
    pub agent_port: u16,
    pub control_port: u16,
    pub audit_log: Option<PathBuf>,
    pub persistence_dirs: Vec<PathBuf>,
    pub health_interval_secs: u64,
    /// The agent's local `GET /status` port (full per-sensor health,
    /// including capability flags); 0 = any free port, unknown to the harness.
    pub status_port: u16,
    /// Pre-built BPF object dir (Phase 11b-1): renders `ebpf: { object_dir }`
    /// so the process sensor runs on eBPF; `None` keeps it on audit.
    pub ebpf_object_dir: Option<PathBuf>,
    /// Explicit filesystem watch list (Phase 11b-3), rendered as
    /// `fs_watch_paths:`; empty renders nothing, so the sensor uses its
    /// default list.
    pub fs_watch_paths: Vec<PathBuf>,
}

/// `$OSIRIS_BPF_DIR` (set by the real-Linux workflow, built by
/// `tools/real-linux/setup.sh`), when set and non-empty.
pub fn bpf_dir_from_env() -> Option<PathBuf> {
    std::env::var_os("OSIRIS_BPF_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

impl AgentYaml {
    pub fn render(&self) -> String {
        let d = &self.dir;
        let mut s = format!(
            "spool_path: {spool}\nstatus_addr: '127.0.0.1:{status}'\nenable_synthetic: false\n\
             proc_root: '/proc'\nnetwork_proc_root: '/proc'\n\
             dns_capture: {{}}\n\
             cloud_metadata:\n  enabled: false\n\
             fleet:\n  health_interval_secs: {hb}\n\
             forward:\n  server_addr: '127.0.0.1:{agent}'\n  server_name: 'localhost'\n  ca: {ca}\n  cert: {acert}\n  key: {akey}\n\
             control:\n  server_addr: '127.0.0.1:{control}'\n  server_name: 'localhost'\n  ca: {ca}\n  cert: {acert}\n  key: {akey}\n  command_public_key: {pubk}\n  vault_dir: {vault}\n",
            spool = f(d, "agent-spool.ndjson"),
            status = self.status_port,
            hb = self.health_interval_secs,
            agent = self.agent_port,
            control = self.control_port,
            ca = f(d, "pki/ca.pem"),
            acert = f(d, "pki/agent.pem"),
            akey = f(d, "pki/agent.key"),
            pubk = f(d, "keys/command.pub"),
            vault = f(d, "vault"),
        );
        if let Some(log) = &self.audit_log {
            for key in [
                "audit_log_path",
                "fs_audit_log_path",
                "identity_audit_log_path",
                "systemd_audit_log_path",
            ] {
                s.push_str(&format!("{key}: {}\n", q(log)));
            }
        }
        if !self.persistence_dirs.is_empty() {
            s.push_str("persistence_watch_paths:\n");
            for p in &self.persistence_dirs {
                s.push_str(&format!("  - path: {}\n    kind: systemd_unit_dir\n", q(p)));
            }
        }
        if !self.fs_watch_paths.is_empty() {
            s.push_str("fs_watch_paths:\n");
            for p in &self.fs_watch_paths {
                s.push_str(&format!("  - {}\n", q(p)));
            }
        }
        if let Some(bpf) = &self.ebpf_object_dir {
            s.push_str(&format!("ebpf:\n  object_dir: {}\n", q(bpf)));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_server_yaml_loads_with_the_real_server_config() {
        let dir = tempfile::tempdir().unwrap();
        let y = ServerYaml {
            dir: dir.path().to_path_buf(),
            api_port: 18080,
            agent_port: 18081,
            control_port: 18082,
            rules_dir: dir.path().join("rules"),
            risk_weights: dir.path().join("weights.yaml"),
            dev_cors: true,
        };
        let path = dir.path().join("server.yaml");
        std::fs::write(&path, y.render()).unwrap();
        let cfg = osiris_server::ServerConfig::load(&path).unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:18080");
        assert_eq!(cfg.agent_listener.unwrap().listen_addr, "127.0.0.1:18081");
        assert_eq!(cfg.control.unwrap().listen_addr, "127.0.0.1:18082");
        assert_eq!(cfg.dev_cors, Some(true));
    }

    #[test]
    fn rendered_agent_yaml_loads_with_the_real_agent_config() {
        let dir = tempfile::tempdir().unwrap();
        let y = AgentYaml {
            dir: dir.path().to_path_buf(),
            agent_port: 18081,
            control_port: 18082,
            audit_log: Some("/var/log/audit/audit.log".into()),
            persistence_dirs: vec![dir.path().join("units")],
            health_interval_secs: 5,
            status_port: 0,
            ebpf_object_dir: None,
            fs_watch_paths: vec![],
        };
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, y.render()).unwrap();
        let cfg = osiris_agent::AgentConfig::load(&path).unwrap();
        assert_eq!(
            cfg.audit_log_path.as_deref(),
            Some("/var/log/audit/audit.log")
        );
        assert_eq!(
            cfg.fs_audit_log_path.as_deref(),
            Some("/var/log/audit/audit.log")
        );
        assert_eq!(
            cfg.identity_audit_log_path.as_deref(),
            Some("/var/log/audit/audit.log")
        );
        assert_eq!(
            cfg.systemd_audit_log_path.as_deref(),
            Some("/var/log/audit/audit.log")
        );
        assert_eq!(cfg.persistence_watch_paths.len(), 1);
        assert_eq!(cfg.fleet.health_interval_secs, 5);
        assert!(!cfg.enable_synthetic);
        // The real-Linux agent captures DNS, on all interfaces.
        assert!(cfg.dns_capture.unwrap().interface.is_none());
        assert_eq!(cfg.forward.unwrap().server_addr, "127.0.0.1:18081");
        // No object dir: the process sensor stays on the audit backend.
        assert!(cfg.ebpf.is_none());
        // No explicit list: the sensor's default watch list applies.
        assert!(cfg.fs_watch_paths.is_empty());
    }

    #[test]
    fn ebpf_object_dir_and_status_port_are_rendered() {
        let dir = tempfile::tempdir().unwrap();
        let bpf = dir.path().join("bpf objects");
        let y = AgentYaml {
            dir: dir.path().to_path_buf(),
            agent_port: 1,
            control_port: 2,
            audit_log: Some("/var/log/audit/audit.log".into()),
            persistence_dirs: vec![],
            health_interval_secs: 5,
            status_port: 18083,
            ebpf_object_dir: Some(bpf.clone()),
            fs_watch_paths: vec![dir.path().join("watched dir"), "/var/www".into()],
        };
        let path = dir.path().join("agent.yaml");
        std::fs::write(&path, y.render()).unwrap();
        let cfg = osiris_agent::AgentConfig::load(&path).unwrap();
        assert_eq!(cfg.ebpf.unwrap().object_dir, bpf);
        assert_eq!(cfg.status_addr, "127.0.0.1:18083");
        assert_eq!(
            cfg.fs_watch_paths,
            vec![
                dir.path().join("watched dir").display().to_string(),
                "/var/www".to_string()
            ]
        );
    }

    #[test]
    fn paths_with_spaces_and_backslashes_survive_rendering() {
        let dir = std::path::PathBuf::from(r"C:\Program Files\osiris dir");
        let y = AgentYaml {
            dir,
            agent_port: 1,
            control_port: 2,
            audit_log: None,
            persistence_dirs: vec![],
            health_interval_secs: 5,
            status_port: 0,
            ebpf_object_dir: None,
            fs_watch_paths: vec![],
        };
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("a.yaml");
        std::fs::write(&p, y.render()).unwrap();
        let cfg = osiris_agent::AgentConfig::load(&p).unwrap();
        assert_eq!(
            cfg.spool_path,
            r"C:\Program Files\osiris dir/agent-spool.ndjson"
        );
    }
}
