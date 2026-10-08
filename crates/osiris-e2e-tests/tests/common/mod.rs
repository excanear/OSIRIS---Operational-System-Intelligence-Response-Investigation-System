//! Helpers shared by the e2e test files that exercise the mTLS command channel.

use std::path::{Path, PathBuf};

use osiris_transport::pki::{generate_ca, issue_agent, issue_server, write_issued};
use uuid::Uuid;

/// Writes a fresh CA, a server certificate valid for `localhost`/`127.0.0.1`
/// and an agent certificate for `host` into `<dir>/pki`, returning that
/// directory (`ca.pem`, `server.{pem,key}`, `agent.{pem,key}`).
pub fn write_control_pki(dir: &Path, host: Uuid) -> PathBuf {
    let pki = dir.join("pki");
    std::fs::create_dir_all(&pki).unwrap();
    let ca = generate_ca("e2e-ca").unwrap();
    write_issued(&pki, "ca", &ca).unwrap();
    let server = issue_server(
        &ca.cert_pem,
        &ca.key_pem,
        &["localhost".into(), "127.0.0.1".into()],
    )
    .unwrap();
    write_issued(&pki, "server", &server).unwrap();
    let agent = issue_agent(&ca.cert_pem, &ca.key_pem, host).unwrap();
    write_issued(&pki, "agent", &agent).unwrap();
    pki
}
