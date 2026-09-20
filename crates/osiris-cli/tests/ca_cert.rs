//! `--ca-cert` against a live TLS server (Phase 9b).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;

use osiris_transport::{pki, tls};

fn spawn_tls_server(cert: &std::path::Path, key: &std::path::Path) -> u16 {
    // This stub only speaks HTTP/1.1, so it must not negotiate h2.
    let mut config = (*tls::server_config_no_client_auth(cert, key).unwrap()).clone();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { continue };
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let Ok(conn) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut s = rustls::StreamOwned::new(conn, tcp);
                let mut buf = [0u8; 4096];
                if s.read(&mut buf).is_err() {
                    return;
                }
                let body = "{\"status\":\"ok\"}";
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.flush();
                s.conn.send_close_notify();
                let _ = s.flush();
            });
        }
    });
    port
}

fn run(port: u16, ca: Option<&std::path::Path>) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_osiris"));
    cmd.env_remove("OSIRIS_CA_CERT")
        .env("HOME", std::env::temp_dir())
        .args(["--server", &format!("https://localhost:{port}")]);
    if let Some(ca) = ca {
        cmd.arg("--ca-cert").arg(ca);
    }
    cmd.arg("health").output().unwrap()
}

#[test]
fn ca_cert_flag_trusts_a_private_ca_and_its_absence_fails() {
    let dir = tempfile::tempdir().unwrap();
    let ca = pki::generate_ca("test-ca").unwrap();
    let srv = pki::issue_server(&ca.cert_pem, &ca.key_pem, &["localhost".to_string()]).unwrap();
    pki::write_issued(dir.path(), "api", &srv).unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).unwrap();
    let port = spawn_tls_server(&dir.path().join("api.pem"), &dir.path().join("api.key"));

    let ok = run(port, Some(&ca_path));
    assert!(
        ok.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&ok.stdout),
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(String::from_utf8_lossy(&ok.stdout).contains("ok"));

    let bad = run(port, None);
    assert!(!bad.status.success());
}

fn pki_cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_osiris"))
        .env("HOME", std::env::temp_dir())
        .args(["pki"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn issue_server_name_allows_a_second_certificate_from_the_same_ca() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    assert!(pki_cli(&["init-ca", "--dir", d]).status.success());
    assert!(pki_cli(&["issue-server", "--dir", d, "agents.example"])
        .status
        .success());
    // Default name is taken; a distinct --name succeeds.
    assert!(!pki_cli(&["issue-server", "--dir", d, "api.example"])
        .status
        .success());
    let out = pki_cli(&["issue-server", "--dir", d, "--name", "api", "api.example"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.path().join("api.pem").exists());
    assert!(dir.path().join("api.key").exists());
    assert!(dir.path().join("server.pem").exists());
}

#[test]
fn ca_cert_accepts_a_pem_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let ca = pki::generate_ca("test-ca").unwrap();
    let other = pki::generate_ca("other-ca").unwrap();
    let srv = pki::issue_server(&ca.cert_pem, &ca.key_pem, &["localhost".to_string()]).unwrap();
    pki::write_issued(dir.path(), "api", &srv).unwrap();
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(&bundle, format!("{}\n{}", other.cert_pem, ca.cert_pem)).unwrap();
    let port = spawn_tls_server(&dir.path().join("api.pem"), &dir.path().join("api.key"));
    assert!(run(port, Some(&bundle)).status.success());
}
