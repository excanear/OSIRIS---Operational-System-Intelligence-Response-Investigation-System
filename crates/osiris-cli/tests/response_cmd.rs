//! `osiris response ...` against a mock HTTP server (Phase 9c-1 Task 7).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc;

/// Serves one request with `status`/`body`; returns (port, receiver of raw request).
fn mock(status: &str, body: &'static str) -> (u16, mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    let status = status.to_string();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = s.read(&mut chunk).unwrap();
            buf.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&buf).to_string();
            if let Some(i) = text.find("\r\n\r\n") {
                let len = text[..i]
                    .to_ascii_lowercase()
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if buf.len() >= i + 4 + len || n == 0 {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        tx.send(String::from_utf8_lossy(&buf).to_string()).unwrap();
        let _ = write!(
            s,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    });
    (port, rx)
}

fn run(port: u16, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_osiris"))
        .args(["--server", &format!("http://127.0.0.1:{port}"), "response"])
        .args(args)
        .env("HOME", std::env::temp_dir())
        .env("USERPROFILE", std::env::temp_dir())
        .output()
        .unwrap()
}

#[test]
fn terminate_posts_target_and_dry_run() {
    let key = "ab".repeat(16);
    let (port, rx) = mock("200 OK", "{\"ok\":true}");
    let out = run(
        port,
        &[
            "terminate-process",
            "--pid-target",
            &key,
            "--reason",
            "bad",
            "--dry-run",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let req = rx.recv().unwrap();
    assert!(
        req.starts_with("POST /api/v1/response/terminate_process "),
        "{req}"
    );
    assert!(
        req.contains("\"kind\":\"PROCESS\"") && req.contains("\"dry_run\":true"),
        "{req}"
    );
}

#[test]
fn restore_posts_ids_without_target() {
    let id = uuid::Uuid::new_v4().to_string();
    let (port, rx) = mock("200 OK", "{}");
    let out = run(
        port,
        &[
            "restore-file",
            "--host",
            &id,
            "--quarantine-id",
            &id,
            "--reason",
            "fp",
        ],
    );
    assert!(out.status.success());
    let req = rx.recv().unwrap();
    assert!(req.starts_with("POST /api/v1/response/restore_file "));
    assert!(req.contains("\"quarantine_id\"") && !req.contains("\"target\""));
}

#[test]
fn quarantine_path_and_non_2xx_surfaces_server_message() {
    let h = uuid::Uuid::nil();
    let (port, rx) = mock("409 Conflict", "{\"error\":\"agent_offline\"}");
    let out = run(
        port,
        &[
            "quarantine-file",
            "--file",
            &format!("5:6:{h}"),
            "--reason",
            "x",
        ],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("409") && err.contains("agent_offline"),
        "{err}"
    );
    assert!(rx
        .recv()
        .unwrap()
        .starts_with("POST /api/v1/response/quarantine_file "));
}

#[test]
fn reason_is_required() {
    let out = run(1, &["terminate-process", "--pid-target", "aa"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--reason"));
}
