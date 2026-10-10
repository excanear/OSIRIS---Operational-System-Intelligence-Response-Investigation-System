use std::path::PathBuf;

/// Repo root (this crate lives at `crates/osiris-real-linux-tests`).
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// A release binary: `$OSIRIS_BIN_DIR/<name>` or `<root>/target/release/<name>`.
pub fn bin_path(name: &str) -> PathBuf {
    let dir = std::env::var_os("OSIRIS_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target").join("release"));
    dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

/// A currently-free loopback port (bind :0, read, release).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("bind :0")
        .port()
}
