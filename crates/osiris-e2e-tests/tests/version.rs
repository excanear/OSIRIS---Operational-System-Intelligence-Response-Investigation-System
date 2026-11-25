//! Every shipped binary answers `--version` without reading any config.

use std::path::PathBuf;
use std::process::Command;

/// Builds the three binaries (cargo does not build a dependency's bins for
/// an integration test) and returns the path to `name`. Walks ancestors of
/// the test executable because Rust 1.100 places test binaries under
/// `target/debug/build/<pkg>/<hash>/out`, while final binaries stay in
/// `target/debug`.
fn binary_path(name: &str) -> PathBuf {
    static BUILD: std::sync::Once = std::sync::Once::new();
    BUILD.call_once(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .args([
                "build",
                "-p",
                "osiris-agent",
                "-p",
                "osiris-server",
                "-p",
                "osiris-cli",
            ])
            .status()
            .expect("run cargo build");
        assert!(status.success(), "cargo build of the binaries failed");
    });
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let exe = std::env::current_exe().unwrap();
    exe.ancestors()
        .skip(1)
        .map(|dir| dir.join(&file))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("no `{file}` in any ancestor of {}", exe.display()))
}

#[test]
fn each_binary_prints_version_without_config() {
    for bin in ["osirisd", "osiris-server", "osiris"] {
        let out = Command::new(binary_path(bin))
            .arg("--version")
            .output()
            .unwrap_or_else(|e| panic!("run {bin}: {e}"));
        assert!(out.status.success(), "{bin} --version failed: {out:?}");
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(
            stdout.starts_with(&format!("{bin} 0.1.0")),
            "{bin} printed {stdout:?}"
        );
    }
}
