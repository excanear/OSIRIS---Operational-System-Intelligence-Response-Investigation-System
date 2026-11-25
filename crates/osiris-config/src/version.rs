//! Single source of truth for the `--version` text of every OSIRIS binary.

/// Build-time git revision, set by `tools/package/build.sh` via the
/// `OSIRIS_GIT_SHA` environment variable. Absent in plain `cargo build`.
const GIT_SHA: Option<&str> = option_env!("OSIRIS_GIT_SHA");

/// The part of the version text that follows the binary name, e.g.
/// `0.1.0` or `0.1.0 (abc1234)`. Useful for clap's `version` attribute,
/// which prints `<command name> <version>`.
pub fn version_suffix() -> &'static str {
    use std::sync::OnceLock;
    static SUFFIX: OnceLock<String> = OnceLock::new();
    SUFFIX.get_or_init(|| match GIT_SHA {
        Some(sha) if !sha.is_empty() => format!("{} ({sha})", env!("CARGO_PKG_VERSION")),
        _ => env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// `"<binary> <version>"`, with the git revision appended when known.
pub fn version_string(binary: &str) -> String {
    format!("{binary} {}", version_suffix())
}

/// True when `arg` is a request for the version text.
pub fn is_version_flag(arg: Option<&str>) -> bool {
    matches!(arg, Some("--version") | Some("-V"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_has_binary_and_workspace_version() {
        assert!(version_string("osirisd")
            .starts_with(&format!("osirisd {}", env!("CARGO_PKG_VERSION"))));
    }

    #[test]
    fn version_flag_detection() {
        assert!(is_version_flag(Some("--version")));
        assert!(is_version_flag(Some("-V")));
        assert!(!is_version_flag(Some("/etc/osiris/agent.yaml")));
        assert!(!is_version_flag(None));
    }
}
