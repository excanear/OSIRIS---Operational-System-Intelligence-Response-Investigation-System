/// Saved OQL query templates (ARCHITECTURE.md §12.2), checked in under
/// `hunts/` at the repo root (same pattern as `rules/`) and embedded at
/// compile time — this CLI is a thin HTTP client that can run on a
/// different machine than the server, so template *content* travels with
/// the binary rather than being read from a server-side path at runtime.
pub fn known_template_names() -> &'static [&'static str] {
    &[
        "network-download-then-write",
        "shell-wrote-file-to-web-root",
        "container-started-in-remote-session",
    ]
}

pub fn template(name: &str) -> Option<&'static str> {
    match name {
        "network-download-then-write" => Some(include_str!("../../../hunts/network-download-then-write.oql")),
        "shell-wrote-file-to-web-root" => Some(include_str!("../../../hunts/shell-wrote-file-to-web-root.oql")),
        "container-started-in-remote-session" => {
            Some(include_str!("../../../hunts/container-started-in-remote-session.oql"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_resolves_a_known_name() {
        let oql = template("network-download-then-write").unwrap();
        assert!(oql.contains("NETWORK_CONNECT"));
    }

    #[test]
    fn template_returns_none_for_an_unknown_name() {
        assert!(template("does-not-exist").is_none());
    }

    #[test]
    fn every_known_template_is_non_empty() {
        for name in known_template_names() {
            let oql = template(name).unwrap();
            assert!(!oql.trim().is_empty());
        }
    }
}
