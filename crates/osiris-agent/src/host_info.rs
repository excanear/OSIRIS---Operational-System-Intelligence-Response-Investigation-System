//! Host facts the Agent reports in its HostRef (distro, kernel). Linux reads
//! /etc/os-release and /proc/sys/kernel/osrelease; anything unreadable falls
//! back to "unknown" so the Agent never fails to start over a cosmetic field.

fn unquote(v: &str) -> &str {
    let v = v.trim();
    v.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
        .unwrap_or(v)
}

pub fn distro_from_os_release(contents: &str) -> Option<String> {
    let mut pretty = None;
    let mut name = None;
    let mut version = None;
    for line in contents.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = unquote(v).to_string();
        match k.trim() {
            "PRETTY_NAME" => pretty = Some(v),
            "NAME" => name = Some(v),
            "VERSION_ID" => version = Some(v),
            _ => {}
        }
    }
    if let Some(p) = pretty.filter(|p| !p.is_empty()) {
        return Some(p);
    }
    match (
        name.filter(|n| !n.is_empty()),
        version.filter(|v| !v.is_empty()),
    ) {
        (Some(n), Some(v)) => Some(format!("{n} {v}")),
        (Some(n), None) => Some(n),
        _ => None,
    }
}

pub fn detect() -> (String, String) {
    let distro = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| distro_from_os_release(&s))
        .unwrap_or_else(|| "unknown".to_string());
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    (distro, kernel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_name_wins_and_quotes_are_stripped() {
        let s = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n";
        assert_eq!(
            distro_from_os_release(s).as_deref(),
            Some("Ubuntu 24.04.3 LTS")
        );
    }

    #[test]
    fn falls_back_to_name_and_version_id_without_pretty_name() {
        let s = "NAME=Debian\nVERSION_ID='12'\n";
        assert_eq!(distro_from_os_release(s).as_deref(), Some("Debian 12"));
    }

    #[test]
    fn garbage_or_empty_yields_none() {
        assert_eq!(distro_from_os_release(""), None);
        assert_eq!(distro_from_os_release("# comment only\n"), None);
        assert_eq!(distro_from_os_release("PRETTY_NAME=\"\"\n"), None);
    }

    #[test]
    fn detect_never_returns_empty_strings() {
        let (d, k) = detect();
        assert!(!d.is_empty() && !k.is_empty());
    }
}
