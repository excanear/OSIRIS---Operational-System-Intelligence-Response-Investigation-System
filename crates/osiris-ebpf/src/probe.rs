//! Capability probe: can this host load the process BPF program?
//!
//! The checks mirror what the program needs: a BPF ring buffer (Linux ≥ 5.8),
//! kernel BTF for CO-RE relocations (`/sys/kernel/btf/vmlinux`), and the
//! privilege to load tracepoint programs (`CAP_SYS_ADMIN`, or `CAP_BPF` plus
//! `CAP_PERFMON`, read from `CapEff` in `/proc/self/status`). The parsing
//! helpers are OS-neutral so they are tested everywhere; only [`probe`]'s
//! file reads are Linux-specific.

/// Outcome of [`probe`]. `reasons` is empty exactly when `supported` is true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub supported: bool,
    pub reasons: Vec<String>,
    /// `uname -r` style release, empty when it could not be read.
    pub kernel_release: String,
}

/// Linux capability bit numbers (`include/uapi/linux/capability.h`).
const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Probe this host. Off Linux the report is always unsupported.
pub fn probe() -> ProbeReport {
    #[cfg(target_os = "linux")]
    {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let btf = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        evaluate(&release, btf, &status)
    }
    #[cfg(not(target_os = "linux"))]
    {
        ProbeReport {
            supported: false,
            reasons: vec!["eBPF requires Linux".to_string()],
            kernel_release: String::new(),
        }
    }
}

/// Build a report from already-gathered facts (OS-neutral, so testable).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn evaluate(release: &str, btf_present: bool, proc_status: &str) -> ProbeReport {
    let mut reasons = Vec::new();
    match parse_kernel_release(release) {
        Some(v) if v >= (5, 8) => {}
        Some(_) => reasons.push(format!(
            "ring buffer needs kernel ≥ 5.8 (running {release})"
        )),
        None => reasons.push(format!("unable to determine kernel version ({release:?})")),
    }
    if !btf_present {
        reasons.push("kernel BTF not available (/sys/kernel/btf/vmlinux missing)".to_string());
    }
    let cap_eff = proc_status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .map(str::trim);
    match cap_eff {
        Some(hex) if caps_allow_bpf(hex) => {}
        Some(_) => reasons
            .push("insufficient privileges: need CAP_SYS_ADMIN or CAP_BPF+CAP_PERFMON".to_string()),
        None => reasons.push("unable to read CapEff from /proc/self/status".to_string()),
    }
    ProbeReport {
        supported: reasons.is_empty(),
        reasons,
        kernel_release: release.to_string(),
    }
}

/// Parse the leading `major.minor` of a kernel release string
/// (`"5.15.0-1057-azure"` → `(5, 15)`).
pub fn parse_kernel_release(s: &str) -> Option<(u32, u32)> {
    let mut parts = s.trim().split('.');
    let major = leading_number(parts.next()?)?;
    let minor = leading_number(parts.next()?)?;
    Some((major, minor))
}

/// The decimal digits at the start of `s` (so `"8-rc1"` → 8); None if none.
fn leading_number(s: &str) -> Option<u32> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    s[..end].parse().ok()
}

/// True when the `CapEff` hex mask grants `CAP_SYS_ADMIN`, or both `CAP_BPF`
/// and `CAP_PERFMON`. A malformed mask grants nothing.
pub fn caps_allow_bpf(cap_eff_hex: &str) -> bool {
    let Ok(mask) = u64::from_str_radix(cap_eff_hex.trim(), 16) else {
        return false;
    };
    let has = |bit: u32| mask & (1u64 << bit) != 0;
    has(CAP_SYS_ADMIN) || (has(CAP_BPF) && has(CAP_PERFMON))
}

/// The wanted kernel symbols that `available` does not list. `available` is
/// the text of `available_filter_functions` (`name` or `name [module]`
/// per line) or `/proc/kallsyms` (`addr type name [module]`). Only exact
/// names count, so `foo.cold` does not satisfy `foo`.
pub fn missing_kernel_symbols(available: &str, wanted: &[&str]) -> Vec<String> {
    let mut names = std::collections::HashSet::new();
    for line in available.lines() {
        let mut tokens = line.split_whitespace();
        let Some(first) = tokens.next() else { continue };
        let looks_like_addr = first.len() >= 8 && first.bytes().all(|b| b.is_ascii_hexdigit());
        let second = tokens.next();
        match (looks_like_addr, second, tokens.next()) {
            // kallsyms: `<addr> <type letter> <name> [module]`
            (true, Some(kind), Some(name)) if kind.len() == 1 => {
                names.insert(name);
            }
            _ => {
                names.insert(first);
            }
        }
    }
    wanted
        .iter()
        .filter(|w| !names.contains(*w))
        .map(|w| (*w).to_string())
        .collect()
}

/// Text listing the kernel's symbols: tracefs `available_filter_functions`
/// (only attachable functions), else `/proc/kallsyms`. `None` off Linux or
/// when nothing is readable.
pub fn kernel_symbols_text() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        [
            "/sys/kernel/tracing/available_filter_functions",
            "/sys/kernel/debug/tracing/available_filter_functions",
            "/proc/kallsyms",
        ]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_release_parsing() {
        assert_eq!(parse_kernel_release("6.8.0-1015-azure"), Some((6, 8)));
        assert_eq!(parse_kernel_release("5.4"), Some((5, 4)));
        assert_eq!(parse_kernel_release("garbage"), None);
        assert_eq!(parse_kernel_release("5.15.0-1057-azure"), Some((5, 15)));
        assert_eq!(parse_kernel_release("6.10-rc1"), Some((6, 10)));
        assert_eq!(parse_kernel_release(""), None);
        assert_eq!(parse_kernel_release("6"), None);
    }

    #[test]
    fn cap_eff_parsing() {
        assert!(caps_allow_bpf("000001ffffffffff"));
        assert!(!caps_allow_bpf("00000000a80425fb"));
        assert!(caps_allow_bpf("0000000000200000"));
        assert!(caps_allow_bpf("000000c000000000"));
        assert!(!caps_allow_bpf("0000000000000000"));
        // CAP_BPF alone is not enough; malformed masks grant nothing.
        assert!(!caps_allow_bpf("0000008000000000"));
        assert!(!caps_allow_bpf("zz"));
        assert!(!caps_allow_bpf(""));
    }

    #[test]
    fn evaluate_collects_every_reason() {
        let ok = evaluate(
            "6.8.0-1015-azure",
            true,
            "Name:\tx\nCapEff:\t000001ffffffffff\n",
        );
        assert!(ok.supported, "{ok:?}");
        assert!(ok.reasons.is_empty());
        assert_eq!(ok.kernel_release, "6.8.0-1015-azure");

        let bad = evaluate("5.4.0-42", false, "CapEff:\t00000000a80425fb\n");
        assert!(!bad.supported);
        assert_eq!(bad.reasons.len(), 3, "{bad:?}");
        assert!(bad.reasons[0].contains("ring buffer needs kernel ≥ 5.8"));
        assert!(bad.reasons[1].contains("kernel BTF not available"));
        assert!(bad.reasons[2].contains("CAP_BPF"));

        let no_caps = evaluate("6.1", true, "Name:\tx\n");
        assert!(!no_caps.supported);
        assert!(no_caps.reasons[0].contains("CapEff"));
    }

    #[test]
    fn missing_kernel_symbols_parses_both_formats() {
        let wanted = [
            "security_path_mknod",
            "security_file_open",
            "security_path_rename",
        ];
        let filter = "security_path_mknod\nsecurity_file_open [kernel]\n";
        assert_eq!(
            missing_kernel_symbols(filter, &wanted),
            vec!["security_path_rename".to_string()]
        );
        let kallsyms = "ffffffff81234560 T security_path_mknod\n";
        assert!(missing_kernel_symbols(kallsyms, &["security_path_mknod"]).is_empty());
        // A `.cold` split is a different symbol.
        assert_eq!(
            missing_kernel_symbols("security_path_mknod.cold\n", &["security_path_mknod"]),
            vec!["security_path_mknod".to_string()]
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn probe_unsupported_off_linux() {
        let r = probe();
        assert!(!r.supported);
        assert!(r.reasons.iter().any(|s| s.contains("Linux")), "{r:?}");
    }
}
