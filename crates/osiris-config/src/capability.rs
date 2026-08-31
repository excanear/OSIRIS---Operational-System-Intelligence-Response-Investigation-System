use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CgroupVersion { V1, V2, Unknown }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemCapabilities {
    pub kernel_version: String,
    pub btf_available: bool,
    pub cgroup_version: CgroupVersion,
    pub lsms: Vec<String>,
}

/// Design surface for kernel/distro capability probing (ARCHITECTURE.md
/// §20/§4.1's `SensorContext.CapabilityProbe`): each sensor's backend
/// choice (eBPF vs. fallback) is decided against this, not assumed.
/// Phase 0 defines the trait and a Linux implementation; sensors consume
/// it starting Phase 1 (ARCHITECTURE.md §29).
pub trait CapabilityProbe: Send + Sync {
    fn probe(&self) -> SystemCapabilities;
}

/// Reads real system state. Only meaningful on Linux; the paths it reads
/// do not exist on other platforms, so probing there degrades to
/// conservative "unavailable" values rather than erroring — this keeps the
/// crate buildable and testable from any dev machine.
pub struct LinuxCapabilityProbe;

impl CapabilityProbe for LinuxCapabilityProbe {
    fn probe(&self) -> SystemCapabilities {
        SystemCapabilities {
            kernel_version: read_kernel_version(),
            btf_available: std::path::Path::new("/sys/kernel/btf/vmlinux").exists(),
            cgroup_version: detect_cgroup_version(),
            lsms: read_lsm_list(),
        }
    }
}

fn read_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn detect_cgroup_version() -> CgroupVersion {
    if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        CgroupVersion::V2
    } else if std::path::Path::new("/sys/fs/cgroup").exists() {
        CgroupVersion::V1
    } else {
        CgroupVersion::Unknown
    }
}

fn read_lsm_list() -> Vec<String> {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.trim().split(',').map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

/// Fixed-response probe for tests and any non-Linux dev environment.
pub struct FakeCapabilityProbe(pub SystemCapabilities);

impl CapabilityProbe for FakeCapabilityProbe {
    fn probe(&self) -> SystemCapabilities {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_probe_returns_configured_capabilities() {
        let caps = SystemCapabilities {
            kernel_version: "6.8.0-generic".to_string(),
            btf_available: true,
            cgroup_version: CgroupVersion::V2,
            lsms: vec!["apparmor".to_string()],
        };
        let probe = FakeCapabilityProbe(caps.clone());
        assert_eq!(probe.probe(), caps);
    }

    #[test]
    fn linux_probe_does_not_panic_when_paths_are_absent() {
        // On any OS/CI runner without these paths (including this dev
        // machine), probing must degrade gracefully, not panic.
        let probe = LinuxCapabilityProbe;
        let caps = probe.probe();
        assert!(caps.kernel_version == "unknown" || !caps.kernel_version.is_empty());
    }
}
