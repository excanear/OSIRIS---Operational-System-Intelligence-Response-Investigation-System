use serde::{Deserialize, Serialize};

/// What a sensor can actually do on this host, reported before start()
/// (ARCHITECTURE.md §4.1). The Supervisor uses this to decide whether to
/// start, degrade, or skip a sensor — never a silent no-op.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SensorCapabilities {
    pub ebpf: bool,
    pub audit_fallback: bool,
    /// Set by backends outside the eBPF/audit dichotomy that are always
    /// usable regardless of host (e.g. Task 6's synthetic/generator
    /// sensor) — kept as its own flag rather than overloading
    /// `audit_fallback`, which specifically means "the real Linux Audit
    /// backend is available on this host."
    pub always_available: bool,
    /// Human-readable reason when no backend is available — required
    /// whenever every flag above is false, so a skip is never silent.
    pub unsupported_reason: Option<String>,
}

impl SensorCapabilities {
    pub fn supported(&self) -> bool {
        self.ebpf || self.audit_fallback || self.always_available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_when_no_backend_available() {
        let caps = SensorCapabilities {
            ebpf: false,
            audit_fallback: false,
            always_available: false,
            unsupported_reason: Some("no audit log configured".to_string()),
        };
        assert!(!caps.supported());
    }

    #[test]
    fn supported_with_audit_fallback_only() {
        let caps = SensorCapabilities {
            ebpf: false,
            audit_fallback: true,
            always_available: false,
            unsupported_reason: None,
        };
        assert!(caps.supported());
    }

    #[test]
    fn supported_when_always_available_even_without_ebpf_or_audit() {
        let caps = SensorCapabilities {
            ebpf: false,
            audit_fallback: false,
            always_available: true,
            unsupported_reason: None,
        };
        assert!(caps.supported());
    }
}
