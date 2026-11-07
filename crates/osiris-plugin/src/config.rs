//! Plugin configuration (spec §5.7): types, strict parsing, validation.

use std::collections::HashSet;
use std::path::PathBuf;

use serde::Deserialize;

pub const MAX_NAME_LEN: usize = 64;
pub const FUEL_RANGE: std::ops::RangeInclusive<u64> = 1..=1_000_000_000;
pub const MEMORY_MIB_RANGE: std::ops::RangeInclusive<u32> = 1..=256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginKind {
    Detection,
    Enrichment,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    pub name: String,
    pub kind: PluginKind,
    pub path: PathBuf,
    pub sha256: String,
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default = "default_fuel")]
    pub fuel_per_event: u64,
    #[serde(default = "default_memory")]
    pub memory_max_mib: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_version() -> u32 {
    1
}
fn default_fuel() -> u64 {
    10_000_000
}
fn default_memory() -> u32 {
    16
}
fn default_enabled() -> bool {
    true
}

/// An invalid plugin configuration. The message always names the plugin.
#[derive(Debug, thiserror::Error)]
#[error("plugin {plugin}: {message}")]
pub struct ConfigError {
    pub plugin: String,
    pub message: String,
}

impl ConfigError {
    fn new(plugin: &str, message: impl Into<String>) -> Self {
        Self {
            plugin: plugin.to_string(),
            message: message.into(),
        }
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Validates every entry and rejects duplicate names.
pub fn validate_plugins(cfgs: &[PluginConfig]) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for c in cfgs {
        if !valid_name(&c.name) {
            return Err(ConfigError::new(
                &c.name,
                "name must match [a-z0-9_-]{1,64}",
            ));
        }
        if !seen.insert(c.name.as_str()) {
            return Err(ConfigError::new(&c.name, "duplicate plugin name"));
        }
        if !valid_sha256(&c.sha256) {
            return Err(ConfigError::new(
                &c.name,
                "sha256 must be 64 lowercase hex characters",
            ));
        }
        if !FUEL_RANGE.contains(&c.fuel_per_event) {
            return Err(ConfigError::new(
                &c.name,
                "fuel_per_event must be in 1..=1000000000",
            ));
        }
        if !MEMORY_MIB_RANGE.contains(&c.memory_max_mib) {
            return Err(ConfigError::new(
                &c.name,
                "memory_max_mib must be in 1..=256",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn cfg(name: &str) -> PluginConfig {
        PluginConfig {
            name: name.to_string(),
            kind: PluginKind::Detection,
            path: "p.wasm".into(),
            sha256: SHA.to_string(),
            version: 1,
            fuel_per_event: 10_000_000,
            memory_max_mib: 16,
            enabled: true,
        }
    }

    fn err_of(c: PluginConfig) -> ConfigError {
        validate_plugins(&[c]).unwrap_err()
    }

    #[test]
    fn defaults_apply() {
        let y = format!("name: p\nkind: enrichment\npath: /x.wasm\nsha256: {SHA}\n");
        let c: PluginConfig = serde_yaml::from_str(&y).unwrap();
        assert_eq!(c.kind, PluginKind::Enrichment);
        assert_eq!(c.fuel_per_event, 10_000_000);
        assert_eq!(c.memory_max_mib, 16);
        assert_eq!(c.version, 1);
        assert!(c.enabled);
        validate_plugins(&[c]).unwrap();
    }

    #[test]
    fn rejects_unknown_key() {
        let y = format!("name: p\nkind: detection\npath: /x\nsha256: {SHA}\nbogus: 1\n");
        assert!(serde_yaml::from_str::<PluginConfig>(&y).is_err());
    }

    #[test]
    fn rejects_bad_name() {
        for n in ["Bad Name", &"a".repeat(65), ""] {
            let e = err_of(cfg(n));
            assert_eq!(e.plugin, n);
            assert!(e.to_string().starts_with(&format!("plugin {n}: ")));
        }
        validate_plugins(&[cfg(&"a".repeat(64))]).unwrap();
    }

    #[test]
    fn rejects_duplicate_name() {
        let e = validate_plugins(&[cfg("dup"), cfg("dup")]).unwrap_err();
        assert_eq!(e.plugin, "dup");
    }

    #[test]
    fn rejects_bad_sha256() {
        for s in [&SHA[..63], &SHA.to_uppercase()] {
            let mut c = cfg("p");
            c.sha256 = s.to_string();
            assert_eq!(err_of(c).plugin, "p");
        }
    }

    #[test]
    fn rejects_fuel_out_of_range() {
        for f in [0, 1_000_000_001] {
            let mut c = cfg("p");
            c.fuel_per_event = f;
            assert_eq!(err_of(c).plugin, "p");
        }
    }

    #[test]
    fn rejects_memory_out_of_range() {
        for m in [0, 257] {
            let mut c = cfg("p");
            c.memory_max_mib = m;
            assert_eq!(err_of(c).plugin, "p");
        }
    }
}
