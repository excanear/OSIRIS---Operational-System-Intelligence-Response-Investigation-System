//! Plugin module loading with integrity and sandbox checks (spec §5.1, §5.6).

use sha2::{Digest, Sha256};
use wasmtime::{
    Config, Engine, ExternType, InstancePre, Linker, Module, Store, StoreLimits,
    StoreLimitsBuilder, ValType,
};

use crate::config::{ConfigError, PluginConfig};

/// Maximum wasm call-stack depth in bytes.
pub const MAX_WASM_STACK: usize = 512 * 1024;
/// Fuel for the load-time `osiris_abi_version` probe.
const PROBE_FUEL: u64 = 100_000;

/// Per-store host state: just the resource limiter.
pub struct HostState {
    pub limits: StoreLimits,
}

/// Resource limits for a plugin's store (spec §5.1).
pub fn store_limits(cfg: &PluginConfig) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(cfg.memory_max_mib as usize * 1024 * 1024)
        .instances(1)
        .tables(1)
        .table_elements(10_000)
        .build()
}

/// An engine with fuel metering and a bounded wasm stack.
pub fn new_engine() -> Engine {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.max_wasm_stack(MAX_WASM_STACK);
    Engine::new(&config).expect("wasmtime engine config is valid")
}

/// A verified, pre-instantiated plugin module.
impl std::fmt::Debug for LoadedPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPlugin")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

pub struct LoadedPlugin {
    pub config: PluginConfig,
    pub pre: InstancePre<HostState>,
}

fn export_sig_ok(
    module: &Module,
    name: &str,
    params: &[ValType],
    results: &[ValType],
) -> Result<(), &'static str> {
    match module.get_export(name) {
        Some(ExternType::Func(ft)) => {
            let p: Vec<ValType> = ft.params().collect();
            let r: Vec<ValType> = ft.results().collect();
            if p.len() == params.len()
                && r.len() == results.len()
                && p.iter().zip(params).all(|(a, b)| ValType::eq(a, b))
                && r.iter().zip(results).all(|(a, b)| ValType::eq(a, b))
            {
                Ok(())
            } else {
                Err("wrong type")
            }
        }
        Some(_) => Err("wrong type"),
        None => Err("missing"),
    }
}

/// Reads, verifies and pre-instantiates a plugin. Every failure names the plugin.
pub fn load_plugin(engine: &Engine, cfg: &PluginConfig) -> Result<LoadedPlugin, ConfigError> {
    let err = |m: String| ConfigError::new(&cfg.name, m);

    let bytes = std::fs::read(&cfg.path)
        .map_err(|e| err(format!("cannot read {}: {}", cfg.path.display(), e.kind())))?;
    if hex::encode(Sha256::digest(&bytes)) != cfg.sha256 {
        return Err(err("sha256 does not match the module file".into()));
    }
    let module =
        Module::new(engine, &bytes).map_err(|_| err("not a valid WebAssembly module".into()))?;

    if module.imports().len() > 0 {
        return Err(err("module declares imports; plugins may have none".into()));
    }
    match module.get_export("memory") {
        Some(ExternType::Memory(_)) => {}
        Some(_) => return Err(err("export `memory` has the wrong type".into())),
        None => return Err(err("missing export `memory`".into())),
    }
    use ValType::{I32, I64};
    let sigs: [(&str, &[ValType], &[ValType]); 3] = [
        ("osiris_abi_version", &[], &[I32]),
        ("osiris_alloc", &[I32], &[I32]),
        ("osiris_on_event", &[I32, I32], &[I64]),
    ];
    for (name, params, results) in sigs {
        export_sig_ok(&module, name, params, results).map_err(|why| match why {
            "missing" => err(format!("missing export `{name}`")),
            _ => err(format!("export `{name}` has the wrong type")),
        })?;
    }

    let linker: Linker<HostState> = Linker::new(engine);
    let pre = linker
        .instantiate_pre(&module)
        .map_err(|_| err("module cannot be instantiated".into()))?;

    // Throwaway instance: check the ABI version with a small fuel budget.
    let mut store = Store::new(
        engine,
        HostState {
            limits: store_limits(cfg),
        },
    );
    store.limiter(|s| &mut s.limits);
    store
        .set_fuel(PROBE_FUEL)
        .map_err(|_| err("cannot set fuel".into()))?;
    let instance = pre
        .instantiate(&mut store)
        .map_err(|_| err("module failed to instantiate".into()))?;
    let version = instance
        .get_typed_func::<(), i32>(&mut store, "osiris_abi_version")
        .and_then(|f| f.call(&mut store, ()))
        .map_err(|_| err("osiris_abi_version call failed".into()))?;
    if version != 1 {
        return Err(err(format!(
            "unsupported abi version {version} (expected 1)"
        )));
    }

    Ok(LoadedPlugin {
        config: cfg.clone(),
        pre,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PluginKind;
    use crate::fixtures;
    use sha2::{Digest, Sha256};

    fn cfg_for(dir: &std::path::Path, name: &str, bytes: &[u8]) -> PluginConfig {
        let path = dir.join(format!("{name}.wasm"));
        std::fs::write(&path, bytes).unwrap();
        PluginConfig {
            name: name.into(),
            kind: PluginKind::Detection,
            path,
            sha256: hex::encode(Sha256::digest(bytes)),
            version: 1,
            fuel_per_event: 10_000_000,
            memory_max_mib: 16,
            enabled: true,
        }
    }

    fn load_fixture(name: &str) -> Result<LoadedPlugin, ConfigError> {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_for(dir.path(), "p", &fixtures::wasm(name));
        load_plugin(&new_engine(), &cfg)
    }

    #[test]
    fn loads_a_valid_module() {
        let p = load_fixture("detect_nc").unwrap();
        assert_eq!(p.config.name, "p");
        assert!(load_fixture("tagger").is_ok());
        assert!(load_fixture("counter").is_ok());
    }

    #[test]
    fn rejects_sha256_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg_for(dir.path(), "p", &fixtures::wasm("tagger"));
        cfg.sha256 = "0".repeat(64);
        let err = load_plugin(&new_engine(), &cfg).unwrap_err();
        assert_eq!(err.plugin, "p");
        assert!(err.message.contains("sha256"), "{}", err.message);
    }

    #[test]
    fn rejects_module_with_import() {
        let err = load_fixture("with_import").unwrap_err();
        assert_eq!(err.plugin, "p");
        assert!(err.message.contains("import"), "{}", err.message);
    }

    #[test]
    fn rejects_wrong_abi_version() {
        let err = load_fixture("abi_v2").unwrap_err();
        assert_eq!(err.plugin, "p");
        assert!(err.message.contains("abi"), "{}", err.message);
    }

    #[test]
    fn rejects_missing_export() {
        let err = load_fixture("missing_alloc").unwrap_err();
        assert_eq!(err.plugin, "p");
        assert!(err.message.contains("osiris_alloc"), "{}", err.message);
    }

    #[test]
    fn rejects_invalid_wasm() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = cfg_for(dir.path(), "p", b"this is not wasm");
        let err = load_plugin(&new_engine(), &cfg).unwrap_err();
        assert_eq!(err.plugin, "p");
        assert!(err.message.contains("valid"), "{}", err.message);
    }

    #[test]
    fn rejects_unreadable_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg_for(dir.path(), "p", &fixtures::wasm("tagger"));
        cfg.path = dir.path().join("missing.wasm");
        let err = load_plugin(&new_engine(), &cfg).unwrap_err();
        assert_eq!(err.plugin, "p");
        assert!(err.message.contains("read"), "{}", err.message);
    }
}
