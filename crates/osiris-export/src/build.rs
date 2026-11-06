//! Turns validated exporter configuration into hub-ready workers.

use std::sync::Arc;

use crate::config::{validate_exporters, ExporterConfig, KindConfig};
use crate::error::ConfigError;
use crate::exporter::Exporter;
use crate::hub::WorkerSettings;
use crate::transport::{FileExporter, OtlpExporter, SyslogExporter, WebhookExporter};

/// One worker: its settings and the exporter it drives.
pub type BuiltExporter = (WorkerSettings, Arc<dyn Exporter>);

/// Validate `cfgs`, then construct every exporter. Fails on the first error.
pub fn build_exporters(
    cfgs: &[ExporterConfig],
    product_version: &str,
) -> Result<Vec<BuiltExporter>, ConfigError> {
    validate_exporters(cfgs)?;
    cfgs.iter()
        .map(|c| {
            let raw = c.common.include_raw;
            let exporter: Arc<dyn Exporter> = match &c.kind {
                KindConfig::File(f) => Arc::new(FileExporter::new(
                    &c.name,
                    f,
                    raw,
                    c.common.streams.first().copied(),
                )?),
                KindConfig::Syslog(s) => {
                    Arc::new(SyslogExporter::new(&c.name, s, raw, product_version)?)
                }
                KindConfig::Otlp(o) => Arc::new(OtlpExporter::new(&c.name, o, raw)?),
                KindConfig::Webhook(w) => Arc::new(WebhookExporter::new(&c.name, w, raw)?),
            };
            Ok((WorkerSettings::from_config(c), exporter))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Vec<ExporterConfig> {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[tokio::test]
    async fn build_exporters_builds_every_kind() {
        let dir = std::env::temp_dir().join(format!("osiris-build-{}", std::process::id()));
        let yaml = format!(
            "
- {{name: f, kind: file, path: '{}/a.ndjson'}}
- {{name: s, kind: syslog, address: '127.0.0.1:514', transport: udp}}
- {{name: o, kind: otlp, endpoint: 'http://127.0.0.1:4318/v1/logs'}}
- {{name: w, kind: webhook, url: 'http://127.0.0.1:9/x'}}
",
            dir.to_string_lossy().replace('\\', "/")
        );
        let built = build_exporters(&parse(&yaml), "1.2.3").unwrap();
        let kinds: Vec<_> = built.iter().map(|(s, _)| s.kind).collect();
        assert_eq!(kinds, ["file", "syslog", "otlp", "webhook"]);
        let names: Vec<_> = built.iter().map(|(_, e)| e.name().to_string()).collect();
        assert_eq!(names, ["f", "s", "o", "w"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn build_exporters_rejects_invalid_config() {
        // Validation runs first: plain http to a non-loopback host.
        let cfgs = parse("- {name: bad, kind: webhook, url: 'http://example.com/x'}");
        let err = build_exporters(&cfgs, "1").err().expect("must fail");
        assert_eq!(err.name, "bad");
        // Construction errors surface too (missing headers file).
        let cfgs = parse(
            "- {name: nohdr, kind: otlp, endpoint: 'http://127.0.0.1:1/x', headers_file: /nonexistent/h}",
        );
        let err = build_exporters(&cfgs, "1").err().expect("must fail");
        assert_eq!(err.name, "nohdr");
    }
}
