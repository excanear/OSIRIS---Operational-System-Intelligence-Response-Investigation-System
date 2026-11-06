//! Exporter configuration (spec §5.2): types, strict parsing, validation, filter.
//!
//! An exporter entry is one flat YAML mapping (`name`, `kind`, common fields
//! and kind fields side by side). `#[serde(flatten)]` silently disables
//! `deny_unknown_fields`, so `ExporterConfig` has a hand-written
//! `Deserialize`: it takes the mapping apart, removes `name` and `kind`, moves
//! the common keys into one mapping and leaves the rest for the kind's struct.
//! Both `CommonOptions` and every kind struct are `deny_unknown_fields`, so a
//! stray key lands in the kind struct's remainder and is rejected there.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use osiris_schema::{Alert, CanonicalEvent, EventType, Severity};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::{Mapping, Value};
use uuid::Uuid;

use crate::error::ConfigError;
use crate::record::{ExportRecord, Stream};

const COMMON_KEYS: &[&str] = &[
    "streams",
    "min_severity",
    "event_types",
    "tenant_id",
    "include_raw",
    "queue_capacity",
    "batch_max",
    "flush_interval_ms",
    "max_retries",
];

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonOptions {
    #[serde(default = "default_streams")]
    pub streams: Vec<Stream>,
    #[serde(default = "default_min_severity", deserialize_with = "de_severity")]
    pub min_severity: Severity,
    #[serde(default)]
    pub event_types: Option<Vec<EventType>>,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub include_raw: bool,
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_batch_max")]
    pub batch_max: usize,
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

fn default_streams() -> Vec<Stream> {
    vec![Stream::Events, Stream::Alerts]
}
fn default_min_severity() -> Severity {
    Severity::Info
}
fn default_queue_capacity() -> usize {
    10_000
}
fn default_batch_max() -> usize {
    500
}
fn default_flush_interval_ms() -> u64 {
    1000
}
fn default_max_retries() -> u32 {
    5
}
fn default_max_bytes() -> u64 {
    100 * 1024 * 1024
}
fn default_max_files() -> u32 {
    5
}
fn default_app_name() -> String {
    "osiris".to_string()
}
fn default_timeout_secs() -> u64 {
    10
}

/// Accepts `info|low|medium|high|critical` (any case), as the spec writes them.
fn de_severity<'de, D: Deserializer<'de>>(d: D) -> Result<Severity, D::Error> {
    let s = String::deserialize(d)?;
    match s.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(D::Error::custom(format!(
            "unknown severity `{s}`, expected one of info, low, medium, high, critical"
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileFormat {
    Ndjson,
    Csv,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub path: PathBuf,
    #[serde(default = "default_file_format")]
    pub format: FileFormat,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_max_files")]
    pub max_files: u32,
}

fn default_file_format() -> FileFormat {
    FileFormat::Ndjson
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogTransport {
    Udp,
    Tcp,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFormat {
    Rfc5424,
    Cef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Facility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Authpriv,
    Ftp,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl Facility {
    /// RFC 5424 facility number.
    pub fn code(self) -> u8 {
        match self {
            Facility::Kern => 0,
            Facility::User => 1,
            Facility::Mail => 2,
            Facility::Daemon => 3,
            Facility::Auth => 4,
            Facility::Syslog => 5,
            Facility::Lpr => 6,
            Facility::News => 7,
            Facility::Uucp => 8,
            Facility::Cron => 9,
            Facility::Authpriv => 10,
            Facility::Ftp => 11,
            Facility::Local0 => 16,
            Facility::Local1 => 17,
            Facility::Local2 => 18,
            Facility::Local3 => 19,
            Facility::Local4 => 20,
            Facility::Local5 => 21,
            Facility::Local6 => 22,
            Facility::Local7 => 23,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogConfig {
    pub address: String,
    pub transport: SyslogTransport,
    #[serde(default = "default_syslog_format")]
    pub format: SyslogFormat,
    #[serde(default = "default_facility")]
    pub facility: Facility,
    #[serde(default = "default_app_name")]
    pub app_name: String,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    #[serde(default)]
    pub client_key: Option<PathBuf>,
    #[serde(default)]
    pub server_name: Option<String>,
}

fn default_syslog_format() -> SyslogFormat {
    SyslogFormat::Rfc5424
}
fn default_facility() -> Facility {
    Facility::Local0
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpConfig {
    pub endpoint: String,
    #[serde(default)]
    pub headers_file: Option<PathBuf>,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    #[serde(default)]
    pub client_key: Option<PathBuf>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default)]
    pub hmac_key_file: Option<PathBuf>,
    #[serde(default)]
    pub headers_file: Option<PathBuf>,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    #[serde(default)]
    pub client_key: Option<PathBuf>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

/// `scheme://host[:port]/path` of a URL; the query (which may hold a token) is hidden.
fn redact_url(url: &str) -> String {
    let no_frag = url.split('#').next().unwrap_or("");
    match no_frag.split_once('?') {
        Some((base, _)) => format!("{base}?<redacted>"),
        None => no_frag.to_string(),
    }
}

impl fmt::Debug for OtlpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpConfig")
            .field("endpoint", &redact_url(&self.endpoint))
            .field("headers_file", &self.headers_file)
            .field("ca_file", &self.ca_file)
            .field("client_cert", &self.client_cert)
            .field("client_key", &self.client_key)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("url", &redact_url(&self.url))
            .field("hmac_key_file", &self.hmac_key_file)
            .field("headers_file", &self.headers_file)
            .field("ca_file", &self.ca_file)
            .field("client_cert", &self.client_cert)
            .field("client_key", &self.client_key)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum KindConfig {
    File(FileConfig),
    Syslog(SyslogConfig),
    Otlp(OtlpConfig),
    Webhook(WebhookConfig),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExporterConfig {
    pub name: String,
    pub common: CommonOptions,
    pub kind: KindConfig,
}

impl<'de> Deserialize<'de> for ExporterConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let map = Mapping::deserialize(d)?;
        build_exporter(map).map_err(D::Error::custom)
    }
}

/// Errors from here already name the exporter.
fn build_exporter(mut map: Mapping) -> Result<ExporterConfig, String> {
    let name = match map.remove("name") {
        Some(Value::String(s)) => s,
        Some(_) => return Err("exporter '<unnamed>': `name` must be a string".into()),
        None => return Err("exporter '<unnamed>': missing field `name`".into()),
    };
    let wrap = |e: String| format!("exporter '{name}': {e}");
    let kind = match map.remove("kind") {
        Some(Value::String(s)) => s,
        Some(_) => return Err(wrap("`kind` must be a string".into())),
        None => return Err(wrap("missing field `kind`".into())),
    };

    let mut common_map = Mapping::new();
    for key in COMMON_KEYS {
        if let Some(v) = map.remove(*key) {
            common_map.insert(Value::String((*key).to_string()), v);
        }
    }
    let common: CommonOptions =
        serde_yaml::from_value(Value::Mapping(common_map)).map_err(|e| wrap(e.to_string()))?;

    let rest = Value::Mapping(map);
    let kind = match kind.as_str() {
        "file" => KindConfig::File(serde_yaml::from_value(rest).map_err(|e| wrap(e.to_string()))?),
        "syslog" => {
            KindConfig::Syslog(serde_yaml::from_value(rest).map_err(|e| wrap(e.to_string()))?)
        }
        "otlp" => KindConfig::Otlp(serde_yaml::from_value(rest).map_err(|e| wrap(e.to_string()))?),
        "webhook" => {
            KindConfig::Webhook(serde_yaml::from_value(rest).map_err(|e| wrap(e.to_string()))?)
        }
        other => {
            return Err(wrap(format!(
                "unknown kind `{other}`, expected one of file, syslog, otlp, webhook"
            )))
        }
    };
    Ok(ExporterConfig { name, common, kind })
}

/// Validates every exporter and the set as a whole. Messages name the exporter.
/// Upper bound on `queue_capacity` (memory guard).
const MAX_QUEUE_CAPACITY: usize = 1_000_000;

pub fn validate_exporters(cfgs: &[ExporterConfig]) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for cfg in cfgs {
        validate_name(&cfg.name)?;
        if !seen.insert(cfg.name.as_str()) {
            return Err(ConfigError::new(&cfg.name, "duplicate exporter name"));
        }
        validate_one(cfg).map_err(|m| ConfigError::new(&cfg.name, m))?;
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), ConfigError> {
    let ok = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(ConfigError::new(name, "name must match [a-z0-9_-]{1,64}"))
    }
}

fn validate_one(cfg: &ExporterConfig) -> Result<(), String> {
    let c = &cfg.common;
    if c.streams.is_empty() {
        return Err("streams must not be empty".into());
    }
    if c.queue_capacity == 0 {
        return Err("queue_capacity must be greater than 0".into());
    }
    if c.queue_capacity > MAX_QUEUE_CAPACITY {
        return Err(format!(
            "queue_capacity must not exceed {MAX_QUEUE_CAPACITY}"
        ));
    }
    if c.batch_max == 0 {
        return Err("batch_max must be greater than 0".into());
    }
    if c.batch_max > c.queue_capacity {
        return Err("batch_max must not exceed queue_capacity".into());
    }
    if c.flush_interval_ms == 0 {
        return Err("flush_interval_ms must be greater than 0".into());
    }
    match &cfg.kind {
        KindConfig::File(f) => {
            let distinct: HashSet<Stream> = c.streams.iter().copied().collect();
            if f.format == FileFormat::Csv && distinct.len() != 1 {
                return Err("format csv requires streams to hold exactly one stream".into());
            }
            if f.max_bytes == 0 {
                return Err("max_bytes must be greater than 0".into());
            }
            if f.max_files == 0 {
                return Err("max_files must be greater than 0".into());
            }
            if f.path.as_os_str().is_empty() {
                return Err("path must not be empty".into());
            }
        }
        KindConfig::Syslog(s) => {
            check_address(&s.address)?;
            check_mtls(&s.client_cert, &s.client_key)?;
            if s.app_name.is_empty() || s.app_name.len() > 48 || !is_printusascii(&s.app_name) {
                return Err("app_name must be 1-48 printable ASCII characters, no spaces".into());
            }
        }
        KindConfig::Otlp(o) => {
            check_url(&o.endpoint)?;
            check_mtls(&o.client_cert, &o.client_key)?;
            check_timeout(o.timeout_secs)?;
        }
        KindConfig::Webhook(w) => {
            check_url(&w.url)?;
            check_mtls(&w.client_cert, &w.client_key)?;
            check_timeout(w.timeout_secs)?;
        }
    }
    Ok(())
}

fn is_printusascii(s: &str) -> bool {
    s.bytes().all(|b| (33..=126).contains(&b))
}

fn check_timeout(secs: u64) -> Result<(), String> {
    if secs == 0 {
        Err("timeout_secs must be greater than 0".into())
    } else {
        Ok(())
    }
}

fn check_mtls(cert: &Option<PathBuf>, key: &Option<PathBuf>) -> Result<(), String> {
    match (cert, key) {
        (Some(_), None) => Err("client_cert requires client_key".into()),
        (None, Some(_)) => Err("client_key requires client_cert".into()),
        _ => Ok(()),
    }
}

/// `host:port` or `[v6]:port`; the port must be 1..=65535.
fn check_address(addr: &str) -> Result<(), String> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| "address must be host:port".to_string())?;
    let host_ok = if let Some(inner) = host.strip_prefix('[') {
        inner
            .strip_suffix(']')
            .is_some_and(|h| h.parse::<IpAddr>().is_ok())
    } else {
        !host.is_empty() && !host.contains(':') && !host.chars().any(char::is_whitespace)
    };
    if !host_ok {
        return Err("address must be host:port (IPv6 hosts in brackets)".into());
    }
    match port.parse::<u16>() {
        Ok(p) if p != 0 => Ok(()),
        _ => Err("address has an invalid port".into()),
    }
}

/// Never echoes the URL: it may carry a secret in its query string.
fn check_url(url: &str) -> Result<(), String> {
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("url must not contain whitespace or control characters".into());
    }
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "url must start with http:// or https://".to_string())?;
    let plain = match scheme.to_ascii_lowercase().as_str() {
        "http" => true,
        "https" => false,
        _ => return Err("url must start with http:// or https://".into()),
    };
    if rest.contains('#') {
        return Err("url must not contain a fragment".into());
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.contains('@') {
        return Err("url must not contain userinfo; use headers_file for credentials".into());
    }
    let host = if let Some(inner) = authority.strip_prefix('[') {
        inner.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    if host.is_empty() {
        return Err("url has no host".into());
    }
    if plain && !is_loopback_host(host) {
        return Err("plain http is accepted only for loopback hosts; use https".into());
    }
    Ok(())
}

/// `localhost`, 127.0.0.0/8 or `::1`.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Per-exporter record filter. Tenant scoping is applied by the hub, not here.
#[derive(Debug, Clone)]
pub struct Filter {
    events: bool,
    alerts: bool,
    min_rank: u8,
    event_types: Option<Vec<EventType>>,
}

impl Filter {
    pub fn from_config(common: &CommonOptions) -> Self {
        Self {
            events: common.streams.contains(&Stream::Events),
            alerts: common.streams.contains(&Stream::Alerts),
            min_rank: severity_rank(common.min_severity),
            event_types: common.event_types.clone(),
        }
    }

    pub fn accepts(&self, rec: &ExportRecord) -> bool {
        match rec {
            ExportRecord::Event(e) => self.accepts_event(e),
            ExportRecord::Alert(a) => self.accepts_alert(a),
        }
    }

    /// [`Filter::accepts`] on a borrowed event, so the hub can filter before
    /// cloning the event into an `ExportRecord`.
    pub fn accepts_event(&self, e: &CanonicalEvent) -> bool {
        self.events
            && severity_rank(e.severity) >= self.min_rank
            && self
                .event_types
                .as_ref()
                .is_none_or(|allow| allow.contains(&e.event_type))
    }

    /// [`Filter::accepts`] on a borrowed alert.
    pub fn accepts_alert(&self, a: &Alert) -> bool {
        self.alerts && severity_rank(a.severity()) >= self.min_rank
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{ExportRecord, Stream};
    use osiris_schema::{
        Alert, CanonicalEvent, Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION,
    };
    use uuid::Uuid;

    fn parse(yaml: &str) -> Result<Vec<ExporterConfig>, String> {
        let cfgs: Vec<ExporterConfig> = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
        validate_exporters(&cfgs).map_err(|e| e.to_string())?;
        Ok(cfgs)
    }

    fn rejected(yaml: &str, name: &str) {
        let err = parse(yaml).expect_err("config must be rejected");
        assert!(err.contains(name), "message {err:?} must name {name:?}");
    }

    #[test]
    fn parses_a_file_exporter_with_defaults() {
        let cfgs = parse("- {name: f1, kind: file, path: /var/log/o.ndjson}").unwrap();
        let c = &cfgs[0];
        assert_eq!(c.name, "f1");
        assert_eq!(c.common.streams, vec![Stream::Events, Stream::Alerts]);
        assert_eq!(c.common.min_severity, Severity::Info);
        assert_eq!(c.common.event_types, None);
        assert_eq!(c.common.tenant_id, None);
        assert!(!c.common.include_raw);
        assert_eq!(c.common.queue_capacity, 10_000);
        assert_eq!(c.common.batch_max, 500);
        assert_eq!(c.common.flush_interval_ms, 1000);
        assert_eq!(c.common.max_retries, 5);
        match &c.kind {
            KindConfig::File(f) => {
                assert_eq!(f.format, FileFormat::Ndjson);
                assert_eq!(f.max_bytes, 100 * 1024 * 1024);
                assert_eq!(f.max_files, 5);
            }
            other => panic!("expected file, got {other:?}"),
        }
    }

    #[test]
    fn parses_each_kind() {
        let yaml = "
- {name: f, kind: file, path: /tmp/a.csv, format: csv, streams: [alerts], max_bytes: 10, max_files: 2}
- {name: s, kind: syslog, address: 'siem:6514', transport: tls, format: cef, facility: local3, app_name: x, ca_file: /ca.pem, client_cert: /c.pem, client_key: /k.pem, server_name: siem.example}
- {name: o, kind: otlp, endpoint: 'https://c:4318/v1/logs', headers_file: /h, timeout_secs: 3}
- {name: w, kind: webhook, url: 'https://h/x', hmac_key_file: /k, min_severity: high, event_types: [PROCESS_EXEC], include_raw: true}
";
        let cfgs = parse(yaml).unwrap();
        assert_eq!(cfgs.len(), 4);
        assert!(matches!(&cfgs[0].kind, KindConfig::File(f) if f.format == FileFormat::Csv));
        match &cfgs[1].kind {
            KindConfig::Syslog(s) => {
                assert_eq!(s.transport, SyslogTransport::Tls);
                assert_eq!(s.format, SyslogFormat::Cef);
                assert_eq!(s.facility, Facility::Local3);
                assert_eq!(s.app_name, "x");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(&cfgs[2].kind, KindConfig::Otlp(o) if o.timeout_secs == 3));
        assert_eq!(cfgs[3].common.min_severity, Severity::High);
        assert_eq!(
            cfgs[3].common.event_types,
            Some(vec![EventType::ProcessExec])
        );
        assert!(cfgs[3].common.include_raw);
    }

    #[test]
    fn syslog_and_webhook_defaults() {
        let cfgs = parse(
            "
- {name: s, kind: syslog, address: '127.0.0.1:514', transport: udp}
- {name: w, kind: webhook, url: 'https://h/x'}
",
        )
        .unwrap();
        match &cfgs[0].kind {
            KindConfig::Syslog(s) => {
                assert_eq!(s.facility, Facility::Local0);
                assert_eq!(s.app_name, "osiris");
                assert_eq!(s.format, SyslogFormat::Rfc5424);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(&cfgs[1].kind, KindConfig::Webhook(w) if w.timeout_secs == 10));
    }

    #[test]
    fn debug_never_prints_url_query() {
        let cfgs = parse(
            "- {name: o, kind: otlp, endpoint: 'https://c:4318/v1/logs?token=SECRET'}
- {name: w, kind: webhook, url: 'https://h/x?key=SECRET'}",
        )
        .unwrap();
        for c in &cfgs {
            let d = format!("{c:?}");
            assert!(!d.contains("SECRET"), "{d}");
            assert!(d.contains("https://"), "{d}");
        }
    }

    #[test]
    fn rejects_duplicate_names() {
        rejected(
            "
- {name: dup, kind: file, path: /a}
- {name: dup, kind: file, path: /b}
",
            "dup",
        );
    }

    #[test]
    fn rejects_bad_name() {
        rejected("- {name: 'Bad Name', kind: file, path: /a}", "Bad Name");
    }

    #[test]
    fn rejects_unknown_key() {
        let err = parse("- {name: u1, kind: file, path: /a, colour: red}").unwrap_err();
        assert!(err.contains("u1") && err.contains("colour"), "{err}");
        // A key valid for another kind is also unknown here.
        let err = parse("- {name: u2, kind: file, path: /a, url: 'https://h/x'}").unwrap_err();
        assert!(err.contains("u2") && err.contains("url"), "{err}");
    }

    #[test]
    fn rejects_csv_with_two_streams() {
        rejected("- {name: c1, kind: file, path: /a, format: csv}", "c1");
    }

    #[test]
    fn rejects_plain_http_to_non_loopback() {
        rejected(
            "- {name: h1, kind: webhook, url: 'http://10.0.0.5/x'}",
            "h1",
        );
    }

    #[test]
    fn accepts_plain_http_to_loopback() {
        parse("- {name: o, kind: otlp, endpoint: 'http://127.0.0.1:4318/v1/logs'}").unwrap();
        parse("- {name: o, kind: otlp, endpoint: 'http://localhost:4318/v1/logs'}").unwrap();
        parse("- {name: o, kind: otlp, endpoint: 'http://[::1]:4318/v1/logs'}").unwrap();
        rejected(
            "- {name: o, kind: otlp, endpoint: 'http://127.0.0.1.evil.com/x'}",
            "o",
        );
    }

    #[test]
    fn rejects_url_with_userinfo() {
        rejected("- {name: u1, kind: webhook, url: 'https://u:p@h/x'}", "u1");
    }

    #[test]
    fn rejects_url_with_fragment() {
        rejected("- {name: fr, kind: webhook, url: 'https://h/x#frag'}", "fr");
    }

    #[test]
    fn rejects_zero_queue_capacity() {
        rejected(
            "- {name: q0, kind: file, path: /a, queue_capacity: 0}",
            "q0",
        );
    }

    #[test]
    fn rejects_zero_batch_max() {
        rejected("- {name: b0, kind: file, path: /a, batch_max: 0}", "b0");
        rejected(
            "- {name: bq, kind: file, path: /a, queue_capacity: 10, batch_max: 11}",
            "bq",
        );
        rejected(
            "- {name: qbig, kind: file, path: /a, queue_capacity: 1000001}",
            "qbig",
        );
        assert!(parse("- {name: ok, kind: file, path: /a, queue_capacity: 1000000}").is_ok());
    }

    #[test]
    fn rejects_syslog_address_without_port() {
        rejected(
            "- {name: np, kind: syslog, address: siem, transport: udp}",
            "np",
        );
    }

    #[test]
    fn rejects_client_cert_without_key() {
        rejected(
            "- {name: mt, kind: syslog, address: 'h:6514', transport: tls, client_cert: /c.pem}",
            "mt",
        );
        rejected(
            "- {name: mt2, kind: webhook, url: 'https://h/x', client_key: /k.pem}",
            "mt2",
        );
    }

    fn event(event_type: EventType, severity: Severity) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1000,
            monotonic_timestamp: 1000,
            event_type,
            category: Category::Process,
            severity,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: None,
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    fn alert(severity: Severity) -> Alert {
        Alert::new(
            "r1",
            1,
            "h",
            severity,
            1,
            Uuid::new_v4(),
            vec!["why".into()],
            vec![Uuid::new_v4()],
        )
        .unwrap()
    }

    fn filter(yaml: &str) -> Filter {
        let cfgs = parse(yaml).unwrap();
        Filter::from_config(&cfgs[0].common)
    }

    fn ev(t: EventType, s: Severity) -> ExportRecord {
        ExportRecord::Event(event(t, s))
    }

    #[test]
    fn filter_drops_below_min_severity() {
        let f = filter("- {name: a, kind: file, path: /a, min_severity: high}");
        assert!(!f.accepts(&ev(EventType::ProcessExec, Severity::Medium)));
        assert!(f.accepts(&ev(EventType::ProcessExec, Severity::High)));
        assert!(f.accepts(&ExportRecord::Alert(alert(Severity::Critical))));
        assert!(!f.accepts(&ExportRecord::Alert(alert(Severity::Low))));
    }

    #[test]
    fn filter_respects_streams() {
        let f = filter("- {name: a, kind: file, path: /a, streams: [alerts]}");
        assert!(!f.accepts(&ev(EventType::ProcessExec, Severity::Info)));
        assert!(f.accepts(&ExportRecord::Alert(alert(Severity::Info))));
    }

    #[test]
    fn event_types_allow_list_ignored_for_alerts() {
        let f = filter("- {name: a, kind: file, path: /a, event_types: [PROCESS_EXEC]}");
        assert!(f.accepts(&ev(EventType::ProcessExec, Severity::Info)));
        assert!(!f.accepts(&ev(EventType::NetworkConnect, Severity::Info)));
        assert!(f.accepts(&ExportRecord::Alert(alert(Severity::Info))));
    }
}
