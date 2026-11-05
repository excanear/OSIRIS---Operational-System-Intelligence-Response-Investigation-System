//! RFC 5424 syslog and CEF (CEF rides inside an RFC 5424 envelope).
//!
//! # CEF extension key map
//!
//! | CEF key | Source | Records |
//! |---|---|---|
//! | `rt` | record timestamp, epoch milliseconds | all |
//! | `dvchost` | event hostname (alert: host_id) | all |
//! | `cs1` / `cs1Label=hostId` | host_id | all |
//! | `cs2` / `cs2Label=eventId` or `alertId` | event_id / alert_id | all |
//! | `cat` | event category | events |
//! | `spid` | process pid | events |
//! | `sproc` | process exe_path | events |
//! | `suser` | username, else numeric uid | events |
//! | `filePath` | file path | file events |
//! | `fname` | file base name | file events |
//! | `src` / `spt` | network src_ip / src_port | network events |
//! | `dst` / `dpt` | network dst_ip / dst_port | network events |
//! | `proto` | network protocol | network events |
//! | `msg` | `DNS query <name>` for DNS events; reasons joined by ` \| ` for alerts | dns, alerts |
//! | `cs3` / `cs3Label=tags` | tags joined by space | events with tags |
//! | `cs3` / `cs3Label=evidence` | evidence event ids joined by space | alerts |
//! | `cs4` / `cs4Label=alertStatus` | alert status | alerts |
//! | `cn1` / `cn1Label=ruleVersion` | rule version | alerts |
//!
//! Header: `CEF:0|OSIRIS|OSIRIS|<version>|<signature>|<name>|<severity>|`
//! where signature = `rule_id` (alert) / `event_type` (event) and name =
//! first reason (alert) / `event_type` (event).

use super::{
    cef_severity, enum_str, hostname, msg_id, ndjson::ndjson_line, rfc3339_ns, syslog_severity,
};
use crate::config::Facility;
use crate::record::ExportRecord;

/// Replace ASCII control chars, space and DEL (illegal in header fields).
fn header_field(s: &str, max_bytes: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let c = if c.is_ascii_control() || c == ' ' || c == '\u{7f}' {
            '_'
        } else {
            c
        };
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    if out.is_empty() {
        "-".to_string()
    } else {
        out
    }
}

/// RFC 5424 §6.3.3 SD-PARAM value escaping.
fn sd_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '"' | '\\' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn envelope(rec: &ExportRecord, facility: Facility, app_name: &str, msg: &str) -> String {
    let pri = u16::from(facility.code()) * 8 + u16::from(syslog_severity(rec.severity()));
    let record_type = match rec {
        ExportRecord::Event(_) => "event",
        ExportRecord::Alert(_) => "alert",
    };
    format!(
        "<{pri}>1 {ts} {host} {app} - {msgid} [osiris@32473 record_type=\"{rt}\" id=\"{id}\" host_id=\"{hid}\"] {msg}",
        ts = rfc3339_ns(rec.timestamp()),
        host = header_field(&hostname(rec), 255),
        app = header_field(app_name, 48),
        msgid = header_field(&msg_id(rec), 32),
        rt = sd_value(record_type),
        id = sd_value(&rec.id().to_string()),
        hid = sd_value(&rec.host_id().to_string()),
    )
}

/// RFC 5424 message; MSG is the NDJSON line.
pub fn rfc5424(
    rec: &ExportRecord,
    facility: Facility,
    app_name: &str,
    include_raw: bool,
) -> String {
    envelope(rec, facility, app_name, &ndjson_line(rec, include_raw))
}

fn cef_header_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn cef_ext_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// CEF inside an RFC 5424 envelope. See the module docs for the key map.
pub fn cef(
    rec: &ExportRecord,
    facility: Facility,
    app_name: &str,
    product_version: &str,
) -> String {
    let mut ext: Vec<(&str, String)> = vec![
        ("rt", (rec.timestamp() / 1_000_000).to_string()),
        ("dvchost", hostname(rec)),
        ("cs1Label", "hostId".into()),
        ("cs1", rec.host_id().to_string()),
    ];
    let (signature, name) = match rec {
        ExportRecord::Event(e) => {
            let et = enum_str(&e.event_type);
            ext.push(("cs2Label", "eventId".into()));
            ext.push(("cs2", e.event_id.to_string()));
            ext.push(("cat", enum_str(&e.category)));
            if let Some(p) = &e.process {
                ext.push(("spid", p.pid.to_string()));
                ext.push(("sproc", p.exe_path.clone()));
            }
            if let Some(u) = &e.user {
                ext.push((
                    "suser",
                    u.username.clone().unwrap_or_else(|| u.uid.to_string()),
                ));
            }
            if let Some(f) = &e.file {
                ext.push(("filePath", f.path.clone()));
                ext.push(("fname", basename(&f.path).to_string()));
            }
            if let Some(n) = &e.network {
                ext.push(("src", n.src_ip.clone()));
                ext.push(("spt", n.src_port.to_string()));
                ext.push(("dst", n.dst_ip.clone()));
                ext.push(("dpt", n.dst_port.to_string()));
                ext.push(("proto", n.proto.clone()));
            }
            if let Some(d) = &e.dns {
                ext.push(("msg", format!("DNS query {}", d.query)));
            }
            if !e.tags.is_empty() {
                ext.push(("cs3Label", "tags".into()));
                ext.push(("cs3", e.tags.join(" ")));
            }
            (et.clone(), et)
        }
        ExportRecord::Alert(a) => {
            ext.push(("cs2Label", "alertId".into()));
            ext.push(("cs2", a.alert_id().to_string()));
            ext.push(("msg", a.reasons().join(" | ")));
            ext.push(("cs3Label", "evidence".into()));
            ext.push((
                "cs3",
                a.evidence()
                    .iter()
                    .map(|u| u.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            ));
            ext.push(("cs4Label", "alertStatus".into()));
            ext.push(("cs4", enum_str(&a.status())));
            ext.push(("cn1Label", "ruleVersion".into()));
            ext.push(("cn1", a.rule_version().to_string()));
            let name = a
                .reasons()
                .first()
                .cloned()
                .unwrap_or_else(|| a.rule_id().to_string());
            (a.rule_id().to_string(), name)
        }
    };
    let ext = ext
        .iter()
        .map(|(k, v)| format!("{k}={}", cef_ext_escape(v)))
        .collect::<Vec<_>>()
        .join(" ");
    let msg = format!(
        "CEF:0|OSIRIS|OSIRIS|{}|{}|{}|{}|{}",
        cef_header_escape(product_version),
        cef_header_escape(&signature),
        cef_header_escape(&name),
        cef_severity(rec.severity()),
        ext
    );
    envelope(rec, facility, app_name, &msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sd_value_escapes_quote_backslash_and_bracket() {
        assert_eq!(sd_value(r#"a"b\c]d"#), "a\\\"b\\\\c\\]d");
    }

    #[test]
    fn header_field_replaces_spaces_and_controls_and_nils_empty() {
        assert_eq!(header_field("a b\nc", 255), "a_b_c");
        assert_eq!(header_field("", 255), "-");
        assert_eq!(header_field("h\u{00f3}st", 255), "h\u{00f3}st");
    }
}
