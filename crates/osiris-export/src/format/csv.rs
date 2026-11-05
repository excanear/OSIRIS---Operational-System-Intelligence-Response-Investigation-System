//! Hand-rolled RFC 4180 CSV (spec §5.3).

use super::{enum_str, rfc3339_ns};
use crate::record::{ExportRecord, Stream};

const EVENT_HEADER: &str = "timestamp,event_id,host_id,hostname,event_type,category,severity,pid,exe_path,user,file_path,src_ip,src_port,dst_ip,dst_port,dns_query,tags\r\n";
const ALERT_HEADER: &str =
    "timestamp,alert_id,host_id,rule_id,rule_version,severity,status,reasons,evidence\r\n";

pub fn csv_header(stream: Stream) -> &'static str {
    match stream {
        Stream::Events => EVENT_HEADER,
        Stream::Alerts => ALERT_HEADER,
    }
}

/// One cell: formula-injection guard, then RFC 4180 quoting.
fn cell(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len() + 2);
    if matches!(
        raw.chars().next(),
        Some('=' | '+' | '-' | '@' | '\t' | '\r')
    ) {
        s.push('\'');
    }
    s.push_str(raw);
    if s.contains(['"', ',', '\r', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// One CSV row (with trailing `\r\n`). Tags are joined by a space.
pub fn csv_row(rec: &ExportRecord) -> String {
    let cells: Vec<String> = match rec {
        ExportRecord::Event(e) => {
            let p = e.process.as_ref();
            let n = e.network.as_ref();
            vec![
                rfc3339_ns(e.timestamp),
                e.event_id.to_string(),
                e.host_id.to_string(),
                e.host.hostname.clone(),
                enum_str(&e.event_type),
                enum_str(&e.category),
                enum_str(&e.severity),
                p.map(|p| p.pid.to_string()).unwrap_or_default(),
                p.map(|p| p.exe_path.clone()).unwrap_or_default(),
                e.user
                    .as_ref()
                    .map(|u| u.username.clone().unwrap_or_else(|| u.uid.to_string()))
                    .unwrap_or_default(),
                e.file.as_ref().map(|f| f.path.clone()).unwrap_or_default(),
                n.map(|n| n.src_ip.clone()).unwrap_or_default(),
                n.map(|n| n.src_port.to_string()).unwrap_or_default(),
                n.map(|n| n.dst_ip.clone()).unwrap_or_default(),
                n.map(|n| n.dst_port.to_string()).unwrap_or_default(),
                e.dns.as_ref().map(|d| d.query.clone()).unwrap_or_default(),
                e.tags.join(" "),
            ]
        }
        ExportRecord::Alert(a) => vec![
            rfc3339_ns(a.timestamp()),
            a.alert_id().to_string(),
            a.host_id().to_string(),
            a.rule_id().to_string(),
            a.rule_version().to_string(),
            enum_str(&a.severity()),
            enum_str(&a.status()),
            a.reasons().join(" | "),
            a.evidence()
                .iter()
                .map(|u| u.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        ],
    };
    let mut line = cells.iter().map(|c| cell(c)).collect::<Vec<_>>().join(",");
    line.push_str("\r\n");
    line
}
