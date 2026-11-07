//! Parsing and validation of plugin output (spec §5.2, §5.3).
//!
//! Plugin output is untrusted. Error strings never contain output bytes.

use osiris_schema::Severity;
use serde::Deserialize;

use crate::config::PluginKind;

pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;
pub const MAX_ALERTS: usize = 8;
pub const MAX_TAGS: usize = 16;
pub const MAX_REASONS: usize = 8;
pub const MAX_REASON_BYTES: usize = 512;
pub const MAX_ID_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginAlert {
    pub id: String,
    pub severity: Severity,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginOutput {
    #[serde(default)]
    pub alerts: Vec<PluginAlert>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn valid_alert_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn valid_tag(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b':' | b'.' | b'-'))
}

/// Parses and validates one call's output. Any violation rejects the whole output.
pub fn parse_output(kind: PluginKind, bytes: &[u8]) -> Result<PluginOutput, String> {
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err("output exceeds 64 KiB".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "output is not valid UTF-8".to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "output is not valid JSON".to_string())?;
    if !value.is_object() {
        return Err("output is not a JSON object".into());
    }
    let out: PluginOutput = serde_json::from_value(value)
        .map_err(|_| "output does not match the plugin output schema".to_string())?;

    if out.alerts.len() > MAX_ALERTS {
        return Err("too many alerts (max 8)".into());
    }
    if out.tags.len() > MAX_TAGS {
        return Err("too many tags (max 16)".into());
    }
    match kind {
        PluginKind::Detection if !out.tags.is_empty() => {
            return Err("detection plugin returned tags".into())
        }
        PluginKind::Enrichment if !out.alerts.is_empty() => {
            return Err("enrichment plugin returned alerts".into())
        }
        _ => {}
    }
    for a in &out.alerts {
        if !valid_alert_id(&a.id) {
            return Err("alert id must match [a-z0-9_]{1,64}".into());
        }
        if a.reasons.is_empty() || a.reasons.len() > MAX_REASONS {
            return Err("alert must have 1 to 8 reasons".into());
        }
        for r in &a.reasons {
            if r.trim().is_empty() {
                return Err("alert reason is blank".into());
            }
            if r.len() > MAX_REASON_BYTES {
                return Err("alert reason exceeds 512 bytes".into());
            }
        }
    }
    for t in &out.tags {
        if !valid_tag(t) {
            return Err("tag must match [a-z0-9_:.-]{1,64}".into());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_alerts_and_tags() {
        let a = parse_output(
            PluginKind::Detection,
            br#"{"alerts":[{"id":"nc_seen","severity":"HIGH","reasons":["process is nc"]}]}"#,
        )
        .unwrap();
        assert_eq!(a.alerts.len(), 1);
        assert_eq!(a.alerts[0].id, "nc_seen");
        assert_eq!(a.alerts[0].severity, Severity::High);
        assert!(a.tags.is_empty());

        let t = parse_output(
            PluginKind::Enrichment,
            br#"{"tags":["dga_suspect","a:b.c-d"]}"#,
        )
        .unwrap();
        assert_eq!(t.tags, vec!["dga_suspect", "a:b.c-d"]);
        assert!(t.alerts.is_empty());

        assert_eq!(
            parse_output(PluginKind::Detection, b"{}").unwrap(),
            PluginOutput::default()
        );
    }

    fn alert(id: &str, reasons: &str) -> Vec<u8> {
        format!(r#"{{"alerts":[{{"id":"{id}","severity":"LOW","reasons":{reasons}}}]}}"#)
            .into_bytes()
    }

    #[test]
    fn invalid_outputs_are_rejected() {
        let nine_alerts = format!(
            r#"{{"alerts":[{}]}}"#,
            [r#"{"id":"a","severity":"LOW","reasons":["r"]}"#; 9].join(",")
        );
        let seventeen_tags = format!(r#"{{"tags":[{}]}}"#, [r#""t""#; 17].join(","));
        let long_reason = alert("a", &format!(r#"["{}"]"#, "x".repeat(513)));
        let nine_reasons = alert("a", &format!("[{}]", [r#""r""#; 9].join(",")));
        let huge = format!(r#"{{"tags":["{}"]}}"#, "a".repeat(70 * 1024));

        let cases: Vec<(&str, PluginKind, Vec<u8>)> = vec![
            (
                "invalid utf8",
                PluginKind::Detection,
                vec![0xff, 0xfe, b'{'],
            ),
            ("not an object", PluginKind::Detection, b"[1,2]".to_vec()),
            ("scalar", PluginKind::Detection, b"7".to_vec()),
            ("unknown key", PluginKind::Detection, br#"{"x":1}"#.to_vec()),
            (
                "unknown alert key",
                PluginKind::Detection,
                br#"{"alerts":[{"id":"a","severity":"LOW","reasons":["r"],"x":1}]}"#.to_vec(),
            ),
            (
                "nine alerts",
                PluginKind::Detection,
                nine_alerts.into_bytes(),
            ),
            (
                "seventeen tags",
                PluginKind::Enrichment,
                seventeen_tags.into_bytes(),
            ),
            ("long reason", PluginKind::Detection, long_reason),
            ("nine reasons", PluginKind::Detection, nine_reasons),
            ("no reasons", PluginKind::Detection, alert("a", "[]")),
            (
                "blank reason",
                PluginKind::Detection,
                alert("a", r#"["  "]"#),
            ),
            (
                "bad id",
                PluginKind::Detection,
                alert("Has-Caps", r#"["r"]"#),
            ),
            ("empty id", PluginKind::Detection, alert("", r#"["r"]"#)),
            (
                "bad tag",
                PluginKind::Enrichment,
                br#"{"tags":["a b"]}"#.to_vec(),
            ),
            (
                "detection with tags",
                PluginKind::Detection,
                br#"{"tags":["a"]}"#.to_vec(),
            ),
            (
                "enrichment with alerts",
                PluginKind::Enrichment,
                alert("a", r#"["r"]"#),
            ),
            (
                "unknown severity",
                PluginKind::Detection,
                br#"{"alerts":[{"id":"a","severity":"EXTREME","reasons":["r"]}]}"#.to_vec(),
            ),
            ("over 64 KiB", PluginKind::Enrichment, huge.into_bytes()),
        ];
        for (name, kind, bytes) in cases {
            let err =
                parse_output(kind, &bytes).expect_err(&format!("case `{name}` should be rejected"));
            assert!(!err.is_empty(), "case `{name}`");
            assert!(err.len() < 100, "case `{name}`: message too long");
            assert!(
                !err.contains("EXTREME") && !err.contains("Has-Caps"),
                "case `{name}` leaked output"
            );
        }
    }
}
