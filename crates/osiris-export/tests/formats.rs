use std::sync::Arc;

use osiris_export::format::Facility;
use osiris_export::*;
use osiris_schema::*;
use uuid::Uuid;

const TS: u64 = 1_762_300_800_123_456_789;
const HOST_A: &str = "11111111-1111-4111-8111-111111111111";
const HOST_B: &str = "22222222-2222-4222-8222-222222222222";

fn uuid(s: &str) -> Uuid {
    Uuid::parse_str(s).unwrap()
}

fn base_event(
    n: u8,
    host: &str,
    hostname: &str,
    event_type: EventType,
    severity: Severity,
) -> CanonicalEvent {
    let host_id = uuid(host);
    CanonicalEvent {
        event_id: uuid(&format!("aaaaaaaa-0000-4000-8000-{n:012}")),
        schema_version: SCHEMA_VERSION.to_string(),
        host_id,
        boot_id: "boot-1".to_string(),
        timestamp: TS,
        monotonic_timestamp: 5_000,
        event_type,
        category: event_type.category(),
        severity,
        host: HostRef {
            host_id,
            hostname: hostname.to_string(),
            distro: "ubuntu-24.04".to_string(),
            kernel_version: "6.8.0".to_string(),
            cloud: None,
        },
        user: Some(UserRef {
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
            username: Some("alice".to_string()),
            loginuid: None,
        }),
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
        source: Source::Ebpf,
        provider: "test".to_string(),
        raw_event: None,
        relationships: vec![],
        tags: vec![],
        risk: None,
        event_data: serde_json::json!({}),
    }
}

fn process(host: &str, pid: u32, exe: &str) -> ProcessRef {
    ProcessRef {
        process_key: ProcessKey::new(uuid(host), "boot-1", pid, 5_000),
        pid,
        exe_path: exe.to_string(),
        cmdline: vec![exe.to_string(), "-l".to_string()],
        exe_hash: None,
        start_time_mono: 5_000,
    }
}

fn exec_event() -> CanonicalEvent {
    let mut e = base_event(1, HOST_A, "web-01", EventType::ProcessExec, Severity::High);
    e.process = Some(process(HOST_A, 4242, "/usr/bin/curl"));
    e.tags = vec!["suspicious".to_string(), "net".to_string()];
    e
}

fn network_event() -> CanonicalEvent {
    let mut e = base_event(
        2,
        HOST_A,
        "web-01",
        EventType::NetworkConnect,
        Severity::Medium,
    );
    e.process = Some(process(HOST_A, 4242, "/usr/bin/curl"));
    e.network = Some(NetworkRef {
        src_ip: "10.0.0.5".to_string(),
        src_port: 53122,
        dst_ip: "93.184.216.34".to_string(),
        dst_port: 443,
        proto: "tcp".to_string(),
        direction: NetworkDirection::Outbound,
        bytes: None,
    });
    e
}

fn dns_event() -> CanonicalEvent {
    let mut e = base_event(3, HOST_A, "web-01", EventType::DnsQuery, Severity::Info);
    e.dns = Some(DnsRef {
        query: "example.com".to_string(),
        qtype: "A".to_string(),
        response_ips: vec!["93.184.216.34".to_string()],
        ttl: Some(300),
    });
    e
}

fn alert() -> Alert {
    serde_json::from_value(serde_json::json!({
        "alert_id": "bbbbbbbb-0000-4000-8000-000000000001",
        "rule_id": "R-100",
        "rule_version": 3,
        "rule_content_hash": "abc123",
        "severity": "CRITICAL",
        "status": "OPEN",
        "timestamp": TS,
        "host_id": HOST_A,
        "reasons": ["curl spawned by nginx", "outbound to rare ip"],
        "evidence": [
            "aaaaaaaa-0000-4000-8000-000000000001",
            "aaaaaaaa-0000-4000-8000-000000000002"
        ]
    }))
    .unwrap()
}

fn fixtures() -> Vec<(&'static str, ExportRecord)> {
    vec![
        ("exec", ExportRecord::Event(exec_event())),
        ("network", ExportRecord::Event(network_event())),
        ("dns", ExportRecord::Event(dns_event())),
        ("alert", ExportRecord::Alert(alert())),
    ]
}

fn check_golden(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing golden {}: {e}", path.display()));
    assert_eq!(actual, expected, "golden mismatch: {name}");
}

#[test]
fn golden_ndjson() {
    for (n, r) in fixtures() {
        check_golden(&format!("{n}.ndjson.txt"), &ndjson_line(&r, false));
    }
}

#[test]
fn golden_csv_row() {
    for (n, r) in fixtures() {
        check_golden(&format!("{n}.csv.txt"), &csv_row(&r));
    }
}

#[test]
fn golden_rfc5424() {
    for (n, r) in fixtures() {
        check_golden(
            &format!("{n}.rfc5424.txt"),
            &rfc5424(&r, Facility::Local0, "osiris", false),
        );
    }
}

#[test]
fn golden_cef() {
    for (n, r) in fixtures() {
        check_golden(
            &format!("{n}.cef.txt"),
            &cef(&r, Facility::Local0, "osiris", "0.12.0"),
        );
    }
}

#[test]
fn otlp_body_groups_records_by_host() {
    let mut other = exec_event();
    other.host_id = uuid(HOST_B);
    other.host.host_id = uuid(HOST_B);
    other.host.hostname = "db-01".to_string();
    let batch = vec![
        Arc::new(ExportRecord::Event(exec_event())),
        Arc::new(ExportRecord::Event(other)),
        Arc::new(ExportRecord::Alert(alert())),
    ];
    let body = otlp_logs_body(&batch, false, 1_762_300_801_000_000_000);
    let rl = body["resourceLogs"].as_array().unwrap();
    assert_eq!(rl.len(), 2);
    let first = &rl[0]["scopeLogs"][0]["logRecords"];
    assert_eq!(
        first.as_array().unwrap().len(),
        2,
        "event + alert of host A"
    );
    check_golden(
        "otlp_batch.json.txt",
        &serde_json::to_string_pretty(&body).unwrap(),
    );
}

#[test]
fn otlp_severity_numbers_match_spec() {
    assert_eq!(severity_number_otlp(Severity::Info), 9);
    assert_eq!(severity_number_otlp(Severity::Low), 10);
    assert_eq!(severity_number_otlp(Severity::Medium), 13);
    assert_eq!(severity_number_otlp(Severity::High), 17);
    assert_eq!(severity_number_otlp(Severity::Critical), 21);
}

#[test]
fn severity_maps_match_spec() {
    let all = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    let sys: Vec<u8> = all.iter().map(|s| syslog_severity(*s)).collect();
    let cefs: Vec<u8> = all.iter().map(|s| cef_severity(*s)).collect();
    assert_eq!(sys, [2, 3, 4, 5, 6]);
    assert_eq!(cefs, [10, 8, 5, 3, 1]);
}

#[test]
fn ndjson_omits_raw_event_by_default() {
    let mut e = exec_event();
    e.raw_event = Some(vec![0, 1, 2, 255]);
    let v = ndjson_value(&ExportRecord::Event(e), false);
    assert!(v.get("raw_event").is_none());
}

#[test]
fn ndjson_includes_raw_event_as_base64_when_enabled() {
    let mut e = exec_event();
    e.raw_event = Some(vec![0, 1, 2, 255]);
    let v = ndjson_value(&ExportRecord::Event(e), true);
    assert_eq!(v["raw_event"], "AAEC/w==");
}

#[test]
fn ndjson_has_record_type() {
    let e = ndjson_value(&ExportRecord::Event(exec_event()), false);
    let a = ndjson_value(&ExportRecord::Alert(alert()), false);
    assert_eq!(e["record_type"], "event");
    assert_eq!(a["record_type"], "alert");
}

#[test]
fn csv_header_matches_row_arity() {
    for (_, r) in fixtures() {
        let cols = |s: &str| s.trim_end().split(',').count();
        assert_eq!(cols(csv_header(r.stream())), cols(&csv_row(&r)));
    }
}

#[test]
fn csv_escapes_quotes_commas_and_newlines() {
    let mut e = exec_event();
    e.process.as_mut().unwrap().exe_path = "a,\"b\"\nc".to_string();
    let row = csv_row(&ExportRecord::Event(e));
    assert!(row.contains("\"a,\"\"b\"\"\nc\""), "{row:?}");
    assert!(row.ends_with("\r\n"));
}

#[test]
fn csv_prefixes_formula_cells() {
    for lead in ["=cmd|' /C calc'!A0", "+1", "-1", "@SUM(A1)", "\tx", "\rx"] {
        let mut e = exec_event();
        e.process.as_mut().unwrap().exe_path = lead.to_string();
        let row = csv_row(&ExportRecord::Event(e));
        assert!(row.contains(&format!("'{lead}")), "{lead:?} -> {row:?}");
    }
}

#[test]
fn cef_escapes_header_pipes_and_backslashes() {
    let a: Alert = serde_json::from_value(serde_json::json!({
        "alert_id": "bbbbbbbb-0000-4000-8000-000000000002",
        "rule_id": "R|1\\x", "rule_version": 1, "rule_content_hash": "h",
        "severity": "LOW", "status": "OPEN", "timestamp": TS, "host_id": HOST_A,
        "reasons": ["a|b"], "evidence": ["aaaaaaaa-0000-4000-8000-000000000001"]
    }))
    .unwrap();
    let s = cef(&ExportRecord::Alert(a), Facility::Local0, "osiris", "1.0");
    assert!(s.contains("|R\\|1\\\\x|a\\|b|3|"), "{s}");
}

#[test]
fn cef_escapes_extension_equals_and_newlines() {
    let mut e = exec_event();
    e.process.as_mut().unwrap().exe_path = "/a=b\nc\\d".to_string();
    let s = cef(&ExportRecord::Event(e), Facility::Local0, "osiris", "1.0");
    assert!(s.contains("sproc=/a\\=b\\nc\\\\d"), "{s}");
    assert!(!s.contains('\n'));
}

#[test]
fn newline_in_a_path_does_not_split_the_record() {
    let mut e = exec_event();
    e.process.as_mut().unwrap().exe_path = "/tmp/dir\nname/\u{00e9}x".to_string();
    e.host.hostname = "h\u{00f3}st\nx".to_string();
    let r = ExportRecord::Event(e);
    let one_line = |s: &str| {
        assert!(!s.contains('\n') && !s.contains('\r'), "split: {s:?}");
    };
    one_line(&ndjson_line(&r, false));
    one_line(&rfc5424(&r, Facility::Local0, "osiris", false));
    one_line(&cef(&r, Facility::Local0, "osiris", "1.0"));
    let row = csv_row(&r);
    assert!(row.contains("\"/tmp/dir\nname/\u{00e9}x\""));
    assert_eq!(row.matches("\r\n").count(), 1);
}

#[test]
fn rfc5424_pri_combines_facility_and_severity() {
    let mut e = exec_event();
    e.severity = Severity::High;
    let s = rfc5424(&ExportRecord::Event(e), Facility::Local0, "osiris", false);
    assert!(s.starts_with("<131>1 "), "{s}");
}

#[test]
fn rfc5424_hostname_is_nilvalue_when_empty() {
    let mut e = exec_event();
    e.host.hostname = String::new();
    let s = rfc5424(&ExportRecord::Event(e), Facility::Local0, "osiris", false);
    assert!(s.contains("Z - osiris - PROCESS_EXEC "), "{s}");
}

#[test]
fn rfc5424_sanitizes_app_name_and_uses_facility() {
    let s = rfc5424(
        &ExportRecord::Event(exec_event()),
        Facility::Local7,
        "o s",
        false,
    );
    assert!(s.starts_with("<187>1 "), "{s}");
    assert!(s.contains(" o_s "), "app name is sanitized: {s}");
}

#[test]
fn facility_codes_follow_rfc5424() {
    assert_eq!(Facility::Kern.code(), 0);
    assert_eq!(Facility::Local0.code(), 16);
    assert_eq!(Facility::Local7.code(), 23);
}

#[test]
fn otlp_host_name_prefers_event_hostname_even_when_alert_comes_first() {
    let batch = vec![
        Arc::new(ExportRecord::Alert(alert())),
        Arc::new(ExportRecord::Event(exec_event())),
    ];
    let body = otlp_logs_body(&batch, false, 1);
    let rl = body["resourceLogs"].as_array().unwrap();
    assert_eq!(rl.len(), 1);
    let attrs = rl[0]["resource"]["attributes"].as_array().unwrap();
    let name = attrs.iter().find(|a| a["key"] == "host.name").unwrap();
    assert_eq!(name["value"]["stringValue"], "web-01");
}

#[test]
fn include_raw_carries_base64_through_rfc5424_and_otlp() {
    let mut e = exec_event();
    e.raw_event = Some(vec![0, 1, 2, 255]);
    let r = ExportRecord::Event(e);
    let s = rfc5424(&r, Facility::Local0, "osiris", true);
    assert!(s.contains("\"raw_event\":\"AAEC/w==\""), "{s}");
    let body = otlp_logs_body(&[Arc::new(r)], true, 1);
    let b = body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["stringValue"]
        .as_str()
        .unwrap();
    assert!(b.contains("\"raw_event\":\"AAEC/w==\""), "{b}");
}
