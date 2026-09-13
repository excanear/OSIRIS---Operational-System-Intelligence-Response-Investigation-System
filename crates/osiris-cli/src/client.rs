use osiris_schema::CanonicalEvent;

/// Builds the `/api/v1/events` request URL from the CLI's optional filters
/// — pure and testable without a network call.
pub fn events_url(
    server: &str,
    event_type: &Option<String>,
    since: &Option<u64>,
    until: &Option<u64>,
    limit: &Option<usize>,
) -> String {
    let mut url = format!("{}/api/v1/events", server.trim_end_matches('/'));
    let mut params = vec![];
    if let Some(et) = event_type {
        params.push(format!("event_type={}", et));
    }
    if let Some(s) = since {
        params.push(format!("since={}", s));
    }
    if let Some(u) = until {
        params.push(format!("until={}", u));
    }
    if let Some(l) = limit {
        params.push(format!("limit={}", l));
    }
    if !params.is_empty() {
        url.push('?');
        url.push_str(&params.join("&"));
    }
    url
}

/// Builds the `/api/v1/containers/story` request URL (Phase 5 plan Task
/// 11 — the CLI's first `*_story` subcommand; container ids are hex
/// strings, so no percent-encoding is needed).
pub fn container_story_url(server: &str, container_id: &str) -> String {
    format!(
        "{}/api/v1/containers/story?container_id={}",
        server.trim_end_matches('/'),
        container_id
    )
}

/// Builds the `/api/v1/graph` request URL (Phase 6 plan Task 12).
/// `entity` is the tagged string `EntityRef::storage_key()` produces
/// (e.g. `PROCESS:<hex>`) — passed through unencoded, the same posture
/// `container_story_url` already takes for hex container ids, since none
/// of this crate's entity key shapes contain characters a query string
/// needs to escape (Ip/Domain names are the one exception in principle,
/// left as a documented limitation rather than adding a URL-encoding
/// dependency for this phase).
pub fn chain_url(server: &str, entity: &str, depth: &Option<usize>) -> String {
    let mut url = format!(
        "{}/api/v1/graph?entity={}",
        server.trim_end_matches('/'),
        entity
    );
    if let Some(d) = depth {
        url.push_str(&format!("&depth={}", d));
    }
    url
}

/// Builds the `/api/v1/risk` request URL (Phase 6 plan Task 12).
pub fn risk_url(server: &str, process_key: &Option<String>, event_id: &Option<String>) -> String {
    let mut url = format!("{}/api/v1/risk", server.trim_end_matches('/'));
    let mut params = vec![];
    if let Some(pk) = process_key {
        params.push(format!("process_key={}", pk));
    }
    if let Some(eid) = event_id {
        params.push(format!("event_id={}", eid));
    }
    if !params.is_empty() {
        url.push('?');
        url.push_str(&params.join("&"));
    }
    url
}

/// Renders events as a human-readable tab-separated table (the default
/// `--format table` output; `--format json` bypasses this and prints the
/// API's raw JSON body instead — ARCHITECTURE.md §15's interactive vs.
/// non-interactive mode requirement).
pub fn format_events_table(events: &[CanonicalEvent]) -> String {
    let mut out = String::from("TIMESTAMP\tEVENT_TYPE\tPID\tEXE_PATH\n");
    for e in events {
        let event_type = serde_json::to_string(&e.event_type).unwrap_or_default();
        let event_type = event_type.trim_matches('"');
        let (pid, exe) = e
            .process
            .as_ref()
            .map(|p| (p.pid.to_string(), p.exe_path.clone()))
            .unwrap_or_else(|| ("-".to_string(), "-".to_string()));
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            e.timestamp, event_type, pid, exe
        ));
    }
    out
}

/// Minimal percent-encoding for the one context this CLI needs it in: an
/// OQL string placed into a `?q=` query parameter. Unreserved characters
/// (letters, digits, `-`, `_`, `.`, `~`) pass through unescaped per RFC
/// 3986; everything else — including the space, `"`, `(`, `)`, `=` that
/// every non-trivial OQL query contains — is escaped, unlike
/// `container_story_url`'s documented no-encoding posture (that function's
/// hex/container-id inputs never contain such characters; OQL always can).
pub fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// Builds the `/api/v1/events?q=...` request URL for `osiris hunt`.
pub fn hunt_url(server: &str, q: &str, since: &Option<u64>, until: &Option<u64>, limit: &Option<usize>) -> String {
    let mut url = format!("{}/api/v1/events?q={}", server.trim_end_matches('/'), percent_encode(q));
    if let Some(s) = since {
        url.push_str(&format!("&since={}", s));
    }
    if let Some(u) = until {
        url.push_str(&format!("&until={}", u));
    }
    if let Some(l) = limit {
        url.push_str(&format!("&limit={}", l));
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{
        Category, EventType, HostRef, ProcessKey, ProcessRef, Severity, Source, SCHEMA_VERSION,
    };
    use uuid::Uuid;

    #[test]
    fn events_url_includes_only_provided_filters() {
        let url = events_url(
            "http://localhost:8080",
            &Some("PROCESS_EXEC".to_string()),
            &None,
            &None,
            &Some(10),
        );
        assert_eq!(
            url,
            "http://localhost:8080/api/v1/events?event_type=PROCESS_EXEC&limit=10"
        );
    }

    #[test]
    fn events_url_with_no_filters_has_no_query_string() {
        let url = events_url("http://localhost:8080", &None, &None, &None, &None);
        assert_eq!(url, "http://localhost:8080/api/v1/events");
    }

    #[test]
    fn events_url_strips_trailing_slash_from_server() {
        let url = events_url("http://localhost:8080/", &None, &None, &None, &None);
        assert_eq!(url, "http://localhost:8080/api/v1/events");
    }

    #[test]
    fn events_url_includes_since_and_until() {
        let url = events_url(
            "http://localhost:8080",
            &None,
            &Some(100),
            &Some(200),
            &None,
        );
        assert_eq!(
            url,
            "http://localhost:8080/api/v1/events?since=100&until=200"
        );
    }

    #[test]
    fn events_url_includes_all_filters_in_order() {
        let url = events_url(
            "http://localhost:8080",
            &Some("PROCESS_EXEC".to_string()),
            &Some(100),
            &Some(200),
            &Some(5),
        );
        assert_eq!(
            url,
            "http://localhost:8080/api/v1/events?event_type=PROCESS_EXEC&since=100&until=200&limit=5"
        );
    }

    fn sample_event(pid: u32, exe_path: &str, timestamp: u64) -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp,
            monotonic_timestamp: 1,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: Some(ProcessRef {
                process_key: ProcessKey::new(host_id, "b", pid, 1),
                pid,
                exe_path: exe_path.to_string(),
                cmdline: vec![],
                exe_hash: None,
                start_time_mono: 1,
            }),
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

    #[test]
    fn container_story_url_includes_the_container_id() {
        let url = container_story_url("http://localhost:8080", &"a".repeat(64));
        assert_eq!(
            url,
            format!("http://localhost:8080/api/v1/containers/story?container_id={}", "a".repeat(64))
        );
    }

    #[test]
    fn container_story_url_strips_trailing_slash_from_server() {
        let url = container_story_url("http://localhost:8080/", "abc123");
        assert_eq!(
            url,
            "http://localhost:8080/api/v1/containers/story?container_id=abc123"
        );
    }

    #[test]
    fn chain_url_includes_the_entity_and_omits_depth_when_not_given() {
        let url = chain_url("http://localhost:8080", "PROCESS:abcd", &None);
        assert_eq!(url, "http://localhost:8080/api/v1/graph?entity=PROCESS:abcd");
    }

    #[test]
    fn chain_url_includes_depth_when_given() {
        let url = chain_url("http://localhost:8080/", "IP:203.0.113.10", &Some(3));
        assert_eq!(
            url,
            "http://localhost:8080/api/v1/graph?entity=IP:203.0.113.10&depth=3"
        );
    }

    #[test]
    fn risk_url_with_no_filters_has_no_query_string() {
        let url = risk_url("http://localhost:8080", &None, &None);
        assert_eq!(url, "http://localhost:8080/api/v1/risk");
    }

    #[test]
    fn risk_url_includes_process_key_and_event_id() {
        let url = risk_url(
            "http://localhost:8080",
            &Some("abcd".to_string()),
            &Some("1234".to_string()),
        );
        assert_eq!(
            url,
            "http://localhost:8080/api/v1/risk?process_key=abcd&event_id=1234"
        );
    }

    #[test]
    fn format_events_table_includes_header_and_row_data() {
        let event = sample_event(42, "/usr/bin/curl", 12345);
        let table = format_events_table(&[event]);
        assert!(table.starts_with("TIMESTAMP\tEVENT_TYPE\tPID\tEXE_PATH\n"));
        assert!(table.contains("12345"));
        assert!(table.contains("PROCESS_EXEC"));
        assert!(table.contains("42"));
        assert!(table.contains("/usr/bin/curl"));
    }

    #[test]
    fn format_events_table_handles_empty_slice() {
        let table = format_events_table(&[]);
        assert_eq!(table, "TIMESTAMP\tEVENT_TYPE\tPID\tEXE_PATH\n");
    }

    #[test]
    fn format_events_table_uses_placeholder_when_process_is_absent() {
        let mut event = sample_event(1, "/bin/x", 1);
        event.process = None;
        let table = format_events_table(&[event]);
        assert!(table.contains("\t-\t-\n"));
    }

    #[test]
    fn percent_encode_escapes_spaces_quotes_and_parens() {
        let encoded = percent_encode("a = \"b\" AND (c = 1)");
        assert_eq!(encoded, "a%20%3D%20%22b%22%20AND%20%28c%20%3D%201%29");
    }

    #[test]
    fn percent_encode_leaves_alphanumerics_and_dots_untouched() {
        assert_eq!(percent_encode("process.pid_1"), "process.pid_1");
    }

    #[test]
    fn hunt_url_includes_the_encoded_query_and_optional_filters() {
        let url = hunt_url("http://localhost:8080", "a = \"b\"", &Some(100), &None, &Some(10));
        assert_eq!(
            url,
            "http://localhost:8080/api/v1/events?q=a%20%3D%20%22b%22&since=100&limit=10"
        );
    }

    #[test]
    fn format_events_table_renders_multiple_rows() {
        let events = vec![
            sample_event(1, "/bin/a", 100),
            sample_event(2, "/bin/b", 200),
        ];
        let table = format_events_table(&events);
        assert_eq!(table.lines().count(), 3);
        assert!(table.contains("/bin/a"));
        assert!(table.contains("/bin/b"));
    }
}
