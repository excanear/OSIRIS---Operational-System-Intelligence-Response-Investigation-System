use std::collections::HashMap;

use osiris_schema::PodRef;

/// Longest pod/namespace name accepted (Kubernetes DNS-1123 subdomain limit).
pub const MAX_NAME_LEN: usize = 253;

/// Longest container id kept as a cache key (real ids are 64 hex chars).
const MAX_ID_LEN: usize = 128;

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= MAX_NAME_LEN && !s.chars().any(|c| c.is_control())
}

/// `containerd://<id>`, `docker://<id>`, `cri-o://<id>` -> `<id>`.
fn strip_runtime(container_id: &str) -> &str {
    container_id.split_once("://").map(|(_, rest)| rest).unwrap_or(container_id)
}

/// Parses a kubelet `GET /pods` `PodList` into `container_id -> PodRef`.
/// Pods with an invalid name/namespace are skipped entirely; statuses with
/// a missing/empty/oversized/control-char id are skipped. `None` when the
/// document is not a `PodList` (bad JSON, no `items`, `items` of the wrong
/// type); `"items": null` is a valid empty list.
pub fn parse_pod_list(json: &str) -> Option<HashMap<String, PodRef>> {
    let doc: serde_json::Value = serde_json::from_str(json).ok()?;
    let items = match doc.get("items")? {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Null => return Some(HashMap::new()),
        _ => return None,
    };

    let mut out = HashMap::new();
    for item in items {
        let Some(name) = item.pointer("/metadata/name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(namespace) = item.pointer("/metadata/namespace").and_then(|v| v.as_str()) else {
            continue;
        };
        if !valid_name(name) || !valid_name(namespace) {
            continue;
        }
        for key in ["containerStatuses", "initContainerStatuses"] {
            let Some(statuses) = item.pointer(&format!("/status/{key}")).and_then(|v| v.as_array()) else {
                continue;
            };
            for status in statuses {
                let Some(raw_id) = status.get("containerID").and_then(|v| v.as_str()) else {
                    continue;
                };
                let id = strip_runtime(raw_id);
                if id.is_empty() || id.chars().count() > MAX_ID_LEN || id.chars().any(|c| c.is_control()) {
                    continue;
                }
                out.insert(
                    id.to_string(),
                    PodRef { pod_name: name.to_string(), namespace: namespace.to_string() },
                );
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &str) -> String {
        format!(r#"{{"kind":"PodList","items":[{items}]}}"#)
    }

    fn pod_json(name: &str, ns: &str, statuses: &str) -> String {
        format!(r#"{{"metadata":{{"name":"{name}","namespace":"{ns}"}},"status":{{{statuses}}}}}"#)
    }

    #[test]
    fn strips_containerd_docker_and_crio_prefixes() {
        let json = list(&pod_json(
            "web-0",
            "prod",
            r#""containerStatuses":[
                {"containerID":"containerd://aaa"},
                {"containerID":"docker://bbb"},
                {"containerID":"cri-o://ccc"}
            ]"#,
        ));
        let map = parse_pod_list(&json).unwrap();
        for id in ["aaa", "bbb", "ccc"] {
            let pod = map.get(id).unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(pod.pod_name, "web-0");
            assert_eq!(pod.namespace, "prod");
        }
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn includes_init_container_statuses() {
        let json = list(&pod_json(
            "job-1",
            "batch",
            r#""initContainerStatuses":[{"containerID":"containerd://init1"}],"containerStatuses":[{"containerID":"containerd://main1"}]"#,
        ));
        let map = parse_pod_list(&json).unwrap();
        assert!(map.contains_key("init1"));
        assert!(map.contains_key("main1"));
    }

    #[test]
    fn pod_without_statuses_contributes_nothing() {
        let json = list(&pod_json("pending", "ns", ""));
        assert!(parse_pod_list(&json).unwrap().is_empty());
    }

    #[test]
    fn status_without_a_container_id_or_with_an_empty_one_is_skipped() {
        let json = list(&pod_json(
            "p",
            "ns",
            r#""containerStatuses":[{"name":"x"},{"containerID":""},{"containerID":"containerd://"}]"#,
        ));
        assert!(parse_pod_list(&json).unwrap().is_empty());
    }

    #[test]
    fn invalid_names_skip_the_whole_pod() {
        let too_long = "x".repeat(MAX_NAME_LEN + 1);
        let statuses = r#""containerStatuses":[{"containerID":"containerd://k1"}]"#;
        let json = list(&format!(
            "{},{},{},{}",
            pod_json(&too_long, "ns", statuses),
            pod_json("bad\\u0007name", "ns", statuses),
            pod_json("", "ns", statuses),
            pod_json("ok", "ns", r#""containerStatuses":[{"containerID":"containerd://k2"}]"#),
        ));
        let map = parse_pod_list(&json).unwrap();
        assert!(!map.contains_key("k1"), "invalid-name pods must be skipped");
        assert_eq!(map.get("k2").unwrap().pod_name, "ok");
    }

    #[test]
    fn duplicate_container_ids_last_one_wins() {
        let statuses = r#""containerStatuses":[{"containerID":"containerd://dup"}]"#;
        let json = list(&format!("{},{}", pod_json("first", "ns", statuses), pod_json("second", "ns", statuses)));
        assert_eq!(parse_pod_list(&json).unwrap().get("dup").unwrap().pod_name, "second");
    }

    #[test]
    fn empty_and_null_item_lists_are_valid_and_empty() {
        assert!(parse_pod_list(r#"{"items":[]}"#).unwrap().is_empty());
        assert!(parse_pod_list(r#"{"items":null}"#).unwrap().is_empty());
    }

    #[test]
    fn malformed_json_or_a_non_podlist_document_is_none() {
        assert!(parse_pod_list("not json").is_none());
        assert!(parse_pod_list(r#"{"message":"Unauthorized"}"#).is_none());
        assert!(parse_pod_list(r#"{"items":"nope"}"#).is_none());
    }
}
