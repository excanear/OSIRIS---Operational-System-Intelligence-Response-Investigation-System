use osiris_schema::{CanonicalEvent, PodRef};

/// Resolves a container id to its Kubernetes pod (ARCHITECTURE.md §21.3).
/// Synchronous because `Pipeline::process` is: implementors serve from an
/// in-memory cache that a background task keeps fresh.
pub trait PodLookup: Send + Sync {
    fn pod_for(&self, container_id: &str) -> Option<PodRef>;
}

/// Attaches `pod_ref` to `event.container` when the event has a container,
/// its `pod_ref` is still `None`, and the lookup knows the container id.
/// An existing `pod_ref` is never overwritten. Category-agnostic: covers
/// both Container lifecycle events and per-process events whose container
/// came from the cgroup path.
pub fn attach_pod_ref(event: &mut CanonicalEvent, lookup: &dyn PodLookup) {
    let Some(container) = event.container.as_mut() else {
        return;
    };
    if container.pod_ref.is_some() {
        return;
    }
    container.pod_ref = lookup.pod_for(&container.container_id);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use osiris_schema::{Category, HostRef, PodRef};
    use osiris_sensor_api::{ContainerEventRaw, ContainerOperation, RawEvent, RawEventSource};
    use uuid::Uuid;

    use super::*;
    use crate::normalize::normalize;

    struct FakeLookup(HashMap<String, PodRef>);
    impl PodLookup for FakeLookup {
        fn pod_for(&self, container_id: &str) -> Option<PodRef> {
            self.0.get(container_id).cloned()
        }
    }

    fn host() -> HostRef {
        HostRef {
            host_id: Uuid::new_v4(),
            hostname: "h".to_string(),
            distro: "d".to_string(),
            kernel_version: "k".to_string(),
            cloud: None,
        }
    }

    fn container_event(pod: Option<(&str, &str)>) -> osiris_schema::CanonicalEvent {
        let raw = RawEvent::Container(ContainerEventRaw {
            operation: ContainerOperation::Start,
            container_id: "c".repeat(64),
            image: String::new(),
            runtime: "cgroup".to_string(),
            cgroup_path: "/kubepods/x".to_string(),
            pid: Some(10),
            pod_name: pod.map(|(n, _)| n.to_string()),
            pod_namespace: pod.map(|(_, ns)| ns.to_string()),
            timestamp_ns: 1,
            source: RawEventSource::Synthetic,
        });
        normalize(raw, &host(), "boot-1")
    }

    fn lookup_with(container_id: &str, name: &str, ns: &str) -> FakeLookup {
        let mut map = HashMap::new();
        map.insert(
            container_id.to_string(),
            PodRef {
                pod_name: name.to_string(),
                namespace: ns.to_string(),
            },
        );
        FakeLookup(map)
    }

    #[test]
    fn fills_pod_ref_when_the_container_is_known_and_pod_ref_is_empty() {
        let mut event = container_event(None);
        assert!(event.container.as_ref().unwrap().pod_ref.is_none());
        attach_pod_ref(&mut event, &lookup_with(&"c".repeat(64), "web-0", "prod"));
        let pod = event.container.unwrap().pod_ref.unwrap();
        assert_eq!(pod.pod_name, "web-0");
        assert_eq!(pod.namespace, "prod");
    }

    #[test]
    fn never_overwrites_an_existing_pod_ref() {
        let mut event = container_event(Some(("original", "ns1")));
        attach_pod_ref(&mut event, &lookup_with(&"c".repeat(64), "web-0", "prod"));
        let pod = event.container.unwrap().pod_ref.unwrap();
        assert_eq!(pod.pod_name, "original");
        assert_eq!(pod.namespace, "ns1");
    }

    #[test]
    fn unknown_container_id_leaves_pod_ref_none() {
        let mut event = container_event(None);
        attach_pod_ref(&mut event, &lookup_with("other-id", "web-0", "prod"));
        assert!(event.container.unwrap().pod_ref.is_none());
    }

    #[test]
    fn events_without_a_container_are_untouched() {
        let mut event = container_event(None);
        event.container = None;
        attach_pod_ref(&mut event, &lookup_with(&"c".repeat(64), "web-0", "prod"));
        assert!(event.container.is_none());
    }

    #[test]
    fn works_for_any_category_such_as_a_per_process_event_in_a_container() {
        let mut event = container_event(None);
        event.category = Category::Process;
        attach_pod_ref(&mut event, &lookup_with(&"c".repeat(64), "web-0", "prod"));
        assert!(event.container.unwrap().pod_ref.is_some());
    }
}
