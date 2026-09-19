use std::path::PathBuf;
use std::sync::Arc;

use osiris_schema::{CanonicalEvent, HostRef};
use osiris_sensor_api::RawEvent;

use crate::enrich::enrich;
use crate::normalize::normalize;
use crate::ns_cgroup_resolver::NsCgroupResolver;
use crate::pod_lookup::{attach_pod_ref, PodLookup};
use crate::prioritize::{prioritize, PriorityLane, PriorityTable};
use crate::process_resolver::ProcessResolver;
use crate::session_resolver::SessionResolver;
use crate::validate::validate;

/// A CanonicalEvent tagged with the lane it was assigned (what Task 3's
/// Event Bus keys its five channels on).
#[derive(Debug, Clone)]
pub struct PrioritizedEvent {
    pub event: CanonicalEvent,
    pub lane: PriorityLane,
}

/// The single fan-in pipeline (ARCHITECTURE.md §3.2's "why one shared
/// pipeline instance, not one per sensor"): Collect happens in the sensor
/// (Task 1/5/6); everything from Normalize onward happens here, in this
/// fixed order, for every event regardless of originating sensor.
pub struct Pipeline {
    host: HostRef,
    boot_id: String,
    resolver: ProcessResolver,
    sessions: SessionResolver,
    ns_cgroup: NsCgroupResolver,
    priority_table: PriorityTable,
    pod_lookup: Option<Arc<dyn PodLookup>>,
}

impl Pipeline {
    pub fn new(host: HostRef, boot_id: String) -> Self {
        Self {
            host,
            boot_id,
            resolver: ProcessResolver::new(),
            sessions: SessionResolver::new(),
            ns_cgroup: NsCgroupResolver::new("/proc"),
            priority_table: PriorityTable::default(),
            pod_lookup: None,
        }
    }

    /// Points the namespace/cgroup resolver at a different procfs root
    /// (Phase 5 plan Task 4) — used by tests and by `osiris-agent`'s
    /// config-driven `proc_root` so a fake or non-default root can be
    /// supplied without touching every existing `Pipeline::new` call site
    /// (mirrors `PersistenceSensor::with_poll_interval`'s builder shape).
    pub fn with_proc_root(mut self, proc_root: impl Into<PathBuf>) -> Self {
        self.ns_cgroup = NsCgroupResolver::new(proc_root);
        self
    }

    /// Attaches Kubernetes pod context to container events (Phase 8e) from
    /// the given lookup. Without one, `pod_ref` is left exactly as
    /// Normalize/Enrich produced it (builder shape of `with_proc_root`).
    pub fn with_pod_lookup(mut self, lookup: Arc<dyn PodLookup>) -> Self {
        self.pod_lookup = Some(lookup);
        self
    }

    /// Runs Normalize -> Enrich(local) -> Validate -> Prioritize on one raw
    /// event (ARCHITECTURE.md §7.1). Validation failures are tagged, never
    /// dropped — the caller always gets a PrioritizedEvent back.
    pub fn process(&mut self, raw: RawEvent) -> PrioritizedEvent {
        let event = normalize(raw, &self.host, &self.boot_id);
        let mut event = enrich(
            event,
            &self.boot_id,
            &mut self.resolver,
            &mut self.sessions,
            &mut self.ns_cgroup,
        );
        if let Some(lookup) = &self.pod_lookup {
            attach_pod_ref(&mut event, lookup.as_ref());
        }
        validate(&mut event);
        let lane = prioritize(&event, &self.priority_table);
        PrioritizedEvent { event, lane }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::PodRef;
    use osiris_sensor_api::{
        ContainerEventRaw, ContainerOperation, ProcessExecRaw, RawEventSource,
    };
    use std::collections::HashMap;
    use uuid::Uuid;

    struct FakePods(HashMap<String, PodRef>);
    impl PodLookup for FakePods {
        fn pod_for(&self, container_id: &str) -> Option<PodRef> {
            self.0.get(container_id).cloned()
        }
    }

    fn container_raw(container_id: &str) -> RawEvent {
        RawEvent::Container(ContainerEventRaw {
            operation: ContainerOperation::Start,
            container_id: container_id.to_string(),
            image: String::new(),
            runtime: "cgroup".to_string(),
            cgroup_path: "/kubepods/x".to_string(),
            pid: Some(10),
            pod_name: None,
            pod_namespace: None,
            timestamp_ns: 1,
            source: RawEventSource::Synthetic,
        })
    }

    #[test]
    fn pipeline_with_a_pod_lookup_attaches_pod_ref_and_without_one_leaves_it_none() {
        let id = "c".repeat(64);
        let mut pods = HashMap::new();
        pods.insert(
            id.clone(),
            PodRef {
                pod_name: "web-0".to_string(),
                namespace: "prod".to_string(),
            },
        );

        let mut with = Pipeline::new(test_host(), "boot-1".to_string())
            .with_pod_lookup(Arc::new(FakePods(pods)));
        let got = with.process(container_raw(&id));
        assert_eq!(
            got.event.container.unwrap().pod_ref.unwrap().pod_name,
            "web-0"
        );

        let mut without = Pipeline::new(test_host(), "boot-1".to_string());
        let got = without.process(container_raw(&id));
        assert!(got.event.container.unwrap().pod_ref.is_none());
    }

    fn test_host() -> HostRef {
        HostRef {
            host_id: Uuid::new_v4(),
            hostname: "h".to_string(),
            distro: "d".to_string(),
            kernel_version: "k".to_string(),
            cloud: None,
        }
    }

    #[test]
    fn end_to_end_pipeline_produces_valid_normal_lane_event() {
        let mut pipeline = Pipeline::new(test_host(), "boot-1".to_string());
        let raw = RawEvent::ProcessExec(ProcessExecRaw {
            pid: 100,
            ppid: 1,
            uid: 0,
            exe_path: "/bin/bash".to_string(),
            comm: "bash".to_string(),
            timestamp_ns: 1_700_000_000_000_000_000,
            start_time_mono: 1,
            source: RawEventSource::Synthetic,
        });
        let result = pipeline.process(raw);
        assert_eq!(result.lane, PriorityLane::Normal);
        assert!(!result.event.tags.contains(&"INVALID".to_string()));
        assert_eq!(result.event.boot_id, "boot-1");
    }

    #[test]
    fn second_event_resolves_parent_from_first() {
        let mut pipeline = Pipeline::new(test_host(), "boot-1".to_string());
        let bash = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 100,
            ppid: 1,
            uid: 0,
            exe_path: "/bin/bash".to_string(),
            comm: "bash".to_string(),
            timestamp_ns: 1,
            start_time_mono: 1,
            source: RawEventSource::Synthetic,
        }));
        let curl = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 200,
            ppid: 100,
            uid: 0,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 2,
            start_time_mono: 2,
            source: RawEventSource::Synthetic,
        }));
        assert_eq!(
            curl.event.parent_process.unwrap().process_key,
            bash.event.process.unwrap().process_key
        );
    }

    /// The whole Normalize -> Enrich -> Validate -> Prioritize path for a
    /// file event that follows its own process's exec — the shape every
    /// real trace has.
    #[test]
    fn file_event_following_its_process_exec_is_fully_resolved_and_valid() {
        use osiris_sensor_api::{FileEventRaw, FileOperation};
        let host = test_host();
        let mut pipeline = Pipeline::new(host.clone(), "boot-1".to_string());

        let curl = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 1_000,
            start_time_mono: 1_000,
            source: RawEventSource::Synthetic,
        }));

        let write = pipeline.process(RawEvent::File(FileEventRaw {
            operation: FileOperation::Write,
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode: Some(131075),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            mode: Some(0o100644),
            owner_uid: Some(33),
            owner_gid: Some(33),
            pid: 300,
            ppid: 200,
            uid: 1000,
            exe_path: "/usr/bin/curl".to_string(),
            comm: "curl".to_string(),
            timestamp_ns: 2_000,
            audit_serial: Some(456),
            source: RawEventSource::Synthetic,
        }));

        assert_eq!(write.lane, PriorityLane::Low);
        assert!(!write.event.tags.contains(&"INVALID".to_string()));
        assert!(!write
            .event
            .tags
            .contains(&"PROCESS_KEY_PROVISIONAL".to_string()));
        assert_eq!(
            write.event.process.as_ref().unwrap().process_key,
            curl.event.process.as_ref().unwrap().process_key,
            "the file event must be attributed to the same process entity as its exec"
        );
        assert_eq!(write.event.relationships.len(), 1);
        assert_eq!(
            write.event.file.as_ref().unwrap().path,
            "/var/www/html/shell.php"
        );
    }

    /// The whole Normalize -> Enrich -> Validate -> Prioritize path for
    /// ARCHITECTURE.md §26's opening: a login, a shell inside it, and a
    /// privilege escalation inside that shell — the shape this phase
    /// exists to make work.
    #[test]
    fn a_login_then_shell_then_escalation_is_fully_session_attributed() {
        use osiris_sensor_api::{
            IdentityEventRaw, IdentityOperation, PrivilegeEventRaw, PrivilegeOperation,
        };
        let host = test_host();
        let mut pipeline = Pipeline::new(host.clone(), "boot-1".to_string());

        let sshd = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 100,
            ppid: 1,
            uid: 0,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: 1_000,
            start_time_mono: 1_000,
            source: RawEventSource::Synthetic,
        }));
        assert!(sshd.event.session.is_none(), "no login observed yet");

        let login = pipeline.process(RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Login,
            session_id: "3".to_string(),
            pid: 100,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some("198.51.100.10".to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: 2_000,
            audit_serial: Some(456),
            source: RawEventSource::Synthetic,
        }));
        assert_eq!(login.lane, PriorityLane::Normal);
        assert!(!login.event.tags.contains(&"INVALID".to_string()));

        let bash = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 200,
            ppid: 100,
            uid: 1000,
            exe_path: "/bin/bash".to_string(),
            comm: "bash".to_string(),
            timestamp_ns: 3_000,
            start_time_mono: 3_000,
            source: RawEventSource::Synthetic,
        }));
        assert_eq!(bash.event.session.as_ref().unwrap().session_id, "3");
        assert!(bash
            .event
            .relationships
            .iter()
            .any(|r| r.relation == osiris_schema::Relation::TriggeredBySession));

        let escalation = pipeline.process(RawEvent::Privilege(PrivilegeEventRaw {
            operation: PrivilegeOperation::UidChange,
            pid: 200,
            ppid: 100,
            uid: 1000,
            gid: Some(1000),
            euid: Some(1000),
            egid: Some(1000),
            auid: Some(1000),
            session_id: Some("3".to_string()),
            username: None,
            target_uid: Some(0),
            target_gid: None,
            command: None,
            success: true,
            exe_path: "/usr/bin/sudo".to_string(),
            comm: "sudo".to_string(),
            timestamp_ns: 4_000,
            audit_serial: Some(470),
            source: RawEventSource::Synthetic,
        }));
        assert_eq!(escalation.lane, PriorityLane::High);
        assert!(!escalation.event.tags.contains(&"INVALID".to_string()));
        assert_eq!(
            escalation
                .event
                .session
                .as_ref()
                .unwrap()
                .remote_addr
                .as_deref(),
            Some("198.51.100.10"),
            "the escalation must carry the SSH session's remote address, which is \
             what makes Task 6's rule expressible"
        );
        assert!(escalation
            .event
            .relationships
            .iter()
            .any(|r| r.relation == osiris_schema::Relation::ExecutedAs));
    }

    /// The whole Normalize -> Enrich -> Validate -> Prioritize path for a
    /// Systemd event whose `ses=` matches an already-open session — proof
    /// that Task 1's fix plus this task's direct-observation normalize
    /// combine to make Global Constraint #3's "free" cross-category
    /// correlation real, not just unit-tested in isolation.
    #[test]
    fn a_systemd_service_start_inherits_no_pid_but_keeps_its_observed_session() {
        use osiris_sensor_api::{
            IdentityEventRaw, IdentityOperation, SystemdEventRaw, SystemdOperation,
        };
        let host = test_host();
        let mut pipeline = Pipeline::new(host.clone(), "boot-1".to_string());

        let _sshd = pipeline.process(RawEvent::ProcessExec(ProcessExecRaw {
            pid: 100,
            ppid: 1,
            uid: 0,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: 1_000,
            start_time_mono: 1_000,
            source: RawEventSource::Synthetic,
        }));
        let _login = pipeline.process(RawEvent::Identity(IdentityEventRaw {
            operation: IdentityOperation::Login,
            session_id: "3".to_string(),
            pid: 100,
            uid: 0,
            auid: Some(1000),
            username: Some("alice".to_string()),
            terminal: Some("/dev/pts/0".to_string()),
            remote_addr: Some("198.51.100.10".to_string()),
            auth_method: Some("sshd".to_string()),
            success: true,
            exe_path: "/usr/sbin/sshd".to_string(),
            comm: "sshd".to_string(),
            timestamp_ns: 2_000,
            audit_serial: Some(456),
            source: RawEventSource::Synthetic,
        }));

        // The systemd service-start record's own outer pid is 1 (systemd
        // itself) — unrelated to pid 100/sshd's ancestry entirely. Its
        // session attribution comes ONLY from its own observed `ses=`.
        let start = pipeline.process(RawEvent::Systemd(SystemdEventRaw {
            operation: SystemdOperation::Start,
            unit_name: "backdoor.service".to_string(),
            pid: 1,
            uid: 0,
            auid: Some(1000),
            session_id: Some("3".to_string()),
            success: true,
            exe_path: "/usr/lib/systemd/systemd".to_string(),
            comm: "systemd".to_string(),
            timestamp_ns: 3_000,
            audit_serial: Some(501),
            source: RawEventSource::Synthetic,
        }));

        assert!(!start.event.tags.contains(&"INVALID".to_string()));
        let session = start.event.session.expect("session must be observed");
        assert_eq!(session.session_id, "3");
        assert_eq!(
            session.remote_addr.as_deref(),
            Some("198.51.100.10"),
            "the systemd event must be enriched to the full session record, \
             which is what makes Task 9's rule expressible"
        );
    }
}
