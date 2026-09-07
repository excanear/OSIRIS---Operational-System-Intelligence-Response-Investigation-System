use osiris_schema::CanonicalEvent;

/// Validate stage (ARCHITECTURE.md §7.1 step 4): a failing event is never
/// silently dropped — it is tagged INVALID and still forwarded, so an
/// operator can see what's malformed rather than have a silent gap.
/// Returns true if the event was valid (no tag added).
pub fn validate(event: &mut CanonicalEvent) -> bool {
    use osiris_schema::EventType::{FileCreate, FileDelete, FileRename, FileWrite};
    let mut valid = true;
    if event.host_id.is_nil() {
        valid = false;
    }
    if event.timestamp == 0 {
        valid = false;
    }
    if event.event_type == osiris_schema::EventType::ProcessExec && event.process.is_none() {
        valid = false;
    }
    if matches!(
        event.event_type,
        FileCreate | FileWrite | FileDelete | FileRename
    ) {
        // A file event with no path names nothing — it cannot be stored,
        // queried by a File Story, or explained in an alert.
        let has_path = event
            .file
            .as_ref()
            .map(|f| !f.path.trim().is_empty())
            .unwrap_or(false);
        if !has_path {
            valid = false;
        }
        if event.event_type == FileRename
            && event
                .file
                .as_ref()
                .and_then(|f| f.previous_path.as_deref())
                .map(|p| p.trim().is_empty())
                .unwrap_or(true)
        {
            valid = false;
        }
    }
    if !valid {
        event.tags.push("INVALID".to_string());
    }
    valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use uuid::Uuid;

    fn valid_event() -> CanonicalEvent {
        let host_id = Uuid::new_v4();
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1,
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
            process: Some(osiris_schema::ProcessRef {
                process_key: osiris_schema::ProcessKey::new(host_id, "b", 1, 1),
                pid: 1,
                exe_path: "/bin/x".to_string(),
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
    fn valid_event_gets_no_tag() {
        let mut event = valid_event();
        assert!(validate(&mut event));
        assert!(!event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn process_exec_without_process_ref_is_invalid_but_still_tagged_not_dropped() {
        let mut event = valid_event();
        event.process = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn nil_host_id_is_invalid() {
        let mut event = valid_event();
        event.host_id = Uuid::nil();
        assert!(!validate(&mut event));
    }

    fn valid_file_event(event_type: EventType) -> CanonicalEvent {
        let mut event = valid_event();
        event.event_type = event_type;
        event.category = Category::File;
        event.file = Some(osiris_schema::FileRef {
            path: "/var/www/html/shell.php".to_string(),
            previous_path: if event_type == EventType::FileRename {
                Some("/var/www/html/.shell.php.tmp".to_string())
            } else {
                None
            },
            inode: Some(131075),
            device_id: Some(osiris_schema::encode_device_id(8, 1)),
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        });
        event
    }

    #[test]
    fn well_formed_file_events_of_every_type_validate() {
        for event_type in [
            EventType::FileCreate,
            EventType::FileWrite,
            EventType::FileDelete,
            EventType::FileRename,
        ] {
            let mut event = valid_file_event(event_type);
            assert!(validate(&mut event), "{event_type:?} should be valid");
            assert!(!event.tags.contains(&"INVALID".to_string()));
        }
    }

    #[test]
    fn file_event_without_a_file_ref_is_invalid_but_still_forwarded() {
        let mut event = valid_file_event(EventType::FileCreate);
        event.file = None;
        assert!(!validate(&mut event));
        assert!(event.tags.contains(&"INVALID".to_string()));
    }

    #[test]
    fn file_event_with_an_empty_path_is_invalid() {
        let mut event = valid_file_event(EventType::FileWrite);
        if let Some(file) = event.file.as_mut() {
            file.path = "   ".to_string();
        }
        assert!(!validate(&mut event));
    }

    /// A FILE_RENAME with no `previous_path` carries no information about
    /// where the file moved from, which is the entire point of the type.
    #[test]
    fn file_rename_without_a_previous_path_is_invalid() {
        let mut event = valid_file_event(EventType::FileRename);
        if let Some(file) = event.file.as_mut() {
            file.previous_path = None;
        }
        assert!(!validate(&mut event));
    }
}
