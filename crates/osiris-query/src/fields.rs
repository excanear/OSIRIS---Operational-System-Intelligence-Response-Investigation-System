/// The OQL field reference (ARCHITECTURE.md §12.3: "generated from the
/// Event Schema so it never drifts out of sync"). This phase implements
/// that as a hand-maintained list checked against a live `CanonicalEvent`
/// by `eval::tests` (Task 4 Step... see eval.rs) rather than a build-time
/// codegen step — a documented simplification matching this workspace's
/// existing "smallest thing that satisfies the requirement" posture
/// (compare `osiris-storage`'s `QueryPlan` doc comment). Whoever adds a
/// field to `osiris-schema::CanonicalEvent` that should be OQL-queryable
/// must add it here too; forgetting to is caught the moment `eval::get_field`
/// is asked for a field this list didn't have a matching path for and a
/// coverage test (Task 4 Step 6, in eval.rs) fails.
const KNOWN_FIELDS: &[&str] = &[
    "event_type",
    "category",
    "severity",
    "timestamp",
    "host_id",
    "process.pid",
    "process.exe_path",
    "process.process_key",
    "parent_process.pid",
    "parent_process.process_key",
    "user.uid",
    "user.username",
    "file.path",
    "file.inode",
    "file.device_id",
    "network.src_ip",
    "network.dst_ip",
    "network.dst_port",
    "dns.query",
    "session.session_id",
    "service.unit_name",
    "container.container_id",
    "tags",
];

pub fn known_fields() -> &'static [&'static str] {
    KNOWN_FIELDS
}

pub fn is_known_field(field: &str) -> bool {
    KNOWN_FIELDS.contains(&field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_fields_includes_every_indexed_and_common_column() {
        for f in [
            "event_type",
            "category",
            "severity",
            "timestamp",
            "host_id",
            "process.pid",
            "process.exe_path",
            "process.process_key",
            "user.uid",
            "user.username",
            "file.path",
            "file.inode",
            "file.device_id",
            "network.src_ip",
            "network.dst_ip",
            "dns.query",
            "session.session_id",
            "service.unit_name",
            "container.container_id",
            "tags",
        ] {
            assert!(is_known_field(f), "expected '{}' to be a known field", f);
        }
    }

    #[test]
    fn rejects_an_unknown_field() {
        assert!(!is_known_field("not_a_real_field"));
    }
}
