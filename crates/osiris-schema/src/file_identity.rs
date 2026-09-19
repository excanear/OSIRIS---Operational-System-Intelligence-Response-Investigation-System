use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::FileRef;
use crate::relationships::EntityRef;

/// Stable filesystem-level identity for a file on one host, per
/// ARCHITECTURE.md §9.4's `file = (host_id, inode, device_id)` composite.
/// The `host_id` half lives on the owning `CanonicalEvent`, so this type
/// carries the host-independent pair and gains `host_id` at the moment it
/// becomes an `EntityRef` (see `to_entity_ref`).
///
/// Why identity and not path: a rename keeps the inode and changes the
/// path, so a path-only model loses the file across `FILE_RENAME`. Path is
/// the lookup key an analyst types; identity is the join key the File Story
/// query (Task 8) uses to follow the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    pub inode: u64,
    pub device_id: u64,
}

impl FileIdentity {
    pub fn new(inode: u64, device_id: u64) -> Self {
        Self { inode, device_id }
    }

    /// Builds an identity from a `FileRef`, returning `None` when the
    /// originating backend could not report both halves (the audit `PATH`
    /// record prints `inode=` and `dev=` for real paths but omits or nulls
    /// them for e.g. `nametype=UNKNOWN` items).
    pub fn from_file_ref(file: &FileRef) -> Option<Self> {
        Some(Self::new(file.inode?, file.device_id?))
    }

    /// The canonical wire/URL form: `"<device_id>:<inode>"`, both decimal.
    pub fn as_key(&self) -> String {
        format!("{}:{}", self.device_id, self.inode)
    }

    pub fn parse_key(s: &str) -> Option<Self> {
        let (device_id, inode) = s.split_once(':')?;
        Some(Self::new(inode.parse().ok()?, device_id.parse().ok()?))
    }

    pub fn to_entity_ref(self, host_id: Uuid) -> EntityRef {
        EntityRef::File {
            host_id,
            inode: self.inode,
            device_id: self.device_id,
        }
    }
}

/// Encodes a device's major:minor pair (as printed by an audit `PATH`
/// record's `dev=MAJ:MIN` field, in hex) into `FileRef::device_id`.
pub const fn encode_device_id(major: u32, minor: u32) -> u64 {
    ((major as u64) << 32) | (minor as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_ref(inode: Option<u64>, device_id: Option<u64>) -> FileRef {
        FileRef {
            path: "/var/www/html/shell.php".to_string(),
            previous_path: None,
            inode,
            device_id,
            size: None,
            mode: None,
            owner_uid: None,
            owner_gid: None,
            hash: None,
        }
    }

    #[test]
    fn encodes_major_minor_losslessly_and_reversibly() {
        // auditd prints `dev=08:01` (hex major:minor) for the usual root
        // block device; 8:1 must round-trip through the encoding.
        let device_id = encode_device_id(8, 1);
        assert_eq!(device_id, (8u64 << 32) | 1u64);
        assert_eq!((device_id >> 32) as u32, 8);
        assert_eq!((device_id & 0xFFFF_FFFF) as u32, 1);
    }

    #[test]
    fn builds_from_a_file_ref_only_when_both_halves_are_known() {
        assert_eq!(
            FileIdentity::from_file_ref(&file_ref(Some(131075), Some(encode_device_id(8, 1)))),
            Some(FileIdentity::new(131075, encode_device_id(8, 1)))
        );
        assert_eq!(
            FileIdentity::from_file_ref(&file_ref(Some(131075), None)),
            None
        );
        assert_eq!(FileIdentity::from_file_ref(&file_ref(None, Some(1))), None);
    }

    #[test]
    fn key_round_trips() {
        let identity = FileIdentity::new(131075, encode_device_id(8, 1));
        let key = identity.as_key();
        assert_eq!(key, format!("{}:{}", encode_device_id(8, 1), 131075));
        assert_eq!(FileIdentity::parse_key(&key), Some(identity));
    }

    #[test]
    fn parse_key_rejects_malformed_input() {
        assert_eq!(FileIdentity::parse_key("not-a-key"), None);
        assert_eq!(FileIdentity::parse_key("12:"), None);
        assert_eq!(FileIdentity::parse_key(":34"), None);
    }

    #[test]
    fn converts_to_the_schema_entity_ref_for_files() {
        let host_id = Uuid::new_v4();
        let identity = FileIdentity::new(131075, encode_device_id(8, 1));
        match identity.to_entity_ref(host_id) {
            crate::relationships::EntityRef::File {
                host_id: got_host,
                inode,
                device_id,
            } => {
                assert_eq!(got_host, host_id);
                assert_eq!(inode, 131075);
                assert_eq!(device_id, encode_device_id(8, 1));
            }
            other => panic!("expected EntityRef::File, got {other:?}"),
        }
    }
}
