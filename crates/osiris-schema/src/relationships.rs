use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::process_key::ProcessKey;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntityRef {
    Process {
        process_key: ProcessKey,
    },
    File {
        host_id: Uuid,
        inode: u64,
        device_id: u64,
    },
    Ip {
        addr: String,
    },
    Domain {
        name: String,
    },
    User {
        host_id: Uuid,
        uid: u32,
    },
    Container {
        container_id: String,
    },
    Session {
        session_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Relation {
    Spawned,
    ExecutedAs,
    Wrote,
    Read,
    ConnectedTo,
    ResolvedTo,
    BelongsToContainer,
    BelongsToPod,
    RunsInCgroup,
    TriggeredBySession,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRelationship {
    pub from: EntityRef,
    pub to: EntityRef,
    pub relation: Relation,
    pub event_id: Uuid,
    pub timestamp: u64,
}

/// Errors constructing an `EntityRef` from its `storage_key()` string form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntityRefParseError {
    #[error("entity key '{0}' has no recognized 'KIND:...' prefix")]
    UnknownKind(String),
    #[error("entity key '{0}' is malformed for its kind")]
    Malformed(String),
}

impl EntityRef {
    /// A stable, prefix-tagged string encoding of this entity, used as the
    /// indexed `from`/`to` column in the persisted `relationships` edge
    /// table (Phase 6 plan Task 3) and as the seed parameter for
    /// `GET /api/v1/graph` (Phase 6 plan Task 11). Two `EntityRef`s that are
    /// `==` produce the same key and vice versa — this is what lets the
    /// storage layer index on a plain `TEXT` column instead of a
    /// per-variant schema.
    pub fn storage_key(&self) -> String {
        match self {
            EntityRef::Process { process_key } => format!("PROCESS:{}", process_key.as_hex()),
            EntityRef::File {
                host_id,
                inode,
                device_id,
            } => format!("FILE:{host_id}:{inode}:{device_id}"),
            EntityRef::Ip { addr } => format!("IP:{addr}"),
            EntityRef::Domain { name } => format!("DOMAIN:{name}"),
            EntityRef::User { host_id, uid } => format!("USER:{host_id}:{uid}"),
            EntityRef::Container { container_id } => format!("CONTAINER:{container_id}"),
            EntityRef::Session { session_id } => format!("SESSION:{session_id}"),
        }
    }

    /// The inverse of `storage_key()`. Used to parse `GET /api/v1/graph`'s
    /// `entity` query parameter back into a typed seed.
    pub fn parse_storage_key(key: &str) -> Result<Self, EntityRefParseError> {
        let (kind, rest) = key
            .split_once(':')
            .ok_or_else(|| EntityRefParseError::UnknownKind(key.to_string()))?;
        let malformed = || EntityRefParseError::Malformed(key.to_string());
        match kind {
            "PROCESS" => {
                // ProcessKey's own Display/as_hex is the hex-encoded form;
                // reuse its Deserialize (which validates 16-byte decode) via
                // a JSON string round-trip rather than duplicating the hex
                // validation here.
                let process_key: ProcessKey =
                    serde_json::from_value(serde_json::Value::String(rest.to_string()))
                        .map_err(|_| malformed())?;
                Ok(EntityRef::Process { process_key })
            }
            "FILE" => {
                let mut parts = rest.splitn(3, ':');
                let host_id: Uuid = parts
                    .next()
                    .ok_or_else(malformed)?
                    .parse()
                    .map_err(|_| malformed())?;
                let inode: u64 = parts
                    .next()
                    .ok_or_else(malformed)?
                    .parse()
                    .map_err(|_| malformed())?;
                let device_id: u64 = parts
                    .next()
                    .ok_or_else(malformed)?
                    .parse()
                    .map_err(|_| malformed())?;
                Ok(EntityRef::File {
                    host_id,
                    inode,
                    device_id,
                })
            }
            "IP" => Ok(EntityRef::Ip {
                addr: rest.to_string(),
            }),
            "DOMAIN" => Ok(EntityRef::Domain {
                name: rest.to_string(),
            }),
            "USER" => {
                let mut parts = rest.splitn(2, ':');
                let host_id: Uuid = parts
                    .next()
                    .ok_or_else(malformed)?
                    .parse()
                    .map_err(|_| malformed())?;
                let uid: u32 = parts
                    .next()
                    .ok_or_else(malformed)?
                    .parse()
                    .map_err(|_| malformed())?;
                Ok(EntityRef::User { host_id, uid })
            }
            "CONTAINER" => Ok(EntityRef::Container {
                container_id: rest.to_string(),
            }),
            "SESSION" => Ok(EntityRef::Session {
                session_id: rest.to_string(),
            }),
            _ => Err(EntityRefParseError::UnknownKind(key.to_string())),
        }
    }
}

#[cfg(test)]
mod storage_key_tests {
    use super::*;

    fn sample_process_key() -> ProcessKey {
        ProcessKey::new(Uuid::new_v4(), "boot-1", 42, 99)
    }

    #[test]
    fn storage_key_round_trips_through_parse_storage_key_for_every_variant() {
        let host_id = Uuid::new_v4();
        let refs = vec![
            EntityRef::Process {
                process_key: sample_process_key(),
            },
            EntityRef::File {
                host_id,
                inode: 12345,
                device_id: 2049,
            },
            EntityRef::Ip {
                addr: "203.0.113.10".to_string(),
            },
            EntityRef::Domain {
                name: "evil.example".to_string(),
            },
            EntityRef::User { host_id, uid: 1000 },
            EntityRef::Container {
                container_id: "d".repeat(64),
            },
            EntityRef::Session {
                session_id: "3".to_string(),
            },
        ];
        for entity in refs {
            let key = entity.storage_key();
            let parsed = EntityRef::parse_storage_key(&key).unwrap();
            assert_eq!(parsed.storage_key(), key, "round-trip must be stable");
        }
    }

    #[test]
    fn storage_key_is_distinct_for_differing_fields_of_the_same_variant() {
        let host_id = Uuid::new_v4();
        let a = EntityRef::Ip {
            addr: "203.0.113.10".to_string(),
        };
        let b = EntityRef::Ip {
            addr: "203.0.113.11".to_string(),
        };
        assert_ne!(a.storage_key(), b.storage_key());

        let c = EntityRef::User { host_id, uid: 1000 };
        let d = EntityRef::User { host_id, uid: 1001 };
        assert_ne!(c.storage_key(), d.storage_key());
    }

    #[test]
    fn storage_key_is_distinct_across_variants_even_with_overlapping_raw_values() {
        // A Domain named "1000" and a User uid 1000 must not collide.
        let domain = EntityRef::Domain {
            name: "1000".to_string(),
        };
        let user = EntityRef::User {
            host_id: Uuid::nil(),
            uid: 1000,
        };
        assert_ne!(domain.storage_key(), user.storage_key());
    }

    #[test]
    fn parse_storage_key_rejects_an_unknown_kind_prefix() {
        assert!(matches!(
            EntityRef::parse_storage_key("BOGUS:whatever"),
            Err(EntityRefParseError::UnknownKind(_))
        ));
    }

    #[test]
    fn parse_storage_key_rejects_a_key_with_no_colon_at_all() {
        assert!(matches!(
            EntityRef::parse_storage_key("nothingatall"),
            Err(EntityRefParseError::UnknownKind(_))
        ));
    }

    #[test]
    fn parse_storage_key_rejects_a_malformed_file_key() {
        assert!(matches!(
            EntityRef::parse_storage_key("FILE:not-a-uuid:abc:def"),
            Err(EntityRefParseError::Malformed(_))
        ));
    }
}
