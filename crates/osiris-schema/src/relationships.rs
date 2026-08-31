use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::process_key::ProcessKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
