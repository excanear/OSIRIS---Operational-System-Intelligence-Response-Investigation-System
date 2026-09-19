use osiris_schema::EntityRef;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSource {
    EventCapture,
    FileSnapshot,
    ManualUpload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integrity {
    pub hash: String,
    pub immutable_since: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence must carry a non-empty integrity hash (ARCHITECTURE.md §12.6)")]
    EmptyHash,
}

/// A DFIR evidence record (ARCHITECTURE.md §12.6). Fields are private —
/// construction goes through the validating `new()`, and deserialization
/// through the same validation, mirroring `osiris_schema::Alert`'s
/// "enforced at the type level" posture. Append-only: there is no setter,
/// no `&mut self` method anywhere on this type — "correcting" a record is
/// always constructing a new one with `supersedes: Some(old_id)` and
/// inserting it (plan Global Constraint #7).
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    evidence_id: Uuid,
    source: EvidenceSource,
    timestamp: u64,
    integrity: Integrity,
    relationships: Vec<EntityRef>,
    supersedes: Option<Uuid>,
    /// Owning tenant; `None` = platform-owned. Set once, before insertion.
    tenant_id: Option<Uuid>,
}

impl Evidence {
    pub fn new(
        source: EvidenceSource,
        timestamp: u64,
        integrity: Integrity,
        relationships: Vec<EntityRef>,
        supersedes: Option<Uuid>,
    ) -> Result<Self, EvidenceError> {
        Self::validate(&integrity)?;
        Ok(Self {
            evidence_id: Uuid::now_v7(),
            source,
            timestamp,
            integrity,
            relationships,
            supersedes,
            tenant_id: None,
        })
    }

    /// Tags this (not yet inserted) record with its owning tenant.
    pub fn with_tenant(mut self, tenant_id: Option<Uuid>) -> Self {
        self.tenant_id = tenant_id;
        self
    }

    fn validate(integrity: &Integrity) -> Result<(), EvidenceError> {
        if integrity.hash.trim().is_empty() {
            return Err(EvidenceError::EmptyHash);
        }
        Ok(())
    }

    pub fn evidence_id(&self) -> Uuid {
        self.evidence_id
    }
    pub fn source(&self) -> EvidenceSource {
        self.source
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn integrity(&self) -> &Integrity {
        &self.integrity
    }
    pub fn relationships(&self) -> &[EntityRef] {
        &self.relationships
    }
    pub fn supersedes(&self) -> Option<Uuid> {
        self.supersedes
    }
    pub fn tenant_id(&self) -> Option<Uuid> {
        self.tenant_id
    }
}

#[derive(Deserialize)]
struct EvidenceWire {
    evidence_id: Uuid,
    source: EvidenceSource,
    timestamp: u64,
    integrity: Integrity,
    relationships: Vec<EntityRef>,
    supersedes: Option<Uuid>,
    #[serde(default)]
    tenant_id: Option<Uuid>,
}

impl<'de> Deserialize<'de> for Evidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = EvidenceWire::deserialize(deserializer)?;
        Evidence::validate(&wire.integrity).map_err(serde::de::Error::custom)?;
        Ok(Evidence {
            evidence_id: wire.evidence_id,
            source: wire.source,
            timestamp: wire.timestamp,
            integrity: wire.integrity,
            relationships: wire.relationships,
            supersedes: wire.supersedes,
            tenant_id: wire.tenant_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn integrity() -> Integrity {
        Integrity { hash: "abc123".to_string(), immutable_since: 1000 }
    }

    #[test]
    fn a_valid_evidence_record_carries_every_field() {
        let evidence = Evidence::new(EvidenceSource::EventCapture, 1000, integrity(), vec![], None).unwrap();
        assert_eq!(evidence.source(), EvidenceSource::EventCapture);
        assert_eq!(evidence.timestamp(), 1000);
        assert_eq!(evidence.integrity().hash, "abc123");
        assert!(evidence.supersedes().is_none());
    }

    #[test]
    fn rejects_an_empty_integrity_hash() {
        let bad = Integrity { hash: String::new(), immutable_since: 1000 };
        let err = Evidence::new(EvidenceSource::EventCapture, 1000, bad, vec![], None).unwrap_err();
        assert_eq!(err, EvidenceError::EmptyHash);
    }

    #[test]
    fn supersedes_links_to_the_record_it_replaces() {
        let old_id = Uuid::now_v7();
        let evidence = Evidence::new(EvidenceSource::ManualUpload, 2000, integrity(), vec![], Some(old_id)).unwrap();
        assert_eq!(evidence.supersedes(), Some(old_id));
    }

    #[test]
    fn json_round_trip_preserves_validation() {
        let evidence = Evidence::new(EvidenceSource::EventCapture, 1000, integrity(), vec![], None).unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back.evidence_id(), evidence.evidence_id());
    }

    #[test]
    fn deserialize_rejects_a_wire_payload_with_an_empty_hash() {
        let json = serde_json::json!({
            "evidence_id": Uuid::now_v7(),
            "source": "EVENT_CAPTURE",
            "timestamp": 1000,
            "integrity": { "hash": "", "immutable_since": 1000 },
            "relationships": [],
            "supersedes": null,
        });
        let result: Result<Evidence, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }
}
