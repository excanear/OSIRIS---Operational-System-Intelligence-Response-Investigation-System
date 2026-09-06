use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::event_type::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlertStatus {
    Open,
    Acknowledged,
    Suppressed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AlertError {
    #[error("alert must cite a non-empty rule_id (ARCHITECTURE.md §11.2)")]
    NoRuleId,
    #[error("alert must cite at least one non-blank reason (ARCHITECTURE.md §11.2)")]
    NoReasons,
    #[error("alert must cite at least one evidence event_id (ARCHITECTURE.md §11.2)")]
    NoEvidence,
}

/// A detection result (ARCHITECTURE.md §11.2/§12.7). Fields are private on
/// purpose: §11.2 requires that an Alert is *never allowed to exist*
/// without `reasons`, `evidence`, and `rule_id`+`rule_version`, and that
/// this is "enforced at the type level". Public fields would leave a
/// struct-literal escape hatch, and a derived `Deserialize` would leave a
/// wire escape hatch — so construction goes through `new()` and
/// deserialization goes through the same validation (see the hand-written
/// `Deserialize` below).
///
/// Everything is immutable after construction except `status`, which
/// §12.7 explicitly allows to transition (`OPEN` -> `ACKNOWLEDGED` /
/// `SUPPRESSED`).
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    alert_id: Uuid,
    rule_id: String,
    rule_version: u32,
    /// SHA-256 hex of the rule file's exact text, so an alert always cites
    /// the precise rule version that fired (§11.1's auditability point).
    rule_content_hash: String,
    severity: Severity,
    status: AlertStatus,
    /// Wall-clock nanoseconds of the event that triggered this alert.
    timestamp: u64,
    host_id: Uuid,
    /// One human-readable reason per matched condition — never a generic
    /// template (§11.2).
    reasons: Vec<String>,
    /// The exact `event_id`s that matched.
    evidence: Vec<Uuid>,
}

impl Alert {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_id: impl Into<String>,
        rule_version: u32,
        rule_content_hash: impl Into<String>,
        severity: Severity,
        timestamp: u64,
        host_id: Uuid,
        reasons: Vec<String>,
        evidence: Vec<Uuid>,
    ) -> Result<Self, AlertError> {
        let rule_id = rule_id.into();
        Self::validate(&rule_id, &reasons, &evidence)?;
        Ok(Self {
            alert_id: Uuid::now_v7(),
            rule_id,
            rule_version,
            rule_content_hash: rule_content_hash.into(),
            severity,
            status: AlertStatus::Open,
            timestamp,
            host_id,
            reasons,
            evidence,
        })
    }

    fn validate(rule_id: &str, reasons: &[String], evidence: &[Uuid]) -> Result<(), AlertError> {
        if rule_id.trim().is_empty() {
            return Err(AlertError::NoRuleId);
        }
        if reasons.iter().all(|r| r.trim().is_empty()) {
            return Err(AlertError::NoReasons);
        }
        if evidence.is_empty() {
            return Err(AlertError::NoEvidence);
        }
        Ok(())
    }

    pub fn alert_id(&self) -> Uuid {
        self.alert_id
    }
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }
    pub fn rule_version(&self) -> u32 {
        self.rule_version
    }
    pub fn rule_content_hash(&self) -> &str {
        &self.rule_content_hash
    }
    pub fn severity(&self) -> Severity {
        self.severity
    }
    pub fn status(&self) -> AlertStatus {
        self.status
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn host_id(&self) -> Uuid {
        self.host_id
    }
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }
    pub fn evidence(&self) -> &[Uuid] {
        &self.evidence
    }

    pub fn set_status(&mut self, status: AlertStatus) {
        self.status = status;
    }
}

/// The on-the-wire shape. Kept private so the only public path back from
/// JSON is the validating `Deserialize` below.
#[derive(Deserialize)]
struct AlertWire {
    alert_id: Uuid,
    rule_id: String,
    rule_version: u32,
    rule_content_hash: String,
    severity: Severity,
    status: AlertStatus,
    timestamp: u64,
    host_id: Uuid,
    reasons: Vec<String>,
    evidence: Vec<Uuid>,
}

impl<'de> Deserialize<'de> for Alert {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AlertWire::deserialize(deserializer)?;
        Alert::validate(&wire.rule_id, &wire.reasons, &wire.evidence)
            .map_err(serde::de::Error::custom)?;
        Ok(Alert {
            alert_id: wire.alert_id,
            rule_id: wire.rule_id,
            rule_version: wire.rule_version,
            rule_content_hash: wire.rule_content_hash,
            severity: wire.severity,
            status: wire.status,
            timestamp: wire.timestamp,
            host_id: wire.host_id,
            reasons: wire.reasons,
            evidence: wire.evidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn ok_alert() -> Alert {
        Alert::new(
            "shell_wrote_file_to_web_root",
            1,
            "abc123",
            Severity::High,
            1_700_000_000_000_000_000,
            Uuid::new_v4(),
            vec!["The file was written inside /var/www/".to_string()],
            vec![Uuid::now_v7()],
        )
        .expect("valid alert")
    }

    #[test]
    fn a_valid_alert_carries_every_required_explanation_field() {
        let alert = ok_alert();
        assert_eq!(alert.rule_id(), "shell_wrote_file_to_web_root");
        assert_eq!(alert.rule_version(), 1);
        assert_eq!(alert.rule_content_hash(), "abc123");
        assert_eq!(alert.status(), AlertStatus::Open);
        assert_eq!(alert.reasons().len(), 1);
        assert_eq!(alert.evidence().len(), 1);
    }

    #[test]
    fn rejects_an_alert_with_no_reasons() {
        let err = Alert::new(
            "r",
            1,
            "h",
            Severity::High,
            1,
            Uuid::new_v4(),
            vec![],
            vec![Uuid::now_v7()],
        )
        .unwrap_err();
        assert_eq!(err, AlertError::NoReasons);
    }

    #[test]
    fn rejects_an_alert_whose_reasons_are_all_blank() {
        let err = Alert::new(
            "r",
            1,
            "h",
            Severity::High,
            1,
            Uuid::new_v4(),
            vec!["   ".to_string()],
            vec![Uuid::now_v7()],
        )
        .unwrap_err();
        assert_eq!(err, AlertError::NoReasons);
    }

    #[test]
    fn rejects_an_alert_with_no_evidence() {
        let err = Alert::new(
            "r",
            1,
            "h",
            Severity::High,
            1,
            Uuid::new_v4(),
            vec!["because".to_string()],
            vec![],
        )
        .unwrap_err();
        assert_eq!(err, AlertError::NoEvidence);
    }

    #[test]
    fn rejects_an_alert_with_a_blank_rule_id() {
        let err = Alert::new(
            "  ",
            1,
            "h",
            Severity::High,
            1,
            Uuid::new_v4(),
            vec!["because".to_string()],
            vec![Uuid::now_v7()],
        )
        .unwrap_err();
        assert_eq!(err, AlertError::NoRuleId);
    }

    #[test]
    fn round_trips_through_json_preserving_identity_and_status() {
        let mut alert = ok_alert();
        alert.set_status(AlertStatus::Acknowledged);
        let json = serde_json::to_string(&alert).unwrap();
        let back: Alert = serde_json::from_str(&json).unwrap();
        assert_eq!(back.alert_id(), alert.alert_id());
        assert_eq!(back.status(), AlertStatus::Acknowledged);
        assert_eq!(back.reasons(), alert.reasons());
        assert_eq!(back.evidence(), alert.evidence());
    }

    /// ARCHITECTURE.md §11.2 says an Alert is *never allowed to exist*
    /// without reasons/evidence/rule identity. A validating constructor
    /// alone would leave a hole: anything could hand-write JSON with empty
    /// arrays and deserialize a bare "Threat detected". Deserialization
    /// must run the same validation.
    #[test]
    fn deserializing_an_alert_with_empty_reasons_is_rejected() {
        let json = serde_json::to_string(&ok_alert()).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["reasons"] = serde_json::json!([]);
        let result: Result<Alert, _> = serde_json::from_value(value);
        assert!(result.is_err(), "empty reasons must not deserialize");
    }

    #[test]
    fn deserializing_an_alert_with_empty_evidence_is_rejected() {
        let json = serde_json::to_string(&ok_alert()).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["evidence"] = serde_json::json!([]);
        let result: Result<Alert, _> = serde_json::from_value(value);
        assert!(result.is_err(), "empty evidence must not deserialize");
    }
}
