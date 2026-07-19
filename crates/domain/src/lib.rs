#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Recommendation {
    Promote,
    Reject,
    Abstain,
    Defer,
    StopProgram,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSnapshotRef {
    pub id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub id: Uuid,
    pub cou_id: String,
    pub recommendation: Recommendation,
    pub evidence: EvidenceSnapshotRef,
    pub rationale: Vec<String>,
}

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("a qualified decision requires at least one rationale")]
    MissingRationale,
    #[error("evidence digest must be a lowercase sha256")]
    InvalidEvidenceDigest,
}

impl DecisionRecord {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.rationale.is_empty() {
            return Err(DomainError::MissingRationale);
        }
        if self.evidence.sha256.len() != 64
            || !self
                .evidence
                .sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(DomainError::InvalidEvidenceDigest);
        }
        Ok(())
    }
}
