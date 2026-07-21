#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_DECISION_IDENTIFIER_CHARS: usize = 200;
pub const MAX_DECISION_IDENTIFIER_BYTES: usize = 800;
pub const MAX_DECISION_RATIONALE_ITEMS: usize = 32;
pub const MAX_DECISION_RATIONALE_ITEM_BYTES: usize = 4_096;
pub const MAX_DECISION_RATIONALE_TOTAL_BYTES: usize = 32_768;
pub const MAX_OOD_DETECTOR_ID_BYTES: usize = 200;
pub const MAX_OOD_DETECTOR_VERSION_BYTES: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Recommendation {
    Promote,
    Reject,
    Abstain,
    Defer,
    StopProgram,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OodStatus {
    InDomain,
    Borderline,
    OutOfDomain,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "OodDetectorRefData")]
pub struct OodDetectorRef {
    detector_id: String,
    detector_version: String,
}

#[derive(Deserialize)]
struct OodDetectorRefData {
    detector_id: String,
    detector_version: String,
}

impl OodDetectorRef {
    pub fn try_new(detector_id: String, detector_version: String) -> Result<Self, DomainError> {
        if !bounded_opaque_value_is_valid(&detector_id, MAX_OOD_DETECTOR_ID_BYTES) {
            return Err(DomainError::InvalidOodDetectorId);
        }
        if !bounded_opaque_value_is_valid(&detector_version, MAX_OOD_DETECTOR_VERSION_BYTES) {
            return Err(DomainError::InvalidOodDetectorVersion);
        }
        Ok(Self {
            detector_id,
            detector_version,
        })
    }

    pub fn detector_id(&self) -> &str {
        &self.detector_id
    }

    pub fn detector_version(&self) -> &str {
        &self.detector_version
    }
}

impl TryFrom<OodDetectorRefData> for OodDetectorRef {
    type Error = DomainError;

    fn try_from(value: OodDetectorRefData) -> Result<Self, Self::Error> {
        Self::try_new(value.detector_id, value.detector_version)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "EvidenceSnapshotRefData")]
pub struct EvidenceSnapshotRef {
    id: String,
    sha256: String,
}

#[derive(Deserialize)]
struct EvidenceSnapshotRefData {
    id: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "DecisionRecordData")]
pub struct DecisionRecord {
    id: Uuid,
    cou_id: String,
    recommendation: Recommendation,
    ood_status: OodStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    ood_detector: Option<OodDetectorRef>,
    evidence: EvidenceSnapshotRef,
    rationale: Vec<String>,
}

#[derive(Deserialize)]
struct DecisionRecordData {
    id: Uuid,
    cou_id: String,
    recommendation: Recommendation,
    #[serde(default)]
    ood_status: OodStatus,
    #[serde(default)]
    ood_detector: Option<OodDetectorRef>,
    evidence: EvidenceSnapshotRef,
    rationale: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("context of use identifier is invalid")]
    InvalidCouId,
    #[error("evidence identifier is invalid")]
    InvalidEvidenceId,
    #[error("OOD detector identifier is invalid")]
    InvalidOodDetectorId,
    #[error("OOD detector version is invalid")]
    InvalidOodDetectorVersion,
    #[error("a qualified decision requires at least one rationale")]
    MissingRationale,
    #[error("a decision has too many rationales")]
    TooManyRationales,
    #[error("a decision rationale is too large")]
    RationaleTooLarge,
    #[error("a decision rationale contains invalid text")]
    InvalidRationale,
    #[error("the decision rationale budget is exceeded")]
    RationaleBudgetExceeded,
    #[error("evidence digest must be a lowercase sha256")]
    InvalidEvidenceDigest,
}

impl EvidenceSnapshotRef {
    pub fn try_new(id: String, sha256: String) -> Result<Self, DomainError> {
        let evidence = Self { id, sha256 };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    fn validate(&self) -> Result<(), DomainError> {
        if !decision_identifier_is_valid(&self.id) {
            return Err(DomainError::InvalidEvidenceId);
        }
        if self.sha256.len() != 64
            || !self
                .sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(DomainError::InvalidEvidenceDigest);
        }
        Ok(())
    }
}

impl TryFrom<EvidenceSnapshotRefData> for EvidenceSnapshotRef {
    type Error = DomainError;

    fn try_from(value: EvidenceSnapshotRefData) -> Result<Self, Self::Error> {
        Self::try_new(value.id, value.sha256)
    }
}

impl DecisionRecord {
    pub fn try_new(
        id: Uuid,
        cou_id: String,
        recommendation: Recommendation,
        ood_status: OodStatus,
        evidence: EvidenceSnapshotRef,
        rationale: Vec<String>,
    ) -> Result<Self, DomainError> {
        Self::try_new_with_ood_detector(
            id,
            cou_id,
            recommendation,
            ood_status,
            None,
            evidence,
            rationale,
        )
    }

    pub fn try_new_with_ood_detector(
        id: Uuid,
        cou_id: String,
        recommendation: Recommendation,
        ood_status: OodStatus,
        ood_detector: Option<OodDetectorRef>,
        evidence: EvidenceSnapshotRef,
        rationale: Vec<String>,
    ) -> Result<Self, DomainError> {
        let decision = Self {
            id,
            cou_id,
            recommendation,
            ood_status,
            ood_detector,
            evidence,
            rationale,
        };
        decision.validate()?;
        Ok(decision)
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn cou_id(&self) -> &str {
        &self.cou_id
    }

    pub fn recommendation(&self) -> &Recommendation {
        &self.recommendation
    }

    pub fn ood_status(&self) -> &OodStatus {
        &self.ood_status
    }

    pub fn ood_detector(&self) -> Option<&OodDetectorRef> {
        self.ood_detector.as_ref()
    }

    pub fn evidence(&self) -> &EvidenceSnapshotRef {
        &self.evidence
    }

    pub fn rationale(&self) -> &[String] {
        &self.rationale
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if !decision_identifier_is_valid(&self.cou_id) {
            return Err(DomainError::InvalidCouId);
        }
        if self.rationale.len() > MAX_DECISION_RATIONALE_ITEMS {
            return Err(DomainError::TooManyRationales);
        }
        if self
            .rationale
            .iter()
            .any(|rationale| rationale.len() > MAX_DECISION_RATIONALE_ITEM_BYTES)
        {
            return Err(DomainError::RationaleTooLarge);
        }
        if self
            .rationale
            .iter()
            .any(|rationale| rationale.contains('\0'))
        {
            return Err(DomainError::InvalidRationale);
        }
        if self.rationale.iter().map(String::len).sum::<usize>()
            > MAX_DECISION_RATIONALE_TOTAL_BYTES
        {
            return Err(DomainError::RationaleBudgetExceeded);
        }
        if self
            .rationale
            .iter()
            .all(|rationale| rationale.trim().is_empty())
        {
            return Err(DomainError::MissingRationale);
        }
        self.evidence.validate()
    }
}

fn decision_identifier_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DECISION_IDENTIFIER_BYTES
        && value.chars().count() <= MAX_DECISION_IDENTIFIER_CHARS
        && value.trim() == value
        && !value.contains('\0')
}

fn bounded_opaque_value_is_valid(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && value.trim() == value && !value.contains('\0')
}

impl TryFrom<DecisionRecordData> for DecisionRecord {
    type Error = DomainError;

    fn try_from(value: DecisionRecordData) -> Result<Self, Self::Error> {
        Self::try_new_with_ood_detector(
            value.id,
            value.cou_id,
            value.recommendation,
            value.ood_status,
            value.ood_detector,
            value.evidence,
            value.rationale,
        )
    }
}
