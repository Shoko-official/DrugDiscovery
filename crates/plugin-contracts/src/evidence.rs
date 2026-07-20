use bioworld_domain::{DomainError, EvidenceSnapshotRef};
use thiserror::Error;

use crate::ArtifactRef;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvidenceContractError {
    #[error("artifact id is required")]
    MissingEvidenceId,
    #[error("artifact digest must be a lowercase sha256")]
    InvalidEvidenceDigest,
    #[error("artifact failed domain validation: {0}")]
    Domain(#[source] DomainError),
}

impl From<DomainError> for EvidenceContractError {
    fn from(error: DomainError) -> Self {
        match error {
            DomainError::InvalidEvidenceDigest => Self::InvalidEvidenceDigest,
            error => Self::Domain(error),
        }
    }
}

impl TryFrom<ArtifactRef> for EvidenceSnapshotRef {
    type Error = EvidenceContractError;

    fn try_from(value: ArtifactRef) -> Result<Self, Self::Error> {
        if value.id.trim().is_empty() {
            return Err(EvidenceContractError::MissingEvidenceId);
        }

        Ok(Self::try_new(value.id, value.sha256)?)
    }
}

impl From<&EvidenceSnapshotRef> for ArtifactRef {
    fn from(value: &EvidenceSnapshotRef) -> Self {
        Self {
            id: value.id().to_owned(),
            sha256: value.sha256().to_owned(),
        }
    }
}
