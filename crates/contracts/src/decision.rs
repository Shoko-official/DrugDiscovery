use std::num::NonZeroU64;

use bioworld_domain::{
    DecisionPredictionInterval as DomainDecisionPredictionInterval,
    DecisionRecord as DomainDecisionRecord, DomainError, EvidenceSnapshotRef,
    MAX_DECISION_RATIONALE_ITEMS, OodDetectorRef as DomainOodDetectorRef,
    OodStatus as DomainOodStatus, Recommendation as DomainRecommendation,
};
use prost::Message;
use thiserror::Error;
use uuid::Uuid;

use crate::v2;

pub const MAX_DECISION_WIRE_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedDecisionRecord {
    decision: DomainDecisionRecord,
    aggregate_version: NonZeroU64,
}

impl VersionedDecisionRecord {
    pub fn new(decision: DomainDecisionRecord, aggregate_version: NonZeroU64) -> Self {
        Self {
            decision,
            aggregate_version,
        }
    }

    pub fn decision(&self) -> &DomainDecisionRecord {
        &self.decision
    }

    pub fn aggregate_version(&self) -> NonZeroU64 {
        self.aggregate_version
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecisionContractError {
    #[error("decision record exceeds the wire size limit")]
    DecisionTooLarge,
    #[error("decision_id must be a UUID")]
    InvalidDecisionId,
    #[error("cou_id is required")]
    MissingCouId,
    #[error("evidence is required")]
    MissingEvidence,
    #[error("evidence id is required")]
    MissingEvidenceId,
    #[error("prediction interval calibration evidence is required")]
    MissingPredictionIntervalCalibrationEvidence,
    #[error("legacy evidence_snapshot_id conflicts with evidence.id")]
    ConflictingEvidenceIds,
    #[error("aggregate_version must be greater than zero")]
    InvalidAggregateVersion,
    #[error("recommendation must not be unspecified")]
    UnspecifiedRecommendation,
    #[error("recommendation value {0} is unknown")]
    UnknownRecommendation(i32),
    #[error("ood_status must not be unspecified")]
    UnspecifiedOodStatus,
    #[error("ood_status value {0} is unknown")]
    UnknownOodStatus(i32),
    #[error(transparent)]
    InvalidDomain(#[from] DomainError),
}

#[allow(deprecated)]
impl TryFrom<v2::DecisionRecord> for VersionedDecisionRecord {
    type Error = DecisionContractError;

    fn try_from(value: v2::DecisionRecord) -> Result<Self, Self::Error> {
        if value.rationale.len() > MAX_DECISION_RATIONALE_ITEMS {
            return Err(Self::Error::InvalidDomain(DomainError::TooManyRationales));
        }
        if value.encoded_len() > MAX_DECISION_WIRE_BYTES {
            return Err(Self::Error::DecisionTooLarge);
        }
        let decision_id =
            Uuid::parse_str(&value.decision_id).map_err(|_| Self::Error::InvalidDecisionId)?;
        if value.cou_id.trim().is_empty() {
            return Err(Self::Error::MissingCouId);
        }

        let evidence = value.evidence.ok_or(Self::Error::MissingEvidence)?;
        if evidence.id.trim().is_empty() {
            return Err(Self::Error::MissingEvidenceId);
        }
        if !value.evidence_snapshot_id.is_empty() && value.evidence_snapshot_id != evidence.id {
            return Err(Self::Error::ConflictingEvidenceIds);
        }

        let aggregate_version =
            NonZeroU64::new(value.aggregate_version).ok_or(Self::Error::InvalidAggregateVersion)?;
        let recommendation = recommendation_from_wire(value.recommendation)?;
        let ood_status = value
            .ood_status
            .map(ood_status_from_wire)
            .transpose()?
            .unwrap_or(DomainOodStatus::Unknown);
        let ood_detector = value
            .ood_detector
            .map(|detector| {
                DomainOodDetectorRef::try_new(detector.detector_id, detector.detector_version)
            })
            .transpose()?;
        let prediction_interval = value
            .prediction_interval
            .map(|interval| {
                let calibration_evidence = interval
                    .calibration_evidence
                    .ok_or(Self::Error::MissingPredictionIntervalCalibrationEvidence)?;
                let calibration_evidence = EvidenceSnapshotRef::try_new(
                    calibration_evidence.id,
                    calibration_evidence.sha256,
                )?;

                DomainDecisionPredictionInterval::try_new(
                    interval.target,
                    interval.unit,
                    interval.lower_decimal,
                    interval.upper_decimal,
                    interval.nominal_coverage_decimal,
                    interval.interval_method_id,
                    interval.interval_method_version,
                    interval.calibration_method_id,
                    interval.calibration_method_version,
                    calibration_evidence,
                )
                .map_err(Self::Error::from)
            })
            .transpose()?;
        let evidence = EvidenceSnapshotRef::try_new(evidence.id, evidence.sha256)?;
        let decision = DomainDecisionRecord::try_new_with_prediction_interval(
            decision_id,
            value.cou_id,
            recommendation,
            ood_status,
            ood_detector,
            prediction_interval,
            evidence,
            value.rationale,
        )?;

        Ok(Self::new(decision, aggregate_version))
    }
}

#[allow(deprecated)]
impl From<&VersionedDecisionRecord> for v2::DecisionRecord {
    fn from(value: &VersionedDecisionRecord) -> Self {
        let decision = value.decision();
        let evidence = decision.evidence();

        Self {
            decision_id: decision.id().to_string(),
            cou_id: decision.cou_id().to_owned(),
            evidence_snapshot_id: evidence.id().to_owned(),
            recommendation: recommendation_to_wire(decision.recommendation()) as i32,
            rationale: decision.rationale().to_vec(),
            aggregate_version: value.aggregate_version().get(),
            evidence: Some(v2::EvidenceSnapshotRef {
                id: evidence.id().to_owned(),
                sha256: evidence.sha256().to_owned(),
            }),
            ood_status: Some(ood_status_to_wire(decision.ood_status()) as i32),
            ood_detector: decision.ood_detector().map(|detector| v2::OodDetectorRef {
                detector_id: detector.detector_id().to_owned(),
                detector_version: detector.detector_version().to_owned(),
            }),
            prediction_interval: decision.prediction_interval().map(|interval| {
                let calibration_evidence = interval.calibration_evidence();

                v2::DecisionPredictionInterval {
                    target: interval.target().to_owned(),
                    unit: interval.unit().to_owned(),
                    lower_decimal: interval.lower_decimal().to_owned(),
                    upper_decimal: interval.upper_decimal().to_owned(),
                    nominal_coverage_decimal: interval.nominal_coverage_decimal().to_owned(),
                    interval_method_id: interval.interval_method_id().to_owned(),
                    interval_method_version: interval.interval_method_version().to_owned(),
                    calibration_method_id: interval.calibration_method_id().to_owned(),
                    calibration_method_version: interval.calibration_method_version().to_owned(),
                    calibration_evidence: Some(v2::EvidenceSnapshotRef {
                        id: calibration_evidence.id().to_owned(),
                        sha256: calibration_evidence.sha256().to_owned(),
                    }),
                }
            }),
        }
    }
}

fn recommendation_from_wire(value: i32) -> Result<DomainRecommendation, DecisionContractError> {
    match v2::Recommendation::try_from(value)
        .map_err(|_| DecisionContractError::UnknownRecommendation(value))?
    {
        v2::Recommendation::Unspecified => Err(DecisionContractError::UnspecifiedRecommendation),
        v2::Recommendation::Promote => Ok(DomainRecommendation::Promote),
        v2::Recommendation::Reject => Ok(DomainRecommendation::Reject),
        v2::Recommendation::Abstain => Ok(DomainRecommendation::Abstain),
        v2::Recommendation::Defer => Ok(DomainRecommendation::Defer),
        v2::Recommendation::StopProgram => Ok(DomainRecommendation::StopProgram),
    }
}

fn recommendation_to_wire(value: &DomainRecommendation) -> v2::Recommendation {
    match value {
        DomainRecommendation::Promote => v2::Recommendation::Promote,
        DomainRecommendation::Reject => v2::Recommendation::Reject,
        DomainRecommendation::Abstain => v2::Recommendation::Abstain,
        DomainRecommendation::Defer => v2::Recommendation::Defer,
        DomainRecommendation::StopProgram => v2::Recommendation::StopProgram,
    }
}

fn ood_status_from_wire(value: i32) -> Result<DomainOodStatus, DecisionContractError> {
    match v2::OodStatus::try_from(value)
        .map_err(|_| DecisionContractError::UnknownOodStatus(value))?
    {
        v2::OodStatus::Unspecified => Err(DecisionContractError::UnspecifiedOodStatus),
        v2::OodStatus::InDomain => Ok(DomainOodStatus::InDomain),
        v2::OodStatus::Borderline => Ok(DomainOodStatus::Borderline),
        v2::OodStatus::OutOfDomain => Ok(DomainOodStatus::OutOfDomain),
        v2::OodStatus::Unknown => Ok(DomainOodStatus::Unknown),
    }
}

fn ood_status_to_wire(value: &DomainOodStatus) -> v2::OodStatus {
    match value {
        DomainOodStatus::InDomain => v2::OodStatus::InDomain,
        DomainOodStatus::Borderline => v2::OodStatus::Borderline,
        DomainOodStatus::OutOfDomain => v2::OodStatus::OutOfDomain,
        DomainOodStatus::Unknown => v2::OodStatus::Unknown,
    }
}
