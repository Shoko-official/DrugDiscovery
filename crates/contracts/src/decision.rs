use std::num::NonZeroU64;

use bioworld_domain::{
    DecisionCriterion as DomainDecisionCriterion,
    DecisionCriterionComparator as DomainDecisionCriterionComparator,
    DecisionPredictionInterval as DomainDecisionPredictionInterval,
    DecisionPredictionPosition as DomainDecisionPredictionPosition,
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
    #[error("prediction position interval is required")]
    MissingPredictionPositionInterval,
    #[error("prediction position evidence is required")]
    MissingPredictionPositionEvidence,
    #[error("decision criterion evidence is required")]
    MissingDecisionCriterionEvidence,
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
    #[error("decision criterion comparator must not be unspecified")]
    UnspecifiedDecisionCriterionComparator,
    #[error("decision criterion comparator value {0} is unknown")]
    UnknownDecisionCriterionComparator(i32),
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
            .map(prediction_interval_from_wire)
            .transpose()?;
        let prediction_positions = value
            .prediction_positions
            .into_iter()
            .map(|position| {
                let interval = position
                    .interval
                    .ok_or(Self::Error::MissingPredictionPositionInterval)?;
                let prediction_evidence = position
                    .prediction_evidence
                    .ok_or(Self::Error::MissingPredictionPositionEvidence)?;

                DomainDecisionPredictionPosition::try_new(
                    position.source_id,
                    position.source_version,
                    position.dependency_group_id,
                    prediction_interval_from_wire(interval)?,
                    evidence_from_wire(prediction_evidence)?,
                )
                .map_err(Self::Error::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let decision_criterion = value
            .decision_criterion
            .map(|criterion| {
                let criterion_evidence = criterion
                    .criterion_evidence
                    .ok_or(Self::Error::MissingDecisionCriterionEvidence)?;
                DomainDecisionCriterion::try_new(
                    criterion.criterion_id,
                    criterion.criterion_version,
                    decision_criterion_comparator_from_wire(criterion.comparator)?,
                    criterion.threshold_decimal,
                    evidence_from_wire(criterion_evidence)?,
                )
                .map_err(Self::Error::from)
            })
            .transpose()?;
        let evidence = evidence_from_wire(evidence)?;
        let decision = DomainDecisionRecord::try_new_with_decision_criterion(
            decision_id,
            value.cou_id,
            recommendation,
            ood_status,
            ood_detector,
            prediction_interval,
            prediction_positions,
            decision_criterion,
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
            evidence: Some(evidence_to_wire(evidence)),
            ood_status: Some(ood_status_to_wire(decision.ood_status()) as i32),
            ood_detector: decision.ood_detector().map(|detector| v2::OodDetectorRef {
                detector_id: detector.detector_id().to_owned(),
                detector_version: detector.detector_version().to_owned(),
            }),
            prediction_interval: decision
                .prediction_interval()
                .map(prediction_interval_to_wire),
            prediction_positions: decision
                .prediction_positions()
                .iter()
                .map(|position| v2::DecisionPredictionPosition {
                    source_id: position.source_id().to_owned(),
                    source_version: position.source_version().to_owned(),
                    dependency_group_id: position.dependency_group_id().to_owned(),
                    interval: Some(prediction_interval_to_wire(position.interval())),
                    prediction_evidence: Some(evidence_to_wire(position.prediction_evidence())),
                })
                .collect(),
            decision_criterion: decision.decision_criterion().map(|criterion| {
                v2::DecisionCriterion {
                    criterion_id: criterion.criterion_id().to_owned(),
                    criterion_version: criterion.criterion_version().to_owned(),
                    comparator: decision_criterion_comparator_to_wire(criterion.comparator())
                        as i32,
                    threshold_decimal: criterion.threshold_decimal().to_owned(),
                    criterion_evidence: Some(evidence_to_wire(criterion.criterion_evidence())),
                }
            }),
        }
    }
}

fn evidence_from_wire(
    value: v2::EvidenceSnapshotRef,
) -> Result<EvidenceSnapshotRef, DecisionContractError> {
    EvidenceSnapshotRef::try_new(value.id, value.sha256).map_err(DecisionContractError::from)
}

fn evidence_to_wire(value: &EvidenceSnapshotRef) -> v2::EvidenceSnapshotRef {
    v2::EvidenceSnapshotRef {
        id: value.id().to_owned(),
        sha256: value.sha256().to_owned(),
    }
}

fn prediction_interval_from_wire(
    value: v2::DecisionPredictionInterval,
) -> Result<DomainDecisionPredictionInterval, DecisionContractError> {
    let calibration_evidence = value
        .calibration_evidence
        .ok_or(DecisionContractError::MissingPredictionIntervalCalibrationEvidence)?;

    DomainDecisionPredictionInterval::try_new(
        value.target,
        value.unit,
        value.lower_decimal,
        value.upper_decimal,
        value.nominal_coverage_decimal,
        value.interval_method_id,
        value.interval_method_version,
        value.calibration_method_id,
        value.calibration_method_version,
        evidence_from_wire(calibration_evidence)?,
    )
    .map_err(DecisionContractError::from)
}

fn prediction_interval_to_wire(
    value: &DomainDecisionPredictionInterval,
) -> v2::DecisionPredictionInterval {
    v2::DecisionPredictionInterval {
        target: value.target().to_owned(),
        unit: value.unit().to_owned(),
        lower_decimal: value.lower_decimal().to_owned(),
        upper_decimal: value.upper_decimal().to_owned(),
        nominal_coverage_decimal: value.nominal_coverage_decimal().to_owned(),
        interval_method_id: value.interval_method_id().to_owned(),
        interval_method_version: value.interval_method_version().to_owned(),
        calibration_method_id: value.calibration_method_id().to_owned(),
        calibration_method_version: value.calibration_method_version().to_owned(),
        calibration_evidence: Some(evidence_to_wire(value.calibration_evidence())),
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

fn decision_criterion_comparator_from_wire(
    value: i32,
) -> Result<DomainDecisionCriterionComparator, DecisionContractError> {
    match v2::DecisionCriterionComparator::try_from(value)
        .map_err(|_| DecisionContractError::UnknownDecisionCriterionComparator(value))?
    {
        v2::DecisionCriterionComparator::Unspecified => {
            Err(DecisionContractError::UnspecifiedDecisionCriterionComparator)
        }
        v2::DecisionCriterionComparator::LessThan => {
            Ok(DomainDecisionCriterionComparator::LessThan)
        }
        v2::DecisionCriterionComparator::LessThanOrEqual => {
            Ok(DomainDecisionCriterionComparator::LessThanOrEqual)
        }
        v2::DecisionCriterionComparator::GreaterThan => {
            Ok(DomainDecisionCriterionComparator::GreaterThan)
        }
        v2::DecisionCriterionComparator::GreaterThanOrEqual => {
            Ok(DomainDecisionCriterionComparator::GreaterThanOrEqual)
        }
    }
}

fn decision_criterion_comparator_to_wire(
    value: &DomainDecisionCriterionComparator,
) -> v2::DecisionCriterionComparator {
    match value {
        DomainDecisionCriterionComparator::LessThan => v2::DecisionCriterionComparator::LessThan,
        DomainDecisionCriterionComparator::LessThanOrEqual => {
            v2::DecisionCriterionComparator::LessThanOrEqual
        }
        DomainDecisionCriterionComparator::GreaterThan => {
            v2::DecisionCriterionComparator::GreaterThan
        }
        DomainDecisionCriterionComparator::GreaterThanOrEqual => {
            v2::DecisionCriterionComparator::GreaterThanOrEqual
        }
    }
}
