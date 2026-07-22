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
pub const MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES: usize = 200;
pub const MAX_PREDICTION_INTERVAL_DECIMAL_BYTES: usize = 64;
pub const MAX_PREDICTION_POSITION_IDENTIFIER_BYTES: usize = 200;
pub const MIN_DECISION_PREDICTION_POSITIONS: usize = 2;
pub const MAX_DECISION_PREDICTION_POSITIONS: usize = 3;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "DecisionPredictionIntervalData")]
pub struct DecisionPredictionInterval {
    target: String,
    unit: String,
    lower_decimal: String,
    upper_decimal: String,
    nominal_coverage_decimal: String,
    interval_method_id: String,
    interval_method_version: String,
    calibration_method_id: String,
    calibration_method_version: String,
    calibration_evidence: EvidenceSnapshotRef,
}

#[derive(Deserialize)]
struct DecisionPredictionIntervalData {
    target: String,
    unit: String,
    lower_decimal: String,
    upper_decimal: String,
    nominal_coverage_decimal: String,
    interval_method_id: String,
    interval_method_version: String,
    calibration_method_id: String,
    calibration_method_version: String,
    calibration_evidence: EvidenceSnapshotRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "DecisionPredictionPositionData")]
pub struct DecisionPredictionPosition {
    source_id: String,
    source_version: String,
    dependency_group_id: String,
    interval: DecisionPredictionInterval,
    prediction_evidence: EvidenceSnapshotRef,
}

#[derive(Deserialize)]
struct DecisionPredictionPositionData {
    source_id: String,
    source_version: String,
    dependency_group_id: String,
    interval: DecisionPredictionInterval,
    prediction_evidence: EvidenceSnapshotRef,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    prediction_interval: Option<DecisionPredictionInterval>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    prediction_positions: Vec<DecisionPredictionPosition>,
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
    #[serde(default)]
    prediction_interval: Option<DecisionPredictionInterval>,
    #[serde(default)]
    prediction_positions: Vec<DecisionPredictionPosition>,
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
    #[error("prediction interval target is invalid")]
    InvalidPredictionIntervalTarget,
    #[error("prediction interval unit is invalid")]
    InvalidPredictionIntervalUnit,
    #[error("prediction interval method identifier is invalid")]
    InvalidPredictionIntervalMethodId,
    #[error("prediction interval method version is invalid")]
    InvalidPredictionIntervalMethodVersion,
    #[error("prediction interval calibration method identifier is invalid")]
    InvalidPredictionIntervalCalibrationMethodId,
    #[error("prediction interval calibration method version is invalid")]
    InvalidPredictionIntervalCalibrationMethodVersion,
    #[error("prediction interval lower bound is invalid")]
    InvalidPredictionIntervalLowerDecimal,
    #[error("prediction interval upper bound is invalid")]
    InvalidPredictionIntervalUpperDecimal,
    #[error("prediction interval lower bound exceeds upper bound")]
    InvalidPredictionIntervalBounds,
    #[error("prediction interval nominal coverage is invalid")]
    InvalidPredictionIntervalNominalCoverageDecimal,
    #[error("prediction position source identifier is invalid")]
    InvalidPredictionPositionSourceId,
    #[error("prediction position source version is invalid")]
    InvalidPredictionPositionSourceVersion,
    #[error("prediction position dependency group identifier is invalid")]
    InvalidPredictionPositionDependencyGroupId,
    #[error("a decision has too few prediction positions")]
    TooFewPredictionPositions,
    #[error("a decision has too many prediction positions")]
    TooManyPredictionPositions,
    #[error("prediction position source and version pairs must be unique")]
    DuplicatePredictionPositionSource,
    #[error("prediction positions require a decision prediction interval")]
    MissingPredictionIntervalForPositions,
    #[error("prediction position target does not match the decision interval")]
    IncomparablePredictionPositionTarget,
    #[error("prediction position unit does not match the decision interval")]
    IncomparablePredictionPositionUnit,
    #[error("prediction position nominal coverage does not match the decision interval")]
    IncomparablePredictionPositionNominalCoverage,
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

impl DecisionPredictionInterval {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        target: String,
        unit: String,
        lower_decimal: String,
        upper_decimal: String,
        nominal_coverage_decimal: String,
        interval_method_id: String,
        interval_method_version: String,
        calibration_method_id: String,
        calibration_method_version: String,
        calibration_evidence: EvidenceSnapshotRef,
    ) -> Result<Self, DomainError> {
        if !bounded_opaque_value_is_valid(&target, MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES) {
            return Err(DomainError::InvalidPredictionIntervalTarget);
        }
        if !bounded_opaque_value_is_valid(&unit, MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES) {
            return Err(DomainError::InvalidPredictionIntervalUnit);
        }
        if !bounded_opaque_value_is_valid(
            &interval_method_id,
            MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES,
        ) {
            return Err(DomainError::InvalidPredictionIntervalMethodId);
        }
        if !bounded_opaque_value_is_valid(
            &interval_method_version,
            MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES,
        ) {
            return Err(DomainError::InvalidPredictionIntervalMethodVersion);
        }
        if !bounded_opaque_value_is_valid(
            &calibration_method_id,
            MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES,
        ) {
            return Err(DomainError::InvalidPredictionIntervalCalibrationMethodId);
        }
        if !bounded_opaque_value_is_valid(
            &calibration_method_version,
            MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES,
        ) {
            return Err(DomainError::InvalidPredictionIntervalCalibrationMethodVersion);
        }
        if !canonical_decimal_is_valid(&lower_decimal) {
            return Err(DomainError::InvalidPredictionIntervalLowerDecimal);
        }
        if !canonical_decimal_is_valid(&upper_decimal) {
            return Err(DomainError::InvalidPredictionIntervalUpperDecimal);
        }
        if !canonical_decimal_is_valid(&nominal_coverage_decimal)
            || !compare_canonical_decimals(&nominal_coverage_decimal, "0").is_gt()
            || !compare_canonical_decimals(&nominal_coverage_decimal, "1").is_lt()
        {
            return Err(DomainError::InvalidPredictionIntervalNominalCoverageDecimal);
        }
        if compare_canonical_decimals(&lower_decimal, &upper_decimal).is_gt() {
            return Err(DomainError::InvalidPredictionIntervalBounds);
        }
        Ok(Self {
            target,
            unit,
            lower_decimal,
            upper_decimal,
            nominal_coverage_decimal,
            interval_method_id,
            interval_method_version,
            calibration_method_id,
            calibration_method_version,
            calibration_evidence,
        })
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub fn lower_decimal(&self) -> &str {
        &self.lower_decimal
    }

    pub fn upper_decimal(&self) -> &str {
        &self.upper_decimal
    }

    pub fn nominal_coverage_decimal(&self) -> &str {
        &self.nominal_coverage_decimal
    }

    pub fn interval_method_id(&self) -> &str {
        &self.interval_method_id
    }

    pub fn interval_method_version(&self) -> &str {
        &self.interval_method_version
    }

    pub fn calibration_method_id(&self) -> &str {
        &self.calibration_method_id
    }

    pub fn calibration_method_version(&self) -> &str {
        &self.calibration_method_version
    }

    pub fn calibration_evidence(&self) -> &EvidenceSnapshotRef {
        &self.calibration_evidence
    }
}

impl TryFrom<DecisionPredictionIntervalData> for DecisionPredictionInterval {
    type Error = DomainError;

    fn try_from(value: DecisionPredictionIntervalData) -> Result<Self, Self::Error> {
        Self::try_new(
            value.target,
            value.unit,
            value.lower_decimal,
            value.upper_decimal,
            value.nominal_coverage_decimal,
            value.interval_method_id,
            value.interval_method_version,
            value.calibration_method_id,
            value.calibration_method_version,
            value.calibration_evidence,
        )
    }
}

impl DecisionPredictionPosition {
    pub fn try_new(
        source_id: String,
        source_version: String,
        dependency_group_id: String,
        interval: DecisionPredictionInterval,
        prediction_evidence: EvidenceSnapshotRef,
    ) -> Result<Self, DomainError> {
        if !bounded_opaque_value_is_valid(&source_id, MAX_PREDICTION_POSITION_IDENTIFIER_BYTES) {
            return Err(DomainError::InvalidPredictionPositionSourceId);
        }
        if !bounded_opaque_value_is_valid(&source_version, MAX_PREDICTION_POSITION_IDENTIFIER_BYTES)
        {
            return Err(DomainError::InvalidPredictionPositionSourceVersion);
        }
        if !bounded_opaque_value_is_valid(
            &dependency_group_id,
            MAX_PREDICTION_POSITION_IDENTIFIER_BYTES,
        ) {
            return Err(DomainError::InvalidPredictionPositionDependencyGroupId);
        }

        Ok(Self {
            source_id,
            source_version,
            dependency_group_id,
            interval,
            prediction_evidence,
        })
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn source_version(&self) -> &str {
        &self.source_version
    }

    pub fn dependency_group_id(&self) -> &str {
        &self.dependency_group_id
    }

    pub fn interval(&self) -> &DecisionPredictionInterval {
        &self.interval
    }

    pub fn prediction_evidence(&self) -> &EvidenceSnapshotRef {
        &self.prediction_evidence
    }
}

impl TryFrom<DecisionPredictionPositionData> for DecisionPredictionPosition {
    type Error = DomainError;

    fn try_from(value: DecisionPredictionPositionData) -> Result<Self, Self::Error> {
        Self::try_new(
            value.source_id,
            value.source_version,
            value.dependency_group_id,
            value.interval,
            value.prediction_evidence,
        )
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
        Self::try_new_with_prediction_interval(
            id,
            cou_id,
            recommendation,
            ood_status,
            ood_detector,
            None,
            evidence,
            rationale,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_new_with_prediction_interval(
        id: Uuid,
        cou_id: String,
        recommendation: Recommendation,
        ood_status: OodStatus,
        ood_detector: Option<OodDetectorRef>,
        prediction_interval: Option<DecisionPredictionInterval>,
        evidence: EvidenceSnapshotRef,
        rationale: Vec<String>,
    ) -> Result<Self, DomainError> {
        Self::try_new_with_prediction_positions(
            id,
            cou_id,
            recommendation,
            ood_status,
            ood_detector,
            prediction_interval,
            Vec::new(),
            evidence,
            rationale,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_new_with_prediction_positions(
        id: Uuid,
        cou_id: String,
        recommendation: Recommendation,
        ood_status: OodStatus,
        ood_detector: Option<OodDetectorRef>,
        prediction_interval: Option<DecisionPredictionInterval>,
        prediction_positions: Vec<DecisionPredictionPosition>,
        evidence: EvidenceSnapshotRef,
        rationale: Vec<String>,
    ) -> Result<Self, DomainError> {
        let decision = Self {
            id,
            cou_id,
            recommendation,
            ood_status,
            ood_detector,
            prediction_interval,
            prediction_positions,
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

    pub fn prediction_interval(&self) -> Option<&DecisionPredictionInterval> {
        self.prediction_interval.as_ref()
    }

    pub fn prediction_positions(&self) -> &[DecisionPredictionPosition] {
        &self.prediction_positions
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
        if !self.prediction_positions.is_empty()
            && self.prediction_positions.len() < MIN_DECISION_PREDICTION_POSITIONS
        {
            return Err(DomainError::TooFewPredictionPositions);
        }
        if self.prediction_positions.len() > MAX_DECISION_PREDICTION_POSITIONS {
            return Err(DomainError::TooManyPredictionPositions);
        }
        if !self.prediction_positions.is_empty() && self.prediction_interval.is_none() {
            return Err(DomainError::MissingPredictionIntervalForPositions);
        }
        if let Some(decision_interval) = self.prediction_interval.as_ref() {
            for position in &self.prediction_positions {
                if position.interval.target != decision_interval.target {
                    return Err(DomainError::IncomparablePredictionPositionTarget);
                }
                if position.interval.unit != decision_interval.unit {
                    return Err(DomainError::IncomparablePredictionPositionUnit);
                }
                if position.interval.nominal_coverage_decimal
                    != decision_interval.nominal_coverage_decimal
                {
                    return Err(DomainError::IncomparablePredictionPositionNominalCoverage);
                }
            }
        }
        if self
            .prediction_positions
            .iter()
            .enumerate()
            .any(|(index, position)| {
                self.prediction_positions[index + 1..].iter().any(|other| {
                    position.source_id == other.source_id
                        && position.source_version == other.source_version
                })
            })
        {
            return Err(DomainError::DuplicatePredictionPositionSource);
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

fn canonical_decimal_is_valid(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_PREDICTION_INTERVAL_DECIMAL_BYTES {
        return false;
    }

    let bytes = value.as_bytes();
    let (negative, magnitude) = match bytes.first() {
        Some(b'-') => (true, &bytes[1..]),
        _ => (false, bytes),
    };
    if magnitude.is_empty() {
        return false;
    }

    let mut parts = magnitude.split(|byte| *byte == b'.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.iter().all(u8::is_ascii_digit)
        || (integer.len() > 1 && integer[0] == b'0')
    {
        return false;
    }

    match fraction {
        Some(fraction) => {
            !fraction.is_empty()
                && fraction.iter().all(u8::is_ascii_digit)
                && fraction.last() != Some(&b'0')
        }
        None => !(negative && integer == b"0"),
    }
}

fn compare_canonical_decimals(left: &str, right: &str) -> std::cmp::Ordering {
    let (left_negative, left_magnitude) = match left.strip_prefix('-') {
        Some(magnitude) => (true, magnitude),
        None => (false, left),
    };
    let (right_negative, right_magnitude) = match right.strip_prefix('-') {
        Some(magnitude) => (true, magnitude),
        None => (false, right),
    };

    match (left_negative, right_negative) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        (true, true) => compare_decimal_magnitudes(left_magnitude, right_magnitude).reverse(),
        (false, false) => compare_decimal_magnitudes(left_magnitude, right_magnitude),
    }
}

fn compare_decimal_magnitudes(left: &str, right: &str) -> std::cmp::Ordering {
    let (left_integer, left_fraction) = left.split_once('.').unwrap_or((left, ""));
    let (right_integer, right_fraction) = right.split_once('.').unwrap_or((right, ""));

    left_integer
        .len()
        .cmp(&right_integer.len())
        .then_with(|| left_integer.cmp(right_integer))
        .then_with(|| {
            let max_fraction_len = left_fraction.len().max(right_fraction.len());
            (0..max_fraction_len)
                .map(|index| {
                    let left_digit = left_fraction.as_bytes().get(index).copied().unwrap_or(b'0');
                    let right_digit = right_fraction
                        .as_bytes()
                        .get(index)
                        .copied()
                        .unwrap_or(b'0');
                    left_digit.cmp(&right_digit)
                })
                .find(|ordering| !ordering.is_eq())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

impl TryFrom<DecisionRecordData> for DecisionRecord {
    type Error = DomainError;

    fn try_from(value: DecisionRecordData) -> Result<Self, Self::Error> {
        Self::try_new_with_prediction_positions(
            value.id,
            value.cou_id,
            value.recommendation,
            value.ood_status,
            value.ood_detector,
            value.prediction_interval,
            value.prediction_positions,
            value.evidence,
            value.rationale,
        )
    }
}
