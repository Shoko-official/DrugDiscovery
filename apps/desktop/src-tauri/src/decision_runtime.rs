use std::sync::Arc;

use bioworld_contracts::v2;
pub(crate) use bioworld_desktop_core::{
    CurrentDecisionSource, DecisionProvenance, DecisionReadFuture, DecisionRuntime,
    DecisionRuntimeError, SourcedDecision,
};

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn prediction_interval(lower_decimal: &str, upper_decimal: &str) -> v2::DecisionPredictionInterval {
    v2::DecisionPredictionInterval {
        target: "binding_affinity".to_owned(),
        unit: "nM".to_owned(),
        lower_decimal: lower_decimal.to_owned(),
        upper_decimal: upper_decimal.to_owned(),
        nominal_coverage_decimal: "0.95".to_owned(),
        interval_method_id: "split_conformal".to_owned(),
        interval_method_version: "1.0".to_owned(),
        calibration_method_id: "held_out_calibration".to_owned(),
        calibration_method_version: "2026.07".to_owned(),
        calibration_evidence: Some(v2::EvidenceSnapshotRef {
            id: "ES-CAL-001".to_owned(),
            sha256: VALID_SHA256.to_owned(),
        }),
    }
}

fn prediction_positions() -> Vec<v2::DecisionPredictionPosition> {
    [
        (
            "model-z",
            "2026.07",
            "shared-training-set",
            "0.4",
            "1.4",
            "ES-PRED-Z",
        ),
        (
            "model-a",
            "2026.06",
            "independent-assay",
            "0.2",
            "1.2",
            "ES-PRED-A",
        ),
    ]
    .into_iter()
    .map(
        |(source_id, source_version, dependency_group_id, lower, upper, evidence_id)| {
            v2::DecisionPredictionPosition {
                source_id: source_id.to_owned(),
                source_version: source_version.to_owned(),
                dependency_group_id: dependency_group_id.to_owned(),
                interval: Some(prediction_interval(lower, upper)),
                prediction_evidence: Some(v2::EvidenceSnapshotRef {
                    id: evidence_id.to_owned(),
                    sha256: VALID_SHA256.to_owned(),
                }),
            }
        },
    )
    .collect()
}

struct BundledDecisionSource;

impl CurrentDecisionSource for BundledDecisionSource {
    fn read_current_decision(&self) -> DecisionReadFuture<'_> {
        Box::pin(async {
            Ok(Some(SourcedDecision::new(
                bundled_decision_record(),
                DecisionProvenance::BundledSample,
            )))
        })
    }
}

pub(crate) fn bundled_runtime() -> DecisionRuntime {
    DecisionRuntime::from_source(Arc::new(BundledDecisionSource))
}

#[allow(deprecated)]
pub(crate) fn bundled_decision_record() -> v2::DecisionRecord {
    v2::DecisionRecord {
        decision_id: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99".to_owned(),
        cou_id: "COU-001".to_owned(),
        evidence_snapshot_id: "ES-001".to_owned(),
        recommendation: v2::Recommendation::Abstain as i32,
        rationale: vec!["Evidence coverage is incomplete.".to_owned()],
        aggregate_version: 1,
        evidence: Some(v2::EvidenceSnapshotRef {
            id: "ES-001".to_owned(),
            sha256: VALID_SHA256.to_owned(),
        }),
        ood_status: Some(v2::OodStatus::InDomain as i32),
        ood_detector: Some(v2::OodDetectorRef {
            detector_id: "mahalanobis".to_owned(),
            detector_version: "model-2026.07".to_owned(),
        }),
        prediction_interval: Some(prediction_interval("0.25", "1.5")),
        prediction_positions: prediction_positions(),
        decision_criterion: Some(v2::DecisionCriterion {
            criterion_id: "potency_policy".to_owned(),
            criterion_version: "2026.07".to_owned(),
            comparator: v2::DecisionCriterionComparator::LessThanOrEqual as i32,
            threshold_decimal: "0.75".to_owned(),
            criterion_evidence: Some(v2::EvidenceSnapshotRef {
                id: "ES-CRITERION-001".to_owned(),
                sha256: VALID_SHA256.to_owned(),
            }),
        }),
    }
}
