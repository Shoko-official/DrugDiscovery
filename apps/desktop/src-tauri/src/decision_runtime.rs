use std::sync::Arc;

use bioworld_contracts::v2;
#[cfg(test)]
pub(crate) use bioworld_desktop_core::DecisionRuntimeError;
pub(crate) use bioworld_desktop_core::{
    CurrentDecisionSource, DecisionProvenance, DecisionReadFuture, DecisionRuntime, SourcedDecision,
};

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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
    }
}
