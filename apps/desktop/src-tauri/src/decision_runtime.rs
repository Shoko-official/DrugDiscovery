use std::{future::Future, pin::Pin, sync::Arc};

use bioworld_contracts::v2;

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecisionProvenance {
    BundledSample,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SourcedDecision {
    record: v2::DecisionRecord,
    provenance: DecisionProvenance,
}

impl SourcedDecision {
    pub(crate) fn new(record: v2::DecisionRecord, provenance: DecisionProvenance) -> Self {
        Self { record, provenance }
    }

    pub(crate) fn into_parts(self) -> (v2::DecisionRecord, DecisionProvenance) {
        (self.record, self.provenance)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecisionRuntimeError;

pub(crate) type DecisionReadFuture<'a> = Pin<
    Box<dyn Future<Output = Result<Option<SourcedDecision>, DecisionRuntimeError>> + Send + 'a>,
>;

pub(crate) trait CurrentDecisionSource: Send + Sync {
    fn read_current_decision(&self) -> DecisionReadFuture<'_>;
}

#[derive(Clone)]
pub(crate) struct DecisionRuntime {
    source: Arc<dyn CurrentDecisionSource>,
}

impl DecisionRuntime {
    pub(crate) fn from_source(source: Arc<dyn CurrentDecisionSource>) -> Self {
        Self { source }
    }

    pub(crate) fn bundled() -> Self {
        Self::from_source(Arc::new(BundledDecisionSource))
    }

    pub(crate) async fn read_current_decision(
        &self,
    ) -> Result<Option<SourcedDecision>, DecisionRuntimeError> {
        self.source.read_current_decision().await
    }
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
