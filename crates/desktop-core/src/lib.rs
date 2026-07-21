#![deny(unsafe_code)]

use std::{future::Future, pin::Pin, sync::Arc};

use bioworld_contracts::v2;
use bioworld_domain::DecisionRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionProvenance {
    BundledSample,
    DecisionService,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SourcedDecision {
    record: v2::DecisionRecord,
    provenance: DecisionProvenance,
}

impl SourcedDecision {
    pub fn new(record: v2::DecisionRecord, provenance: DecisionProvenance) -> Self {
        Self { record, provenance }
    }

    pub fn into_parts(self) -> (v2::DecisionRecord, DecisionProvenance) {
        (self.record, self.provenance)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecisionRuntimeError {
    #[error("decision runtime authentication is unavailable")]
    AuthenticationUnavailable,
    #[error("decision runtime authentication was rejected")]
    AuthenticationRejected,
    #[error("decision runtime access was denied")]
    AccessDenied,
    #[error("decision runtime capacity is exhausted")]
    CapacityExhausted,
    #[error("decision runtime deadline exceeded")]
    DeadlineExceeded,
    #[error("decision runtime is unavailable")]
    Unavailable,
    #[error("decision runtime response is invalid")]
    InvalidResponse,
}

pub type DecisionReadFuture<'a> = Pin<
    Box<dyn Future<Output = Result<Option<SourcedDecision>, DecisionRuntimeError>> + Send + 'a>,
>;

pub trait CurrentDecisionSource: Send + Sync {
    fn read_current_decision(&self) -> DecisionReadFuture<'_>;
}

#[derive(Clone)]
pub struct DecisionRuntime {
    source: Arc<dyn CurrentDecisionSource>,
}

impl DecisionRuntime {
    pub fn from_source(source: Arc<dyn CurrentDecisionSource>) -> Self {
        Self { source }
    }

    pub async fn read_current_decision(
        &self,
    ) -> Result<Option<SourcedDecision>, DecisionRuntimeError> {
        self.source.read_current_decision().await
    }
}

pub trait DecisionRepository: Send + Sync {
    fn save_draft(&self, decision: &DecisionRecord) -> Result<(), RepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("concurrent version conflict")]
    Conflict,
    #[error("storage unavailable")]
    Unavailable,
}
