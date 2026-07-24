#![deny(unsafe_code)]

use std::{future::Future, pin::Pin};

use bioworld_contracts::{VersionedDecisionRecord, v2};
use thiserror::Error;
use uuid::Uuid;

fn parse_canonical_decision_id(value: &str) -> Option<Uuid> {
    let decision_id = Uuid::parse_str(value).ok()?;
    (decision_id.to_string() == value).then_some(decision_id)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WatchDecisionQuery {
    decision_id: Uuid,
}

impl WatchDecisionQuery {
    pub fn new(decision_id: Uuid) -> Self {
        Self { decision_id }
    }

    pub fn decision_id(self) -> Uuid {
        self.decision_id
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum WatchDecisionRequestError {
    #[error("watch decision request identifier is invalid")]
    InvalidDecisionId,
}

impl TryFrom<v2::WatchDecisionRequest> for WatchDecisionQuery {
    type Error = WatchDecisionRequestError;

    fn try_from(request: v2::WatchDecisionRequest) -> Result<Self, Self::Error> {
        let decision_id = parse_canonical_decision_id(&request.decision_id)
            .ok_or(WatchDecisionRequestError::InvalidDecisionId)?;

        Ok(Self::new(decision_id))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GetDecisionQuery {
    decision_id: Uuid,
}

impl GetDecisionQuery {
    pub fn new(decision_id: Uuid) -> Self {
        Self { decision_id }
    }

    pub fn decision_id(self) -> Uuid {
        self.decision_id
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum GetDecisionRequestError {
    #[error("decision request identifier is invalid")]
    InvalidDecisionId,
}

impl TryFrom<v2::GetDecisionRequest> for GetDecisionQuery {
    type Error = GetDecisionRequestError;

    fn try_from(request: v2::GetDecisionRequest) -> Result<Self, Self::Error> {
        let decision_id = parse_canonical_decision_id(&request.decision_id)
            .ok_or(GetDecisionRequestError::InvalidDecisionId)?;

        Ok(Self::new(decision_id))
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum LatestDecisionSourceError {
    #[error("latest decision source is unavailable")]
    Unavailable,
    #[error("latest decision source rejected stored state")]
    StoredStateRejected,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum GetDecisionError {
    #[error("decision source is unavailable")]
    SourceUnavailable,
    #[error("stored decision state was rejected")]
    StoredStateRejected,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum GetDecisionRequestExecutionError {
    #[error("decision request is invalid")]
    InvalidRequest,
    #[error("decision was not found")]
    NotFound,
    #[error("decision source is unavailable")]
    SourceUnavailable,
    #[error("stored decision state was rejected")]
    StoredStateRejected,
}

pub type LatestDecisionFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<Option<v2::DecisionRecord>, LatestDecisionSourceError>>
            + Send
            + 'a,
    >,
>;

pub trait LatestDecisionSource: Send {
    fn read_latest(&mut self, query: GetDecisionQuery) -> LatestDecisionFuture<'_>;
}

pub struct GetDecision<S> {
    source: S,
}

impl<S> GetDecision<S>
where
    S: LatestDecisionSource,
{
    pub fn new(source: S) -> Self {
        Self { source }
    }

    pub async fn execute_request(
        &mut self,
        request: v2::GetDecisionRequest,
    ) -> Result<v2::DecisionRecord, GetDecisionRequestExecutionError> {
        let query = match GetDecisionQuery::try_from(request) {
            Ok(query) => query,
            Err(GetDecisionRequestError::InvalidDecisionId) => {
                return Err(GetDecisionRequestExecutionError::InvalidRequest);
            }
        };

        self.execute_validated(query).await
    }

    pub async fn execute_validated(
        &mut self,
        query: GetDecisionQuery,
    ) -> Result<v2::DecisionRecord, GetDecisionRequestExecutionError> {
        let decision = match self.execute(query).await {
            Ok(Some(decision)) => decision,
            Ok(None) => return Err(GetDecisionRequestExecutionError::NotFound),
            Err(GetDecisionError::SourceUnavailable) => {
                return Err(GetDecisionRequestExecutionError::SourceUnavailable);
            }
            Err(GetDecisionError::StoredStateRejected) => {
                return Err(GetDecisionRequestExecutionError::StoredStateRejected);
            }
        };

        Ok(v2::DecisionRecord::from(&decision))
    }

    pub async fn execute(
        &mut self,
        query: GetDecisionQuery,
    ) -> Result<Option<VersionedDecisionRecord>, GetDecisionError> {
        let expected_decision_id = query.decision_id().to_string();
        let record = match self.source.read_latest(query).await {
            Ok(record) => record,
            Err(LatestDecisionSourceError::Unavailable) => {
                return Err(GetDecisionError::SourceUnavailable);
            }
            Err(LatestDecisionSourceError::StoredStateRejected) => {
                return Err(GetDecisionError::StoredStateRejected);
            }
        };
        let Some(record) = record else {
            return Ok(None);
        };
        if record.decision_id != expected_decision_id {
            return Err(GetDecisionError::StoredStateRejected);
        }
        let decision = VersionedDecisionRecord::try_from(record)
            .map_err(|_| GetDecisionError::StoredStateRejected)?;

        Ok(Some(decision))
    }
}
