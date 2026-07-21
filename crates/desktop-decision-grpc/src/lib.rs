#![deny(unsafe_code)]

use std::{future::Future, pin::Pin};

use bioworld_contracts::{VersionedDecisionRecord, v2};
use bioworld_decision_grpc_client::{
    AccessTokenProvider, DecisionGrpcClient, DecisionGrpcClientError,
};
use bioworld_decision_query::GetDecisionQuery;
use bioworld_desktop_core::{
    CurrentDecisionSource, DecisionProvenance, DecisionReadFuture, DecisionRuntimeError,
    SourcedDecision,
};
use thiserror::Error;

type DecisionServiceReadFuture<'a> = Pin<
    Box<dyn Future<Output = Result<VersionedDecisionRecord, DecisionGrpcClientError>> + Send + 'a>,
>;

trait DecisionServiceReader: Send + Sync {
    fn get_decision<'a>(&'a self, decision_id: &'a str) -> DecisionServiceReadFuture<'a>;
}

impl<P> DecisionServiceReader for DecisionGrpcClient<P>
where
    P: AccessTokenProvider,
{
    fn get_decision<'a>(&'a self, decision_id: &'a str) -> DecisionServiceReadFuture<'a> {
        Box::pin(DecisionGrpcClient::get_decision(self, decision_id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("decision service source configuration is invalid")]
pub struct InvalidDecisionServiceSource;

struct DecisionSourceAdapter<R> {
    reader: R,
    decision_id: String,
}

impl<R> DecisionSourceAdapter<R>
where
    R: DecisionServiceReader,
{
    fn try_new(reader: R, decision_id: &str) -> Result<Self, InvalidDecisionServiceSource> {
        let query = GetDecisionQuery::try_from(v2::GetDecisionRequest {
            decision_id: decision_id.to_owned(),
        })
        .map_err(|_| InvalidDecisionServiceSource)?;

        Ok(Self {
            reader,
            decision_id: query.decision_id().to_string(),
        })
    }
}

impl<R> CurrentDecisionSource for DecisionSourceAdapter<R>
where
    R: DecisionServiceReader,
{
    fn read_current_decision(&self) -> DecisionReadFuture<'_> {
        Box::pin(async move {
            match self.reader.get_decision(&self.decision_id).await {
                Ok(record) => {
                    if record.decision().id().to_string() != self.decision_id {
                        return Err(DecisionRuntimeError::InvalidResponse);
                    }
                    Ok(Some(SourcedDecision::new(
                        v2::DecisionRecord::from(&record),
                        DecisionProvenance::DecisionService,
                    )))
                }
                Err(DecisionGrpcClientError::NotFound) => Ok(None),
                Err(
                    DecisionGrpcClientError::InvalidConfiguration
                    | DecisionGrpcClientError::Unavailable,
                ) => Err(DecisionRuntimeError::Unavailable),
                Err(DecisionGrpcClientError::InvalidDecisionId) => {
                    Err(DecisionRuntimeError::InvalidResponse)
                }
                Err(DecisionGrpcClientError::AuthenticationUnavailable) => {
                    Err(DecisionRuntimeError::AuthenticationUnavailable)
                }
                Err(DecisionGrpcClientError::CapacityExhausted) => {
                    Err(DecisionRuntimeError::CapacityExhausted)
                }
                Err(DecisionGrpcClientError::Unauthenticated) => {
                    Err(DecisionRuntimeError::AuthenticationRejected)
                }
                Err(DecisionGrpcClientError::PermissionDenied) => {
                    Err(DecisionRuntimeError::AccessDenied)
                }
                Err(DecisionGrpcClientError::DeadlineExceeded) => {
                    Err(DecisionRuntimeError::DeadlineExceeded)
                }
                Err(DecisionGrpcClientError::InvalidResponse) => {
                    Err(DecisionRuntimeError::InvalidResponse)
                }
            }
        })
    }
}

pub struct DecisionServiceSource<P> {
    adapter: DecisionSourceAdapter<DecisionGrpcClient<P>>,
}

impl<P> DecisionServiceSource<P>
where
    P: AccessTokenProvider,
{
    pub fn try_new(
        client: DecisionGrpcClient<P>,
        decision_id: &str,
    ) -> Result<Self, InvalidDecisionServiceSource> {
        Ok(Self {
            adapter: DecisionSourceAdapter::try_new(client, decision_id)?,
        })
    }
}

impl<P> CurrentDecisionSource for DecisionServiceSource<P>
where
    P: AccessTokenProvider,
{
    fn read_current_decision(&self) -> DecisionReadFuture<'_> {
        self.adapter.read_current_decision()
    }
}

#[cfg(test)]
mod tests;
