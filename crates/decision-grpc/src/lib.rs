#![deny(unsafe_code)]

use std::{error::Error, fmt, future::Future, pin::Pin};

use bioworld_contracts::{
    VersionedDecisionRecord, tenant_id_is_valid,
    v2::{DecisionRecord, GetDecisionRequest},
};
use bioworld_decision_query::{
    GetDecisionQuery, GetDecisionRequestError, GetDecisionRequestExecutionError,
};
use tonic::{Request, Response, Status};

mod service;

pub use service::{
    AuthenticateTenantError, AuthenticateTenantFuture, DecisionGrpcService,
    DecisionGrpcServiceConfig, InvalidDecisionGrpcServiceConfig, TenantAuthenticationContext,
    TenantAuthenticator,
};

pub struct TenantScope(Box<str>);

impl TenantScope {
    pub fn try_from_trusted_tenant_id(tenant_id: String) -> Result<Self, InvalidTenantScope> {
        if !tenant_id_is_valid(&tenant_id) {
            return Err(InvalidTenantScope);
        }

        Ok(Self(tenant_id.into_boxed_str()))
    }

    pub fn tenant_id(&self) -> &str {
        self.0.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTenantScope;

impl fmt::Display for InvalidTenantScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("tenant scope is invalid")
    }
}

impl Error for InvalidTenantScope {}

pub type TenantScopedGetDecisionFuture<'a> = Pin<
    Box<dyn Future<Output = Result<DecisionRecord, GetDecisionRequestExecutionError>> + Send + 'a>,
>;

pub trait TenantScopedGetDecisionExecutor: Send + Sync {
    fn execute_get_decision(
        &self,
        scope: TenantScope,
        query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_>;
}

pub async fn get_decision<E>(
    executor: &E,
    scope: TenantScope,
    request: Request<GetDecisionRequest>,
) -> Result<Response<DecisionRecord>, Status>
where
    E: TenantScopedGetDecisionExecutor + ?Sized,
{
    let query = match GetDecisionQuery::try_from(request.into_inner()) {
        Ok(query) => query,
        Err(GetDecisionRequestError::InvalidDecisionId) => {
            return Err(Status::invalid_argument("decision request is invalid"));
        }
    };

    let decision = executor
        .execute_get_decision(scope, query)
        .await
        .map_err(map_status)?;
    let boundary = VersionedDecisionRecord::try_from(decision)
        .map_err(|_| Status::unavailable("decision service is unavailable"))?;

    Ok(Response::new(DecisionRecord::from(&boundary)))
}

fn map_status(error: GetDecisionRequestExecutionError) -> Status {
    match error {
        GetDecisionRequestExecutionError::InvalidRequest => {
            Status::invalid_argument("decision request is invalid")
        }
        GetDecisionRequestExecutionError::NotFound => Status::not_found("decision was not found"),
        GetDecisionRequestExecutionError::SourceUnavailable
        | GetDecisionRequestExecutionError::StoredStateRejected => {
            Status::unavailable("decision service is unavailable")
        }
    }
}
