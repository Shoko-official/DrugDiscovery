use std::{
    error::Error, fmt, future::Future, num::NonZeroUsize, pin::Pin, sync::Arc, time::Duration,
};

use bioworld_contracts::v2::{
    DecisionEvent, DecisionRecord, GetDecisionRequest, ProposeDecisionRequest,
    WatchDecisionRequest,
    decision_service_server::{DecisionService, DecisionServiceServer},
};
use tokio::sync::Semaphore;
use tonic::{Extensions, Request, Response, Status, metadata::MetadataMap};

use crate::{TenantScope, TenantScopedGetDecisionExecutor, get_decision};

const MAX_IN_FLIGHT_REQUESTS: usize = 4_096;
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

pub struct TenantAuthenticationContext<'request> {
    metadata: &'request MetadataMap,
    extensions: &'request Extensions,
}

impl<'request> TenantAuthenticationContext<'request> {
    pub fn metadata(&self) -> &'request MetadataMap {
        self.metadata
    }

    pub fn extensions(&self) -> &'request Extensions {
        self.extensions
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
/// Fixed, redacted failure returned by tenant authentication adapters.
pub struct AuthenticateTenantError {
    kind: AuthenticateTenantErrorKind,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AuthenticateTenantErrorKind {
    Rejected,
    CapacityExhausted,
    Unavailable,
}

impl AuthenticateTenantError {
    /// Reports invalid, missing, or rejected credentials.
    pub const fn rejected() -> Self {
        Self {
            kind: AuthenticateTenantErrorKind::Rejected,
        }
    }

    /// Reports that bounded authentication capacity is currently exhausted.
    pub const fn capacity_exhausted() -> Self {
        Self {
            kind: AuthenticateTenantErrorKind::CapacityExhausted,
        }
    }

    /// Reports that authentication infrastructure is unavailable.
    pub const fn unavailable() -> Self {
        Self {
            kind: AuthenticateTenantErrorKind::Unavailable,
        }
    }

    fn status(self) -> Status {
        match self.kind {
            AuthenticateTenantErrorKind::Rejected => {
                Status::unauthenticated("authentication is required")
            }
            AuthenticateTenantErrorKind::CapacityExhausted => {
                Status::resource_exhausted("authentication service is at capacity")
            }
            AuthenticateTenantErrorKind::Unavailable => {
                Status::unavailable("authentication service is unavailable")
            }
        }
    }
}

impl fmt::Debug for AuthenticateTenantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticateTenantError")
    }
}

impl fmt::Display for AuthenticateTenantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("tenant authentication failed")
    }
}

impl Error for AuthenticateTenantError {}

pub type AuthenticateTenantFuture<'a> =
    Pin<Box<dyn Future<Output = Result<String, AuthenticateTenantError>> + Send + 'a>>;

/// Authenticates a request and returns the tenant bound to its verified principal.
///
/// Implementations must derive the tenant from a successfully verified identity.
/// Client-provided tenant selectors in metadata or messages must never establish or
/// override tenant authority. The method must return without blocking, and the
/// returned future must be cancellation-safe because the service can drop it when
/// the request deadline expires or the client disconnects.
pub trait TenantAuthenticator: Send + Sync {
    fn authenticate_tenant<'a>(
        &'a self,
        context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionGrpcServiceConfig {
    max_in_flight: NonZeroUsize,
    request_timeout: Duration,
}

impl DecisionGrpcServiceConfig {
    pub fn try_new(
        max_in_flight: usize,
        request_timeout: Duration,
    ) -> Result<Self, InvalidDecisionGrpcServiceConfig> {
        let max_in_flight =
            NonZeroUsize::new(max_in_flight).ok_or(InvalidDecisionGrpcServiceConfig)?;
        if max_in_flight.get() > MAX_IN_FLIGHT_REQUESTS
            || request_timeout.is_zero()
            || request_timeout > MAX_REQUEST_TIMEOUT
        {
            return Err(InvalidDecisionGrpcServiceConfig);
        }

        Ok(Self {
            max_in_flight,
            request_timeout,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDecisionGrpcServiceConfig;

impl fmt::Display for InvalidDecisionGrpcServiceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("gRPC decision service configuration is invalid")
    }
}

impl Error for InvalidDecisionGrpcServiceConfig {}

pub struct DecisionGrpcService<A, E> {
    authenticator: A,
    executor: E,
    admission: Arc<Semaphore>,
    request_timeout: Duration,
}

impl<A, E> DecisionGrpcService<A, E> {
    pub fn new(authenticator: A, executor: E, config: DecisionGrpcServiceConfig) -> Self {
        Self {
            authenticator,
            executor,
            admission: Arc::new(Semaphore::new(config.max_in_flight.get())),
            request_timeout: config.request_timeout,
        }
    }

    pub fn into_server(self) -> DecisionServiceServer<Self> {
        DecisionServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl<A, E> DecisionService for DecisionGrpcService<A, E>
where
    A: TenantAuthenticator + 'static,
    E: TenantScopedGetDecisionExecutor + 'static,
{
    async fn get_decision(
        &self,
        request: Request<GetDecisionRequest>,
    ) -> Result<Response<DecisionRecord>, Status> {
        let _permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("decision service is at capacity"))?;
        tokio::time::timeout(self.request_timeout, async {
            let tenant_id = self
                .authenticator
                .authenticate_tenant(TenantAuthenticationContext {
                    metadata: request.metadata(),
                    extensions: request.extensions(),
                })
                .await
                .map_err(AuthenticateTenantError::status)?;
            let scope = TenantScope::try_from_trusted_tenant_id(tenant_id)
                .map_err(|_| Status::unauthenticated("authentication is required"))?;

            get_decision(&self.executor, scope, request).await
        })
        .await
        .map_err(|_| Status::deadline_exceeded("decision request deadline exceeded"))?
    }

    async fn propose_decision(
        &self,
        _request: Request<ProposeDecisionRequest>,
    ) -> Result<Response<DecisionRecord>, Status> {
        Err(Status::unimplemented(
            "decision operation is not implemented",
        ))
    }

    type WatchDecisionStream = tonic::codegen::BoxStream<DecisionEvent>;

    async fn watch_decision(
        &self,
        _request: Request<WatchDecisionRequest>,
    ) -> Result<Response<Self::WatchDecisionStream>, Status> {
        Err(Status::unimplemented(
            "decision operation is not implemented",
        ))
    }
}
