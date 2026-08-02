use std::{
    error::Error, fmt, future::Future, num::NonZeroUsize, pin::Pin, sync::Arc, time::Duration,
};

use bioworld_contracts::{
    MAX_DECISION_WIRE_BYTES,
    v2::{
        DecisionEvent, DecisionRecord, GetDecisionRequest, ProposeDecisionRequest,
        WatchDecisionRequest,
        decision_service_server::{DecisionService, DecisionServiceServer},
    },
};
use bioworld_decision_query::{DecisionReplaySource, WatchDecisionQuery};
use tokio::{sync::Semaphore, time::Instant};
use tonic::{Extensions, Request, Response, Status, metadata::MetadataMap};

use crate::{
    TenantScope, TenantScopedGetDecisionExecutor, TenantScopedWatchDecisionExecutor, get_decision,
    watch_runtime::{DecisionGrpcWatchRuntime, WorkerDeadline, watch_encoding_limit},
};

/// Hard ceiling for admitted decision RPCs across one service instance.
pub const MAX_DECISION_GRPC_IN_FLIGHT_REQUESTS: usize = 4_096;
/// Hard ceiling for supervised WatchDecision sessions across one service instance.
pub const MAX_DECISION_GRPC_WATCH_IN_FLIGHT_REQUESTS: usize = 256;
/// Hard ceiling for one authenticated decision RPC.
pub const MAX_DECISION_GRPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
/// Stable public message for an expired decision RPC.
pub const DECISION_GRPC_REQUEST_DEADLINE_MESSAGE: &str = "decision request deadline exceeded";

pub struct TenantAuthenticationContext<'request> {
    metadata: &'request MetadataMap,
    extensions: &'request Extensions,
}

/// Verified tenant scope paired with its absolute monotonic authority boundary.
pub struct TenantAuthority {
    scope: TenantScope,
    valid_until: Instant,
}

impl TenantAuthority {
    /// Constructs authority from a verified tenant identifier and future deadline.
    pub fn try_new(
        tenant_id: String,
        valid_until: Instant,
    ) -> Result<Self, InvalidTenantAuthority> {
        if valid_until <= Instant::now() {
            return Err(InvalidTenantAuthority);
        }
        let scope = TenantScope::try_from_trusted_tenant_id(tenant_id)
            .map_err(|_| InvalidTenantAuthority)?;

        Ok(Self { scope, valid_until })
    }

    fn into_parts(self) -> (TenantScope, Instant) {
        (self.scope, self.valid_until)
    }
}

impl fmt::Debug for TenantAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TenantAuthority")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTenantAuthority;

impl fmt::Display for InvalidTenantAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("tenant authority is invalid")
    }
}

impl Error for InvalidTenantAuthority {}

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
    Pin<Box<dyn Future<Output = Result<TenantAuthority, AuthenticateTenantError>> + Send + 'a>>;

/// Authenticates a request and returns bounded authority for its verified principal.
///
/// Implementations must derive the tenant from a successfully verified identity.
/// Client-provided tenant selectors in metadata or messages must never establish or
/// override tenant authority. The method must return without blocking, and the
/// returned authority must not outlive any credential or verification-key boundary.
/// The future must be cancellation-safe because the service can drop it when the
/// request deadline expires or the client disconnects.
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
        if max_in_flight.get() > MAX_DECISION_GRPC_IN_FLIGHT_REQUESTS
            || request_timeout.is_zero()
            || request_timeout > MAX_DECISION_GRPC_REQUEST_TIMEOUT
        {
            return Err(InvalidDecisionGrpcServiceConfig);
        }

        Ok(Self {
            max_in_flight,
            request_timeout,
        })
    }

    pub const fn max_in_flight(self) -> usize {
        self.max_in_flight.get()
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionGrpcWatchConfig {
    max_in_flight: NonZeroUsize,
    max_in_flight_per_tenant: NonZeroUsize,
}

impl DecisionGrpcWatchConfig {
    pub fn try_new(
        max_in_flight: usize,
        max_in_flight_per_tenant: usize,
    ) -> Result<Self, InvalidDecisionGrpcWatchConfig> {
        let max_in_flight =
            NonZeroUsize::new(max_in_flight).ok_or(InvalidDecisionGrpcWatchConfig)?;
        let max_in_flight_per_tenant =
            NonZeroUsize::new(max_in_flight_per_tenant).ok_or(InvalidDecisionGrpcWatchConfig)?;
        if max_in_flight.get() > MAX_DECISION_GRPC_WATCH_IN_FLIGHT_REQUESTS
            || max_in_flight_per_tenant > max_in_flight
        {
            return Err(InvalidDecisionGrpcWatchConfig);
        }

        Ok(Self {
            max_in_flight,
            max_in_flight_per_tenant,
        })
    }

    pub fn validate_for_service(
        self,
        service: DecisionGrpcServiceConfig,
    ) -> Result<Self, InvalidDecisionGrpcWatchConfig> {
        if self.max_in_flight.get() >= service.max_in_flight() {
            return Err(InvalidDecisionGrpcWatchConfig);
        }
        Ok(self)
    }

    pub const fn max_in_flight(self) -> usize {
        self.max_in_flight.get()
    }

    pub const fn max_in_flight_per_tenant(self) -> usize {
        self.max_in_flight_per_tenant.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDecisionGrpcWatchConfig;

impl fmt::Display for InvalidDecisionGrpcWatchConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("gRPC decision Watch configuration is invalid")
    }
}

impl Error for InvalidDecisionGrpcWatchConfig {}

pub struct DecisionGrpcService<A, E> {
    authenticator: A,
    executor: Arc<E>,
    admission: Arc<Semaphore>,
    request_timeout: Duration,
    watch: Option<DecisionGrpcWatchRuntime>,
}

impl<A, E> DecisionGrpcService<A, E> {
    pub fn new(authenticator: A, executor: E, config: DecisionGrpcServiceConfig) -> Self {
        Self {
            authenticator,
            executor: Arc::new(executor),
            admission: Arc::new(Semaphore::new(config.max_in_flight.get())),
            request_timeout: config.request_timeout,
            watch: None,
        }
    }

    pub fn into_server(self) -> DecisionServiceServer<Self> {
        let max_encoding_message_size = if self.watch.is_some() {
            watch_encoding_limit()
        } else {
            MAX_DECISION_WIRE_BYTES
        };
        DecisionServiceServer::new(self)
            .max_decoding_message_size(MAX_DECISION_WIRE_BYTES)
            .max_encoding_message_size(max_encoding_message_size)
    }

    /// Returns the fixed request deadline enforced by this service instance.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub fn watch_lifecycle(&self) -> Option<crate::DecisionGrpcWatchLifecycle> {
        self.watch.as_ref().map(DecisionGrpcWatchRuntime::lifecycle)
    }
}

impl<A, E> DecisionGrpcService<A, E>
where
    E: TenantScopedWatchDecisionExecutor + 'static,
    <E::Source as DecisionReplaySource>::Continuation: 'static,
{
    pub fn try_new_with_watch(
        authenticator: A,
        executor: E,
        service_config: DecisionGrpcServiceConfig,
        watch_config: DecisionGrpcWatchConfig,
    ) -> Result<Self, InvalidDecisionGrpcWatchConfig> {
        let watch_config = watch_config.validate_for_service(service_config)?;
        let executor = Arc::new(executor);
        let watch = DecisionGrpcWatchRuntime::new(Arc::clone(&executor), watch_config);
        Ok(Self {
            authenticator,
            executor,
            admission: Arc::new(Semaphore::new(service_config.max_in_flight.get())),
            request_timeout: service_config.request_timeout,
            watch: Some(watch),
        })
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
        let service_deadline = Instant::now() + self.request_timeout;
        let authority = {
            let authentication =
                self.authenticator
                    .authenticate_tenant(TenantAuthenticationContext {
                        metadata: request.metadata(),
                        extensions: request.extensions(),
                    });
            tokio::pin!(authentication);
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(service_deadline) => {
                    return Err(Status::deadline_exceeded(DECISION_GRPC_REQUEST_DEADLINE_MESSAGE));
                }
                result = &mut authentication => {
                    result.map_err(AuthenticateTenantError::status)?
                }
            }
        };
        let (scope, authority_deadline) = authority.into_parts();
        let execution = get_decision(self.executor.as_ref(), scope, request);
        tokio::pin!(execution);
        if authority_deadline < service_deadline {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(authority_deadline) => {
                    Err(Status::unauthenticated("authentication is required"))
                }
                result = &mut execution => result,
            }
        } else {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(service_deadline) => {
                    Err(Status::deadline_exceeded(DECISION_GRPC_REQUEST_DEADLINE_MESSAGE))
                }
                result = &mut execution => result,
            }
        }
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
        request: Request<WatchDecisionRequest>,
    ) -> Result<Response<Self::WatchDecisionStream>, Status> {
        let Some(watch) = self.watch.as_ref() else {
            return Err(Status::unimplemented(
                "decision operation is not implemented",
            ));
        };
        if watch.is_cancelled() {
            return Err(Status::unavailable("decision service is unavailable"));
        }

        let global_permit = watch.try_acquire_global()?;
        let service_permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("decision service is at capacity"))?;
        let service_deadline = Instant::now() + self.request_timeout;
        let authority = {
            let authentication =
                self.authenticator
                    .authenticate_tenant(TenantAuthenticationContext {
                        metadata: request.metadata(),
                        extensions: request.extensions(),
                    });
            tokio::pin!(authentication);
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(service_deadline) => {
                    return Err(Status::deadline_exceeded(DECISION_GRPC_REQUEST_DEADLINE_MESSAGE));
                }
                _ = watch.cancelled() => {
                    return Err(Status::unavailable("decision service is unavailable"));
                }
                result = &mut authentication => {
                    result.map_err(AuthenticateTenantError::status)?
                }
            }
        };
        let (scope, authority_deadline) = authority.into_parts();
        let query = WatchDecisionQuery::try_from(request.into_inner())
            .map_err(|_| Status::invalid_argument("decision request is invalid"))?;
        let tenant_permit = watch.try_acquire_tenant(scope.tenant_id())?;
        let deadline = WorkerDeadline::select(service_deadline, authority_deadline);
        let stream = watch.start(
            scope,
            query,
            deadline,
            service_permit,
            global_permit,
            tenant_permit,
        )?;
        Ok(Response::new(stream))
    }
}
