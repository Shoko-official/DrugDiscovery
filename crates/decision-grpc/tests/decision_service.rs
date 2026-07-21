use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bioworld_contracts::v2::{
    DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest, ProposeDecisionRequest,
    Recommendation, WatchDecisionRequest,
    decision_service_server::DecisionService as GeneratedDecisionService,
};
use bioworld_decision_grpc::{
    AuthenticateTenantError, AuthenticateTenantFuture, DecisionGrpcService,
    DecisionGrpcServiceConfig, InvalidDecisionGrpcServiceConfig, TenantAuthenticationContext,
    TenantAuthenticator, TenantScope, TenantScopedGetDecisionExecutor,
    TenantScopedGetDecisionFuture,
};
use bioworld_decision_query::{GetDecisionQuery, GetDecisionRequestExecutionError};
use tokio::sync::Notify;
use tonic::{Code, Request, Status};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";

#[test]
fn rejects_unsafe_service_configuration_with_a_fixed_error() {
    for (max_in_flight, request_timeout) in [
        (0, Duration::from_secs(1)),
        (usize::MAX, Duration::from_secs(1)),
        (1, Duration::ZERO),
        (1, Duration::MAX),
    ] {
        assert_eq!(
            DecisionGrpcServiceConfig::try_new(max_in_flight, request_timeout),
            Err(InvalidDecisionGrpcServiceConfig)
        );
    }

    let error = InvalidDecisionGrpcServiceConfig;
    assert_eq!(format!("{error:?}"), "InvalidDecisionGrpcServiceConfig");
    assert_eq!(
        error.to_string(),
        "gRPC decision service configuration is invalid"
    );

    fn assert_error<T: std::error::Error + Send + Sync + Copy>(_: T) {}
    assert_error(error);

    assert!(DecisionGrpcServiceConfig::try_new(4_096, Duration::from_secs(300)).is_ok());
    assert_eq!(
        DecisionGrpcServiceConfig::try_new(4_097, Duration::from_secs(1)),
        Err(InvalidDecisionGrpcServiceConfig)
    );
    assert_eq!(
        DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(301)),
        Err(InvalidDecisionGrpcServiceConfig)
    );
}

#[test]
fn authentication_error_is_fixed_and_thread_safe() {
    for error in [
        AuthenticateTenantError::rejected(),
        AuthenticateTenantError::capacity_exhausted(),
        AuthenticateTenantError::unavailable(),
    ] {
        assert_eq!(format!("{error:?}"), "AuthenticateTenantError");
        assert_eq!(error.to_string(), "tenant authentication failed");

        fn assert_error<T: std::error::Error + Send + Sync + Copy>(_: T) {}
        assert_error(error);
    }
}

#[test]
fn generated_server_is_constructible_and_thread_safe() {
    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    let observed = Arc::new(Mutex::new(Vec::new()));
    let service = DecisionGrpcService::new(
        StaticAuthenticator,
        RecordingExecutor {
            observed,
            response: record(),
        },
        DecisionGrpcServiceConfig::try_new(2, Duration::from_secs(1)).unwrap(),
    );

    let server = service.into_server();

    assert_send_sync(&server);
}

struct StaticAuthenticator;

impl TenantAuthenticator for StaticAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        Box::pin(async { Ok("trusted-tenant".to_owned()) })
    }
}

struct RejectingAuthenticator {
    calls: Arc<AtomicUsize>,
}

struct ErrorAuthenticator(AuthenticateTenantError);

impl TenantAuthenticator for ErrorAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        let error = self.0;
        Box::pin(async move { Err(error) })
    }
}

struct CountingAuthenticator {
    calls: Arc<AtomicUsize>,
    tenant_id: &'static str,
}

impl TenantAuthenticator for CountingAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let tenant_id = self.tenant_id.to_owned();
        Box::pin(async move { Ok(tenant_id) })
    }
}

struct TimeoutThenAuthenticate {
    calls: Arc<AtomicUsize>,
    first_dropped: Arc<AtomicBool>,
}

impl TenantAuthenticator for TimeoutThenAuthenticate {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Box::pin(PendingAuthentication {
                dropped: Arc::clone(&self.first_dropped),
            })
        } else {
            Box::pin(async { Ok("trusted-tenant".to_owned()) })
        }
    }
}

struct PendingAuthentication {
    dropped: Arc<AtomicBool>,
}

impl Future for PendingAuthentication {
    type Output = Result<String, AuthenticateTenantError>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PendingAuthentication {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl TenantAuthenticator for RejectingAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(AuthenticateTenantError::rejected()) })
    }
}

struct RecordingExecutor {
    observed: Arc<Mutex<Vec<(String, String)>>>,
    response: DecisionRecord,
}

impl TenantScopedGetDecisionExecutor for RecordingExecutor {
    fn execute_get_decision(
        &self,
        scope: TenantScope,
        query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        self.observed.lock().unwrap().push((
            scope.tenant_id().to_owned(),
            query.decision_id().to_string(),
        ));
        let response = self.response.clone();
        Box::pin(async move { Ok(response) })
    }
}

struct BlockingFirstExecutor {
    calls: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
    response: DecisionRecord,
}

struct TimeoutThenExecute {
    calls: Arc<AtomicUsize>,
    first_dropped: Arc<AtomicBool>,
    response: DecisionRecord,
}

impl TenantScopedGetDecisionExecutor for TimeoutThenExecute {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Box::pin(PendingExecution {
                dropped: Arc::clone(&self.first_dropped),
            })
        } else {
            let response = self.response.clone();
            Box::pin(async move { Ok(response) })
        }
    }
}

struct PendingExecution {
    dropped: Arc<AtomicBool>,
}

impl Future for PendingExecution {
    type Output = Result<DecisionRecord, GetDecisionRequestExecutionError>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PendingExecution {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl TenantScopedGetDecisionExecutor for BlockingFirstExecutor {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let entered = Arc::clone(&self.entered);
        let release = Arc::clone(&self.release);
        let response = self.response.clone();
        Box::pin(async move {
            if call == 0 {
                entered.notify_one();
                release.notified().await;
            }
            Ok(response)
        })
    }
}

#[allow(deprecated)]
fn record() -> DecisionRecord {
    DecisionRecord {
        decision_id: DECISION_ID.to_owned(),
        cou_id: "COU-SERVICE-001".to_owned(),
        evidence_snapshot_id: "ES-SERVICE-001".to_owned(),
        recommendation: Recommendation::Promote as i32,
        rationale: vec!["Evidence supports promotion.".to_owned()],
        aggregate_version: u64::MAX,
        evidence: Some(EvidenceSnapshotRef {
            id: "ES-SERVICE-001".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        }),
    }
}

fn assert_public_status(status: &Status, code: Code, message: &str) {
    assert_eq!(status.code(), code);
    assert_eq!(status.message(), message);
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
}

fn request(decision_id: &str) -> Request<GetDecisionRequest> {
    Request::new(GetDecisionRequest {
        decision_id: decision_id.to_owned(),
    })
}

#[tokio::test]
async fn authenticates_and_executes_the_exact_tenant_scoped_query() {
    let expected = record();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let executor = RecordingExecutor {
        observed: Arc::clone(&observed),
        response: expected.clone(),
    };
    let config = DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(1)).unwrap();
    let service = DecisionGrpcService::new(StaticAuthenticator, executor, config);
    let mut request = Request::new(GetDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    });
    request
        .metadata_mut()
        .insert("x-tenant-id", "attacker-tenant".parse().unwrap());

    let response = GeneratedDecisionService::get_decision(&service, request)
        .await
        .unwrap();

    assert_eq!(response.into_inner(), expected);
    assert_eq!(
        *observed.lock().unwrap(),
        vec![("trusted-tenant".to_owned(), DECISION_ID.to_owned())]
    );
}

#[tokio::test]
async fn rejects_authentication_before_request_validation_or_execution() {
    let sensitive_credential = "sensitive-bearer-credential";
    let sensitive_tenant = "sensitive-attacker-tenant";
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let executor = RecordingExecutor {
        observed: Arc::clone(&observed),
        response: record(),
    };
    let config = DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(1)).unwrap();
    let service = DecisionGrpcService::new(
        RejectingAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        executor,
        config,
    );
    let mut request = Request::new(GetDecisionRequest {
        decision_id: "invalid-sensitive-decision-id".to_owned(),
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {sensitive_credential}").parse().unwrap(),
    );
    request
        .metadata_mut()
        .insert("x-tenant-id", sensitive_tenant.parse().unwrap());

    let status = GeneratedDecisionService::get_decision(&service, request)
        .await
        .expect_err("rejected authentication must fail before validation");

    assert_public_status(&status, Code::Unauthenticated, "authentication is required");
    let rendered = format!("{status:?} {status}");
    assert!(!rendered.contains(sensitive_credential));
    assert!(!rendered.contains(sensitive_tenant));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert!(observed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn maps_authentication_capacity_and_availability_without_execution() {
    for (error, code, message) in [
        (
            AuthenticateTenantError::capacity_exhausted(),
            Code::ResourceExhausted,
            "authentication service is at capacity",
        ),
        (
            AuthenticateTenantError::unavailable(),
            Code::Unavailable,
            "authentication service is unavailable",
        ),
    ] {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let service = DecisionGrpcService::new(
            ErrorAuthenticator(error),
            RecordingExecutor {
                observed: Arc::clone(&observed),
                response: record(),
            },
            DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(1)).unwrap(),
        );

        let status = GeneratedDecisionService::get_decision(&service, request(DECISION_ID))
            .await
            .expect_err("authentication infrastructure error must fail");

        assert_public_status(&status, code, message);
        assert!(observed.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn rejects_an_invalid_authenticated_tenant_without_reflection_or_execution() {
    let invalid_tenant = " invalid-authenticated-tenant\0";
    let hostile_metadata_tenant = "hostile-metadata-tenant";
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let service = DecisionGrpcService::new(
        CountingAuthenticator {
            calls: Arc::clone(&auth_calls),
            tenant_id: invalid_tenant,
        },
        RecordingExecutor {
            observed: Arc::clone(&observed),
            response: record(),
        },
        DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(1)).unwrap(),
    );
    let mut request = request(DECISION_ID);
    request
        .metadata_mut()
        .insert("x-tenant-id", hostile_metadata_tenant.parse().unwrap());

    let status = GeneratedDecisionService::get_decision(&service, request)
        .await
        .expect_err("invalid authenticated tenant must fail closed");

    assert_public_status(&status, Code::Unauthenticated, "authentication is required");
    let rendered = format!("{status:?} {status}");
    assert!(!rendered.contains(invalid_tenant));
    assert!(!rendered.contains(hostile_metadata_tenant));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert!(observed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn validates_the_request_after_authentication_without_invalid_execution() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let service = DecisionGrpcService::new(
        CountingAuthenticator {
            calls: Arc::clone(&auth_calls),
            tenant_id: "trusted-tenant",
        },
        RecordingExecutor {
            observed: Arc::clone(&observed),
            response: record(),
        },
        DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(1)).unwrap(),
    );

    let status =
        GeneratedDecisionService::get_decision(&service, request("invalid-sensitive-decision-id"))
            .await
            .expect_err("invalid request must fail after authentication");

    assert_public_status(
        &status,
        Code::InvalidArgument,
        "decision request is invalid",
    );
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert!(observed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejects_saturation_before_authentication_and_recovers_capacity() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let config = DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(1)).unwrap();
    let service = Arc::new(DecisionGrpcService::new(
        CountingAuthenticator {
            calls: Arc::clone(&auth_calls),
            tenant_id: "trusted-tenant",
        },
        BlockingFirstExecutor {
            calls: Arc::clone(&executor_calls),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            response: record(),
        },
        config,
    ));
    let first_service = Arc::clone(&service);
    let first = tokio::spawn(async move {
        GeneratedDecisionService::get_decision(first_service.as_ref(), request(DECISION_ID)).await
    });
    entered.notified().await;

    let status = GeneratedDecisionService::get_decision(service.as_ref(), request(DECISION_ID))
        .await
        .expect_err("saturated service must reject the next request");

    assert_public_status(
        &status,
        Code::ResourceExhausted,
        "decision service is at capacity",
    );
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 1);

    release.notify_one();
    first.await.unwrap().unwrap();
    GeneratedDecisionService::get_decision(service.as_ref(), request(DECISION_ID))
        .await
        .expect("released admission must serve the next request");
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn times_out_authentication_drops_its_future_and_recovers_capacity() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let first_dropped = Arc::new(AtomicBool::new(false));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let config = DecisionGrpcServiceConfig::try_new(1, Duration::from_millis(25)).unwrap();
    let service = DecisionGrpcService::new(
        TimeoutThenAuthenticate {
            calls: Arc::clone(&auth_calls),
            first_dropped: Arc::clone(&first_dropped),
        },
        RecordingExecutor {
            observed: Arc::clone(&observed),
            response: record(),
        },
        config,
    );

    let status = tokio::time::timeout(
        Duration::from_millis(250),
        GeneratedDecisionService::get_decision(&service, request(DECISION_ID)),
    )
    .await
    .expect("service must enforce its configured timeout")
    .expect_err("timed out authentication must fail");

    assert_public_status(
        &status,
        Code::DeadlineExceeded,
        "decision request deadline exceeded",
    );
    assert!(first_dropped.load(Ordering::SeqCst));
    assert!(observed.lock().unwrap().is_empty());

    GeneratedDecisionService::get_decision(&service, request(DECISION_ID))
        .await
        .expect("capacity must recover after authentication timeout");
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(observed.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn times_out_execution_drops_its_future_and_recovers_capacity() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let first_dropped = Arc::new(AtomicBool::new(false));
    let config = DecisionGrpcServiceConfig::try_new(1, Duration::from_millis(25)).unwrap();
    let service = DecisionGrpcService::new(
        CountingAuthenticator {
            calls: Arc::clone(&auth_calls),
            tenant_id: "trusted-tenant",
        },
        TimeoutThenExecute {
            calls: Arc::clone(&executor_calls),
            first_dropped: Arc::clone(&first_dropped),
            response: record(),
        },
        config,
    );

    let status = tokio::time::timeout(
        Duration::from_millis(250),
        GeneratedDecisionService::get_decision(&service, request(DECISION_ID)),
    )
    .await
    .expect("service must enforce its configured timeout")
    .expect_err("timed out execution must fail");

    assert_public_status(
        &status,
        Code::DeadlineExceeded,
        "decision request deadline exceeded",
    );
    assert!(first_dropped.load(Ordering::SeqCst));

    GeneratedDecisionService::get_decision(&service, request(DECISION_ID))
        .await
        .expect("capacity must recover after execution timeout");
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn external_cancellation_drops_execution_and_recovers_capacity() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let first_dropped = Arc::new(AtomicBool::new(false));
    let service = Arc::new(DecisionGrpcService::new(
        CountingAuthenticator {
            calls: Arc::clone(&auth_calls),
            tenant_id: "trusted-tenant",
        },
        TimeoutThenExecute {
            calls: Arc::clone(&executor_calls),
            first_dropped: Arc::clone(&first_dropped),
            response: record(),
        },
        DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(1)).unwrap(),
    ));
    let active_service = Arc::clone(&service);
    let active = tokio::spawn(async move {
        GeneratedDecisionService::get_decision(active_service.as_ref(), request(DECISION_ID)).await
    });
    tokio::time::timeout(Duration::from_millis(250), async {
        while executor_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first execution must start");

    active.abort();
    assert!(active.await.unwrap_err().is_cancelled());
    assert!(first_dropped.load(Ordering::SeqCst));

    GeneratedDecisionService::get_decision(service.as_ref(), request(DECISION_ID))
        .await
        .expect("capacity must recover after external cancellation");
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unimplemented_operations_have_no_authentication_or_execution_side_effects() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let service = DecisionGrpcService::new(
        CountingAuthenticator {
            calls: Arc::clone(&auth_calls),
            tenant_id: "trusted-tenant",
        },
        RecordingExecutor {
            observed: Arc::clone(&observed),
            response: record(),
        },
        DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(1)).unwrap(),
    );
    let sensitive_cou = "sensitive-unimplemented-cou";
    let propose_status = GeneratedDecisionService::propose_decision(
        &service,
        Request::new(ProposeDecisionRequest {
            idempotency_key: "sensitive-idempotency-key".to_owned(),
            cou_id: sensitive_cou.to_owned(),
            evidence_snapshot_id: "sensitive-evidence".to_owned(),
            recommendation: Recommendation::Promote as i32,
            rationale: vec!["sensitive rationale".to_owned()],
        }),
    )
    .await
    .expect_err("propose must remain unavailable");
    let watch_status = match GeneratedDecisionService::watch_decision(
        &service,
        Request::new(WatchDecisionRequest {
            decision_id: "sensitive-watch-decision".to_owned(),
        }),
    )
    .await
    {
        Ok(_) => panic!("watch must remain unavailable"),
        Err(status) => status,
    };

    for status in [propose_status, watch_status] {
        assert_public_status(
            &status,
            Code::Unimplemented,
            "decision operation is not implemented",
        );
        assert!(!format!("{status:?} {status}").contains(sensitive_cou));
    }
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert!(observed.lock().unwrap().is_empty());
}
