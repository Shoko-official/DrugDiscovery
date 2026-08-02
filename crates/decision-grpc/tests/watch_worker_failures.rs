use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bioworld_contracts::v2::{
    GetDecisionRequest, ProposeDecisionRequest, WatchDecisionRequest,
    decision_service_server::DecisionService as GeneratedDecisionService,
};
use bioworld_decision_grpc::{
    AuthenticateTenantFuture, DecisionGrpcService, DecisionGrpcServiceConfig,
    DecisionGrpcWatchConfig, DecisionGrpcWatchLifecycle, TenantAuthenticationContext,
    TenantAuthenticator, TenantAuthority, TenantScope, TenantScopedGetDecisionExecutor,
    TenantScopedGetDecisionFuture, TenantScopedWatchDecisionExecutor,
};
use bioworld_decision_query::{
    DecisionReplay, DecisionReplayPageSize, DecisionReplaySource, DecisionReplaySourceError,
    DecisionReplaySourceFuture, GetDecisionQuery, GetDecisionRequestExecutionError,
    WatchDecisionQuery,
};
use tokio::time::Instant;
use tonic::{Code, Request, Status, codegen::tokio_stream::StreamExt};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
const PRIVATE_EXECUTOR_FAILURE: &str = "private executor failure payload";

struct CountingAuthenticator {
    calls: Arc<AtomicUsize>,
}

impl TenantAuthenticator for CountingAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(TenantAuthority::try_new(
                "trusted-tenant".to_owned(),
                Instant::now() + Duration::from_secs(60),
            )
            .expect("test authority must be valid"))
        })
    }
}

#[derive(Clone, Copy)]
enum WatchFailure {
    ExecutorPanic,
    SourceUnavailable,
}

struct FailingSource {
    reads: Arc<AtomicUsize>,
}

impl DecisionReplaySource for FailingSource {
    type Continuation = ();

    fn read_page<'a>(
        &'a mut self,
        _query: WatchDecisionQuery,
        _page_size: DecisionReplayPageSize,
        _continuation: Option<&'a Self::Continuation>,
    ) -> DecisionReplaySourceFuture<'a, Self::Continuation> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(DecisionReplaySourceError::Unavailable) })
    }
}

struct FailureExecutor {
    failures: Mutex<VecDeque<WatchFailure>>,
    get_calls: Arc<AtomicUsize>,
    watch_calls: Arc<AtomicUsize>,
    source_reads: Arc<AtomicUsize>,
}

impl TenantScopedGetDecisionExecutor for FailureExecutor {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(GetDecisionRequestExecutionError::NotFound) })
    }
}

impl TenantScopedWatchDecisionExecutor for FailureExecutor {
    type Source = FailingSource;

    fn execute_watch_decision(
        &self,
        _scope: TenantScope,
        query: WatchDecisionQuery,
        page_size: DecisionReplayPageSize,
    ) -> DecisionReplay<Self::Source> {
        self.watch_calls.fetch_add(1, Ordering::SeqCst);
        let failure = self
            .failures
            .lock()
            .unwrap()
            .pop_front()
            .expect("test executor must own a scripted failure");
        match failure {
            WatchFailure::ExecutorPanic => panic!("{PRIVATE_EXECUTOR_FAILURE}"),
            WatchFailure::SourceUnavailable => DecisionReplay::new(
                FailingSource {
                    reads: Arc::clone(&self.source_reads),
                },
                query,
                page_size,
            ),
        }
    }
}

struct TestState {
    auth_calls: Arc<AtomicUsize>,
    get_calls: Arc<AtomicUsize>,
    watch_calls: Arc<AtomicUsize>,
    source_reads: Arc<AtomicUsize>,
}

impl TestState {
    fn new() -> Self {
        Self {
            auth_calls: Arc::new(AtomicUsize::new(0)),
            get_calls: Arc::new(AtomicUsize::new(0)),
            watch_calls: Arc::new(AtomicUsize::new(0)),
            source_reads: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn service(
        &self,
        failures: impl IntoIterator<Item = WatchFailure>,
    ) -> DecisionGrpcService<CountingAuthenticator, FailureExecutor> {
        DecisionGrpcService::try_new_with_watch(
            CountingAuthenticator {
                calls: Arc::clone(&self.auth_calls),
            },
            FailureExecutor {
                failures: Mutex::new(failures.into_iter().collect()),
                get_calls: Arc::clone(&self.get_calls),
                watch_calls: Arc::clone(&self.watch_calls),
                source_reads: Arc::clone(&self.source_reads),
            },
            DecisionGrpcServiceConfig::try_new(2, Duration::from_secs(5)).unwrap(),
            DecisionGrpcWatchConfig::try_new(1, 1).unwrap(),
        )
        .expect("test Watch configuration must be valid")
    }
}

fn watch_request() -> Request<WatchDecisionRequest> {
    Request::new(WatchDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    })
}

fn assert_redacted_unavailable(status: &Status) {
    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(status.message(), "decision service is unavailable");
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
    assert!(!format!("{status:?} {status}").contains(PRIVATE_EXECUTOR_FAILURE));
}

async fn wait_for_worker_count(lifecycle: &DecisionGrpcWatchLifecycle, expected: usize) {
    for _ in 0..32 {
        if lifecycle.active_workers() == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(lifecycle.active_workers(), expected);
}

async fn assert_supervised_failure(failure: WatchFailure, expected_source_reads: usize) {
    let state = TestState::new();
    let service = state.service([failure]);
    let lifecycle = service
        .watch_lifecycle()
        .expect("Watch-enabled service must expose its lifecycle");
    let mut stream = GeneratedDecisionService::watch_decision(&service, watch_request())
        .await
        .expect("Watch admission must succeed before worker execution")
        .into_inner();

    assert_eq!(state.watch_calls.load(Ordering::SeqCst), 0);
    assert_eq!(lifecycle.active_workers(), 1);

    let status = stream
        .next()
        .await
        .expect("worker failure must emit one terminal status")
        .expect_err("worker failure must not emit an event");
    assert_redacted_unavailable(&status);
    assert!(stream.next().await.is_none());
    assert!(stream.next().await.is_none());
    wait_for_worker_count(&lifecycle, 0).await;

    assert_eq!(state.watch_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        state.source_reads.load(Ordering::SeqCst),
        expected_source_reads
    );

    let recovered = GeneratedDecisionService::watch_decision(&service, watch_request())
        .await
        .expect("worker failure must release Watch and tenant capacity");
    assert_eq!(lifecycle.active_workers(), 1);

    let get_status = GeneratedDecisionService::get_decision(
        &service,
        Request::new(GetDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        }),
    )
    .await
    .expect_err("test Get executor returns not found");
    assert_eq!(get_status.code(), Code::NotFound);
    assert_eq!(state.get_calls.load(Ordering::SeqCst), 1);

    drop(recovered);
    wait_for_worker_count(&lifecycle, 0).await;
    assert_eq!(state.auth_calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn executor_panic_emits_one_redacted_unavailable_then_fuses_and_recovers_capacity() {
    assert_supervised_failure(WatchFailure::ExecutorPanic, 0).await;
}

#[tokio::test]
async fn source_error_emits_one_redacted_unavailable_then_fuses_and_recovers_capacity() {
    assert_supervised_failure(WatchFailure::SourceUnavailable, 1).await;
}

#[tokio::test]
async fn propose_remains_unimplemented_without_authentication_or_execution() {
    let state = TestState::new();
    let service = state.service([]);

    let status = GeneratedDecisionService::propose_decision(
        &service,
        Request::new(ProposeDecisionRequest::default()),
    )
    .await
    .expect_err("Propose must remain unimplemented");

    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(status.message(), "decision operation is not implemented");
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
    assert_eq!(state.auth_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.get_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.watch_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.source_reads.load(Ordering::SeqCst), 0);
}
