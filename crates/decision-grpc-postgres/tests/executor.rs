use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bioworld_contracts::v2::{GetDecisionRequest, WatchDecisionRequest};
use bioworld_decision_grpc::{
    TenantScope, TenantScopedGetDecisionExecutor, TenantScopedWatchDecisionExecutor, get_decision,
    watch_decision,
};
use bioworld_decision_grpc_postgres::{
    AcquirePostgresReaderError, AcquirePostgresReaderFuture, FinishPostgresReaderLeaseError,
    PostgresDecisionExecutor, PostgresDecisionReplaySource, PostgresGetDecisionExecutor,
    PostgresReaderLease, PostgresReaderLeaseDisposition, PostgresReaderLeaseProvider,
};
use bioworld_decision_query::{
    DecisionReplayPageSize, DecisionReplaySource, DecisionReplaySourceError,
    MAX_DECISION_REPLAY_PAGE_EVENTS, WatchDecisionQuery,
};
use bioworld_event_store_contracts::{DecisionEventVerificationClock, DecisionEventVerifier};
use bioworld_event_store_postgres::{DecisionStreamPageSize, MAX_DECISION_STREAM_PAGE_EVENTS};
use serde_json::json;
use tokio_postgres::Client;
use tonic::{Code, Request, Status, codegen::tokio_stream::StreamExt};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
const TEST_NOW: u64 = 1_800_000_000;

#[derive(Clone, Copy)]
struct TestClock;

impl DecisionEventVerificationClock for TestClock {
    fn unix_timestamp(&self) -> Option<u64> {
        Some(TEST_NOW)
    }
}

fn verifier() -> DecisionEventVerifier {
    let key = Ed25519KeyPair::from_seed_unchecked(&[53_u8; 32])
        .expect("deterministic Ed25519 seed must be valid");
    let snapshot = serde_json::to_vec(&json!({
        "version": "1",
        "valid_until": TEST_NOW + 60,
        "keys": [{
            "tenant_id": "trusted-tenant",
            "key_id": "grpc-executor-test",
            "algorithm": "Ed25519",
            "public_key": URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
            "not_before": 1,
            "not_after": 4_102_444_800_u64,
            "status": "trusted"
        }]
    }))
    .expect("fixture verifier snapshot must serialize");
    DecisionEventVerifier::try_from_snapshot_with_clock(&snapshot, TestClock)
        .expect("fixture verifier snapshot must be valid")
}

struct UnreachableLease;

impl PostgresReaderLease for UnreachableLease {
    fn client(&mut self) -> &mut Client {
        panic!("rejected acquisition cannot expose a client")
    }

    fn finish(
        self,
        _disposition: PostgresReaderLeaseDisposition,
    ) -> Result<(), FinishPostgresReaderLeaseError> {
        panic!("rejected acquisition cannot finish a lease")
    }
}

#[derive(Clone)]
struct RejectingProvider {
    calls: Arc<AtomicUsize>,
}

impl PostgresReaderLeaseProvider for RejectingProvider {
    type Lease<'provider>
        = UnreachableLease
    where
        Self: 'provider;

    fn acquire(&self) -> AcquirePostgresReaderFuture<'_, Self::Lease<'_>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(AcquirePostgresReaderError) })
    }
}

fn scope() -> TenantScope {
    TenantScope::try_from_trusted_tenant_id("trusted-tenant".to_owned()).unwrap()
}

fn request(decision_id: &str) -> Request<GetDecisionRequest> {
    Request::new(GetDecisionRequest {
        decision_id: decision_id.to_owned(),
    })
}

fn watch_request(decision_id: &str) -> Request<WatchDecisionRequest> {
    Request::new(WatchDecisionRequest {
        decision_id: decision_id.to_owned(),
    })
}

fn assert_public_status(status: &Status, code: Code, message: &str) {
    assert_eq!(status.code(), code);
    assert_eq!(status.message(), message);
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
}

#[test]
fn replay_page_limit_matches_the_postgres_stream_limit() {
    assert_eq!(
        MAX_DECISION_REPLAY_PAGE_EVENTS,
        MAX_DECISION_STREAM_PAGE_EVENTS
    );

    for value in 1..=MAX_DECISION_REPLAY_PAGE_EVENTS {
        DecisionReplayPageSize::try_from(value).expect("application page size must be valid");
        DecisionStreamPageSize::try_from(value).expect("storage page size must be valid");
    }
}

#[tokio::test]
async fn canonical_and_compatible_executors_adapt_watch_requests_lazily() {
    fn assert_ports<T: TenantScopedGetDecisionExecutor + TenantScopedWatchDecisionExecutor>() {}
    fn as_compatible_alias<P>(
        executor: PostgresDecisionExecutor<P>,
    ) -> PostgresGetDecisionExecutor<P> {
        executor
    }

    assert_ports::<PostgresDecisionExecutor<RejectingProvider>>();
    assert_ports::<PostgresGetDecisionExecutor<RejectingProvider>>();

    let calls = Arc::new(AtomicUsize::new(0));
    let executor = as_compatible_alias(PostgresDecisionExecutor::new(
        RejectingProvider {
            calls: Arc::clone(&calls),
        },
        verifier(),
    ));
    let query = WatchDecisionQuery::try_from(WatchDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    })
    .expect("fixed watch query must be valid");
    let page_size =
        DecisionReplayPageSize::try_from(16).expect("fixed replay page size must be valid");
    let replay = executor.execute_watch_decision(scope(), query, page_size);

    assert_eq!(replay.page_size(), page_size);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(replay);

    let submitted = "sensitive-invalid-watch-decision-id";

    let status = match watch_decision(&executor, scope(), watch_request(submitted)) {
        Ok(_) => panic!("invalid Watch request must be rejected synchronously"),
        Err(status) => status,
    };

    assert_public_status(
        &status,
        Code::InvalidArgument,
        "decision request is invalid",
    );
    assert!(!format!("{status:?} {status}").contains(submitted));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let response = watch_decision(&executor, scope(), watch_request(DECISION_ID))
        .expect("valid Watch request must create a response stream");
    assert!(response.metadata().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let mut stream = response.into_inner();
    let status = stream
        .next()
        .await
        .expect("failed replay acquisition must emit one status")
        .expect_err("failed replay acquisition must not expose an event");

    assert_public_status(
        &status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(stream.next().await.is_none());
    assert!(stream.next().await.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_requests_do_not_acquire_a_reader_lease() {
    let calls = Arc::new(AtomicUsize::new(0));
    let executor = PostgresGetDecisionExecutor::new(
        RejectingProvider {
            calls: Arc::clone(&calls),
        },
        verifier(),
    );

    let result = get_decision(&executor, scope(), request("sensitive-invalid-decision-id")).await;
    let status = result.expect_err("invalid request must fail");

    assert_public_status(
        &status,
        Code::InvalidArgument,
        "decision request is invalid",
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn acquisition_failures_are_fixed_and_redacted() {
    let calls = Arc::new(AtomicUsize::new(0));
    let executor = PostgresGetDecisionExecutor::new(
        RejectingProvider {
            calls: Arc::clone(&calls),
        },
        verifier(),
    );

    let result = get_decision(&executor, scope(), request(DECISION_ID)).await;
    let status = result.expect_err("failed acquisition must fail");

    assert_public_status(
        &status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn replay_acquisition_failures_are_fixed_and_redacted() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut source = PostgresDecisionReplaySource::new(
        RejectingProvider {
            calls: Arc::clone(&calls),
        },
        scope(),
        verifier(),
    );
    let query = WatchDecisionQuery::try_from(WatchDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    })
    .expect("fixed replay query must be valid");

    let result = source
        .read_page(
            query,
            DecisionReplayPageSize::try_from(1).expect("fixed replay page size must be valid"),
            None,
        )
        .await;

    assert!(matches!(
        result,
        Err(DecisionReplaySourceError::Unavailable)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn lifecycle_errors_are_fixed_and_thread_safe() {
    fn assert_error<T: Error + Send + Sync + Copy>(_: T) {}

    let acquisition = AcquirePostgresReaderError;
    assert_eq!(format!("{acquisition:?}"), "AcquirePostgresReaderError");
    assert_eq!(
        acquisition.to_string(),
        "PostgreSQL reader acquisition failed"
    );
    assert_error(acquisition);

    let finish = FinishPostgresReaderLeaseError;
    assert_eq!(format!("{finish:?}"), "FinishPostgresReaderLeaseError");
    assert_eq!(finish.to_string(), "PostgreSQL reader cleanup failed");
    assert_error(finish);
}

#[test]
fn executor_and_futures_support_concurrent_service_use() {
    fn assert_send<T: Send>(_: T) {}
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<PostgresGetDecisionExecutor<RejectingProvider>>();

    let executor = PostgresGetDecisionExecutor::new(
        RejectingProvider {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        verifier(),
    );
    let tenant_a = get_decision(&executor, scope(), request(DECISION_ID));
    let tenant_b = get_decision(&executor, scope(), request(DECISION_ID));

    assert_send((tenant_a, tenant_b));
}
