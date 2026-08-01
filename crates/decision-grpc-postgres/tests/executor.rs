use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bioworld_contracts::v2::{GetDecisionRequest, WatchDecisionRequest};
use bioworld_decision_grpc::{TenantScope, get_decision};
use bioworld_decision_grpc_postgres::{
    AcquirePostgresReaderError, AcquirePostgresReaderFuture, FinishPostgresReaderLeaseError,
    PostgresDecisionReplaySource, PostgresGetDecisionExecutor, PostgresReaderLease,
    PostgresReaderLeaseDisposition, PostgresReaderLeaseProvider,
};
use bioworld_decision_query::{
    DecisionReplayPageSize, DecisionReplaySource, DecisionReplaySourceError,
    MAX_DECISION_REPLAY_PAGE_EVENTS, WatchDecisionQuery,
};
use bioworld_event_store_postgres::{DecisionStreamPageSize, MAX_DECISION_STREAM_PAGE_EVENTS};
use tokio_postgres::Client;
use tonic::{Code, Request, Status};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";

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
async fn invalid_requests_do_not_acquire_a_reader_lease() {
    let calls = Arc::new(AtomicUsize::new(0));
    let executor = PostgresGetDecisionExecutor::new(RejectingProvider {
        calls: Arc::clone(&calls),
    });

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
    let executor = PostgresGetDecisionExecutor::new(RejectingProvider {
        calls: Arc::clone(&calls),
    });

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

    let executor = PostgresGetDecisionExecutor::new(RejectingProvider {
        calls: Arc::new(AtomicUsize::new(0)),
    });
    let tenant_a = get_decision(&executor, scope(), request(DECISION_ID));
    let tenant_b = get_decision(&executor, scope(), request(DECISION_ID));

    assert_send((tenant_a, tenant_b));
}
