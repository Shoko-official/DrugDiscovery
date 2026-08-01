use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bioworld_contracts::v2::{
    DecisionEvent, DecisionRecord, EvidenceSnapshotRef, Recommendation, WatchDecisionRequest,
};
use bioworld_decision_grpc::{
    MAX_DECISION_EVENT_WIRE_BYTES, TenantScope, TenantScopedWatchDecisionExecutor, watch_decision,
};
use bioworld_decision_query::{
    DecisionReplay, DecisionReplayPageSize, DecisionReplaySource, DecisionReplaySourceError,
    DecisionReplaySourceFuture, DecisionReplaySourcePage, WatchDecisionQuery,
};
use tonic::{Code, Request, Status, codegen::tokio_stream::StreamExt};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
const FIRST_EVENT_ID: &str = "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba";
const SECOND_EVENT_ID: &str = "0193a72e-71cc-7d40-b59c-f6eb4f0bf6bb";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Cursor(u64);

#[derive(Debug, Eq, PartialEq)]
struct ExecutorObservation {
    tenant_id: String,
    decision_id: String,
    page_size: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct SourceObservation {
    decision_id: String,
    page_size: usize,
    continuation: Option<u64>,
}

enum ReadStep {
    Page(DecisionReplaySourcePage<Cursor>),
    Error(DecisionReplaySourceError),
    Pending(Arc<AtomicBool>),
}

struct ScriptedSource {
    observations: Arc<Mutex<Vec<SourceObservation>>>,
    steps: VecDeque<ReadStep>,
}

impl DecisionReplaySource for ScriptedSource {
    type Continuation = Cursor;

    fn read_page<'a>(
        &'a mut self,
        query: WatchDecisionQuery,
        page_size: DecisionReplayPageSize,
        continuation: Option<&'a Self::Continuation>,
    ) -> DecisionReplaySourceFuture<'a, Self::Continuation> {
        self.observations
            .lock()
            .expect("source observation recorder must be usable")
            .push(SourceObservation {
                decision_id: query.decision_id().to_string(),
                page_size: page_size.get(),
                continuation: continuation.map(|cursor| cursor.0),
            });

        match self
            .steps
            .pop_front()
            .expect("adapter performed an unexpected replay source read")
        {
            ReadStep::Page(page) => Box::pin(async move { Ok(page) }),
            ReadStep::Error(error) => Box::pin(async move { Err(error) }),
            ReadStep::Pending(dropped) => Box::pin(PendingRead { dropped }),
        }
    }
}

struct PendingRead {
    dropped: Arc<AtomicBool>,
}

impl Future for PendingRead {
    type Output = Result<DecisionReplaySourcePage<Cursor>, DecisionReplaySourceError>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PendingRead {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct ScriptedExecutor {
    observations: Arc<Mutex<Vec<ExecutorObservation>>>,
    source: Mutex<Option<ScriptedSource>>,
    returned_page_size: usize,
}

impl TenantScopedWatchDecisionExecutor for ScriptedExecutor {
    type Source = ScriptedSource;

    fn execute_watch_decision(
        &self,
        scope: TenantScope,
        query: WatchDecisionQuery,
        page_size: DecisionReplayPageSize,
    ) -> DecisionReplay<Self::Source> {
        self.observations
            .lock()
            .expect("executor observation recorder must be usable")
            .push(ExecutorObservation {
                tenant_id: scope.tenant_id().to_owned(),
                decision_id: query.decision_id().to_string(),
                page_size: page_size.get(),
            });
        let source = self
            .source
            .lock()
            .expect("scripted source slot must be usable")
            .take()
            .expect("executor must be invoked at most once");

        DecisionReplay::new(source, query, replay_page_size(self.returned_page_size))
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn replay_page_size(value: usize) -> DecisionReplayPageSize {
    DecisionReplayPageSize::try_from(value).expect("fixture page size must be valid")
}

fn tenant_scope() -> TenantScope {
    TenantScope::try_from_trusted_tenant_id("trusted-tenant".to_owned())
        .expect("fixture tenant must be valid")
}

fn request(decision_id: &str) -> Request<WatchDecisionRequest> {
    Request::new(WatchDecisionRequest {
        decision_id: decision_id.to_owned(),
    })
}

fn source(
    observations: Arc<Mutex<Vec<SourceObservation>>>,
    steps: impl IntoIterator<Item = ReadStep>,
) -> ScriptedSource {
    ScriptedSource {
        observations,
        steps: steps.into_iter().collect(),
    }
}

fn executor(
    observations: Arc<Mutex<Vec<ExecutorObservation>>>,
    source: ScriptedSource,
    returned_page_size: usize,
) -> ScriptedExecutor {
    ScriptedExecutor {
        observations,
        source: Mutex::new(Some(source)),
        returned_page_size,
    }
}

#[allow(deprecated)]
fn event(event_id: &str, aggregate_version: u64, rationale: &str) -> DecisionEvent {
    DecisionEvent {
        decision: Some(DecisionRecord {
            decision_id: DECISION_ID.to_owned(),
            cou_id: "COU-WATCH-001".to_owned(),
            evidence_snapshot_id: String::new(),
            recommendation: Recommendation::Abstain as i32,
            rationale: vec![rationale.to_owned()],
            aggregate_version,
            evidence: Some(EvidenceSnapshotRef {
                id: "ES-WATCH-001".to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
            ood_status: None,
            ood_detector: None,
            prediction_interval: None,
            prediction_positions: Vec::new(),
            decision_criterion: None,
        }),
        event_id: event_id.to_owned(),
    }
}

fn assert_public_status(status: &Status, code: Code, message: &str) {
    assert_eq!(status.code(), code);
    assert_eq!(status.message(), message);
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
}

#[test]
fn exposes_the_fixed_public_watch_contract() {
    fn assert_executor<T: TenantScopedWatchDecisionExecutor>() {
        fn assert_send_sync<U: Send + Sync>() {}
        fn assert_source<U: DecisionReplaySource + 'static>() {}

        assert_send_sync::<T>();
        assert_source::<T::Source>();
    }

    assert_executor::<ScriptedExecutor>();
    assert_eq!(MAX_DECISION_EVENT_WIRE_BYTES, 65_578);
}

#[test]
fn rejects_an_invalid_request_before_execution_without_reflecting_request_data() {
    let submitted = "sensitive-invalid-watch-decision-id";
    let sensitive_credential = "sensitive-watch-credential";
    let executor_observations = Arc::new(Mutex::new(Vec::new()));
    let source_observations = Arc::new(Mutex::new(Vec::new()));
    let executor = executor(
        Arc::clone(&executor_observations),
        source(Arc::clone(&source_observations), []),
        1,
    );
    let mut request = request(submitted);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {sensitive_credential}").parse().unwrap(),
    );
    request
        .metadata_mut()
        .insert("x-tenant-id", "hostile-metadata-tenant".parse().unwrap());

    let status = match watch_decision(&executor, tenant_scope(), request) {
        Ok(_) => panic!("invalid request must be rejected synchronously"),
        Err(status) => status,
    };

    assert_public_status(
        &status,
        Code::InvalidArgument,
        "decision request is invalid",
    );
    let rendered = format!("{status:?} {status}");
    assert!(!rendered.contains(submitted));
    assert!(!rendered.contains(sensitive_credential));
    assert!(!rendered.contains("hostile-metadata-tenant"));
    assert!(executor_observations.lock().unwrap().is_empty());
    assert!(source_observations.lock().unwrap().is_empty());
}

#[test]
fn rejects_a_replay_with_a_non_fixed_page_size_before_any_source_read() {
    let executor_observations = Arc::new(Mutex::new(Vec::new()));
    let source_observations = Arc::new(Mutex::new(Vec::new()));
    let executor = executor(
        Arc::clone(&executor_observations),
        source(
            Arc::clone(&source_observations),
            [ReadStep::Page(DecisionReplaySourcePage::new(
                vec![event(FIRST_EVENT_ID, 1, "must not be read")],
                None,
            ))],
        ),
        16,
    );

    let status = match watch_decision(&executor, tenant_scope(), request(DECISION_ID)) {
        Ok(_) => panic!("non-fixed replay page size must be rejected synchronously"),
        Err(status) => status,
    };

    assert_public_status(
        &status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    assert_eq!(
        *executor_observations.lock().unwrap(),
        [ExecutorObservation {
            tenant_id: "trusted-tenant".to_owned(),
            decision_id: DECISION_ID.to_owned(),
            page_size: 1,
        }]
    );
    assert!(source_observations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn lazily_moves_two_pages_in_order_without_prefetch_or_payload_reallocation() {
    let first = event(FIRST_EVENT_ID, 3, "first recorded rationale");
    let second = event(SECOND_EVENT_ID, 8, "second recorded rationale");
    let first_event_id_address = first.event_id.as_ptr() as usize;
    let first_rationale_address = first.decision.as_ref().unwrap().rationale[0].as_ptr() as usize;
    let second_event_id_address = second.event_id.as_ptr() as usize;
    let second_rationale_address = second.decision.as_ref().unwrap().rationale[0].as_ptr() as usize;
    let expected_first = first.clone();
    let expected_second = second.clone();
    let executor_observations = Arc::new(Mutex::new(Vec::new()));
    let source_observations = Arc::new(Mutex::new(Vec::new()));
    let executor = executor(
        Arc::clone(&executor_observations),
        source(
            Arc::clone(&source_observations),
            [
                ReadStep::Page(DecisionReplaySourcePage::new(vec![first], Some(Cursor(73)))),
                ReadStep::Page(DecisionReplaySourcePage::new(vec![second], None)),
            ],
        ),
        1,
    );
    let mut request = request(DECISION_ID);
    request
        .metadata_mut()
        .insert("x-tenant-id", "hostile-metadata-tenant".parse().unwrap());
    request
        .metadata_mut()
        .insert("x-correlation-id", "sensitive-correlation".parse().unwrap());

    let response = watch_decision(&executor, tenant_scope(), request)
        .expect("valid watch request must return a stream");

    assert!(response.metadata().is_empty());
    assert_eq!(
        *executor_observations.lock().unwrap(),
        [ExecutorObservation {
            tenant_id: "trusted-tenant".to_owned(),
            decision_id: DECISION_ID.to_owned(),
            page_size: 1,
        }]
    );
    assert!(source_observations.lock().unwrap().is_empty());

    let mut stream = response.into_inner();
    let first = stream
        .next()
        .await
        .expect("first event must exist")
        .expect("first event must succeed");

    assert_eq!(first, expected_first);
    assert_eq!(first.event_id.as_ptr() as usize, first_event_id_address);
    assert_eq!(
        first.decision.as_ref().unwrap().rationale[0].as_ptr() as usize,
        first_rationale_address
    );
    assert_eq!(source_observations.lock().unwrap().len(), 1);

    let second = stream
        .next()
        .await
        .expect("second event must exist")
        .expect("second event must succeed");

    assert_eq!(second, expected_second);
    assert_eq!(second.event_id.as_ptr() as usize, second_event_id_address);
    assert_eq!(
        second.decision.as_ref().unwrap().rationale[0].as_ptr() as usize,
        second_rationale_address
    );
    assert_eq!(source_observations.lock().unwrap().len(), 2);
    assert!(stream.next().await.is_none());
    assert!(stream.next().await.is_none());
    assert_eq!(
        *source_observations.lock().unwrap(),
        [
            SourceObservation {
                decision_id: DECISION_ID.to_owned(),
                page_size: 1,
                continuation: None,
            },
            SourceObservation {
                decision_id: DECISION_ID.to_owned(),
                page_size: 1,
                continuation: Some(73),
            },
        ]
    );
}

#[tokio::test]
async fn an_empty_replay_is_fused_after_one_pull() {
    let executor_observations = Arc::new(Mutex::new(Vec::new()));
    let source_observations = Arc::new(Mutex::new(Vec::new()));
    let executor = executor(
        executor_observations,
        source(
            Arc::clone(&source_observations),
            [ReadStep::Page(DecisionReplaySourcePage::new(
                Vec::new(),
                None,
            ))],
        ),
        1,
    );
    let mut stream = watch_decision(&executor, tenant_scope(), request(DECISION_ID))
        .unwrap()
        .into_inner();

    assert!(source_observations.lock().unwrap().is_empty());
    assert!(stream.next().await.is_none());
    assert!(stream.next().await.is_none());
    assert_eq!(source_observations.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn rejects_an_overlong_source_page_once_then_fuses_without_exposure() {
    let sensitive_first = "sensitive-overlong-first";
    let sensitive_second = "sensitive-overlong-second";
    let executor_observations = Arc::new(Mutex::new(Vec::new()));
    let source_observations = Arc::new(Mutex::new(Vec::new()));
    let executor = executor(
        executor_observations,
        source(
            Arc::clone(&source_observations),
            [ReadStep::Page(DecisionReplaySourcePage::new(
                vec![
                    event(FIRST_EVENT_ID, 1, sensitive_first),
                    event(SECOND_EVENT_ID, 2, sensitive_second),
                ],
                None,
            ))],
        ),
        1,
    );
    let mut stream = watch_decision(&executor, tenant_scope(), request(DECISION_ID))
        .unwrap()
        .into_inner();

    let status = stream
        .next()
        .await
        .expect("policy rejection must emit one status")
        .expect_err("overlong source page must be rejected");

    assert_public_status(
        &status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    let rendered = format!("{status:?} {status}");
    assert!(!rendered.contains(sensitive_first));
    assert!(!rendered.contains(sensitive_second));
    assert!(stream.next().await.is_none());
    assert!(stream.next().await.is_none());
    assert_eq!(source_observations.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn each_replay_error_emits_one_fixed_unavailable_status_then_fuses() {
    for error in [
        DecisionReplaySourceError::Unavailable,
        DecisionReplaySourceError::StoredStateRejected,
    ] {
        let executor_observations = Arc::new(Mutex::new(Vec::new()));
        let source_observations = Arc::new(Mutex::new(Vec::new()));
        let executor = executor(
            executor_observations,
            source(Arc::clone(&source_observations), [ReadStep::Error(error)]),
            1,
        );
        let mut stream = watch_decision(&executor, tenant_scope(), request(DECISION_ID))
            .unwrap()
            .into_inner();

        let status = stream
            .next()
            .await
            .expect("replay error must emit one status")
            .expect_err("replay error must not expose an event");

        assert_public_status(
            &status,
            Code::Unavailable,
            "decision service is unavailable",
        );
        assert!(stream.next().await.is_none());
        assert!(stream.next().await.is_none());
        assert_eq!(source_observations.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn dropping_the_stream_drops_an_in_flight_page_read() {
    let pending_dropped = Arc::new(AtomicBool::new(false));
    let executor_observations = Arc::new(Mutex::new(Vec::new()));
    let source_observations = Arc::new(Mutex::new(Vec::new()));
    let executor = executor(
        executor_observations,
        source(
            Arc::clone(&source_observations),
            [ReadStep::Pending(Arc::clone(&pending_dropped))],
        ),
        1,
    );
    let mut stream = watch_decision(&executor, tenant_scope(), request(DECISION_ID))
        .unwrap()
        .into_inner();
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);

    assert!(stream.as_mut().poll_next(&mut context).is_pending());
    assert_eq!(source_observations.lock().unwrap().len(), 1);
    assert!(!pending_dropped.load(Ordering::SeqCst));

    drop(stream);

    assert!(pending_dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn returned_stream_is_send_and_static() {
    fn assert_send_static<T: Send + 'static>(value: T) -> T {
        value
    }

    let executor_observations = Arc::new(Mutex::new(Vec::new()));
    let source_observations = Arc::new(Mutex::new(Vec::new()));
    let executor = executor(
        executor_observations,
        source(
            source_observations,
            [ReadStep::Page(DecisionReplaySourcePage::new(
                Vec::new(),
                None,
            ))],
        ),
        1,
    );
    let response: tonic::Response<tonic::codegen::BoxStream<DecisionEvent>> =
        watch_decision(&executor, tenant_scope(), request(DECISION_ID)).unwrap();
    let mut stream = assert_send_static(response.into_inner());

    assert!(stream.next().await.is_none());
}
