use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bioworld_contracts::v2::{
    DecisionEvent, DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest, Recommendation,
    WatchDecisionRequest, decision_service_server::DecisionService as GeneratedDecisionService,
};
use bioworld_decision_grpc::{
    AuthenticateTenantError, AuthenticateTenantFuture, DecisionGrpcService,
    DecisionGrpcServiceConfig, DecisionGrpcWatchConfig, DecisionGrpcWatchLifecycle,
    TenantAuthenticationContext, TenantAuthenticator, TenantAuthority, TenantScope,
    TenantScopedGetDecisionExecutor, TenantScopedGetDecisionFuture,
    TenantScopedWatchDecisionExecutor,
};
use bioworld_decision_query::{
    DecisionReplay, DecisionReplayPageSize, DecisionReplaySource, DecisionReplaySourceError,
    DecisionReplaySourceFuture, DecisionReplaySourcePage, GetDecisionQuery,
    GetDecisionRequestExecutionError, WatchDecisionQuery,
};
use tokio::time::Instant;
use tonic::{Code, Request, Status, codegen::tokio_stream::StreamExt};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
const EVENT_ID: &str = "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba";
const SIGNED_TOKEN_A: &str = "simulated-signed-token-a";
const SIGNED_TOKEN_B: &str = "simulated-signed-token-b";
const SIGNED_TOKEN_C: &str = "simulated-signed-token-c";
const SIGNED_TENANT_A: &str = "signed-tenant-a";
const SIGNED_TENANT_B: &str = "signed-tenant-b";
const SIGNED_TENANT_C: &str = "signed-tenant-c";

struct UnusedAuthenticator;

impl TenantAuthenticator for UnusedAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        panic!("configuration validation must not authenticate")
    }
}

struct CompatibleExecutor;

impl TenantScopedGetDecisionExecutor for CompatibleExecutor {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        Box::pin(async { Err(GetDecisionRequestExecutionError::NotFound) })
    }
}

impl TenantScopedWatchDecisionExecutor for CompatibleExecutor {
    type Source = UnusedReplaySource;

    fn execute_watch_decision(
        &self,
        _scope: TenantScope,
        _query: WatchDecisionQuery,
        _page_size: DecisionReplayPageSize,
    ) -> DecisionReplay<Self::Source> {
        panic!("configuration validation must not execute WatchDecision")
    }
}

struct UnusedReplaySource;

impl DecisionReplaySource for UnusedReplaySource {
    type Continuation = ();

    fn read_page<'a>(
        &'a mut self,
        _query: WatchDecisionQuery,
        _page_size: DecisionReplayPageSize,
        _continuation: Option<&'a Self::Continuation>,
    ) -> DecisionReplaySourceFuture<'a, Self::Continuation> {
        Box::pin(async { Ok(DecisionReplaySourcePage::new(Vec::new(), None::<()>)) })
    }
}

struct RecordingAuthenticator {
    calls: Arc<AtomicUsize>,
    authority_for: Duration,
}

impl TenantAuthenticator for RecordingAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let authority_for = self.authority_for;
        Box::pin(async move {
            TenantAuthority::try_new("trusted-tenant".to_owned(), Instant::now() + authority_for)
                .map_err(|_| AuthenticateTenantError::rejected())
        })
    }
}

struct SimulatedSignedTokenAuthenticator;

impl TenantAuthenticator for SimulatedSignedTokenAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        let tenant_id = context
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .and_then(|token| match token {
                SIGNED_TOKEN_A => Some(SIGNED_TENANT_A),
                SIGNED_TOKEN_B => Some(SIGNED_TENANT_B),
                SIGNED_TOKEN_C => Some(SIGNED_TENANT_C),
                _ => None,
            });
        Box::pin(async move {
            let tenant_id = tenant_id.ok_or_else(AuthenticateTenantError::rejected)?;
            TenantAuthority::try_new(
                tenant_id.to_owned(),
                Instant::now() + Duration::from_secs(60),
            )
            .map_err(|_| AuthenticateTenantError::rejected())
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct WatchObservation {
    tenant_id: String,
    decision_id: String,
    page_size: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct GetObservation {
    tenant_id: String,
    decision_id: String,
}

struct RecordingReplaySource {
    reads: Arc<AtomicUsize>,
    behavior: Option<ReadBehavior>,
}

enum ReadBehavior {
    Page(DecisionReplaySourcePage<()>),
    Pending(Arc<AtomicBool>),
}

struct PendingRead {
    dropped: Arc<AtomicBool>,
}

impl Future for PendingRead {
    type Output = Result<DecisionReplaySourcePage<()>, DecisionReplaySourceError>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PendingRead {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

impl DecisionReplaySource for RecordingReplaySource {
    type Continuation = ();

    fn read_page<'a>(
        &'a mut self,
        _query: WatchDecisionQuery,
        _page_size: DecisionReplayPageSize,
        _continuation: Option<&'a Self::Continuation>,
    ) -> DecisionReplaySourceFuture<'a, Self::Continuation> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        match self
            .behavior
            .take()
            .expect("finite replay source must be read once")
        {
            ReadBehavior::Page(page) => Box::pin(async move { Ok(page) }),
            ReadBehavior::Pending(dropped) => Box::pin(PendingRead { dropped }),
        }
    }
}

struct RecordingExecutor {
    get_observations: Arc<Mutex<Vec<GetObservation>>>,
    observations: Arc<Mutex<Vec<WatchObservation>>>,
    sources: Mutex<VecDeque<RecordingReplaySource>>,
}

impl TenantScopedGetDecisionExecutor for RecordingExecutor {
    fn execute_get_decision(
        &self,
        scope: TenantScope,
        query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        self.get_observations.lock().unwrap().push(GetObservation {
            tenant_id: scope.tenant_id().to_owned(),
            decision_id: query.decision_id().to_string(),
        });
        Box::pin(async { Err(GetDecisionRequestExecutionError::NotFound) })
    }
}

impl TenantScopedWatchDecisionExecutor for RecordingExecutor {
    type Source = RecordingReplaySource;

    fn execute_watch_decision(
        &self,
        scope: TenantScope,
        query: WatchDecisionQuery,
        page_size: DecisionReplayPageSize,
    ) -> DecisionReplay<Self::Source> {
        self.observations.lock().unwrap().push(WatchObservation {
            tenant_id: scope.tenant_id().to_owned(),
            decision_id: query.decision_id().to_string(),
            page_size: page_size.get(),
        });
        let source = self
            .sources
            .lock()
            .unwrap()
            .pop_front()
            .expect("Watch executor must own one source per admitted request");

        DecisionReplay::new(source, query, page_size)
    }
}

fn recording_service(
    auth_calls: Arc<AtomicUsize>,
    observations: Arc<Mutex<Vec<WatchObservation>>>,
    reads: Arc<AtomicUsize>,
    events: Vec<DecisionEvent>,
) -> DecisionGrpcService<RecordingAuthenticator, RecordingExecutor> {
    recording_service_with(
        auth_calls,
        observations,
        reads,
        [ReadBehavior::Page(DecisionReplaySourcePage::new(
            events, None,
        ))],
        Duration::from_secs(5),
        Duration::from_secs(60),
    )
}

fn recording_service_with(
    auth_calls: Arc<AtomicUsize>,
    observations: Arc<Mutex<Vec<WatchObservation>>>,
    reads: Arc<AtomicUsize>,
    behaviors: impl IntoIterator<Item = ReadBehavior>,
    request_timeout: Duration,
    authority_for: Duration,
) -> DecisionGrpcService<RecordingAuthenticator, RecordingExecutor> {
    DecisionGrpcService::try_new_with_watch(
        RecordingAuthenticator {
            calls: auth_calls,
            authority_for,
        },
        RecordingExecutor {
            get_observations: Arc::new(Mutex::new(Vec::new())),
            observations,
            sources: Mutex::new(
                behaviors
                    .into_iter()
                    .map(|behavior| RecordingReplaySource {
                        reads: Arc::clone(&reads),
                        behavior: Some(behavior),
                    })
                    .collect(),
            ),
        },
        DecisionGrpcServiceConfig::try_new(2, request_timeout).unwrap(),
        DecisionGrpcWatchConfig::try_new(1, 1).unwrap(),
    )
    .expect("valid Watch configuration must construct the service")
}

#[allow(deprecated)]
fn event() -> DecisionEvent {
    DecisionEvent {
        decision: Some(DecisionRecord {
            decision_id: DECISION_ID.to_owned(),
            cou_id: "COU-WATCH-SERVICE-001".to_owned(),
            evidence_snapshot_id: String::new(),
            recommendation: Recommendation::Abstain as i32,
            rationale: vec!["Recorded Watch service rationale.".to_owned()],
            aggregate_version: 1,
            evidence: Some(EvidenceSnapshotRef {
                id: "ES-WATCH-SERVICE-001".to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
            ood_status: None,
            ood_detector: None,
            prediction_interval: None,
            prediction_positions: Vec::new(),
            decision_criterion: None,
        }),
        event_id: EVENT_ID.to_owned(),
    }
}

fn page(events: Vec<DecisionEvent>) -> ReadBehavior {
    ReadBehavior::Page(DecisionReplaySourcePage::new(events, None))
}

fn watch_request() -> Request<WatchDecisionRequest> {
    Request::new(WatchDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    })
}

fn signed_request<T>(message: T, token: &str, hostile_tenant: &str) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
        .metadata_mut()
        .insert("x-tenant-id", hostile_tenant.parse().unwrap());
    request
}

fn assert_public_status(status: &Status, code: Code, message: &str) {
    assert_eq!(status.code(), code);
    assert_eq!(status.message(), message);
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
}

async fn wait_for_worker_count(lifecycle: &DecisionGrpcWatchLifecycle, expected: usize) {
    for _ in 0..16 {
        if lifecycle.active_workers() == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(lifecycle.active_workers(), expected);
}

async fn wait_for_reads(reads: &AtomicUsize, expected: usize) {
    for _ in 0..16 {
        if reads.load(Ordering::SeqCst) == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(reads.load(Ordering::SeqCst), expected);
}

#[test]
fn watch_configuration_accepts_its_exact_supported_bounds() {
    assert!(DecisionGrpcWatchConfig::try_new(1, 1).is_ok());
    assert!(DecisionGrpcWatchConfig::try_new(256, 256).is_ok());
}

#[test]
fn watch_configuration_rejects_zero_excess_and_tenant_over_global() {
    for (global, per_tenant) in [(0, 1), (1, 0), (2, 3), (256, 257), (257, 1)] {
        assert!(DecisionGrpcWatchConfig::try_new(global, per_tenant).is_err());
    }
}

#[test]
fn watch_construction_requires_global_capacity_below_service_capacity() {
    let service_config = DecisionGrpcServiceConfig::try_new(2, Duration::from_secs(5)).unwrap();
    let watch_config = DecisionGrpcWatchConfig::try_new(2, 1).unwrap();

    let result = DecisionGrpcService::try_new_with_watch(
        UnusedAuthenticator,
        CompatibleExecutor,
        service_config,
        watch_config,
    );

    assert!(result.is_err());
}

#[tokio::test]
async fn activated_watch_uses_authenticated_tenant_and_returns_its_first_event() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observations = Arc::new(Mutex::new(Vec::new()));
    let reads = Arc::new(AtomicUsize::new(0));
    let expected = event();
    let service = recording_service(
        Arc::clone(&auth_calls),
        Arc::clone(&observations),
        Arc::clone(&reads),
        vec![expected.clone()],
    );
    let mut request = Request::new(WatchDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    });
    request
        .metadata_mut()
        .insert("x-tenant-id", "hostile-client-tenant".parse().unwrap());

    let mut stream = GeneratedDecisionService::watch_decision(&service, request)
        .await
        .expect("authenticated Watch request must return a stream")
        .into_inner();
    let actual = stream
        .next()
        .await
        .expect("recorded event must exist")
        .expect("recorded event must succeed");

    assert_eq!(actual, expected);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *observations.lock().unwrap(),
        [WatchObservation {
            tenant_id: "trusted-tenant".to_owned(),
            decision_id: DECISION_ID.to_owned(),
            page_size: 1,
        }]
    );
}

#[tokio::test]
async fn activated_watch_does_not_read_its_source_before_the_first_stream_poll() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observations = Arc::new(Mutex::new(Vec::new()));
    let reads = Arc::new(AtomicUsize::new(0));
    let service = recording_service(auth_calls, observations, Arc::clone(&reads), vec![event()]);

    let response = GeneratedDecisionService::watch_decision(
        &service,
        Request::new(WatchDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        }),
    )
    .await
    .expect("authenticated Watch request must return a stream");
    tokio::task::yield_now().await;

    assert_eq!(reads.load(Ordering::SeqCst), 0);

    let mut stream = response.into_inner();
    assert!(stream.next().await.unwrap().is_ok());
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn expired_worker_never_constructs_its_replay() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let service = recording_service(
        Arc::new(AtomicUsize::new(0)),
        Arc::clone(&observations),
        Arc::new(AtomicUsize::new(0)),
        vec![event()],
    );
    let response = GeneratedDecisionService::watch_decision(
        &service,
        Request::new(WatchDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        }),
    )
    .await
    .expect("Watch admission must complete before its deadline");

    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;

    assert!(observations.lock().unwrap().is_empty());
    let status = response
        .into_inner()
        .next()
        .await
        .expect("deadline terminal must be emitted")
        .expect_err("expired Watch must not emit an event");
    assert_eq!(status.code(), Code::DeadlineExceeded);
}

#[tokio::test]
async fn shutdown_worker_never_constructs_its_replay() {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let service = recording_service(
        Arc::new(AtomicUsize::new(0)),
        Arc::clone(&observations),
        Arc::new(AtomicUsize::new(0)),
        vec![event()],
    );
    let response = GeneratedDecisionService::watch_decision(
        &service,
        Request::new(WatchDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        }),
    )
    .await
    .expect("Watch admission must complete before shutdown");
    let lifecycle = service.watch_lifecycle().unwrap();

    lifecycle.begin_shutdown();
    lifecycle.wait().await;

    assert!(observations.lock().unwrap().is_empty());
    drop(response);
}

#[tokio::test(start_paused = true)]
async fn unpolled_watch_body_expires_releases_workers_and_recovers_capacity() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observations = Arc::new(Mutex::new(Vec::new()));
    let reads = Arc::new(AtomicUsize::new(0));
    let service = recording_service_with(
        auth_calls,
        observations,
        Arc::clone(&reads),
        [page(Vec::new()), page(Vec::new())],
        Duration::from_secs(5),
        Duration::from_secs(60),
    );
    let lifecycle = service
        .watch_lifecycle()
        .expect("Watch-enabled service must expose its lifecycle");

    let unpolled = GeneratedDecisionService::watch_decision(&service, watch_request())
        .await
        .expect("first Watch request must be admitted");

    assert_eq!(lifecycle.active_workers(), 1);
    assert_eq!(reads.load(Ordering::SeqCst), 0);

    tokio::time::advance(Duration::from_secs(5)).await;
    wait_for_worker_count(&lifecycle, 0).await;

    assert_eq!(reads.load(Ordering::SeqCst), 0);
    let recovered = GeneratedDecisionService::watch_decision(&service, watch_request())
        .await
        .expect("deadline must release service, Watch, and tenant capacity");
    assert_eq!(lifecycle.active_workers(), 1);

    drop(recovered);
    wait_for_worker_count(&lifecycle, 0).await;
    drop(unpolled);
}

#[tokio::test(start_paused = true)]
async fn watch_stream_uses_earliest_deadline_with_service_precedence_on_equality() {
    for (request_timeout, authority_for, expected_code, expected_message) in [
        (
            Duration::from_secs(5),
            Duration::from_secs(2),
            Code::Unauthenticated,
            "authentication is required",
        ),
        (
            Duration::from_secs(2),
            Duration::from_secs(5),
            Code::DeadlineExceeded,
            "decision request deadline exceeded",
        ),
        (
            Duration::from_secs(3),
            Duration::from_secs(3),
            Code::DeadlineExceeded,
            "decision request deadline exceeded",
        ),
    ] {
        let reads = Arc::new(AtomicUsize::new(0));
        let service = recording_service_with(
            Arc::new(AtomicUsize::new(0)),
            Arc::new(Mutex::new(Vec::new())),
            Arc::clone(&reads),
            [page(Vec::new())],
            request_timeout,
            authority_for,
        );
        let lifecycle = service.watch_lifecycle().unwrap();
        let response = GeneratedDecisionService::watch_decision(&service, watch_request())
            .await
            .expect("Watch request must return its response stream before expiry");

        tokio::time::advance(request_timeout.min(authority_for)).await;
        wait_for_worker_count(&lifecycle, 0).await;

        let status = response
            .into_inner()
            .next()
            .await
            .expect("deadline must emit one terminal status")
            .expect_err("deadline must not expose an event");
        assert_public_status(&status, expected_code, expected_message);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn repeated_pending_stream_polls_issue_only_one_source_read() {
    let pending_dropped = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let service = recording_service_with(
        Arc::new(AtomicUsize::new(0)),
        Arc::new(Mutex::new(Vec::new())),
        Arc::clone(&reads),
        [ReadBehavior::Pending(Arc::clone(&pending_dropped))],
        Duration::from_secs(5),
        Duration::from_secs(60),
    );
    let lifecycle = service.watch_lifecycle().unwrap();
    let mut stream = GeneratedDecisionService::watch_decision(&service, watch_request())
        .await
        .unwrap()
        .into_inner();

    let first = poll_fn(|context| Poll::Ready(stream.as_mut().poll_next(context))).await;
    assert!(first.is_pending());
    wait_for_reads(reads.as_ref(), 1).await;

    for _ in 0..4 {
        let repoll = poll_fn(|context| Poll::Ready(stream.as_mut().poll_next(context))).await;
        assert!(repoll.is_pending());
    }
    assert_eq!(reads.load(Ordering::SeqCst), 1);

    drop(stream);
    wait_for_worker_count(&lifecycle, 0).await;
    assert!(pending_dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn dropping_client_during_pending_read_cancels_source_and_recovers_capacity() {
    let pending_dropped = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let service = recording_service_with(
        Arc::new(AtomicUsize::new(0)),
        Arc::new(Mutex::new(Vec::new())),
        Arc::clone(&reads),
        [
            ReadBehavior::Pending(Arc::clone(&pending_dropped)),
            page(Vec::new()),
        ],
        Duration::from_secs(5),
        Duration::from_secs(60),
    );
    let lifecycle = service.watch_lifecycle().unwrap();
    let mut stream = GeneratedDecisionService::watch_decision(&service, watch_request())
        .await
        .unwrap()
        .into_inner();

    let first = poll_fn(|context| Poll::Ready(stream.as_mut().poll_next(context))).await;
    assert!(first.is_pending());
    wait_for_reads(reads.as_ref(), 1).await;

    drop(stream);
    wait_for_worker_count(&lifecycle, 0).await;

    assert!(pending_dropped.load(Ordering::SeqCst));
    let recovered = GeneratedDecisionService::watch_decision(&service, watch_request())
        .await
        .expect("client drop must release service, Watch, and tenant capacity");
    drop(recovered);
    wait_for_worker_count(&lifecycle, 0).await;
}

#[tokio::test]
async fn watch_quotas_preserve_get_capacity_and_recover_after_client_drop() {
    let reads = Arc::new(AtomicUsize::new(0));
    let first_a_dropped = Arc::new(AtomicBool::new(false));
    let tenant_b_dropped = Arc::new(AtomicBool::new(false));
    let recovered_a_dropped = Arc::new(AtomicBool::new(false));
    let get_observations = Arc::new(Mutex::new(Vec::new()));
    let watch_observations = Arc::new(Mutex::new(Vec::new()));
    let service = DecisionGrpcService::try_new_with_watch(
        SimulatedSignedTokenAuthenticator,
        RecordingExecutor {
            get_observations: Arc::clone(&get_observations),
            observations: Arc::clone(&watch_observations),
            sources: Mutex::new(
                [
                    Arc::clone(&first_a_dropped),
                    Arc::clone(&tenant_b_dropped),
                    Arc::clone(&recovered_a_dropped),
                ]
                .into_iter()
                .map(|dropped| RecordingReplaySource {
                    reads: Arc::clone(&reads),
                    behavior: Some(ReadBehavior::Pending(dropped)),
                })
                .collect(),
            ),
        },
        DecisionGrpcServiceConfig::try_new(3, Duration::from_secs(5)).unwrap(),
        DecisionGrpcWatchConfig::try_new(2, 1).unwrap(),
    )
    .expect("service and Watch quotas must be compatible");
    let lifecycle = service.watch_lifecycle().unwrap();

    let mut first_a = GeneratedDecisionService::watch_decision(
        &service,
        signed_request(
            watch_request().into_inner(),
            SIGNED_TOKEN_A,
            SIGNED_TENANT_B,
        ),
    )
    .await
    .expect("first tenant A Watch must be admitted")
    .into_inner();
    assert!(
        poll_fn(|context| Poll::Ready(first_a.as_mut().poll_next(context)))
            .await
            .is_pending()
    );
    wait_for_reads(reads.as_ref(), 1).await;

    let second_a = match GeneratedDecisionService::watch_decision(
        &service,
        signed_request(
            watch_request().into_inner(),
            SIGNED_TOKEN_A,
            SIGNED_TENANT_C,
        ),
    )
    .await
    {
        Ok(_) => panic!("per-tenant quota must reject a second tenant A Watch"),
        Err(status) => status,
    };
    assert_public_status(
        &second_a,
        Code::ResourceExhausted,
        "decision service is at capacity",
    );

    let mut tenant_b = GeneratedDecisionService::watch_decision(
        &service,
        signed_request(
            watch_request().into_inner(),
            SIGNED_TOKEN_B,
            SIGNED_TENANT_A,
        ),
    )
    .await
    .expect("tenant B Watch must use the remaining global slot")
    .into_inner();
    assert!(
        poll_fn(|context| Poll::Ready(tenant_b.as_mut().poll_next(context)))
            .await
            .is_pending()
    );
    wait_for_reads(reads.as_ref(), 2).await;
    assert_eq!(lifecycle.active_workers(), 2);

    let tenant_c = match GeneratedDecisionService::watch_decision(
        &service,
        signed_request(
            watch_request().into_inner(),
            SIGNED_TOKEN_C,
            SIGNED_TENANT_A,
        ),
    )
    .await
    {
        Ok(_) => panic!("global quota must reject tenant C Watch"),
        Err(status) => status,
    };
    assert_public_status(
        &tenant_c,
        Code::ResourceExhausted,
        "decision service is at capacity",
    );

    let get = GeneratedDecisionService::get_decision(
        &service,
        signed_request(
            GetDecisionRequest {
                decision_id: DECISION_ID.to_owned(),
            },
            SIGNED_TOKEN_C,
            SIGNED_TENANT_A,
        ),
    )
    .await
    .expect_err("instrumented Get executor returns NotFound after admission");
    assert_public_status(&get, Code::NotFound, "decision was not found");
    assert_eq!(
        *get_observations.lock().unwrap(),
        [GetObservation {
            tenant_id: SIGNED_TENANT_C.to_owned(),
            decision_id: DECISION_ID.to_owned(),
        }]
    );

    drop(first_a);
    wait_for_worker_count(&lifecycle, 1).await;
    assert!(first_a_dropped.load(Ordering::SeqCst));

    let mut recovered_a = GeneratedDecisionService::watch_decision(
        &service,
        signed_request(
            watch_request().into_inner(),
            SIGNED_TOKEN_A,
            SIGNED_TENANT_C,
        ),
    )
    .await
    .expect("dropping tenant A Watch must recover its tenant quota")
    .into_inner();
    assert!(
        poll_fn(|context| Poll::Ready(recovered_a.as_mut().poll_next(context)))
            .await
            .is_pending()
    );
    wait_for_reads(reads.as_ref(), 3).await;
    assert_eq!(
        *watch_observations.lock().unwrap(),
        [
            WatchObservation {
                tenant_id: SIGNED_TENANT_A.to_owned(),
                decision_id: DECISION_ID.to_owned(),
                page_size: 1,
            },
            WatchObservation {
                tenant_id: SIGNED_TENANT_B.to_owned(),
                decision_id: DECISION_ID.to_owned(),
                page_size: 1,
            },
            WatchObservation {
                tenant_id: SIGNED_TENANT_A.to_owned(),
                decision_id: DECISION_ID.to_owned(),
                page_size: 1,
            },
        ]
    );

    drop(tenant_b);
    drop(recovered_a);
    wait_for_worker_count(&lifecycle, 0).await;
    assert!(tenant_b_dropped.load(Ordering::SeqCst));
    assert!(recovered_a_dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn forced_worker_abort_drops_pending_work_and_recovers_capacity() {
    let pending_dropped = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let service = recording_service_with(
        Arc::new(AtomicUsize::new(0)),
        Arc::new(Mutex::new(Vec::new())),
        Arc::clone(&reads),
        [
            ReadBehavior::Pending(Arc::clone(&pending_dropped)),
            page(Vec::new()),
        ],
        Duration::from_secs(5),
        Duration::from_secs(60),
    );
    let lifecycle = service.watch_lifecycle().unwrap();
    let mut stream = GeneratedDecisionService::watch_decision(&service, watch_request())
        .await
        .unwrap()
        .into_inner();
    let first = poll_fn(|context| Poll::Ready(stream.as_mut().poll_next(context))).await;
    assert!(first.is_pending());
    wait_for_reads(reads.as_ref(), 1).await;

    lifecycle.abort_workers();
    wait_for_worker_count(&lifecycle, 0).await;

    assert!(pending_dropped.load(Ordering::SeqCst));
    let status = stream
        .next()
        .await
        .expect("aborted worker must close with one terminal status")
        .expect_err("aborted worker must not emit an event");
    assert_public_status(
        &status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    let recovered = GeneratedDecisionService::watch_decision(&service, watch_request())
        .await
        .expect("forced abort must release service, Watch, and tenant capacity");
    drop(recovered);
    wait_for_worker_count(&lifecycle, 0).await;
}
