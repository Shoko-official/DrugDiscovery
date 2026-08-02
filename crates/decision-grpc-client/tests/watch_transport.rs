use std::{
    collections::VecDeque,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bioworld_contracts::v2::{
    DecisionEvent, DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest, ProposeDecisionRequest,
    Recommendation, WatchDecisionRequest,
    decision_service_server::{DecisionService, DecisionServiceServer},
};
use bioworld_decision_grpc_client::{
    AccessToken, AccessTokenFuture, AccessTokenProvider, AccessTokenProviderError,
    DecisionGrpcClient, DecisionGrpcClientConfig, DecisionGrpcClientError,
    DecisionGrpcClientLimits, DecisionGrpcWatchLimits,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::{sync::oneshot, task::JoinHandle};
use tonic::{
    Request, Response, Status,
    transport::{Identity, Server, ServerTlsConfig, server::TcpIncoming},
};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
const FIRST_EVENT_ID: &str = "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba";
const SECOND_EVENT_ID: &str = "0193a72e-71cc-7d40-b59c-f6eb4f0bf6bb";
const ACCESS_TOKEN: &str = "header.payload.signature";
const TEST_TIMEOUT: Duration = Duration::from_secs(3);

struct StaticAccessTokenProvider {
    calls: Arc<AtomicUsize>,
}

impl AccessTokenProvider for StaticAccessTokenProvider {
    fn access_token(&self) -> AccessTokenFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            AccessToken::try_new(ACCESS_TOKEN.to_owned()).map_err(|_| AccessTokenProviderError)
        })
    }
}

struct FiniteEventStream {
    events: VecDeque<Result<DecisionEvent, Status>>,
}

impl tonic::codegen::tokio_stream::Stream for FiniteEventStream {
    type Item = Result<DecisionEvent, Status>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.events.pop_front())
    }
}

struct GatedResponse {
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
    event_reads: Arc<AtomicUsize>,
}

struct GatedEventStream {
    event: Option<DecisionEvent>,
    entered: Option<oneshot::Sender<()>>,
    release: oneshot::Receiver<()>,
    event_reads: Arc<AtomicUsize>,
    read_started: bool,
}

struct ObservedPendingResponse {
    entered: oneshot::Sender<()>,
    dropped: oneshot::Sender<()>,
}

struct ObservedPendingStream {
    entered: Option<oneshot::Sender<()>>,
    dropped: Option<oneshot::Sender<()>>,
}

impl tonic::codegen::tokio_stream::Stream for ObservedPendingStream {
    type Item = Result<DecisionEvent, Status>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
        }
        Poll::Pending
    }
}

impl Drop for ObservedPendingStream {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl tonic::codegen::tokio_stream::Stream for GatedEventStream {
    type Item = Result<DecisionEvent, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.event.is_none() {
            return Poll::Ready(None);
        }
        if !self.read_started {
            self.read_started = true;
            self.event_reads.fetch_add(1, Ordering::SeqCst);
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
        }
        match Pin::new(&mut self.release).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(self.event.take().map(Ok)),
            Poll::Ready(Err(_)) => Poll::Ready(Some(Err(Status::unavailable(
                "decision service is unavailable",
            )))),
        }
    }
}

struct WatchService {
    calls: Arc<AtomicUsize>,
    get_calls: Arc<AtomicUsize>,
    response_delay: Duration,
    gated: Mutex<Option<GatedResponse>>,
    observed_pending: Mutex<Option<ObservedPendingResponse>>,
}

#[tonic::async_trait]
impl DecisionService for WatchService {
    async fn get_decision(
        &self,
        request: Request<GetDecisionRequest>,
    ) -> Result<Response<DecisionRecord>, Status> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        if authorization != Some("Bearer header.payload.signature") {
            return Err(Status::unauthenticated("authentication is required"));
        }
        if request.get_ref().decision_id != DECISION_ID {
            return Err(Status::invalid_argument("decision request is invalid"));
        }

        Ok(Response::new(
            decision_event(FIRST_EVENT_ID, 1)
                .decision
                .expect("test event must contain a decision"),
        ))
    }

    async fn propose_decision(
        &self,
        _request: Request<ProposeDecisionRequest>,
    ) -> Result<Response<DecisionRecord>, Status> {
        Err(Status::unimplemented("unused operation"))
    }

    type WatchDecisionStream = Pin<
        Box<
            dyn tonic::codegen::tokio_stream::Stream<Item = Result<DecisionEvent, Status>>
                + Send
                + 'static,
        >,
    >;

    async fn watch_decision(
        &self,
        request: Request<WatchDecisionRequest>,
    ) -> Result<Response<Self::WatchDecisionStream>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        if authorization != Some("Bearer header.payload.signature") {
            return Err(Status::unauthenticated("authentication is required"));
        }
        if request.get_ref().decision_id != DECISION_ID {
            return Err(Status::invalid_argument("decision request is invalid"));
        }
        tokio::time::sleep(self.response_delay).await;

        if let Some(gated) = self
            .gated
            .lock()
            .expect("gated response lock poisoned")
            .take()
        {
            return Ok(Response::new(Box::pin(GatedEventStream {
                event: Some(decision_event(FIRST_EVENT_ID, 1)),
                entered: Some(gated.entered),
                release: gated.release,
                event_reads: gated.event_reads,
                read_started: false,
            })));
        }

        if let Some(observed) = self
            .observed_pending
            .lock()
            .expect("observed pending response lock poisoned")
            .take()
        {
            return Ok(Response::new(Box::pin(ObservedPendingStream {
                entered: Some(observed.entered),
                dropped: Some(observed.dropped),
            })));
        }

        let events = [
            decision_event(FIRST_EVENT_ID, 1),
            decision_event(SECOND_EVENT_ID, 2),
        ]
        .into_iter()
        .map(Ok)
        .collect();
        Ok(Response::new(Box::pin(FiniteEventStream { events })))
    }
}

struct TestServer {
    address: SocketAddr,
    certificate_pem: Vec<u8>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl TestServer {
    fn client_config(&self) -> DecisionGrpcClientConfig {
        self.client_config_with_limits(Duration::from_secs(2), 4)
    }

    fn client_config_with_request_timeout(
        &self,
        request_timeout: Duration,
    ) -> DecisionGrpcClientConfig {
        self.client_config_with_limits(request_timeout, 4)
    }

    fn client_config_with_limits(
        &self,
        request_timeout: Duration,
        max_in_flight: usize,
    ) -> DecisionGrpcClientConfig {
        DecisionGrpcClientConfig::try_new(
            format!("https://{}", self.address),
            "localhost".to_owned(),
            self.certificate_pem.clone(),
            DecisionGrpcClientLimits::try_new_with_watch_capacity(
                Duration::from_secs(2),
                Duration::from_secs(2),
                request_timeout,
                max_in_flight,
                max_in_flight - 1,
            )
            .expect("test client limits must be valid"),
        )
        .expect("test client configuration must be valid")
    }

    async fn stop(self) {
        self.shutdown.send(()).expect("test server must be running");
        guarded(self.task)
            .await
            .expect("test server task must join")
            .expect("test server must stop cleanly");
    }
}

async fn start_server(calls: Arc<AtomicUsize>, response_delay: Duration) -> TestServer {
    start_server_with_responses(
        calls,
        Arc::new(AtomicUsize::new(0)),
        response_delay,
        None,
        None,
    )
    .await
}

async fn start_server_with_gated_response(
    calls: Arc<AtomicUsize>,
    response_delay: Duration,
    gated: Option<GatedResponse>,
) -> TestServer {
    start_server_with_responses(
        calls,
        Arc::new(AtomicUsize::new(0)),
        response_delay,
        gated,
        None,
    )
    .await
}

async fn start_server_with_responses(
    calls: Arc<AtomicUsize>,
    get_calls: Arc<AtomicUsize>,
    response_delay: Duration,
    gated: Option<GatedResponse>,
    observed_pending: Option<ObservedPendingResponse>,
) -> TestServer {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("test TLS identity must be generated");
    let certificate_pem = cert.pem().into_bytes();
    let identity = Identity::from_pem(
        certificate_pem.clone(),
        signing_key.serialize_pem().into_bytes(),
    );
    let incoming = TcpIncoming::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("test listener must bind");
    let address = incoming
        .local_addr()
        .expect("test address must be available");
    let (shutdown, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))?
            .add_service(DecisionServiceServer::new(WatchService {
                calls,
                get_calls,
                response_delay,
                gated: Mutex::new(gated),
                observed_pending: Mutex::new(observed_pending),
            }))
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    TestServer {
        address,
        certificate_pem,
        shutdown,
        task,
    }
}

#[allow(deprecated)]
fn decision_event(event_id: &str, aggregate_version: u64) -> DecisionEvent {
    DecisionEvent {
        event_id: event_id.to_owned(),
        decision: Some(DecisionRecord {
            decision_id: DECISION_ID.to_owned(),
            cou_id: "COU-WATCH-CLIENT".to_owned(),
            evidence_snapshot_id: "ES-WATCH-CLIENT".to_owned(),
            recommendation: Recommendation::Promote as i32,
            rationale: vec!["Bounded authenticated replay event.".to_owned()],
            aggregate_version,
            evidence: Some(EvidenceSnapshotRef {
                id: "ES-WATCH-CLIENT".to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
            ood_status: None,
            ood_detector: None,
            prediction_interval: None,
            prediction_positions: Vec::new(),
            decision_criterion: None,
        }),
    }
}

async fn guarded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TEST_TIMEOUT, future)
        .await
        .expect("test operation timed out")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consumes_two_authenticated_events_in_order_then_stays_at_eof() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let rpc_calls = Arc::new(AtomicUsize::new(0));
    let server = start_server(Arc::clone(&rpc_calls), Duration::ZERO).await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");

    let mut watch = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("authenticated Watch must open");
    let first = guarded(watch.next_event())
        .await
        .expect("first event read must succeed")
        .expect("first event must exist");
    let second = guarded(watch.next_event())
        .await
        .expect("second event read must succeed")
        .expect("second event must exist");

    assert_eq!(first.event_id().to_string(), FIRST_EVENT_ID);
    assert_eq!(first.decision().aggregate_version().get(), 1);
    assert_eq!(first.decision().decision().id().to_string(), DECISION_ID);
    assert_eq!(second.event_id().to_string(), SECOND_EVENT_ID);
    assert_eq!(second.decision().aggregate_version().get(), 2);
    assert_eq!(second.decision().decision().id().to_string(), DECISION_ID);
    assert!(guarded(watch.next_event()).await.unwrap().is_none());
    assert!(guarded(watch.next_event()).await.unwrap().is_none());
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rpc_calls.load(Ordering::SeqCst), 1);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_setup_uses_the_shorter_request_deadline() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let rpc_calls = Arc::new(AtomicUsize::new(0));
    let server = start_server(Arc::clone(&rpc_calls), Duration::from_millis(200)).await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config_with_request_timeout(Duration::from_millis(50)),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");

    let error = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .err()
        .expect("Watch headers beyond the request deadline must fail");

    assert_eq!(
        error,
        bioworld_decision_grpc_client::DecisionGrpcClientError::DeadlineExceeded,
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rpc_calls.load(Ordering::SeqCst), 1);

    server.stop().await;
}

#[tokio::test]
async fn dropping_a_watch_releases_admission_before_the_next_call() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let rpc_calls = Arc::new(AtomicUsize::new(0));
    let server = start_server(Arc::clone(&rpc_calls), Duration::ZERO).await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config_with_limits(Duration::from_secs(2), 2),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");
    let first = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("first Watch must open");

    drop(first);

    let recovered = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("dropping a Watch must restore admission before the next call");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(rpc_calls.load(Ordering::SeqCst), 2);

    drop(recovered);
    server.stop().await;
}

#[tokio::test]
async fn live_watch_saturation_reserves_get_capacity_and_recovers_after_drop() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let get_calls = Arc::new(AtomicUsize::new(0));
    let server = start_server_with_responses(
        Arc::clone(&watch_calls),
        Arc::clone(&get_calls),
        Duration::ZERO,
        None,
        None,
    )
    .await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config_with_limits(Duration::from_secs(2), 2),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let cloned = client.clone();
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");
    let first = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("first Watch must open");

    let saturated = guarded(cloned.watch_decision(DECISION_ID, limits))
        .await
        .err()
        .expect("second Watch must fail while the first Watch retains admission");
    assert_eq!(saturated, DecisionGrpcClientError::CapacityExhausted);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 1);

    let decision = guarded(cloned.get_decision(DECISION_ID))
        .await
        .expect("Get must use the reserved admission slot");
    assert_eq!(decision.aggregate_version().get(), 1);
    assert_eq!(decision.decision().id().to_string(), DECISION_ID);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 1);
    assert_eq!(get_calls.load(Ordering::SeqCst), 1);

    drop(first);

    let recovered = guarded(cloned.watch_decision(DECISION_ID, limits))
        .await
        .expect("dropping the first Watch must restore Watch admission");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 3);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 2);
    assert_eq!(get_calls.load(Ordering::SeqCst), 1);

    drop(recovered);
    server.stop().await;
}

#[tokio::test]
async fn unpolled_watch_expires_cancels_body_and_reports_terminal_once() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = oneshot::channel();
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let server = start_server_with_responses(
        Arc::clone(&watch_calls),
        Arc::new(AtomicUsize::new(0)),
        Duration::ZERO,
        None,
        Some(ObservedPendingResponse {
            entered: entered_tx,
            dropped: dropped_tx,
        }),
    )
    .await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config_with_limits(Duration::from_secs(2), 2),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let cloned = client.clone();
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(1), 2)
        .expect("test Watch limits must be valid");
    let mut expired = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("first Watch must open");
    guarded(entered_rx)
        .await
        .expect("server must start the first response body");

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    guarded(dropped_rx)
        .await
        .expect("server must observe cancellation of the expired body");
    tokio::time::resume();

    let recovered = guarded(cloned.watch_decision(DECISION_ID, limits))
        .await
        .expect("Watch admission must recover before an immediate retry");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 2);

    let terminal = match guarded(expired.next_event()).await {
        Ok(_) => panic!("late terminal read must report the total deadline"),
        Err(error) => error,
    };
    assert_eq!(terminal, DecisionGrpcClientError::DeadlineExceeded);
    assert!(guarded(expired.next_event()).await.unwrap().is_none());

    drop(recovered);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_a_pending_next_event_resumes_without_duplicate_remote_demand() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let rpc_calls = Arc::new(AtomicUsize::new(0));
    let event_reads = Arc::new(AtomicUsize::new(0));
    let (entered_tx, mut entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let server = start_server_with_gated_response(
        Arc::clone(&rpc_calls),
        Duration::ZERO,
        Some(GatedResponse {
            entered: entered_tx,
            release: release_rx,
            event_reads: Arc::clone(&event_reads),
        }),
    )
    .await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");
    let mut watch = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("authenticated Watch must open");
    let mut cancelled = Box::pin(watch.next_event());

    guarded(async {
        tokio::select! {
            result = &mut cancelled => {
                panic!("gated next_event completed before cancellation: {result:?}");
            }
            entered = &mut entered_rx => {
                entered.expect("server must observe one pending event read");
            }
        }
    })
    .await;
    assert_eq!(event_reads.load(Ordering::SeqCst), 1);
    drop(cancelled);
    release_tx
        .send(())
        .expect("gated server stream must remain pending");

    let event = guarded(watch.next_event())
        .await
        .expect("resumed event read must succeed")
        .expect("released event must exist");
    assert_eq!(event.event_id().to_string(), FIRST_EVENT_ID);
    assert_eq!(event_reads.load(Ordering::SeqCst), 1);
    assert!(guarded(watch.next_event()).await.unwrap().is_none());
    assert_eq!(event_reads.load(Ordering::SeqCst), 1);
    assert!(guarded(watch.next_event()).await.unwrap().is_none());
    assert_eq!(event_reads.load(Ordering::SeqCst), 1);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(rpc_calls.load(Ordering::SeqCst), 1);

    server.stop().await;
}
