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

use bioworld_contracts::{
    MAX_DECISION_EVENT_WIRE_BYTES,
    v2::{
        DecisionEvent, DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest,
        ProposeDecisionRequest, Recommendation, WatchDecisionRequest,
        decision_service_server::{DecisionService, DecisionServiceServer},
    },
};
use bioworld_decision_grpc_client::{
    AccessToken, AccessTokenFuture, AccessTokenProvider, AccessTokenProviderError,
    DecisionGrpcClient, DecisionGrpcClientConfig, DecisionGrpcClientError,
    DecisionGrpcClientLimits, DecisionGrpcWatch, DecisionGrpcWatchLimits,
};
use prost::Message;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::{sync::oneshot, task::JoinHandle};
use tonic::{
    Code, Request, Response, Status,
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

struct PendingFirstAccessTokenProvider {
    calls: Arc<AtomicUsize>,
    entered: Mutex<Option<oneshot::Sender<()>>>,
}

struct FailOnAccessTokenCallProvider {
    calls: Arc<AtomicUsize>,
    fail_on: usize,
}

impl AccessTokenProvider for StaticAccessTokenProvider {
    fn access_token(&self) -> AccessTokenFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            AccessToken::try_new(ACCESS_TOKEN.to_owned()).map_err(|_| AccessTokenProviderError)
        })
    }
}

impl AccessTokenProvider for PendingFirstAccessTokenProvider {
    fn access_token(&self) -> AccessTokenFuture<'_> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let entered = self
            .entered
            .lock()
            .expect("token provider lock poisoned")
            .take();
        Box::pin(async move {
            if call == 0 {
                if let Some(entered) = entered {
                    let _ = entered.send(());
                }
                std::future::pending::<()>().await;
            }
            AccessToken::try_new(ACCESS_TOKEN.to_owned()).map_err(|_| AccessTokenProviderError)
        })
    }
}

impl AccessTokenProvider for FailOnAccessTokenCallProvider {
    fn access_token(&self) -> AccessTokenFuture<'_> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let fail_on = self.fail_on;
        Box::pin(async move {
            if call == fail_on {
                return Err(AccessTokenProviderError);
            }
            AccessToken::try_new(ACCESS_TOKEN.to_owned()).map_err(|_| AccessTokenProviderError)
        })
    }
}

struct FiniteEventStream {
    events: VecDeque<Result<DecisionEvent, Status>>,
}

#[derive(Clone, PartialEq, Message)]
struct PaddedDecisionEvent {
    #[prost(message, optional, tag = "1")]
    decision: Option<DecisionRecord>,
    #[prost(string, tag = "2")]
    event_id: String,
    #[prost(bytes = "vec", tag = "100")]
    padding: Vec<u8>,
}

struct PaddedEventStream {
    events: VecDeque<Result<PaddedDecisionEvent, Status>>,
}

impl tonic::codegen::tokio_stream::Stream for PaddedEventStream {
    type Item = Result<PaddedDecisionEvent, Status>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.events.pop_front())
    }
}

struct PaddedWatchService {
    calls: Arc<AtomicUsize>,
    responses: Mutex<VecDeque<Vec<PaddedDecisionEvent>>>,
}

struct PaddedWatchRpc(Arc<PaddedWatchService>);

impl tonic::server::ServerStreamingService<WatchDecisionRequest> for PaddedWatchRpc {
    type Response = PaddedDecisionEvent;
    type ResponseStream = PaddedEventStream;
    type Future = tonic::codegen::BoxFuture<Response<Self::ResponseStream>, Status>;

    fn call(&mut self, request: Request<WatchDecisionRequest>) -> Self::Future {
        let service = Arc::clone(&self.0);
        Box::pin(async move {
            service.calls.fetch_add(1, Ordering::SeqCst);
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
            let events = service
                .responses
                .lock()
                .expect("padded responses lock poisoned")
                .pop_front()
                .expect("padded response must exist")
                .into_iter()
                .map(Ok)
                .collect();
            Ok(Response::new(PaddedEventStream { events }))
        })
    }
}

#[derive(Clone, Copy, Default)]
struct PaddedWatchCodec;

#[derive(Clone, Copy, Default)]
struct PaddedWatchEncoder;

#[derive(Clone, Copy, Default)]
struct WatchRequestDecoder;

impl tonic::codec::Codec for PaddedWatchCodec {
    type Encode = PaddedDecisionEvent;
    type Decode = WatchDecisionRequest;
    type Encoder = PaddedWatchEncoder;
    type Decoder = WatchRequestDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        PaddedWatchEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        WatchRequestDecoder
    }
}

impl tonic::codec::Encoder for PaddedWatchEncoder {
    type Item = PaddedDecisionEvent;
    type Error = Status;

    fn encode(
        &mut self,
        item: Self::Item,
        destination: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        item.encode(destination)
            .map_err(|_| Status::internal("test response encoding failed"))
    }
}

impl tonic::codec::Decoder for WatchRequestDecoder {
    type Item = WatchDecisionRequest;
    type Error = Status;

    fn decode(
        &mut self,
        source: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        WatchDecisionRequest::decode(source)
            .map(Some)
            .map_err(|_| Status::invalid_argument("decision request is invalid"))
    }
}

#[derive(Clone)]
struct PaddedWatchServiceServer {
    inner: Arc<PaddedWatchService>,
}

impl<B> tonic::codegen::Service<tonic::codegen::http::Request<B>> for PaddedWatchServiceServer
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
    type Response = tonic::codegen::http::Response<tonic::body::Body>;
    type Error = std::convert::Infallible;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: tonic::codegen::http::Request<B>) -> Self::Future {
        if request.uri().path() == "/bioworld.v2.DecisionService/WatchDecision" {
            let method = PaddedWatchRpc(Arc::clone(&self.inner));
            return Box::pin(async move {
                let response = tonic::server::Grpc::new(PaddedWatchCodec)
                    .server_streaming(method, request)
                    .await;
                Ok(response)
            });
        }

        Box::pin(async move {
            let mut response = tonic::codegen::http::Response::new(tonic::body::Body::default());
            response.headers_mut().insert(
                tonic::Status::GRPC_STATUS,
                (tonic::Code::Unimplemented as i32).into(),
            );
            response.headers_mut().insert(
                tonic::codegen::http::header::CONTENT_TYPE,
                tonic::metadata::GRPC_CONTENT_TYPE,
            );
            Ok(response)
        })
    }
}

impl tonic::server::NamedService for PaddedWatchServiceServer {
    const NAME: &'static str = "bioworld.v2.DecisionService";
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
    event_sequences: Mutex<VecDeque<Vec<DecisionEvent>>>,
}

enum StatusWatchPlan {
    Startup(Code),
    Midstream(Code),
    Success,
}

struct StatusWatchService {
    calls: Arc<AtomicUsize>,
    plans: Mutex<VecDeque<StatusWatchPlan>>,
}

#[tonic::async_trait]
impl DecisionService for StatusWatchService {
    async fn get_decision(
        &self,
        _request: Request<GetDecisionRequest>,
    ) -> Result<Response<DecisionRecord>, Status> {
        Err(Status::unimplemented("unused operation"))
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

        let plan = self
            .plans
            .lock()
            .expect("status plans lock poisoned")
            .pop_front()
            .expect("status response plan must exist");
        let events = match plan {
            StatusWatchPlan::Startup(code) => {
                return Err(Status::new(code, "PRIVATE-SERVER-MARKER"));
            }
            StatusWatchPlan::Midstream(code) => vec![
                Ok(decision_event(FIRST_EVENT_ID, 1)),
                Err(Status::new(code, "PRIVATE-SERVER-MARKER")),
            ],
            StatusWatchPlan::Success => vec![
                Ok(decision_event(FIRST_EVENT_ID, 1)),
                Ok(decision_event(SECOND_EVENT_ID, 2)),
            ],
        }
        .into_iter()
        .collect();

        Ok(Response::new(Box::pin(FiniteEventStream { events })))
    }
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

        if let Some(events) = self
            .event_sequences
            .lock()
            .expect("event sequences lock poisoned")
            .pop_front()
        {
            return Ok(Response::new(Box::pin(FiniteEventStream {
                events: events.into_iter().map(Ok).collect(),
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
        VecDeque::new(),
    )
    .await
}

async fn start_server_with_event_sequences(
    calls: Arc<AtomicUsize>,
    event_sequences: VecDeque<Vec<DecisionEvent>>,
) -> TestServer {
    start_server_with_responses(
        calls,
        Arc::new(AtomicUsize::new(0)),
        Duration::ZERO,
        None,
        None,
        event_sequences,
    )
    .await
}

async fn start_padded_watch_server(
    calls: Arc<AtomicUsize>,
    responses: VecDeque<Vec<PaddedDecisionEvent>>,
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
    let service = PaddedWatchServiceServer {
        inner: Arc::new(PaddedWatchService {
            calls,
            responses: Mutex::new(responses),
        }),
    };
    let task = tokio::spawn(async move {
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))?
            .add_service(service)
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

async fn start_status_watch_server(
    calls: Arc<AtomicUsize>,
    plans: VecDeque<StatusWatchPlan>,
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
    let service = DecisionServiceServer::new(StatusWatchService {
        calls,
        plans: Mutex::new(plans),
    });
    let task = tokio::spawn(async move {
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))?
            .add_service(service)
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
        VecDeque::new(),
    )
    .await
}

async fn start_server_with_responses(
    calls: Arc<AtomicUsize>,
    get_calls: Arc<AtomicUsize>,
    response_delay: Duration,
    gated: Option<GatedResponse>,
    observed_pending: Option<ObservedPendingResponse>,
    event_sequences: VecDeque<Vec<DecisionEvent>>,
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
                event_sequences: Mutex::new(event_sequences),
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

fn padded_decision_event(target_size: usize, aggregate_version: u64) -> PaddedDecisionEvent {
    let event = decision_event(FIRST_EVENT_ID, aggregate_version);
    let mut padded = PaddedDecisionEvent {
        event_id: event.event_id,
        decision: event.decision,
        padding: Vec::new(),
    };
    let base_size = padded.encoded_len();
    assert!(base_size < target_size);
    padded.padding.resize(target_size - base_size, 0);

    loop {
        match padded.encoded_len().cmp(&target_size) {
            std::cmp::Ordering::Less => {
                let missing = target_size - padded.encoded_len();
                padded.padding.resize(padded.padding.len() + missing, 0);
            }
            std::cmp::Ordering::Greater => {
                let excess = padded.encoded_len() - target_size;
                padded.padding.truncate(padded.padding.len() - excess);
            }
            std::cmp::Ordering::Equal => return padded,
        }
    }
}

async fn guarded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TEST_TIMEOUT, future)
        .await
        .expect("test operation timed out")
}

async fn assert_two_events_then_eof(mut watch: DecisionGrpcWatch) {
    assert!(guarded(watch.next_event()).await.unwrap().is_some());
    assert!(guarded(watch.next_event()).await.unwrap().is_some());
    assert!(guarded(watch.next_event()).await.unwrap().is_none());
    assert!(guarded(watch.next_event()).await.unwrap().is_none());
}

fn tonic_error_cases() -> [(Code, DecisionGrpcClientError); 16] {
    [
        (Code::Cancelled, DecisionGrpcClientError::DeadlineExceeded),
        (Code::Unknown, DecisionGrpcClientError::Unavailable),
        (
            Code::InvalidArgument,
            DecisionGrpcClientError::InvalidResponse,
        ),
        (
            Code::DeadlineExceeded,
            DecisionGrpcClientError::DeadlineExceeded,
        ),
        (Code::NotFound, DecisionGrpcClientError::NotFound),
        (
            Code::AlreadyExists,
            DecisionGrpcClientError::InvalidResponse,
        ),
        (
            Code::PermissionDenied,
            DecisionGrpcClientError::PermissionDenied,
        ),
        (
            Code::ResourceExhausted,
            DecisionGrpcClientError::CapacityExhausted,
        ),
        (
            Code::FailedPrecondition,
            DecisionGrpcClientError::InvalidResponse,
        ),
        (Code::Aborted, DecisionGrpcClientError::Unavailable),
        (Code::OutOfRange, DecisionGrpcClientError::InvalidResponse),
        (
            Code::Unimplemented,
            DecisionGrpcClientError::InvalidResponse,
        ),
        (Code::Internal, DecisionGrpcClientError::InvalidResponse),
        (Code::Unavailable, DecisionGrpcClientError::Unavailable),
        (Code::DataLoss, DecisionGrpcClientError::InvalidResponse),
        (
            Code::Unauthenticated,
            DecisionGrpcClientError::Unauthenticated,
        ),
    ]
}

fn assert_server_detail_is_redacted(error: DecisionGrpcClientError) {
    assert!(!error.to_string().contains("PRIVATE-SERVER-MARKER"));
    assert!(!format!("{error:?}").contains("PRIVATE-SERVER-MARKER"));
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

    let (first_event_id, first_decision) = first.into_parts();

    assert_eq!(first_event_id.to_string(), FIRST_EVENT_ID);
    assert_eq!(first_decision.aggregate_version().get(), 1);
    assert_eq!(first_decision.decision().id().to_string(), DECISION_ID);
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
        VecDeque::new(),
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
        VecDeque::new(),
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

#[tokio::test]
async fn pending_token_setup_times_out_without_rpc_and_restores_watch_capacity() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let (provider_entered_tx, mut provider_entered_rx) = oneshot::channel();
    let server = start_server(Arc::clone(&watch_calls), Duration::ZERO).await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config_with_limits(Duration::from_secs(1), 2),
        PendingFirstAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
            entered: Mutex::new(Some(provider_entered_tx)),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");
    let mut stalled = Box::pin(client.watch_decision(DECISION_ID, limits));

    guarded(async {
        tokio::select! {
            result = &mut stalled => {
                panic!("Watch setup completed before its pending token deadline: {}", result.is_ok());
            }
            entered = &mut provider_entered_rx => {
                entered.expect("token provider must enter its pending first call");
            }
        }
    })
    .await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(1)).await;
    let error = match guarded(&mut stalled).await {
        Ok(_) => panic!("pending token setup must reach its deadline"),
        Err(error) => error,
    };
    tokio::time::resume();

    assert_eq!(error, DecisionGrpcClientError::DeadlineExceeded);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 0);

    let mut recovered = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("global and Watch admission must recover after setup timeout");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 1);
    assert!(guarded(recovered.next_event()).await.unwrap().is_some());
    assert!(guarded(recovered.next_event()).await.unwrap().is_some());
    assert!(guarded(recovered.next_event()).await.unwrap().is_none());
    assert!(guarded(recovered.next_event()).await.unwrap().is_none());

    server.stop().await;
}

#[tokio::test]
async fn dropping_pending_watch_setup_immediately_restores_both_capacity_quotas() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let (provider_entered_tx, mut provider_entered_rx) = oneshot::channel();
    let server = start_server(Arc::clone(&watch_calls), Duration::ZERO).await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config_with_limits(Duration::from_secs(2), 2),
        PendingFirstAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
            entered: Mutex::new(Some(provider_entered_tx)),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");
    let mut stalled = Box::pin(client.watch_decision(DECISION_ID, limits));

    guarded(async {
        tokio::select! {
            result = &mut stalled => {
                panic!("Watch setup completed before cancellation: {}", result.is_ok());
            }
            entered = &mut provider_entered_rx => {
                entered.expect("token provider must enter its pending first call");
            }
        }
    })
    .await;
    drop(stalled);

    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 0);
    let recovered = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("cancelled setup must immediately restore global and Watch capacity");
    assert_two_events_then_eof(recovered).await;
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 1);

    server.stop().await;
}

#[tokio::test]
async fn pending_next_event_reaches_absolute_deadline_drops_body_and_restores_capacity() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, mut entered_rx) = oneshot::channel();
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
        VecDeque::new(),
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
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(1), 2)
        .expect("test Watch limits must be valid");
    let mut watch = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("pending-body Watch must open");
    let mut pending = Box::pin(watch.next_event());

    guarded(async {
        tokio::select! {
            biased;
            result = &mut pending => {
                panic!("pending body completed before its deadline: {}", result.is_ok());
            }
            entered = &mut entered_rx => {
                entered.expect("server must enter its pending response body");
            }
        }
    })
    .await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    let error = match guarded(&mut pending).await {
        Ok(event) => panic!(
            "pending body must fail at the absolute deadline: {}",
            event.is_some()
        ),
        Err(error) => error,
    };
    drop(pending);
    guarded(dropped_rx)
        .await
        .expect("server must observe cancellation of the pending body");
    tokio::time::resume();

    assert_eq!(error, DecisionGrpcClientError::DeadlineExceeded);
    assert!(guarded(watch.next_event()).await.unwrap().is_none());
    assert!(guarded(watch.next_event()).await.unwrap().is_none());
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 1);

    let recovered = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("deadline termination must restore global and Watch capacity");
    assert_two_events_then_eof(recovered).await;
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 2);

    server.stop().await;
}

#[tokio::test]
async fn aborting_task_during_stream_read_drops_body_and_restores_capacity() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let (body_entered_tx, body_entered_rx) = oneshot::channel();
    let (body_dropped_tx, body_dropped_rx) = oneshot::channel();
    let server = start_server_with_responses(
        Arc::clone(&watch_calls),
        Arc::new(AtomicUsize::new(0)),
        Duration::ZERO,
        None,
        Some(ObservedPendingResponse {
            entered: body_entered_tx,
            dropped: body_dropped_tx,
        }),
        VecDeque::new(),
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
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");
    let mut watch = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("pending-body Watch must open");
    let (task_started_tx, task_started_rx) = oneshot::channel();
    let pending_task = tokio::spawn(async move {
        let _ = task_started_tx.send(());
        let result = watch.next_event().await;
        panic!("pending stream read completed before task abort: {result:?}");
    });

    guarded(task_started_rx)
        .await
        .expect("next_event task must start");
    guarded(body_entered_rx)
        .await
        .expect("server must enter its pending response body");
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    pending_task.abort();
    let cancellation = guarded(pending_task)
        .await
        .expect_err("pending next_event task must be cancelled");
    assert!(cancellation.is_cancelled());
    guarded(body_dropped_rx)
        .await
        .expect("server must observe the cancelled response body");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 1);

    let recovered = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("task cancellation must restore global and Watch capacity");
    assert_two_events_then_eof(recovered).await;
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 2);

    server.stop().await;
}

#[tokio::test]
async fn rejects_invalid_ids_and_redacts_token_failure_without_capacity_leaks() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let server = start_server(Arc::clone(&watch_calls), Duration::ZERO).await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config_with_limits(Duration::from_secs(2), 2),
        FailOnAccessTokenCallProvider {
            calls: Arc::clone(&provider_calls),
            fail_on: 2,
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");
    let oversized_decision_id = "x".repeat(1024 * 1024);

    for (invalid_id, expected_provider_calls, expected_rpc_calls) in [
        (oversized_decision_id.as_str(), 0, 0),
        ("018F5A72-9C4B-7D31-8F6A-26F08F3F4D99", 1, 1),
    ] {
        let error = guarded(client.watch_decision(invalid_id, limits))
            .await
            .err()
            .expect("invalid decision ID must fail before Watch setup");
        assert_eq!(error, DecisionGrpcClientError::InvalidDecisionId);
        assert_eq!(
            provider_calls.load(Ordering::SeqCst),
            expected_provider_calls
        );
        assert_eq!(watch_calls.load(Ordering::SeqCst), expected_rpc_calls);

        let recovered = guarded(client.watch_decision(DECISION_ID, limits))
            .await
            .expect("invalid decision ID must not consume Watch capacity");
        assert_two_events_then_eof(recovered).await;
    }

    let error = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .err()
        .expect("token provider failure must reject Watch setup");
    assert_eq!(error, DecisionGrpcClientError::AuthenticationUnavailable);
    assert_eq!(error.to_string(), "decision authentication is unavailable");
    assert_eq!(format!("{error:?}"), "AuthenticationUnavailable");
    assert!(!error.to_string().contains(ACCESS_TOKEN));
    assert_eq!(provider_calls.load(Ordering::SeqCst), 3);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 2);

    let recovered = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("token provider failure must restore global and Watch capacity");
    assert_two_events_then_eof(recovered).await;
    assert_eq!(provider_calls.load(Ordering::SeqCst), 4);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 3);

    server.stop().await;
}

#[tokio::test]
async fn rejects_invalid_watch_events_once_after_only_the_valid_prefix() {
    let mut invalid_event_id = decision_event("invalid-event-id", 1);
    invalid_event_id.event_id = "invalid-event-id".to_owned();

    let noncanonical_event_id = decision_event(&FIRST_EVENT_ID.to_uppercase(), 1);

    let mut missing_decision = decision_event(FIRST_EVENT_ID, 1);
    missing_decision.decision = None;

    let mut wrong_decision_id = decision_event(FIRST_EVENT_ID, 1);
    wrong_decision_id
        .decision
        .as_mut()
        .expect("test event must contain a decision")
        .decision_id = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d98".to_owned();

    let mut invalid_record = decision_event(FIRST_EVENT_ID, 1);
    invalid_record
        .decision
        .as_mut()
        .expect("test event must contain a decision")
        .evidence
        .as_mut()
        .expect("test decision must contain evidence")
        .sha256 = "invalid".to_owned();

    let cases = VecDeque::from([
        (vec![invalid_event_id], None),
        (vec![noncanonical_event_id], None),
        (vec![missing_decision], None),
        (vec![wrong_decision_id], None),
        (vec![invalid_record], None),
        (
            vec![
                decision_event(FIRST_EVENT_ID, 1),
                decision_event(FIRST_EVENT_ID, 2),
            ],
            Some(1),
        ),
        (
            vec![
                decision_event(FIRST_EVENT_ID, 1),
                decision_event(SECOND_EVENT_ID, 1),
            ],
            Some(1),
        ),
        (
            vec![
                decision_event(FIRST_EVENT_ID, 2),
                decision_event(SECOND_EVENT_ID, 1),
            ],
            Some(2),
        ),
    ]);
    let expected_prefix_versions = cases
        .iter()
        .map(|(_, expected_prefix_version)| *expected_prefix_version)
        .collect::<Vec<_>>();
    let event_sequences = cases
        .into_iter()
        .map(|(events, _)| events)
        .collect::<VecDeque<_>>();
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let server = start_server_with_event_sequences(Arc::clone(&watch_calls), event_sequences).await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 4)
        .expect("test Watch limits must be valid");

    for (case_index, expected_prefix_version) in expected_prefix_versions.into_iter().enumerate() {
        let mut watch = guarded(client.watch_decision(DECISION_ID, limits))
            .await
            .expect("authenticated Watch must open before event validation");
        if let Some(expected_version) = expected_prefix_version {
            let event = guarded(watch.next_event())
                .await
                .expect("valid prefix read must succeed")
                .expect("valid prefix event must exist");
            assert_eq!(event.event_id().to_string(), FIRST_EVENT_ID);
            assert_eq!(event.decision().aggregate_version().get(), expected_version);
        }

        let error = match guarded(watch.next_event()).await {
            Ok(_) => panic!("invalid Watch event must terminate the stream"),
            Err(error) => error,
        };
        assert_eq!(error, DecisionGrpcClientError::InvalidResponse);
        assert!(guarded(watch.next_event()).await.unwrap().is_none());
        assert!(guarded(watch.next_event()).await.unwrap().is_none());
        assert_eq!(provider_calls.load(Ordering::SeqCst), case_index + 1);
        assert_eq!(watch_calls.load(Ordering::SeqCst), case_index + 1);
    }

    server.stop().await;
}

#[tokio::test]
async fn enforces_the_exact_watch_transport_message_boundary() {
    let exact = padded_decision_event(MAX_DECISION_EVENT_WIRE_BYTES, 1);
    let oversized = padded_decision_event(MAX_DECISION_EVENT_WIRE_BYTES + 1, 1);
    assert_eq!(exact.encoded_len(), MAX_DECISION_EVENT_WIRE_BYTES);
    assert_eq!(oversized.encoded_len(), MAX_DECISION_EVENT_WIRE_BYTES + 1);

    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let server = start_padded_watch_server(
        Arc::clone(&watch_calls),
        VecDeque::from([vec![exact.clone()], vec![oversized], vec![exact]]),
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
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");

    let mut boundary = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("boundary-sized Watch must open");
    let event = guarded(boundary.next_event())
        .await
        .expect("boundary-sized message must decode")
        .expect("boundary-sized event must be exposed");
    assert_eq!(event.event_id().to_string(), FIRST_EVENT_ID);
    assert_eq!(event.decision().aggregate_version().get(), 1);
    assert_eq!(event.decision().decision().id().to_string(), DECISION_ID);
    assert!(guarded(boundary.next_event()).await.unwrap().is_none());

    let mut rejected = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("oversized Watch must open before body decoding");
    let error = match guarded(rejected.next_event()).await {
        Ok(_) => panic!("message one byte above the boundary must fail"),
        Err(error) => error,
    };
    assert_eq!(error, DecisionGrpcClientError::InvalidResponse);
    assert!(guarded(rejected.next_event()).await.unwrap().is_none());
    assert!(guarded(rejected.next_event()).await.unwrap().is_none());
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 2);

    let mut recovered = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("transport rejection must restore global and Watch capacity");
    assert!(guarded(recovered.next_event()).await.unwrap().is_some());
    assert!(guarded(recovered.next_event()).await.unwrap().is_none());
    assert_eq!(provider_calls.load(Ordering::SeqCst), 3);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 3);

    server.stop().await;
}

#[tokio::test]
async fn enforces_the_runtime_watch_event_budget_and_recovers_capacity() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let server = start_server_with_event_sequences(
        Arc::clone(&watch_calls),
        VecDeque::from([
            vec![
                decision_event(FIRST_EVENT_ID, 1),
                decision_event(SECOND_EVENT_ID, 2),
                decision_event("0193a72e-71cc-7d40-b59c-f6eb4f0bf6bc", 3),
            ],
            vec![
                decision_event(FIRST_EVENT_ID, 1),
                decision_event(SECOND_EVENT_ID, 2),
            ],
        ]),
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
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(2), 2)
        .expect("test Watch limits must be valid");

    let mut bounded = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("bounded Watch must open");
    let first = guarded(bounded.next_event())
        .await
        .expect("first event read must succeed")
        .expect("first event must be exposed");
    let second = guarded(bounded.next_event())
        .await
        .expect("second event read must succeed")
        .expect("second event must be exposed");
    assert_eq!(first.event_id().to_string(), FIRST_EVENT_ID);
    assert_eq!(first.decision().aggregate_version().get(), 1);
    assert_eq!(second.event_id().to_string(), SECOND_EVENT_ID);
    assert_eq!(second.decision().aggregate_version().get(), 2);

    let error = match guarded(bounded.next_event()).await {
        Ok(_) => panic!("event beyond the Watch budget must fail"),
        Err(error) => error,
    };
    assert_eq!(error, DecisionGrpcClientError::InvalidResponse);
    assert!(guarded(bounded.next_event()).await.unwrap().is_none());
    assert!(guarded(bounded.next_event()).await.unwrap().is_none());
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 1);

    let recovered = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("event budget termination must restore global and Watch capacity");
    assert_two_events_then_eof(recovered).await;
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(watch_calls.load(Ordering::SeqCst), 2);

    server.stop().await;
}

#[tokio::test]
async fn maps_all_tonic_errors_at_watch_start_and_midstream_without_retry() {
    let cases = tonic_error_cases();
    let mut plans = cases
        .iter()
        .map(|(code, _)| StatusWatchPlan::Startup(*code))
        .collect::<VecDeque<_>>();
    plans.extend(
        cases
            .iter()
            .map(|(code, _)| StatusWatchPlan::Midstream(*code)),
    );
    plans.push_back(StatusWatchPlan::Success);

    let provider_calls = Arc::new(AtomicUsize::new(0));
    let watch_calls = Arc::new(AtomicUsize::new(0));
    let server = start_status_watch_server(Arc::clone(&watch_calls), plans).await;
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

    for (case_index, (_, expected)) in cases.iter().enumerate() {
        let error = match guarded(client.watch_decision(DECISION_ID, limits)).await {
            Ok(_) => panic!("scripted Watch startup status must fail"),
            Err(error) => error,
        };
        assert_eq!(error, *expected);
        assert_server_detail_is_redacted(error);
        assert_eq!(provider_calls.load(Ordering::SeqCst), case_index + 1);
        assert_eq!(watch_calls.load(Ordering::SeqCst), case_index + 1);
    }

    for (case_index, (_, expected)) in cases.iter().enumerate() {
        let mut watch = guarded(client.watch_decision(DECISION_ID, limits))
            .await
            .expect("midstream status Watch must open");
        let prefix = guarded(watch.next_event())
            .await
            .expect("valid prefix read must succeed")
            .expect("valid prefix event must be exposed");
        assert_eq!(prefix.event_id().to_string(), FIRST_EVENT_ID);
        assert_eq!(prefix.decision().aggregate_version().get(), 1);

        let error = match guarded(watch.next_event()).await {
            Ok(event) => panic!(
                "scripted midstream status must fail before EOF: {}",
                event.is_some()
            ),
            Err(error) => error,
        };
        assert_eq!(error, *expected);
        assert_server_detail_is_redacted(error);
        assert!(guarded(watch.next_event()).await.unwrap().is_none());
        assert!(guarded(watch.next_event()).await.unwrap().is_none());

        let expected_attempts = cases.len() + case_index + 1;
        assert_eq!(provider_calls.load(Ordering::SeqCst), expected_attempts);
        assert_eq!(watch_calls.load(Ordering::SeqCst), expected_attempts);
    }

    let recovered = guarded(client.watch_decision(DECISION_ID, limits))
        .await
        .expect("all mapped terminals must restore global and Watch capacity");
    assert_two_events_then_eof(recovered).await;
    assert_eq!(provider_calls.load(Ordering::SeqCst), cases.len() * 2 + 1);
    assert_eq!(watch_calls.load(Ordering::SeqCst), cases.len() * 2 + 1);

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
