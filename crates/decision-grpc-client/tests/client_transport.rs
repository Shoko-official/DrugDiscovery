use std::{
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bioworld_contracts::{
    MAX_DECISION_WIRE_BYTES,
    v2::{
        DecisionCriterion, DecisionCriterionComparator, DecisionEvent, DecisionPredictionInterval,
        DecisionPredictionPosition, DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest,
        OodDetectorRef, OodStatus, ProposeDecisionRequest, Recommendation, WatchDecisionRequest,
        decision_service_server::{DecisionService, DecisionServiceServer},
    },
};
use bioworld_decision_grpc::{
    AuthenticateTenantError, AuthenticateTenantFuture, DecisionGrpcService,
    DecisionGrpcServiceConfig, TenantAuthenticationContext, TenantAuthenticator, TenantScope,
    TenantScopedGetDecisionExecutor, TenantScopedGetDecisionFuture,
};
use bioworld_decision_grpc_client::{
    AccessToken, AccessTokenFuture, AccessTokenProvider, AccessTokenProviderError,
    DecisionGrpcClient, DecisionGrpcClientConfig, DecisionGrpcClientError,
    DecisionGrpcClientLimits,
};
use bioworld_decision_grpc_server::{
    DecisionGrpcBind, DecisionGrpcServer, DecisionGrpcServerConfig, DecisionGrpcServerLimits,
    DecisionGrpcTlsIdentity, ServeDecisionGrpcServerError,
};
use bioworld_decision_query::GetDecisionQuery;
use prost::Message;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::{
    net::TcpListener,
    sync::{Notify, oneshot},
    task::JoinHandle,
};
use tonic::{
    Code, Request, Response, Status,
    transport::{Identity, Server, ServerTlsConfig, server::TcpIncoming},
};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
const ACCESS_TOKEN: &str = "privateHeader.privatePayload.privateSignature";
const TEST_TIMEOUT: Duration = Duration::from_secs(3);
const SLOW_OPERATION_DELAY: Duration = Duration::from_secs(2);

struct StaticAccessTokenProvider {
    calls: Arc<AtomicUsize>,
}

struct UnavailableAccessTokenProvider {
    calls: Arc<AtomicUsize>,
}

struct RejectedAccessTokenProvider;

impl AccessTokenProvider for RejectedAccessTokenProvider {
    fn access_token(&self) -> AccessTokenFuture<'_> {
        Box::pin(async {
            AccessToken::try_new("wrongHeader.wrongPayload.wrongSignature".to_owned())
                .map_err(|_| AccessTokenProviderError)
        })
    }
}

struct SlowFirstAccessTokenProvider {
    calls: Arc<AtomicUsize>,
}

impl AccessTokenProvider for SlowFirstAccessTokenProvider {
    fn access_token(&self) -> AccessTokenFuture<'_> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if call == 0 {
                tokio::time::sleep(SLOW_OPERATION_DELAY).await;
            }
            AccessToken::try_new(ACCESS_TOKEN.to_owned()).map_err(|_| AccessTokenProviderError)
        })
    }
}

impl AccessTokenProvider for UnavailableAccessTokenProvider {
    fn access_token(&self) -> AccessTokenFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(AccessTokenProviderError) })
    }
}

impl AccessTokenProvider for StaticAccessTokenProvider {
    fn access_token(&self) -> AccessTokenFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            AccessToken::try_new(ACCESS_TOKEN.to_owned()).map_err(|_| AccessTokenProviderError)
        })
    }
}

struct ExactAuthenticator {
    calls: Arc<AtomicUsize>,
}

impl TenantAuthenticator for ExactAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let authorization = context.metadata().get("authorization");
        let accepted = authorization
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == format!("Bearer {ACCESS_TOKEN}"));
        Box::pin(async move {
            if accepted {
                Ok("tenant-a".to_owned())
            } else {
                Err(AuthenticateTenantError::rejected())
            }
        })
    }
}

struct RecordingExecutor {
    observed: Arc<Mutex<Vec<(String, String)>>>,
}

struct SequencedRecordingExecutor {
    observed: Arc<Mutex<Vec<(String, String)>>>,
    responses: Mutex<VecDeque<DecisionRecord>>,
}

struct WrongIdentityExecutor;

impl TenantScopedGetDecisionExecutor for WrongIdentityExecutor {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        Box::pin(async {
            let mut response = decision_record();
            response.decision_id = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d98".to_owned();
            Ok(response)
        })
    }
}

struct BlockingFirstExecutor {
    calls: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

struct SlowFirstExecutor {
    calls: Arc<AtomicUsize>,
}

impl TenantScopedGetDecisionExecutor for SlowFirstExecutor {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if call == 0 {
                tokio::time::sleep(SLOW_OPERATION_DELAY).await;
            }
            Ok(decision_record())
        })
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
        Box::pin(async move {
            if call == 0 {
                entered.notify_one();
                release.notified().await;
            }
            Ok(decision_record())
        })
    }
}

impl TenantScopedGetDecisionExecutor for RecordingExecutor {
    fn execute_get_decision(
        &self,
        scope: TenantScope,
        query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        self.observed
            .lock()
            .expect("observations lock poisoned")
            .push((
                scope.tenant_id().to_owned(),
                query.decision_id().to_string(),
            ));
        Box::pin(async { Ok(decision_record()) })
    }
}

impl TenantScopedGetDecisionExecutor for SequencedRecordingExecutor {
    fn execute_get_decision(
        &self,
        scope: TenantScope,
        query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        self.observed
            .lock()
            .expect("observations lock poisoned")
            .push((
                scope.tenant_id().to_owned(),
                query.decision_id().to_string(),
            ));
        let response = self
            .responses
            .lock()
            .expect("responses lock poisoned")
            .pop_front()
            .expect("test response sequence exhausted");
        Box::pin(async move { Ok(response) })
    }
}

fn prediction_interval(lower_decimal: &str, upper_decimal: &str) -> DecisionPredictionInterval {
    DecisionPredictionInterval {
        target: "binding_affinity".to_owned(),
        unit: "nM".to_owned(),
        lower_decimal: lower_decimal.to_owned(),
        upper_decimal: upper_decimal.to_owned(),
        nominal_coverage_decimal: "0.95".to_owned(),
        interval_method_id: "split_conformal".to_owned(),
        interval_method_version: "1.0".to_owned(),
        calibration_method_id: "held_out_calibration".to_owned(),
        calibration_method_version: "2026.07".to_owned(),
        calibration_evidence: Some(EvidenceSnapshotRef {
            id: "ES-CAL-001".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        }),
    }
}

fn prediction_positions() -> Vec<DecisionPredictionPosition> {
    [
        (
            "model-z",
            "2026.07",
            "shared-training-set",
            "0.4",
            "1.4",
            "ES-PRED-Z",
        ),
        (
            "model-a",
            "2026.06",
            "independent-assay",
            "0.2",
            "1.2",
            "ES-PRED-A",
        ),
    ]
    .into_iter()
    .map(
        |(source_id, source_version, dependency_group_id, lower, upper, evidence_id)| {
            DecisionPredictionPosition {
                source_id: source_id.to_owned(),
                source_version: source_version.to_owned(),
                dependency_group_id: dependency_group_id.to_owned(),
                interval: Some(prediction_interval(lower, upper)),
                prediction_evidence: Some(EvidenceSnapshotRef {
                    id: evidence_id.to_owned(),
                    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                }),
            }
        },
    )
    .collect()
}

#[allow(deprecated)]
fn decision_record() -> DecisionRecord {
    DecisionRecord {
        decision_id: DECISION_ID.to_owned(),
        cou_id: "COU-CLIENT-001".to_owned(),
        evidence_snapshot_id: "ES-CLIENT-001".to_owned(),
        recommendation: Recommendation::Promote as i32,
        rationale: vec!["Evidence supports promotion.".to_owned()],
        aggregate_version: u64::MAX,
        evidence: Some(EvidenceSnapshotRef {
            id: "ES-CLIENT-001".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        }),
        ood_status: Some(OodStatus::InDomain as i32),
        ood_detector: Some(OodDetectorRef {
            detector_id: "client-domain-detector".to_owned(),
            detector_version: "2026.07".to_owned(),
        }),
        prediction_interval: Some(prediction_interval("0.25", "1.5")),
        prediction_positions: prediction_positions(),
        decision_criterion: Some(DecisionCriterion {
            criterion_id: "client_policy".to_owned(),
            criterion_version: "2026.07".to_owned(),
            comparator: DecisionCriterionComparator::LessThanOrEqual as i32,
            threshold_decimal: "0.75".to_owned(),
            criterion_evidence: Some(EvidenceSnapshotRef {
                id: "ES-CLIENT-CRITERION".to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
        }),
    }
}

fn decision_response_with_encoded_len(target: usize) -> DecisionRecord {
    let mut response = decision_record();
    response.rationale = vec![String::new()];
    for _ in 0..8 {
        match response.encoded_len().cmp(&target) {
            std::cmp::Ordering::Equal => return response,
            std::cmp::Ordering::Less => {
                let missing = target - response.encoded_len();
                response.rationale[0].extend(std::iter::repeat_n('x', missing));
            }
            std::cmp::Ordering::Greater => {
                let excess = response.encoded_len() - target;
                let new_len = response.rationale[0].len() - excess;
                response.rationale[0].truncate(new_len);
            }
        }
    }
    panic!("could not construct response with target wire size");
}

fn server_config() -> DecisionGrpcServerConfig {
    let limits = DecisionGrpcServerLimits::try_new(
        4,
        4,
        Duration::from_millis(250),
        Duration::from_secs(2),
        Duration::from_secs(30),
        Duration::from_secs(1),
        Duration::from_secs(3),
    )
    .expect("test server limits must be valid");
    DecisionGrpcServerConfig::new(
        DecisionGrpcBind::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("loopback bind must be valid"),
        limits,
    )
}

fn client_limits() -> DecisionGrpcClientLimits {
    DecisionGrpcClientLimits::try_new(
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(1),
        2,
    )
    .expect("test client limits must be valid")
}

struct TestServer {
    address: SocketAddr,
    certificate_pem: Vec<u8>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), ServeDecisionGrpcServerError>>,
}

impl TestServer {
    fn client_config(&self, limits: DecisionGrpcClientLimits) -> DecisionGrpcClientConfig {
        DecisionGrpcClientConfig::try_new(
            format!("https://{}", self.address),
            "localhost".to_owned(),
            self.certificate_pem.clone(),
            limits,
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

async fn start_server<A, E>(authenticator: A, executor: E) -> TestServer
where
    A: TenantAuthenticator + 'static,
    E: TenantScopedGetDecisionExecutor + 'static,
{
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("test TLS identity must be generated");
    let certificate_pem = cert.pem().into_bytes();
    let identity = DecisionGrpcTlsIdentity::try_from_pem(
        certificate_pem.clone(),
        signing_key.serialize_pem().into_bytes(),
    )
    .expect("test TLS identity must be valid");
    let server = guarded(DecisionGrpcServer::bind(server_config(), identity))
        .await
        .expect("test server must bind");
    let address = server.local_addr();
    let service = DecisionGrpcService::new(
        authenticator,
        executor,
        DecisionGrpcServiceConfig::try_new(4, Duration::from_secs(2))
            .expect("test service limits must be valid"),
    );
    let (shutdown, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(server.serve(service, async move {
        let _ = shutdown_rx.await;
    }));

    TestServer {
        address,
        certificate_pem,
        shutdown,
        task,
    }
}

enum RawReply {
    Record(Box<DecisionRecord>),
    Status(Code),
}

struct RawDecisionService {
    replies: Arc<Mutex<VecDeque<RawReply>>>,
}

#[tonic::async_trait]
impl DecisionService for RawDecisionService {
    async fn get_decision(
        &self,
        _request: Request<GetDecisionRequest>,
    ) -> Result<Response<DecisionRecord>, Status> {
        match self
            .replies
            .lock()
            .expect("raw replies lock poisoned")
            .pop_front()
            .expect("raw test reply must exist")
        {
            RawReply::Record(record) => Ok(Response::new(*record)),
            RawReply::Status(code) => Err(Status::new(code, "PRIVATE-SERVER-MARKER")),
        }
    }

    async fn propose_decision(
        &self,
        _request: Request<ProposeDecisionRequest>,
    ) -> Result<Response<DecisionRecord>, Status> {
        Err(Status::unimplemented("not used"))
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
        _request: Request<WatchDecisionRequest>,
    ) -> Result<Response<Self::WatchDecisionStream>, Status> {
        Err(Status::unimplemented("not used"))
    }
}

struct RawTestServer {
    address: SocketAddr,
    certificate_pem: Vec<u8>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl RawTestServer {
    fn client_config(&self, limits: DecisionGrpcClientLimits) -> DecisionGrpcClientConfig {
        DecisionGrpcClientConfig::try_new(
            format!("https://{}", self.address),
            "localhost".to_owned(),
            self.certificate_pem.clone(),
            limits,
        )
        .expect("raw test client configuration must be valid")
    }

    async fn stop(self) {
        self.shutdown
            .send(())
            .expect("raw test server must be running");
        guarded(self.task)
            .await
            .expect("raw test server task must join")
            .expect("raw test server must stop cleanly");
    }
}

async fn start_raw_server(replies: Vec<RawReply>) -> RawTestServer {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("raw test TLS identity must be generated");
    let certificate_pem = cert.pem().into_bytes();
    let identity = Identity::from_pem(
        certificate_pem.clone(),
        signing_key.serialize_pem().into_bytes(),
    );
    let incoming = TcpIncoming::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("raw test listener must bind");
    let address = incoming
        .local_addr()
        .expect("raw test address must be available");
    let service = RawDecisionService {
        replies: Arc::new(Mutex::new(replies.into())),
    };
    let (shutdown, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))?
            .add_service(DecisionServiceServer::new(service))
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await
    });

    RawTestServer {
        address,
        certificate_pem,
        shutdown,
        task,
    }
}

async fn guarded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TEST_TIMEOUT, future)
        .await
        .expect("test operation timed out")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_the_exact_decision_over_explicit_trusted_tls() {
    let statuses = [
        OodStatus::InDomain,
        OodStatus::Borderline,
        OodStatus::OutOfDomain,
        OodStatus::Unknown,
    ];
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let responses = statuses
        .iter()
        .map(|status| {
            let mut response = decision_record();
            response.ood_status = Some(*status as i32);
            response
        })
        .collect();
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        SequencedRecordingExecutor {
            observed: Arc::clone(&observed),
            responses: Mutex::new(responses),
        },
    )
    .await;
    let config = server.client_config(client_limits());
    let client = guarded(DecisionGrpcClient::connect(
        config,
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");

    for expected_status in statuses {
        let actual = guarded(client.get_decision(DECISION_ID)).await;
        let actual = actual.expect("authenticated decision read must succeed");
        let actual = DecisionRecord::from(&actual);
        let mut expected = decision_record();
        expected.ood_status = Some(expected_status as i32);

        assert_eq!(actual.ood_status, Some(expected_status as i32));
        assert_eq!(
            actual.prediction_interval,
            Some(prediction_interval("0.25", "1.5"))
        );
        assert_eq!(actual.prediction_positions, prediction_positions());
        assert_eq!(actual, expected);
    }
    assert_eq!(provider_calls.load(Ordering::SeqCst), statuses.len());
    assert_eq!(auth_calls.load(Ordering::SeqCst), statuses.len());
    assert_eq!(
        observed
            .lock()
            .expect("observations lock poisoned")
            .as_slice(),
        vec![("tenant-a".to_owned(), DECISION_ID.to_owned()); statuses.len()],
    );

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_noncanonical_decision_ids_before_token_or_rpc_work() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        RecordingExecutor {
            observed: Arc::clone(&observed),
        },
    )
    .await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(client_limits()),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");

    for decision_id in [
        "",
        "not-a-uuid",
        "018F5A72-9C4B-7D31-8F6A-26F08F3F4D99",
        "018f5a729c4b7d318f6a26f08f3f4d99",
    ] {
        assert_eq!(
            guarded(client.get_decision(decision_id)).await,
            Err(DecisionGrpcClientError::InvalidDecisionId),
        );
    }
    let oversized_decision_id = "x".repeat(1024 * 1024);
    assert_eq!(
        guarded(client.get_decision(&oversized_decision_id)).await,
        Err(DecisionGrpcClientError::InvalidDecisionId),
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert!(
        observed
            .lock()
            .expect("observations lock poisoned")
            .is_empty()
    );

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maps_token_provider_failure_without_reaching_the_server() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        RecordingExecutor {
            observed: Arc::clone(&observed),
        },
    )
    .await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(client_limits()),
        UnavailableAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");

    let error = guarded(client.get_decision(DECISION_ID))
        .await
        .expect_err("missing access token must fail");
    assert_eq!(error, DecisionGrpcClientError::AuthenticationUnavailable);
    assert_eq!(error.to_string(), "decision authentication is unavailable");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert!(
        observed
            .lock()
            .expect("observations lock poisoned")
            .is_empty()
    );

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maps_authentication_rejection_without_reflecting_the_token() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        RecordingExecutor {
            observed: Arc::clone(&observed),
        },
    )
    .await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(client_limits()),
        RejectedAccessTokenProvider,
    ))
    .await
    .expect("trusted TLS client must connect");

    let error = guarded(client.get_decision(DECISION_ID))
        .await
        .expect_err("rejected access token must fail");
    let rendered = format!("{error:?} {error}");
    assert_eq!(error, DecisionGrpcClientError::Unauthenticated);
    assert!(!rendered.contains("wrongHeader"));
    assert!(!rendered.contains("wrongPayload"));
    assert!(!rendered.contains("wrongSignature"));
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert!(
        observed
            .lock()
            .expect("observations lock poisoned")
            .is_empty()
    );

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_untrusted_ca_and_wrong_server_name_before_authentication() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        RecordingExecutor {
            observed: Arc::clone(&observed),
        },
    )
    .await;
    let untrusted_certificate = generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("untrusted test identity must be generated")
        .cert
        .pem()
        .into_bytes();
    let configurations = [
        DecisionGrpcClientConfig::try_new(
            format!("https://{}", server.address),
            "localhost".to_owned(),
            untrusted_certificate,
            client_limits(),
        )
        .expect("bounded untrusted configuration must be accepted"),
        DecisionGrpcClientConfig::try_new(
            format!("https://{}", server.address),
            "wrong.example".to_owned(),
            server.certificate_pem.clone(),
            client_limits(),
        )
        .expect("bounded wrong-name configuration must be accepted"),
    ];

    for config in configurations {
        let error = guarded(DecisionGrpcClient::connect(
            config,
            StaticAccessTokenProvider {
                calls: Arc::clone(&provider_calls),
            },
        ))
        .await
        .err()
        .expect("TLS verification must fail");
        assert_eq!(error, DecisionGrpcClientError::Unavailable);
        assert_eq!(error.to_string(), "decision service is unavailable");
    }
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert!(
        observed
            .lock()
            .expect("observations lock poisoned")
            .is_empty()
    );

    server.stop().await;
}

#[test]
fn rejects_malformed_ca_material_during_configuration() {
    let error = DecisionGrpcClientConfig::try_new(
        "https://127.0.0.1:9".to_owned(),
        "localhost".to_owned(),
        b"MALFORMED-CA-MARKER".to_vec(),
        client_limits(),
    )
    .expect_err("malformed CA must fail");
    let rendered = format!("{error:?} {error}");
    assert_eq!(error, DecisionGrpcClientError::InvalidConfiguration);
    assert!(!rendered.contains("MALFORMED-CA-MARKER"));
    assert!(!rendered.contains("127.0.0.1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_a_valid_response_with_a_different_decision_identity() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        WrongIdentityExecutor,
    )
    .await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(client_limits()),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");

    let error = guarded(client.get_decision(DECISION_ID))
        .await
        .expect_err("wrong response identity must fail");
    assert_eq!(error, DecisionGrpcClientError::InvalidResponse);
    assert_eq!(error.to_string(), "decision service response is invalid");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_a_contract_invalid_response_from_the_transport() {
    let mut invalid = decision_record();
    invalid.aggregate_version = 0;
    let server = start_raw_server(vec![RawReply::Record(Box::new(invalid))]).await;
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(client_limits()),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted raw TLS client must connect");

    let error = guarded(client.get_decision(DECISION_ID))
        .await
        .expect_err("invalid response contract must fail");
    assert_eq!(error, DecisionGrpcClientError::InvalidResponse);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maps_every_server_status_to_a_fixed_redacted_client_category() {
    let cases = [
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
    ];
    let server = start_raw_server(
        cases
            .iter()
            .map(|(code, _)| RawReply::Status(*code))
            .collect(),
    )
    .await;
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(client_limits()),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted raw TLS client must connect");

    for (_, expected) in cases {
        let error = guarded(client.get_decision(DECISION_ID))
            .await
            .expect_err("scripted server status must fail");
        assert_eq!(error, expected);
        assert!(!format!("{error:?} {error}").contains("PRIVATE-SERVER-MARKER"));
    }
    assert_eq!(provider_calls.load(Ordering::SeqCst), cases.len());

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_a_response_above_the_decoding_budget() {
    let response = decision_response_with_encoded_len(MAX_DECISION_WIRE_BYTES + 1);
    assert_eq!(response.encoded_len(), MAX_DECISION_WIRE_BYTES + 1);
    let server = start_raw_server(vec![RawReply::Record(Box::new(response))]).await;
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(client_limits()),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted raw TLS client must connect");

    let error = guarded(client.get_decision(DECISION_ID))
        .await
        .expect_err("oversized response must fail");
    assert_eq!(error, DecisionGrpcClientError::InvalidResponse);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fails_fast_at_capacity_then_recovers_after_completion() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        BlockingFirstExecutor {
            calls: Arc::clone(&executor_calls),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        },
    )
    .await;
    let limits = DecisionGrpcClientLimits::try_new(
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(1),
        1,
    )
    .expect("single-call client limit must be valid");
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(limits),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let first_client = client.clone();
    let first = tokio::spawn(async move { first_client.get_decision(DECISION_ID).await });
    guarded(entered.notified()).await;

    let second = tokio::time::timeout(Duration::from_millis(100), client.get_decision(DECISION_ID))
        .await
        .expect("capacity rejection must be immediate");
    assert_eq!(second, Err(DecisionGrpcClientError::CapacityExhausted));
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 1);

    release.notify_one();
    guarded(first)
        .await
        .expect("first client task must join")
        .expect("first decision read must finish");
    guarded(client.get_decision(DECISION_ID))
        .await
        .expect("client capacity must recover");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 2);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn times_out_slow_transport_work_and_releases_client_capacity() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        SlowFirstExecutor {
            calls: Arc::clone(&executor_calls),
        },
    )
    .await;
    let limits = DecisionGrpcClientLimits::try_new(
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_millis(500),
        1,
    )
    .expect("short request timeout must be valid");
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(limits),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");

    let first = guarded(client.get_decision(DECISION_ID))
        .await
        .expect_err("slow response must time out");
    assert_eq!(first, DecisionGrpcClientError::DeadlineExceeded);
    guarded(client.get_decision(DECISION_ID))
        .await
        .expect("capacity must recover after timeout");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 2);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_releases_client_capacity_without_retrying() {
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        BlockingFirstExecutor {
            calls: Arc::clone(&executor_calls),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        },
    )
    .await;
    let limits = DecisionGrpcClientLimits::try_new(
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(1),
        1,
    )
    .expect("single-call client limit must be valid");
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(limits),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");
    let cancelled_client = client.clone();
    let cancelled = tokio::spawn(async move { cancelled_client.get_decision(DECISION_ID).await });
    guarded(entered.notified()).await;
    cancelled.abort();
    assert!(
        guarded(cancelled)
            .await
            .expect_err("aborted client task must be cancelled")
            .is_cancelled()
    );

    guarded(client.get_decision(DECISION_ID))
        .await
        .expect("capacity must recover after cancellation");
    release.notify_one();
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 2);

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounds_a_stalled_tls_handshake_before_token_work() {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("stalled test listener must bind");
    let address = listener
        .local_addr()
        .expect("stalled test address must be available");
    let (release_tx, release_rx) = oneshot::channel();
    let listener_task = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("client must reach stalled test listener");
        let _ = release_rx.await;
        drop(stream);
    });
    let certificate_pem = generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("test CA must be generated")
        .cert
        .pem()
        .into_bytes();
    let limits = DecisionGrpcClientLimits::try_new(
        Duration::from_secs(1),
        Duration::from_millis(200),
        Duration::from_secs(1),
        1,
    )
    .expect("short connect limits must be valid");
    let config = DecisionGrpcClientConfig::try_new(
        format!("https://{address}"),
        "localhost".to_owned(),
        certificate_pem,
        limits,
    )
    .expect("stalled endpoint configuration must be valid");
    let provider_calls = Arc::new(AtomicUsize::new(0));

    let error = tokio::time::timeout(
        Duration::from_secs(2),
        DecisionGrpcClient::connect(
            config,
            StaticAccessTokenProvider {
                calls: Arc::clone(&provider_calls),
            },
        ),
    )
    .await
    .expect("stalled TLS connect must remain bounded")
    .err()
    .expect("stalled TLS handshake must fail");
    assert_eq!(error, DecisionGrpcClientError::Unavailable);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 0);

    release_tx
        .send(())
        .expect("stalled listener task must still run");
    guarded(listener_task)
        .await
        .expect("stalled listener task must join");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounds_token_acquisition_and_releases_client_capacity() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        RecordingExecutor {
            observed: Arc::clone(&observed),
        },
    )
    .await;
    let limits = DecisionGrpcClientLimits::try_new(
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_millis(500),
        1,
    )
    .expect("short provider timeout must be valid");
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(limits),
        SlowFirstAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .expect("trusted TLS client must connect");

    let first = guarded(client.get_decision(DECISION_ID))
        .await
        .expect_err("slow token acquisition must time out");
    assert_eq!(first, DecisionGrpcClientError::DeadlineExceeded);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    guarded(client.get_decision(DECISION_ID))
        .await
        .expect("capacity must recover after token timeout");
    assert_eq!(provider_calls.load(Ordering::SeqCst), 2);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        observed.lock().expect("observations lock poisoned").len(),
        1,
    );

    server.stop().await;
}
