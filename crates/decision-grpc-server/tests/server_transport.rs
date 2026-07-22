use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bioworld_contracts::MAX_DECISION_WIRE_BYTES;
use bioworld_contracts::v2::{
    DecisionPredictionInterval, DecisionPredictionPosition, DecisionRecord, EvidenceSnapshotRef,
    GetDecisionRequest, OodDetectorRef, OodStatus, Recommendation,
    decision_service_client::DecisionServiceClient,
};
use bioworld_decision_grpc::{
    AuthenticateTenantFuture, DecisionGrpcService, DecisionGrpcServiceConfig,
    TenantAuthenticationContext, TenantAuthenticator, TenantScope, TenantScopedGetDecisionExecutor,
    TenantScopedGetDecisionFuture,
};
use bioworld_decision_grpc_server::{
    DecisionGrpcBind, DecisionGrpcServer, DecisionGrpcServerConfig, DecisionGrpcServerLimits,
    DecisionGrpcTlsIdentity, ServeDecisionGrpcServerError,
};
use bioworld_decision_query::{GetDecisionQuery, GetDecisionRequestExecutionError};
use prost::Message;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    sync::{Notify, oneshot},
};
use tonic::{
    Code, Request,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
const TEST_TIMEOUT: Duration = Duration::from_secs(3);

struct TestTls {
    identity: DecisionGrpcTlsIdentity,
    certificate_pem: Vec<u8>,
}

fn test_tls() -> TestTls {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate_pem = cert.pem().into_bytes();
    let identity = DecisionGrpcTlsIdentity::try_from_pem(
        certificate_pem.clone(),
        signing_key.serialize_pem().into_bytes(),
    )
    .unwrap();
    TestTls {
        identity,
        certificate_pem,
    }
}

fn transport_config(max_connections: usize) -> DecisionGrpcServerConfig {
    transport_config_with(
        max_connections,
        4,
        Duration::from_millis(250),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
}

fn transport_config_with(
    max_connections: usize,
    max_streams: u32,
    handshake_timeout: Duration,
    request_timeout: Duration,
    shutdown_grace: Duration,
) -> DecisionGrpcServerConfig {
    let limits = DecisionGrpcServerLimits::try_new(
        max_connections,
        max_streams,
        handshake_timeout,
        request_timeout,
        Duration::from_secs(30),
        Duration::from_secs(1),
        shutdown_grace,
    )
    .unwrap();
    DecisionGrpcServerConfig::new(
        DecisionGrpcBind::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap(),
        limits,
    )
}

struct CountingAuthenticator {
    calls: Arc<AtomicUsize>,
}

impl TenantAuthenticator for CountingAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok("trusted-tenant".to_owned()) })
    }
}

struct RecordingExecutor {
    observed: Arc<Mutex<Vec<(String, String)>>>,
}

struct BlockingFirstExecutor {
    calls: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

struct FlowControlledExecutor {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    completed: Arc<Notify>,
}

struct TransportTimeoutThenExecutor {
    calls: Arc<AtomicUsize>,
    first_entered: Arc<Notify>,
    first_dropped: Arc<AtomicBool>,
}

impl TenantScopedGetDecisionExecutor for TransportTimeoutThenExecutor {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first_entered.notify_one();
            Box::pin(PendingExecution {
                dropped: Arc::clone(&self.first_dropped),
            })
        } else {
            Box::pin(async { Ok(record()) })
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
        Box::pin(async move {
            if call == 0 {
                entered.notify_one();
                release.notified().await;
            }
            Ok(record())
        })
    }
}

impl TenantScopedGetDecisionExecutor for FlowControlledExecutor {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        let entered = Arc::clone(&self.entered);
        let release = Arc::clone(&self.release);
        let completed = Arc::clone(&self.completed);
        Box::pin(async move {
            entered.notify_one();
            release.notified().await;
            completed.notify_one();
            Ok(record())
        })
    }
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
        Box::pin(async { Ok(record()) })
    }
}

fn service(
    auth_calls: Arc<AtomicUsize>,
    observed: Arc<Mutex<Vec<(String, String)>>>,
) -> DecisionGrpcService<CountingAuthenticator, RecordingExecutor> {
    DecisionGrpcService::new(
        CountingAuthenticator { calls: auth_calls },
        RecordingExecutor { observed },
        DecisionGrpcServiceConfig::try_new(4, Duration::from_secs(1)).unwrap(),
    )
}

fn blocking_service(
    auth_calls: Arc<AtomicUsize>,
    executor_calls: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
) -> DecisionGrpcService<CountingAuthenticator, BlockingFirstExecutor> {
    DecisionGrpcService::new(
        CountingAuthenticator { calls: auth_calls },
        BlockingFirstExecutor {
            calls: executor_calls,
            entered,
            release,
        },
        DecisionGrpcServiceConfig::try_new(4, Duration::from_secs(1)).unwrap(),
    )
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
fn record() -> DecisionRecord {
    DecisionRecord {
        decision_id: DECISION_ID.to_owned(),
        cou_id: "COU-TRANSPORT-001".to_owned(),
        evidence_snapshot_id: "ES-TRANSPORT-001".to_owned(),
        recommendation: Recommendation::Promote as i32,
        rationale: vec!["Evidence supports promotion.".to_owned()],
        aggregate_version: 7,
        evidence: Some(EvidenceSnapshotRef {
            id: "ES-TRANSPORT-001".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        }),
        ood_status: Some(OodStatus::InDomain as i32),
        ood_detector: Some(OodDetectorRef {
            detector_id: "transport-domain-detector".to_owned(),
            detector_version: "2026.07".to_owned(),
        }),
        prediction_interval: Some(prediction_interval("0.25", "1.5")),
        prediction_positions: prediction_positions(),
    }
}

async fn trusted_channel(address: SocketAddr, certificate_pem: Vec<u8>) -> Channel {
    guarded(try_trusted_channel(address, certificate_pem))
        .await
        .unwrap()
}

async fn trusted_channel_with_stream_window(
    address: SocketAddr,
    certificate_pem: Vec<u8>,
    stream_window: u32,
) -> Channel {
    guarded(
        Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(certificate_pem))
                    .domain_name("localhost"),
            )
            .unwrap()
            .initial_stream_window_size(stream_window)
            .connect(),
    )
    .await
    .unwrap()
}

async fn guarded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TEST_TIMEOUT, future)
        .await
        .expect("test operation timed out")
}

async fn try_trusted_channel(
    address: SocketAddr,
    certificate_pem: Vec<u8>,
) -> Result<Channel, tonic::transport::Error> {
    Endpoint::from_shared(format!("https://{address}"))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(certificate_pem))
                .domain_name("localhost"),
        )
        .unwrap()
        .connect()
        .await
}

async fn get_decision(channel: Channel) -> Result<DecisionRecord, tonic::Status> {
    DecisionServiceClient::new(channel)
        .get_decision(GetDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        })
        .await
        .map(tonic::Response::into_inner)
}

fn request_with_encoded_len(target: usize) -> GetDecisionRequest {
    let mut request = GetDecisionRequest::default();
    let mut decision_id_bytes = target;

    for _ in 0..4 {
        request.decision_id = "x".repeat(decision_id_bytes);
        match request.encoded_len().cmp(&target) {
            std::cmp::Ordering::Equal => return request,
            std::cmp::Ordering::Less => decision_id_bytes += target - request.encoded_len(),
            std::cmp::Ordering::Greater => decision_id_bytes -= request.encoded_len() - target,
        }
    }

    panic!("could not construct target wire size");
}

#[tokio::test]
async fn serves_get_decision_over_trusted_tls() {
    let tls = test_tls();
    let server = DecisionGrpcServer::bind(transport_config(1), tls.identity)
        .await
        .unwrap();
    let address = server.local_addr();
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.serve(
        service(Arc::clone(&auth_calls), Arc::clone(&observed)),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let channel = tokio::time::timeout(
        Duration::from_secs(3),
        trusted_channel(address, tls.certificate_pem),
    )
    .await
    .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), get_decision(channel))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        response.prediction_interval,
        Some(prediction_interval("0.25", "1.5"))
    );
    assert_eq!(response.prediction_positions, prediction_positions());
    assert_eq!(response, record());
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *observed.lock().unwrap(),
        vec![("trusted-tenant".to_owned(), DECISION_ID.to_owned())]
    );

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn bounds_stalled_handshakes_and_recovers_connection_capacity() {
    let tls = test_tls();
    let server = DecisionGrpcServer::bind(
        transport_config_with(
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        tls.identity,
    )
    .await
    .unwrap();
    let address = server.local_addr();
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.serve(
        service(Arc::clone(&auth_calls), observed),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let mut stalled = guarded(TcpStream::connect(address)).await.unwrap();
    let blocked = tokio::time::timeout(
        Duration::from_millis(100),
        try_trusted_channel(address, tls.certificate_pem.clone()),
    )
    .await;
    assert!(blocked.is_err());
    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);

    let mut byte = [0_u8; 1];
    let stalled_result = tokio::time::timeout(Duration::from_secs(3), stalled.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(stalled_result, Ok(0) | Err(_)));

    let recovered = tokio::time::timeout(
        Duration::from_secs(3),
        trusted_channel(address, tls.certificate_pem),
    )
    .await
    .unwrap();
    guarded(get_decision(recovered)).await.unwrap();
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn preserves_message_bounds_and_rejects_oversized_headers_before_authentication() {
    let tls = test_tls();
    let server = DecisionGrpcServer::bind(transport_config(2), tls.identity)
        .await
        .unwrap();
    let address = server.local_addr();
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.serve(
        service(Arc::clone(&auth_calls), Arc::clone(&observed)),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let channel = trusted_channel(address, tls.certificate_pem.clone()).await;
    let mut client = DecisionServiceClient::new(channel);
    let exact_status =
        guarded(client.get_decision(request_with_encoded_len(MAX_DECISION_WIRE_BYTES)))
            .await
            .unwrap_err();
    assert_eq!(exact_status.code(), Code::InvalidArgument);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert!(observed.lock().unwrap().is_empty());

    let oversized_status =
        guarded(client.get_decision(request_with_encoded_len(MAX_DECISION_WIRE_BYTES + 1)))
            .await
            .unwrap_err();
    assert_eq!(oversized_status.code(), Code::OutOfRange);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    drop(client);

    let channel = trusted_channel(address, tls.certificate_pem.clone()).await;
    let mut client = DecisionServiceClient::new(channel);
    let mut accepted_headers = Request::new(GetDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    });
    accepted_headers.metadata_mut().insert_bin(
        "x-padding-bin",
        MetadataValue::from_bytes(&vec![b'a'; 8_192]),
    );
    guarded(client.get_decision(accepted_headers))
        .await
        .unwrap();
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);

    let mut oversized_headers = Request::new(GetDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    });
    oversized_headers.metadata_mut().insert_bin(
        "x-padding-bin",
        MetadataValue::from_bytes(&vec![b'a'; 16_385]),
    );
    assert!(
        guarded(client.get_decision(oversized_headers))
            .await
            .is_err()
    );
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    drop(client);

    let recovered = trusted_channel(address, tls.certificate_pem).await;
    guarded(get_decision(recovered)).await.unwrap();
    assert_eq!(auth_calls.load(Ordering::SeqCst), 3);

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn bounds_concurrent_streams_on_each_connection() {
    let tls = test_tls();
    let server = DecisionGrpcServer::bind(
        transport_config_with(
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        tls.identity,
    )
    .await
    .unwrap();
    let address = server.local_addr();
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.serve(
        blocking_service(
            Arc::clone(&auth_calls),
            Arc::clone(&executor_calls),
            Arc::clone(&entered),
            Arc::clone(&release),
        ),
        async move {
            let _ = shutdown_rx.await;
        },
    ));
    let channel = trusted_channel(address, tls.certificate_pem).await;
    let mut first_client = DecisionServiceClient::new(channel.clone());
    let mut second_client = DecisionServiceClient::new(channel);
    let first = tokio::spawn(async move {
        first_client
            .get_decision(GetDecisionRequest {
                decision_id: DECISION_ID.to_owned(),
            })
            .await
    });
    guarded(entered.notified()).await;
    let mut second = tokio::spawn(async move {
        second_client
            .get_decision(GetDecisionRequest {
                decision_id: DECISION_ID.to_owned(),
            })
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut second)
            .await
            .is_err()
    );

    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 1);
    assert!(!second.is_finished());

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), second)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 2);

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn drains_active_rpc_then_closes_the_listener_on_shutdown() {
    let tls = test_tls();
    let server = DecisionGrpcServer::bind(transport_config(1), tls.identity)
        .await
        .unwrap();
    let address = server.local_addr();
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let shutdown_observed = Arc::new(Notify::new());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let observed_shutdown = Arc::clone(&shutdown_observed);
    let mut server_task = tokio::spawn(server.serve(
        blocking_service(
            auth_calls,
            executor_calls,
            Arc::clone(&entered),
            Arc::clone(&release),
        ),
        async move {
            let _ = shutdown_rx.await;
            observed_shutdown.notify_one();
        },
    ));
    let channel = trusted_channel(address, tls.certificate_pem).await;
    let active_rpc = tokio::spawn(get_decision(channel));
    guarded(entered.notified()).await;

    shutdown_tx.send(()).unwrap();
    guarded(shutdown_observed.notified()).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut server_task)
            .await
            .is_err()
    );

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), active_rpc)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(guarded(TcpStream::connect(address)).await.is_err());
}

#[tokio::test]
async fn transport_timeout_drops_work_and_recovers_capacity() {
    let tls = test_tls();
    let server = DecisionGrpcServer::bind(
        transport_config_with(
            1,
            1,
            Duration::from_secs(1),
            Duration::from_millis(100),
            Duration::from_millis(500),
        ),
        tls.identity,
    )
    .await
    .unwrap();
    let address = server.local_addr();
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let first_entered = Arc::new(Notify::new());
    let first_dropped = Arc::new(AtomicBool::new(false));
    let service = DecisionGrpcService::new(
        CountingAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        TransportTimeoutThenExecutor {
            calls: Arc::clone(&executor_calls),
            first_entered: Arc::clone(&first_entered),
            first_dropped: Arc::clone(&first_dropped),
        },
        DecisionGrpcServiceConfig::try_new(1, Duration::from_millis(400)).unwrap(),
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.serve(service, async move {
        let _ = shutdown_rx.await;
    }));
    let channel = trusted_channel(address, tls.certificate_pem).await;
    let mut client = DecisionServiceClient::new(channel);

    let status = {
        let first_request = client.get_decision(GetDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        });
        tokio::pin!(first_request);
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                response = &mut first_request => response,
                () = first_entered.notified() => first_request.await,
            }
        })
        .await
        .unwrap()
        .unwrap_err()
    };
    assert_eq!(status.code(), Code::DeadlineExceeded);
    assert_eq!(status.message(), "decision request deadline exceeded");
    assert!(status.details().is_empty());
    assert!(
        status
            .metadata()
            .get_bin("grpc-status-details-bin")
            .is_none()
    );
    assert!(first_dropped.load(Ordering::SeqCst));

    guarded(client.get_decision(GetDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    }))
    .await
    .unwrap();
    assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 2);
    drop(client);

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn rejects_a_service_timeout_that_cannot_drain_before_shutdown() {
    let tls = test_tls();
    let server = DecisionGrpcServer::bind(
        transport_config_with(
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
        ),
        tls.identity,
    )
    .await
    .unwrap();
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let server_result =
        guarded(server.serve(service(auth_calls, observed), std::future::pending::<()>())).await;

    assert_eq!(
        server_result,
        Err(ServeDecisionGrpcServerError::ServiceLimitsRejected)
    );
}

#[tokio::test]
async fn force_closes_flow_controlled_response_when_shutdown_deadline_expires() {
    let tls = test_tls();
    let server = DecisionGrpcServer::bind(
        transport_config_with(
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
        ),
        tls.identity,
    )
    .await
    .unwrap();
    let address = server.local_addr();
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let completed = Arc::new(Notify::new());
    let service = DecisionGrpcService::new(
        CountingAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        FlowControlledExecutor {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            completed: Arc::clone(&completed),
        },
        DecisionGrpcServiceConfig::try_new(1, Duration::from_millis(500)).unwrap(),
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.serve(service, async move {
        let _ = shutdown_rx.await;
    }));
    let channel = trusted_channel_with_stream_window(address, tls.certificate_pem, 1).await;
    let mut client = DecisionServiceClient::new(channel);
    let response = client.get_decision(GetDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    });
    tokio::pin!(response);
    guarded(async {
        tokio::select! {
            () = entered.notified() => {},
            result = &mut response => panic!("response completed before executor release: {result:?}"),
        }
    })
    .await;
    release.notify_one();
    guarded(completed.notified()).await;
    let first_poll =
        std::future::poll_fn(|context| Poll::Ready(response.as_mut().poll(context))).await;
    assert!(first_poll.is_pending());

    shutdown_tx.send(()).unwrap();
    let server_result = guarded(server_task).await.unwrap();

    assert_eq!(
        server_result,
        Err(ServeDecisionGrpcServerError::ShutdownDeadlineExceeded)
    );
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejects_untrusted_tls_and_plaintext_before_authentication() {
    let tls = test_tls();
    let server = DecisionGrpcServer::bind(transport_config(4), tls.identity)
        .await
        .unwrap();
    let address = server.local_addr();
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.serve(
        service(Arc::clone(&auth_calls), Arc::clone(&observed)),
        async move {
            let _ = shutdown_rx.await;
        },
    ));

    let untrusted = test_tls();
    let untrusted_result = tokio::time::timeout(
        Duration::from_secs(3),
        Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(untrusted.certificate_pem))
                    .domain_name("localhost"),
            )
            .unwrap()
            .connect(),
    )
    .await
    .unwrap();
    assert!(untrusted_result.is_err());

    let plaintext_result = tokio::time::timeout(
        Duration::from_secs(3),
        Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect(),
    )
    .await
    .unwrap();
    if let Ok(channel) = plaintext_result {
        assert!(guarded(get_decision(channel)).await.is_err());
    }

    assert_eq!(auth_calls.load(Ordering::SeqCst), 0);
    assert!(observed.lock().unwrap().is_empty());

    let trusted = trusted_channel(address, tls.certificate_pem).await;
    guarded(get_decision(trusted)).await.unwrap();
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
