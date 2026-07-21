use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::{Pin, pin},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use bioworld_contracts::{VersionedDecisionRecord, v2};
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
use bioworld_desktop_core::{CurrentDecisionSource, DecisionProvenance, DecisionRuntimeError};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::{sync::oneshot, task::JoinHandle};

use super::{
    DecisionServiceReadFuture, DecisionServiceReader, DecisionServiceSource, DecisionSourceAdapter,
};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3fa630";
const ACCESS_TOKEN: &str = "privateHeader.privatePayload.privateSignature";
const TEST_TIMEOUT: Duration = Duration::from_secs(3);

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly remained pending"),
    }
}

struct StaticReader {
    calls: Arc<Mutex<Vec<String>>>,
    result: Result<VersionedDecisionRecord, DecisionGrpcClientError>,
}

impl DecisionServiceReader for StaticReader {
    fn get_decision<'a>(&'a self, decision_id: &'a str) -> DecisionServiceReadFuture<'a> {
        self.calls.lock().unwrap().push(decision_id.to_owned());
        let result = self.result.clone();
        Box::pin(async move { result })
    }
}

struct PendingRead {
    dropped: Arc<AtomicBool>,
}

impl Future for PendingRead {
    type Output = Result<VersionedDecisionRecord, DecisionGrpcClientError>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PendingRead {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct PendingReader {
    dropped: Arc<AtomicBool>,
}

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

struct ExactAuthenticator {
    calls: Arc<AtomicUsize>,
}

impl TenantAuthenticator for ExactAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let accepted = context
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == format!("Bearer {ACCESS_TOKEN}"));
        Box::pin(async move {
            if accepted {
                Ok("tenant-m30".to_owned())
            } else {
                Err(AuthenticateTenantError::rejected())
            }
        })
    }
}

struct ExactExecutor {
    observed: Arc<Mutex<Vec<(String, String)>>>,
}

impl TenantScopedGetDecisionExecutor for ExactExecutor {
    fn execute_get_decision(
        &self,
        scope: TenantScope,
        query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        self.observed.lock().unwrap().push((
            scope.tenant_id().to_owned(),
            query.decision_id().to_string(),
        ));
        Box::pin(async { Ok(decision_record()) })
    }
}

struct TestServer {
    address: SocketAddr,
    certificate_pem: Vec<u8>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<(), ServeDecisionGrpcServerError>>,
}

impl TestServer {
    fn client_config(&self) -> DecisionGrpcClientConfig {
        DecisionGrpcClientConfig::try_new(
            format!("https://{}", self.address),
            "localhost".to_owned(),
            self.certificate_pem.clone(),
            DecisionGrpcClientLimits::try_new(
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(1),
                2,
            )
            .unwrap(),
        )
        .unwrap()
    }

    async fn stop(self) {
        self.shutdown.send(()).unwrap();
        guarded(self.task).await.unwrap().unwrap();
    }
}

async fn start_server(authenticator: ExactAuthenticator, executor: ExactExecutor) -> TestServer {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate_pem = cert.pem().into_bytes();
    let identity = DecisionGrpcTlsIdentity::try_from_pem(
        certificate_pem.clone(),
        signing_key.serialize_pem().into_bytes(),
    )
    .unwrap();
    let limits = DecisionGrpcServerLimits::try_new(
        4,
        4,
        Duration::from_millis(250),
        Duration::from_secs(2),
        Duration::from_secs(30),
        Duration::from_secs(1),
        Duration::from_secs(3),
    )
    .unwrap();
    let config = DecisionGrpcServerConfig::new(
        DecisionGrpcBind::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap(),
        limits,
    );
    let server = guarded(DecisionGrpcServer::bind(config, identity))
        .await
        .unwrap();
    let address = server.local_addr();
    let service = DecisionGrpcService::new(
        authenticator,
        executor,
        DecisionGrpcServiceConfig::try_new(4, Duration::from_secs(2)).unwrap(),
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

async fn guarded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TEST_TIMEOUT, future)
        .await
        .expect("test operation timed out")
}

impl DecisionServiceReader for PendingReader {
    fn get_decision<'a>(&'a self, _decision_id: &'a str) -> DecisionServiceReadFuture<'a> {
        Box::pin(PendingRead {
            dropped: Arc::clone(&self.dropped),
        })
    }
}

#[allow(deprecated)]
fn decision_record() -> v2::DecisionRecord {
    v2::DecisionRecord {
        decision_id: DECISION_ID.to_owned(),
        cou_id: "COU-M30".to_owned(),
        evidence_snapshot_id: "ES-M30".to_owned(),
        recommendation: v2::Recommendation::Promote as i32,
        rationale: vec!["Authenticated service result.".to_owned()],
        aggregate_version: u64::MAX,
        evidence: Some(v2::EvidenceSnapshotRef {
            id: "ES-M30".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        }),
    }
}

#[test]
fn reads_one_exact_decision_with_service_provenance() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let expected = decision_record();
    let reader = StaticReader {
        calls: Arc::clone(&calls),
        result: Ok(VersionedDecisionRecord::try_from(expected.clone()).unwrap()),
    };
    let source = DecisionSourceAdapter::try_new(reader, DECISION_ID).unwrap();

    let sourced = block_on_ready(source.read_current_decision())
        .unwrap()
        .unwrap();
    let (record, provenance) = sourced.into_parts();

    assert_eq!(record, expected);
    assert_eq!(provenance, DecisionProvenance::DecisionService);
    assert_eq!(*calls.lock().unwrap(), vec![DECISION_ID]);
}

#[test]
fn rejects_a_noncanonical_identifier_before_reader_work() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let reader = StaticReader {
        calls: Arc::clone(&calls),
        result: Err(DecisionGrpcClientError::Unavailable),
    };

    let result = DecisionSourceAdapter::try_new(reader, &DECISION_ID.to_uppercase());

    assert!(result.is_err());
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn maps_not_found_to_an_absent_current_decision() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let reader = StaticReader {
        calls: Arc::clone(&calls),
        result: Err(DecisionGrpcClientError::NotFound),
    };
    let source = DecisionSourceAdapter::try_new(reader, DECISION_ID).unwrap();

    let result = block_on_ready(source.read_current_decision());

    assert_eq!(result, Ok(None));
    assert_eq!(*calls.lock().unwrap(), vec![DECISION_ID]);
}

#[test]
fn rejects_a_reader_response_for_a_different_decision() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut response = decision_record();
    response.decision_id = "018f5a72-9c4b-7d31-8f6a-26f08f3fa631".to_owned();
    let reader = StaticReader {
        calls: Arc::clone(&calls),
        result: Ok(VersionedDecisionRecord::try_from(response).unwrap()),
    };
    let source = DecisionSourceAdapter::try_new(reader, DECISION_ID).unwrap();

    let result = block_on_ready(source.read_current_decision());

    assert_eq!(result, Err(DecisionRuntimeError::InvalidResponse));
    assert_eq!(*calls.lock().unwrap(), vec![DECISION_ID]);
}

#[test]
fn maps_client_failures_to_fixed_runtime_categories() {
    let cases = [
        (
            DecisionGrpcClientError::InvalidConfiguration,
            DecisionRuntimeError::Unavailable,
        ),
        (
            DecisionGrpcClientError::InvalidDecisionId,
            DecisionRuntimeError::InvalidResponse,
        ),
        (
            DecisionGrpcClientError::AuthenticationUnavailable,
            DecisionRuntimeError::AuthenticationUnavailable,
        ),
        (
            DecisionGrpcClientError::CapacityExhausted,
            DecisionRuntimeError::CapacityExhausted,
        ),
        (
            DecisionGrpcClientError::Unauthenticated,
            DecisionRuntimeError::AuthenticationRejected,
        ),
        (
            DecisionGrpcClientError::PermissionDenied,
            DecisionRuntimeError::AccessDenied,
        ),
        (
            DecisionGrpcClientError::DeadlineExceeded,
            DecisionRuntimeError::DeadlineExceeded,
        ),
        (
            DecisionGrpcClientError::Unavailable,
            DecisionRuntimeError::Unavailable,
        ),
        (
            DecisionGrpcClientError::InvalidResponse,
            DecisionRuntimeError::InvalidResponse,
        ),
    ];

    for (client_error, expected) in cases {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let source = DecisionSourceAdapter::try_new(
            StaticReader {
                calls: Arc::clone(&calls),
                result: Err(client_error),
            },
            DECISION_ID,
        )
        .unwrap();

        assert_eq!(
            block_on_ready(source.read_current_decision()),
            Err(expected),
            "unexpected mapping for {client_error:?}"
        );
        assert_eq!(*calls.lock().unwrap(), vec![DECISION_ID]);
    }
}

#[test]
fn dropping_the_source_future_cancels_reader_work() {
    let dropped = Arc::new(AtomicBool::new(false));
    let source = DecisionSourceAdapter::try_new(
        PendingReader {
            dropped: Arc::clone(&dropped),
        },
        DECISION_ID,
    )
    .unwrap();
    let mut future = source.read_current_decision();
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);

    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    drop(future);

    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_authenticated_decision_through_real_client_source_over_tls() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let auth_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let server = start_server(
        ExactAuthenticator {
            calls: Arc::clone(&auth_calls),
        },
        ExactExecutor {
            observed: Arc::clone(&observed),
        },
    )
    .await;
    let client = guarded(DecisionGrpcClient::connect(
        server.client_config(),
        StaticAccessTokenProvider {
            calls: Arc::clone(&provider_calls),
        },
    ))
    .await
    .unwrap();
    let source = DecisionServiceSource::try_new(client, DECISION_ID).unwrap();

    let sourced = guarded(source.read_current_decision())
        .await
        .unwrap()
        .unwrap();
    let (record, provenance) = sourced.into_parts();

    assert_eq!(record, decision_record());
    assert_eq!(provenance, DecisionProvenance::DecisionService);
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(auth_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *observed.lock().unwrap(),
        vec![("tenant-m30".to_owned(), DECISION_ID.to_owned())]
    );

    server.stop().await;
}
