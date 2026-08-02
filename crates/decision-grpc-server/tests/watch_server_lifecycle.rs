use std::{
    future,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bioworld_contracts::v2::{
    WatchDecisionRequest, decision_service_client::DecisionServiceClient,
    decision_service_server::DecisionService as GeneratedDecisionService,
};
use bioworld_decision_grpc::{
    AuthenticateTenantFuture, DecisionGrpcService, DecisionGrpcServiceConfig,
    DecisionGrpcWatchConfig, TenantAuthenticationContext, TenantAuthenticator, TenantAuthority,
    TenantScope, TenantScopedGetDecisionExecutor, TenantScopedGetDecisionFuture,
    TenantScopedWatchDecisionExecutor,
};
use bioworld_decision_grpc_server::{
    DecisionGrpcBind, DecisionGrpcServer, DecisionGrpcServerConfig, DecisionGrpcServerLimits,
    DecisionGrpcTlsIdentity,
};
use bioworld_decision_query::{
    DecisionReplay, DecisionReplayPageSize, DecisionReplaySource, DecisionReplaySourceFuture,
    DecisionReplaySourcePage, GetDecisionQuery, GetDecisionRequestExecutionError,
    WatchDecisionQuery,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::sync::oneshot;
use tonic::{
    Code, Request,
    transport::{Certificate, ClientTlsConfig, Endpoint},
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

fn transport_config() -> DecisionGrpcServerConfig {
    let limits = DecisionGrpcServerLimits::try_new(
        2,
        1,
        1,
        Duration::from_secs(1),
        Duration::from_secs(5),
        Duration::from_secs(30),
        Duration::from_secs(1),
        Duration::from_secs(10),
    )
    .unwrap();

    DecisionGrpcServerConfig::new(
        DecisionGrpcBind::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap(),
        limits,
    )
}

struct StaticAuthenticator;

impl TenantAuthenticator for StaticAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        Box::pin(async {
            TenantAuthority::try_new(
                "trusted-tenant".to_owned(),
                tokio::time::Instant::now() + Duration::from_secs(60),
            )
            .map_err(|_| bioworld_decision_grpc::AuthenticateTenantError::rejected())
        })
    }
}

struct DormantSource {
    entered: Option<oneshot::Sender<()>>,
    dropped: Option<oneshot::Sender<()>>,
    dropped_flag: Arc<AtomicBool>,
}

impl Drop for DormantSource {
    fn drop(&mut self) {
        self.dropped_flag.store(true, Ordering::SeqCst);
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl DecisionReplaySource for DormantSource {
    type Continuation = u64;

    fn read_page<'a>(
        &'a mut self,
        _query: WatchDecisionQuery,
        _page_size: DecisionReplayPageSize,
        _continuation: Option<&'a Self::Continuation>,
    ) -> DecisionReplaySourceFuture<'a, Self::Continuation> {
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
        }
        Box::pin(future::pending::<
            Result<
                DecisionReplaySourcePage<Self::Continuation>,
                bioworld_decision_query::DecisionReplaySourceError,
            >,
        >())
    }
}

struct DormantWatchExecutor {
    source: Mutex<Option<DormantSource>>,
}

impl TenantScopedGetDecisionExecutor for DormantWatchExecutor {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        Box::pin(async { Err(GetDecisionRequestExecutionError::NotFound) })
    }
}

impl TenantScopedWatchDecisionExecutor for DormantWatchExecutor {
    type Source = DormantSource;

    fn execute_watch_decision(
        &self,
        _scope: TenantScope,
        query: WatchDecisionQuery,
        page_size: DecisionReplayPageSize,
    ) -> DecisionReplay<Self::Source> {
        let source = self
            .source
            .lock()
            .unwrap()
            .take()
            .expect("watch executor must be invoked once");
        DecisionReplay::new(source, query, page_size)
    }
}

async fn guarded<T>(operation: impl future::Future<Output = T>) -> T {
    tokio::time::timeout(TEST_TIMEOUT, operation)
        .await
        .expect("test operation timed out")
}

#[tokio::test]
async fn shutdown_drops_a_dormant_watch_source_before_serve_returns() {
    let tls = test_tls();
    let server = DecisionGrpcServer::bind(transport_config(), tls.identity)
        .await
        .unwrap();
    let address = server.local_addr();
    let (source_entered_tx, source_entered_rx) = oneshot::channel();
    let (source_dropped_tx, mut source_dropped_rx) = oneshot::channel();
    let source_dropped = Arc::new(AtomicBool::new(false));
    let executor = DormantWatchExecutor {
        source: Mutex::new(Some(DormantSource {
            entered: Some(source_entered_tx),
            dropped: Some(source_dropped_tx),
            dropped_flag: Arc::clone(&source_dropped),
        })),
    };
    let service = DecisionGrpcService::try_new_with_watch(
        StaticAuthenticator,
        executor,
        DecisionGrpcServiceConfig::try_new(2, Duration::from_secs(5)).unwrap(),
        DecisionGrpcWatchConfig::try_new(1, 1).unwrap(),
    )
    .unwrap();
    let watch_lifecycle = service
        .watch_lifecycle()
        .expect("Watch-enabled service must expose its lifecycle");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut server_task = tokio::spawn(server.serve(service, async move {
        let _ = shutdown_rx.await;
    }));
    let channel = guarded(
        Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(tls.certificate_pem))
                    .domain_name("localhost"),
            )
            .unwrap()
            .connect(),
    )
    .await
    .unwrap();
    let mut stream = guarded(DecisionServiceClient::new(channel).watch_decision(
        WatchDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        },
    ))
    .await
    .unwrap()
    .into_inner();
    let pending_event = tokio::spawn(async move { stream.message().await });

    guarded(source_entered_rx)
        .await
        .expect("Watch source must enter a pending read");
    assert_eq!(watch_lifecycle.active_workers(), 1);
    shutdown_tx.send(()).unwrap();

    tokio::select! {
        biased;
        source_result = &mut source_dropped_rx => {
            source_result.expect("Watch source drop signal must remain available");
        }
        server_result = &mut server_task => {
            panic!("server returned before the dormant Watch source dropped: {server_result:?}");
        }
    }

    assert!(source_dropped.load(Ordering::SeqCst));
    guarded(server_task).await.unwrap().unwrap();
    assert_eq!(watch_lifecycle.active_workers(), 0);
    let _ = guarded(pending_event).await;
}

#[tokio::test]
async fn closed_watch_lifecycle_rejects_new_worker_registration() {
    let (source_entered_tx, mut source_entered_rx) = oneshot::channel();
    let (source_dropped_tx, _source_dropped_rx) = oneshot::channel();
    let executor = DormantWatchExecutor {
        source: Mutex::new(Some(DormantSource {
            entered: Some(source_entered_tx),
            dropped: Some(source_dropped_tx),
            dropped_flag: Arc::new(AtomicBool::new(false)),
        })),
    };
    let service = DecisionGrpcService::try_new_with_watch(
        StaticAuthenticator,
        executor,
        DecisionGrpcServiceConfig::try_new(2, Duration::from_secs(5)).unwrap(),
        DecisionGrpcWatchConfig::try_new(1, 1).unwrap(),
    )
    .unwrap();
    let watch_lifecycle = service
        .watch_lifecycle()
        .expect("Watch-enabled service must expose its lifecycle");

    watch_lifecycle.begin_shutdown();
    let status = match GeneratedDecisionService::watch_decision(
        &service,
        Request::new(WatchDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        }),
    )
    .await
    {
        Ok(_) => panic!("closed Watch lifecycle must reject new work"),
        Err(status) => status,
    };

    assert_eq!(status.code(), Code::Unavailable);
    assert_eq!(status.message(), "decision service is unavailable");
    assert_eq!(watch_lifecycle.active_workers(), 0);
    assert!(matches!(
        source_entered_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    guarded(watch_lifecycle.wait()).await;
}
