use std::{
    collections::VecDeque,
    future::pending,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    digest::{SHA256, digest},
    rand::SystemRandom,
    rsa::{KeyPair, KeySize, PublicKeyComponents},
    signature::{Ed25519KeyPair, KeyPair as _, RSA_PKCS1_SHA256},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bioworld_contracts::v2::{
    DecisionPredictionInterval, DecisionPredictionPosition, DecisionRecord, EvidenceSnapshotRef,
    GetDecisionRequest, OodStatus, Recommendation, WatchDecisionRequest,
    decision_service_server::DecisionService as GeneratedDecisionService,
};
use bioworld_decision_grpc::{
    AuthenticateTenantError, AuthenticateTenantFuture, DecisionGrpcConnectInfo,
    DecisionGrpcPeerKey, DecisionGrpcService, DecisionGrpcServiceConfig,
    TenantAuthenticationContext, TenantAuthenticator, TenantAuthority, TenantScope, get_decision,
    watch_decision,
};
use bioworld_decision_grpc_jwt::{
    BIOWORLD_TENANT_CLAIM, JwtTenantAuthenticator, JwtTenantAuthenticatorConfig,
};
use bioworld_decision_grpc_postgres::{
    AcquirePostgresReaderError, AcquirePostgresReaderFuture, FinishPostgresReaderLeaseError,
    PooledPostgresReaderLease, PostgresDecisionExecutor, PostgresDecisionReplaySource,
    PostgresGetDecisionExecutor, PostgresReaderLease, PostgresReaderLeaseDisposition,
    PostgresReaderLeaseProvider, PostgresReaderPool, PostgresReaderPoolConfig,
};
use bioworld_decision_query::{
    DecisionReplay, DecisionReplayError, DecisionReplayPageSize, DecisionReplaySource,
    DecisionReplaySourceError, WatchDecisionQuery,
};
use bioworld_event_store_contracts::{
    DECISION_AGGREGATE_TYPE, DECISION_EVENT_TYPE, DECISION_SCHEMA_VERSION,
    DecisionEventVerificationClock, DecisionEventVerifier, ScientificEventRow,
    decision_event_signature_message, decision_event_signature_value, reconstruct_decision_event,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use tokio::task::JoinHandle;
use tokio_postgres::Client;
use tonic::{Code, Request, Status, codegen::tokio_stream::StreamExt};
use uuid::Uuid;

const POSTGRES_HOST: &str = "127.0.0.1";
const POSTGRES_PORT: u16 = 5432;
const POSTGRES_DATABASE: &str = "bioworld_migrations";
const POSTGRES_WRITER_USER: &str = "bioworld_writer";
const POSTGRES_READER_USER: &str = "bioworld_reader";
const POSTGRES_READER_APPLICATION_NAME: &str = "bioworld-decision-reader";
const WRITER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_WRITER_PASSWORD";
const READER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_READER_PASSWORD";
const INTEGRATION_REQUIRED_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_INTEGRATION_REQUIRED";
const OCCURRED_AT: &str = "2026-07-21T00:00:00Z";
const EVENT_KEY_ID: &str = "grpc-postgres-test";
const TEST_NOW: u64 = 1_800_000_000;
const TENANT_CONTEXT_IS_ABSENT: &str =
    "SELECT NULLIF(pg_catalog.current_setting('bioworld.tenant_id', true), '') IS NULL";
const INSERT_EVENT: &str = "INSERT INTO public.scientific_event (event_id, event_type, schema_version, aggregate_type, aggregate_id, aggregate_version, occurred_at, tenant_id, payload, payload_sha256, signature) VALUES ($1::text::uuid, $2, $3, $4, $5, $6::text::numeric, $7::text::timestamptz, $8, $9::text::jsonb, $10, $11::text::jsonb)";

const SHARED_DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3fa601";
const TENANT_A: &str = "tenant-grpc-postgres-a";
const TENANT_B: &str = "tenant-grpc-postgres-b";
const POOL_TENANT_A: &str = "tenant-grpc-pool-a";
const POOL_TENANT_B: &str = "tenant-grpc-pool-b";
const SERVICE_TENANT_A: &str = "tenant-grpc-service-a";
const SERVICE_TENANT_B: &str = "tenant-grpc-service-b";
const JWT_SERVICE_TENANT_A: &str = "tenant-jwt-service-a";
const JWT_SERVICE_TENANT_B: &str = "tenant-jwt-service-b";
const SERVICE_TIMEOUT_TENANT: &str = "tenant-grpc-service-timeout";
const REPLAY_TENANT_A: &str = "tenant-grpc-replay-a";
const REPLAY_TENANT_B: &str = "tenant-grpc-replay-b";
const REPLAY_HORIZON_TENANT: &str = "tenant-grpc-replay-horizon";
const REPLAY_ROTATION_TENANT: &str = "tenant-grpc-replay-rotation";
const REPLAY_CORRUPT_TENANT: &str = "tenant-grpc-replay-corrupt";
const REPLAY_CLEANUP_TENANT: &str = "tenant-grpc-replay-cleanup";
const REPLAY_DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3fa701";
const REPLAY_HIDDEN_DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3fa702";
const REPLAY_MISSING_DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3fa703";
const JWT_ISSUER: &str = "https://identity.bioworld.test";
const JWT_AUDIENCE: &str = "https://decision.bioworld.test";
const JWT_REQUIRED_SCOPE: &str = "decision:read";
const JWT_KEY_ID: &str = "postgres-integration-key";
const TEST_TENANTS: [&str; 24] = [
    TENANT_A,
    TENANT_B,
    POOL_TENANT_A,
    POOL_TENANT_B,
    SERVICE_TENANT_A,
    SERVICE_TENANT_B,
    JWT_SERVICE_TENANT_A,
    JWT_SERVICE_TENANT_B,
    SERVICE_TIMEOUT_TENANT,
    REPLAY_TENANT_A,
    REPLAY_TENANT_B,
    REPLAY_HORIZON_TENANT,
    REPLAY_ROTATION_TENANT,
    REPLAY_CORRUPT_TENANT,
    REPLAY_CLEANUP_TENANT,
    "tenant-grpc-postgres-cleanup",
    "tenant-grpc-postgres-closed",
    "tenant-grpc-postgres-corrupt",
    "tenant-grpc-postgres-finish",
    "tenant-grpc-postgres-hidden",
    "tenant-grpc-postgres-visible",
    "tenant-grpc-postgres-writer-role",
    "tenant-grpc-watch-executor-a",
    "tenant-grpc-watch-executor-b",
];
const TENANT_A_PAYLOAD: &str = r#"{"aggregate_version":"18446744073709551615","cou_id":"COU-GRPC-PG-A","decision_id":"018f5a72-9c4b-7d31-8f6a-26f08f3fa601","evidence":{"id":"ES-GRPC-PG-A","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"prediction_interval":{"calibration_evidence":{"id":"ES-CAL-001","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"calibration_method_id":"held_out_calibration","calibration_method_version":"2026.07","interval_method_id":"split_conformal","interval_method_version":"1.0","lower_decimal":"0.25","nominal_coverage_decimal":"0.95","target":"binding_affinity","unit":"nM","upper_decimal":"1.5"},"prediction_positions":[{"dependency_group_id":"shared-training-set","interval":{"calibration_evidence":{"id":"ES-CAL-001","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"calibration_method_id":"held_out_calibration","calibration_method_version":"2026.07","interval_method_id":"split_conformal","interval_method_version":"1.0","lower_decimal":"0.4","nominal_coverage_decimal":"0.95","target":"binding_affinity","unit":"nM","upper_decimal":"1.4"},"prediction_evidence":{"id":"ES-PRED-Z","sha256":"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},"source_id":"model-z","source_version":"2026.07"},{"dependency_group_id":"independent-assay","interval":{"calibration_evidence":{"id":"ES-CAL-001","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"calibration_method_id":"held_out_calibration","calibration_method_version":"2026.07","interval_method_id":"split_conformal","interval_method_version":"1.0","lower_decimal":"0.2","nominal_coverage_decimal":"0.95","target":"binding_affinity","unit":"nM","upper_decimal":"1.2"},"prediction_evidence":{"id":"ES-PRED-A","sha256":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},"source_id":"model-a","source_version":"2026.06"}],"rationale":["Tenant A decision."],"recommendation":"promote"}"#;
const TENANT_A_PAYLOAD_SHA256: &str =
    "fb6f8025346e9471ff088157960c3ae647d68056079772615db61948a0611b79";
const TENANT_B_PAYLOAD: &str = r#"{"aggregate_version":"7","cou_id":"COU-GRPC-PG-B","decision_id":"018f5a72-9c4b-7d31-8f6a-26f08f3fa601","evidence":{"id":"ES-GRPC-PG-B","sha256":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},"prediction_interval":{"calibration_evidence":{"id":"ES-CAL-001","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"calibration_method_id":"held_out_calibration","calibration_method_version":"2026.07","interval_method_id":"split_conformal","interval_method_version":"1.0","lower_decimal":"0.25","nominal_coverage_decimal":"0.95","target":"binding_affinity","unit":"nM","upper_decimal":"1.5"},"prediction_positions":[{"dependency_group_id":"shared-training-set","interval":{"calibration_evidence":{"id":"ES-CAL-001","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"calibration_method_id":"held_out_calibration","calibration_method_version":"2026.07","interval_method_id":"split_conformal","interval_method_version":"1.0","lower_decimal":"0.4","nominal_coverage_decimal":"0.95","target":"binding_affinity","unit":"nM","upper_decimal":"1.4"},"prediction_evidence":{"id":"ES-PRED-Z","sha256":"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},"source_id":"model-z","source_version":"2026.07"},{"dependency_group_id":"independent-assay","interval":{"calibration_evidence":{"id":"ES-CAL-001","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"calibration_method_id":"held_out_calibration","calibration_method_version":"2026.07","interval_method_id":"split_conformal","interval_method_version":"1.0","lower_decimal":"0.2","nominal_coverage_decimal":"0.95","target":"binding_affinity","unit":"nM","upper_decimal":"1.2"},"prediction_evidence":{"id":"ES-PRED-A","sha256":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},"source_id":"model-a","source_version":"2026.06"}],"rationale":["Tenant B decision."],"recommendation":"stop_program"}"#;
const TENANT_B_PAYLOAD_SHA256: &str =
    "55ca24153725158d6eb59c8c415c763625aad8b5162631cb2535aded1f7c6bbd";

struct IntegrationPasswords {
    writer: String,
    reader: String,
}

struct EventFixture {
    event_id: &'static str,
    tenant_id: &'static str,
    payload: &'static str,
    payload_sha256: &'static str,
    record: DecisionRecord,
}

#[derive(Clone, Copy)]
struct TestClock;

impl DecisionEventVerificationClock for TestClock {
    fn unix_timestamp(&self) -> Option<u64> {
        Some(TEST_NOW)
    }
}

fn event_signing_key(tenant_id: &str) -> Ed25519KeyPair {
    let seed = u8::try_from(
        TEST_TENANTS
            .iter()
            .position(|candidate| *candidate == tenant_id)
            .expect("fixture tenant must have a signing key")
            + 1,
    )
    .expect("fixture key index must fit in a byte");
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
        .expect("deterministic Ed25519 seed must be valid")
}

fn event_verifier() -> DecisionEventVerifier {
    let keys = TEST_TENANTS
        .iter()
        .map(|tenant_id| {
            let key = event_signing_key(tenant_id);
            json!({
                "tenant_id": tenant_id,
                "key_id": EVENT_KEY_ID,
                "algorithm": "Ed25519",
                "public_key": URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
                "not_before": 1,
                "not_after": 4_102_444_800_u64,
                "status": "trusted"
            })
        })
        .collect::<Vec<_>>();
    let snapshot = serde_json::to_vec(&json!({
        "version": "1",
        "valid_until": TEST_NOW + 60,
        "keys": keys
    }))
    .expect("fixture verifier snapshot must serialize");
    DecisionEventVerifier::try_from_snapshot_with_clock(&snapshot, TestClock)
        .expect("fixture verifier snapshot must be valid")
}

fn event_signature(
    event_id: &str,
    tenant_id: &str,
    decision_id: &str,
    aggregate_version: u64,
    payload: &str,
) -> String {
    let payload_sha256 = digest(&SHA256, payload.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let occurred_at = DateTime::parse_from_rfc3339(OCCURRED_AT)
        .expect("fixed event timestamp must parse")
        .with_timezone(&Utc);
    let row = ScientificEventRow {
        event_id: Uuid::parse_str(event_id).expect("fixed event identifier must parse"),
        event_type: DECISION_EVENT_TYPE.to_owned(),
        schema_version: DECISION_SCHEMA_VERSION.to_owned(),
        aggregate_type: DECISION_AGGREGATE_TYPE.to_owned(),
        aggregate_id: decision_id.to_owned(),
        aggregate_version,
        occurred_at,
        tenant_id: tenant_id.to_owned(),
        payload: serde_json::from_str(payload).expect("fixture payload must parse"),
        payload_sha256,
        signature: json!({"placeholder": true})
            .as_object()
            .expect("placeholder signature must be an object")
            .clone(),
    };
    let event = reconstruct_decision_event(&row).expect("fixture event must reconstruct");
    let message =
        decision_event_signature_message(event, tenant_id.to_owned(), occurred_at, EVENT_KEY_ID)
            .expect("fixture signature message must be valid");
    let signature = event_signing_key(tenant_id).sign(&message);
    serde_json::to_string(
        &decision_event_signature_value(EVENT_KEY_ID, signature.as_ref())
            .expect("fixture signature must be valid"),
    )
    .expect("fixture signature must serialize")
}

#[derive(Clone, Copy)]
struct VerifiedTestTenant(&'static str);

struct TestTenantAuthenticator;

struct IntegrationJwtKey {
    key_pair: KeyPair,
    jwks: Vec<u8>,
}

impl IntegrationJwtKey {
    fn generate() -> Self {
        let key_pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let components = PublicKeyComponents::<Vec<u8>>::from(key_pair.public_key());
        let jwks = serde_json::to_vec(&json!({
            "keys": [{
                "alg": "RS256",
                "e": URL_SAFE_NO_PAD.encode(components.e),
                "kid": JWT_KEY_ID,
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode(components.n),
                "use": "sig"
            }]
        }))
        .unwrap();

        Self { key_pair, jwks }
    }

    fn token(&self, now: u64, tenant_id: &str) -> String {
        let encoded_header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "RS256",
                "kid": JWT_KEY_ID,
                "typ": "at+jwt"
            }))
            .unwrap(),
        );
        let encoded_claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "aud": JWT_AUDIENCE,
                "client_id": "postgres-integration-client",
                "exp": now + 300,
                "iat": now,
                "iss": JWT_ISSUER,
                "jti": format!("postgres-integration-{tenant_id}"),
                "scope": JWT_REQUIRED_SCOPE,
                "sub": "postgres-integration-subject",
                BIOWORLD_TENANT_CLAIM: tenant_id
            }))
            .unwrap(),
        );
        let message = format!("{encoded_header}.{encoded_claims}");
        let mut signature = vec![0; self.key_pair.public_modulus_len()];
        self.key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message.as_bytes(),
                &mut signature,
            )
            .unwrap();

        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}

impl TenantAuthenticator for TestTenantAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        let result = context
            .extensions()
            .get::<VerifiedTestTenant>()
            .map(|tenant| {
                TenantAuthority::try_new(
                    tenant.0.to_owned(),
                    tokio::time::Instant::now() + Duration::from_secs(60),
                )
                .expect("fixed tenant authority must be valid")
            })
            .ok_or_else(AuthenticateTenantError::rejected);
        Box::pin(async move { result })
    }
}

#[derive(Clone)]
struct DelayFirstProductionLease {
    pool: PostgresReaderPool,
    acquired: Arc<AtomicUsize>,
}

impl PostgresReaderLeaseProvider for DelayFirstProductionLease {
    type Lease<'provider>
        = PooledPostgresReaderLease
    where
        Self: 'provider;

    fn acquire(&self) -> AcquirePostgresReaderFuture<'_, Self::Lease<'_>> {
        Box::pin(async move {
            let lease = self.pool.acquire().await?;
            if self.acquired.fetch_add(1, Ordering::SeqCst) == 0 {
                pending::<()>().await;
            }
            Ok(lease)
        })
    }
}

struct ReaderConnection {
    client: Client,
    connection_task: JoinHandle<()>,
}

impl ReaderConnection {
    async fn disconnect(&mut self) {
        self.connection_task.abort();
        let _ = (&mut self.connection_task).await;
        assert!(self.client.is_closed());
    }

    fn discard(self) {
        self.connection_task.abort();
    }
}

struct TestReaderPoolState {
    available: Mutex<VecDeque<ReaderConnection>>,
    acquisitions: AtomicUsize,
    active: AtomicUsize,
    maximum_active: AtomicUsize,
    finish_requests: Mutex<Vec<PostgresReaderLeaseDisposition>>,
    dispositions: Mutex<Vec<PostgresReaderLeaseDisposition>>,
    fail_next_finish: AtomicBool,
}

#[derive(Clone)]
struct TestReaderPool {
    state: Arc<TestReaderPoolState>,
}

impl TestReaderPool {
    fn new(connections: Vec<ReaderConnection>) -> Self {
        Self {
            state: Arc::new(TestReaderPoolState {
                available: Mutex::new(connections.into()),
                acquisitions: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                maximum_active: AtomicUsize::new(0),
                finish_requests: Mutex::new(Vec::new()),
                dispositions: Mutex::new(Vec::new()),
                fail_next_finish: AtomicBool::new(false),
            }),
        }
    }

    fn fail_next_finish(&self) {
        self.state.fail_next_finish.store(true, Ordering::SeqCst);
    }

    fn acquisitions(&self) -> usize {
        self.state.acquisitions.load(Ordering::SeqCst)
    }

    fn active(&self) -> usize {
        self.state.active.load(Ordering::SeqCst)
    }

    fn maximum_active(&self) -> usize {
        self.state.maximum_active.load(Ordering::SeqCst)
    }

    fn available(&self) -> usize {
        self.state
            .available
            .lock()
            .expect("reader pool lock must not be poisoned")
            .len()
    }

    fn finish_requests(&self) -> Vec<PostgresReaderLeaseDisposition> {
        self.state
            .finish_requests
            .lock()
            .expect("reader pool metrics lock must not be poisoned")
            .clone()
    }

    fn dispositions(&self) -> Vec<PostgresReaderLeaseDisposition> {
        self.state
            .dispositions
            .lock()
            .expect("reader pool metrics lock must not be poisoned")
            .clone()
    }

    async fn assert_available_sessions_are_clean(&self, expected: usize) {
        let mut connections = {
            let mut available = self
                .state
                .available
                .lock()
                .expect("reader pool lock must not be poisoned");
            available.drain(..).collect::<Vec<_>>()
        };

        assert_eq!(connections.len(), expected);
        for connection in &mut connections {
            let context_is_absent: bool = connection
                .client
                .query_one(TENANT_CONTEXT_IS_ABSENT, &[])
                .await
                .expect("reusable reader session must remain queryable")
                .get(0);
            assert!(context_is_absent);
        }

        self.state
            .available
            .lock()
            .expect("reader pool lock must not be poisoned")
            .extend(connections);
    }

    fn shutdown(&self) {
        let connections = self
            .state
            .available
            .lock()
            .expect("reader pool lock must not be poisoned")
            .drain(..)
            .collect::<Vec<_>>();
        for connection in connections {
            connection.discard();
        }
    }
}

struct TestReaderLease {
    connection: Option<ReaderConnection>,
    state: Arc<TestReaderPoolState>,
    finished: bool,
}

impl TestReaderLease {
    fn conclude(&mut self, disposition: PostgresReaderLeaseDisposition) {
        self.finished = true;
        self.state.active.fetch_sub(1, Ordering::SeqCst);
        self.state
            .dispositions
            .lock()
            .expect("reader pool metrics lock must not be poisoned")
            .push(disposition);

        let connection = self
            .connection
            .take()
            .expect("active reader lease must own one connection");
        match disposition {
            PostgresReaderLeaseDisposition::Reuse => self
                .state
                .available
                .lock()
                .expect("reader pool lock must not be poisoned")
                .push_back(connection),
            PostgresReaderLeaseDisposition::Discard => connection.discard(),
        }
    }
}

impl PostgresReaderLease for TestReaderLease {
    fn client(&mut self) -> &mut Client {
        &mut self
            .connection
            .as_mut()
            .expect("active reader lease must own one connection")
            .client
    }

    fn finish(
        mut self,
        disposition: PostgresReaderLeaseDisposition,
    ) -> Result<(), FinishPostgresReaderLeaseError> {
        self.state
            .finish_requests
            .lock()
            .expect("reader pool metrics lock must not be poisoned")
            .push(disposition);

        if self.state.fail_next_finish.swap(false, Ordering::SeqCst) {
            self.conclude(PostgresReaderLeaseDisposition::Discard);
            return Err(FinishPostgresReaderLeaseError);
        }

        self.conclude(disposition);
        Ok(())
    }
}

impl Drop for TestReaderLease {
    fn drop(&mut self) {
        if !self.finished {
            self.conclude(PostgresReaderLeaseDisposition::Discard);
        }
    }
}

impl PostgresReaderLeaseProvider for TestReaderPool {
    type Lease<'provider>
        = TestReaderLease
    where
        Self: 'provider;

    fn acquire(&self) -> AcquirePostgresReaderFuture<'_, Self::Lease<'_>> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.acquisitions.fetch_add(1, Ordering::SeqCst);
            let connection = state
                .available
                .lock()
                .expect("reader pool lock must not be poisoned")
                .pop_front()
                .ok_or(AcquirePostgresReaderError)?;
            let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
            state.maximum_active.fetch_max(active, Ordering::SeqCst);

            Ok(TestReaderLease {
                connection: Some(connection),
                state,
                finished: false,
            })
        })
    }
}

fn integration_passwords() -> Option<IntegrationPasswords> {
    let writer = std::env::var(WRITER_PASSWORD_ENVIRONMENT_VARIABLE)
        .ok()
        .filter(|password| !password.is_empty());
    let reader = std::env::var(READER_PASSWORD_ENVIRONMENT_VARIABLE)
        .ok()
        .filter(|password| !password.is_empty());

    match (writer, reader) {
        (Some(writer), Some(reader)) => Some(IntegrationPasswords { writer, reader }),
        _ if std::env::var(INTEGRATION_REQUIRED_ENVIRONMENT_VARIABLE).as_deref() == Ok("1") => {
            panic!("required PostgreSQL integration credentials are unavailable")
        }
        _ => None,
    }
}

async fn connect(role: &str, password: String) -> ReaderConnection {
    let mut configuration = tokio_postgres::Config::new();
    configuration
        .host(POSTGRES_HOST)
        .port(POSTGRES_PORT)
        .dbname(POSTGRES_DATABASE)
        .user(role)
        .password(password);
    let (client, connection) = match configuration.connect(tokio_postgres::NoTls).await {
        Ok(connected) => connected,
        Err(_) => panic!("runtime role must connect through internal PostgreSQL TCP"),
    };
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });

    ReaderConnection {
        client,
        connection_task,
    }
}

fn production_reader_pool(
    password: String,
    max_size: usize,
    acquire_timeout: Duration,
) -> PostgresReaderPool {
    let mut configuration = tokio_postgres::Config::new();
    configuration
        .host(POSTGRES_HOST)
        .port(POSTGRES_PORT)
        .dbname(POSTGRES_DATABASE)
        .user(POSTGRES_READER_USER)
        .application_name(POSTGRES_READER_APPLICATION_NAME)
        .password(password);
    let pool_config = PostgresReaderPoolConfig::try_new(max_size, acquire_timeout)
        .expect("fixed reader pool configuration must be valid");

    PostgresReaderPool::try_new(configuration, tokio_postgres::NoTls, pool_config)
        .expect("reader pool must be constructible")
}

async fn seed_event(writer: &mut Client, fixture: &EventFixture) {
    seed_raw_event(
        writer,
        fixture.event_id,
        fixture.tenant_id,
        &fixture.record.decision_id,
        fixture.record.aggregate_version,
        fixture.payload,
        fixture.payload_sha256,
    )
    .await;
}

async fn seed_raw_event(
    writer: &mut Client,
    event_id: &str,
    tenant_id: &str,
    decision_id: &str,
    aggregate_version: u64,
    payload: &str,
    payload_sha256: &str,
) {
    let signature = event_signature(event_id, tenant_id, decision_id, aggregate_version, payload);
    let transaction = writer
        .transaction()
        .await
        .expect("fixture transaction must begin");
    let context_is_exact: bool = transaction
        .query_one(
            "SELECT pg_catalog.set_config('bioworld.tenant_id', $1, true) = $1",
            &[&tenant_id],
        )
        .await
        .expect("fixture tenant context must be set")
        .get(0);
    assert!(context_is_exact);

    let aggregate_version = aggregate_version.to_string();
    transaction
        .execute(
            INSERT_EVENT,
            &[
                &event_id,
                &DECISION_EVENT_TYPE,
                &DECISION_SCHEMA_VERSION,
                &DECISION_AGGREGATE_TYPE,
                &decision_id,
                &aggregate_version.as_str(),
                &OCCURRED_AT,
                &tenant_id,
                &payload,
                &payload_sha256,
                &signature.as_str(),
            ],
        )
        .await
        .expect("fixture event must be inserted");
    transaction
        .commit()
        .await
        .expect("fixture transaction must commit");
}

fn replay_payload(decision_id: &str, aggregate_version: u64, cou_id: &str) -> (String, String) {
    let payload = TENANT_A_PAYLOAD
        .replace(SHARED_DECISION_ID, decision_id)
        .replace(
            r#""aggregate_version":"18446744073709551615""#,
            &format!(r#""aggregate_version":"{aggregate_version}""#),
        )
        .replace("COU-GRPC-PG-A", cou_id)
        .replace("Tenant A decision.", cou_id);
    let payload_sha256 = digest(&SHA256, payload.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    (payload, payload_sha256)
}

async fn seed_replay_event(
    writer: &mut Client,
    event_id: &str,
    tenant_id: &str,
    decision_id: &str,
    aggregate_version: u64,
    cou_id: &str,
) {
    let (payload, payload_sha256) = replay_payload(decision_id, aggregate_version, cou_id);
    seed_raw_event(
        writer,
        event_id,
        tenant_id,
        decision_id,
        aggregate_version,
        &payload,
        &payload_sha256,
    )
    .await;
}

async fn tenant_context_is_absent(client: &Client) -> bool {
    client
        .query_one(TENANT_CONTEXT_IS_ABSENT, &[])
        .await
        .expect("tenant context reset must be queryable")
        .get(0)
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
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ),
        (
            "model-a",
            "2026.06",
            "independent-assay",
            "0.2",
            "1.2",
            "ES-PRED-A",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        ),
    ]
    .into_iter()
    .map(
        |(
            source_id,
            source_version,
            dependency_group_id,
            lower,
            upper,
            evidence_id,
            evidence_sha256,
        )| {
            DecisionPredictionPosition {
                source_id: source_id.to_owned(),
                source_version: source_version.to_owned(),
                dependency_group_id: dependency_group_id.to_owned(),
                interval: Some(prediction_interval(lower, upper)),
                prediction_evidence: Some(EvidenceSnapshotRef {
                    id: evidence_id.to_owned(),
                    sha256: evidence_sha256.to_owned(),
                }),
            }
        },
    )
    .collect()
}

#[allow(deprecated)]
fn record(
    decision_id: &str,
    cou_id: &str,
    evidence_id: &str,
    evidence_sha256: &str,
    recommendation: Recommendation,
    rationale: &str,
    aggregate_version: u64,
) -> DecisionRecord {
    DecisionRecord {
        decision_id: decision_id.to_owned(),
        cou_id: cou_id.to_owned(),
        evidence_snapshot_id: evidence_id.to_owned(),
        recommendation: recommendation as i32,
        rationale: vec![rationale.to_owned()],
        aggregate_version,
        evidence: Some(EvidenceSnapshotRef {
            id: evidence_id.to_owned(),
            sha256: evidence_sha256.to_owned(),
        }),
        ood_status: Some(OodStatus::Unknown as i32),
        ood_detector: None,
        prediction_interval: Some(prediction_interval("0.25", "1.5")),
        prediction_positions: prediction_positions(),
        decision_criterion: None,
    }
}

fn tenant_a_fixture() -> EventFixture {
    EventFixture {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6bc601",
        tenant_id: TENANT_A,
        payload: TENANT_A_PAYLOAD,
        payload_sha256: TENANT_A_PAYLOAD_SHA256,
        record: record(
            SHARED_DECISION_ID,
            "COU-GRPC-PG-A",
            "ES-GRPC-PG-A",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            Recommendation::Promote,
            "Tenant A decision.",
            u64::MAX,
        ),
    }
}

fn tenant_b_fixture() -> EventFixture {
    EventFixture {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6bc601",
        tenant_id: TENANT_B,
        payload: TENANT_B_PAYLOAD,
        payload_sha256: TENANT_B_PAYLOAD_SHA256,
        record: record(
            SHARED_DECISION_ID,
            "COU-GRPC-PG-B",
            "ES-GRPC-PG-B",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            Recommendation::StopProgram,
            "Tenant B decision.",
            7,
        ),
    }
}

fn pool_tenant_a_fixture() -> EventFixture {
    EventFixture {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6bc611",
        tenant_id: POOL_TENANT_A,
        payload: TENANT_A_PAYLOAD,
        payload_sha256: TENANT_A_PAYLOAD_SHA256,
        record: tenant_a_fixture().record,
    }
}

fn pool_tenant_b_fixture() -> EventFixture {
    EventFixture {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6bc612",
        tenant_id: POOL_TENANT_B,
        payload: TENANT_B_PAYLOAD,
        payload_sha256: TENANT_B_PAYLOAD_SHA256,
        record: tenant_b_fixture().record,
    }
}

fn service_tenant_a_fixture() -> EventFixture {
    EventFixture {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6bc621",
        tenant_id: SERVICE_TENANT_A,
        payload: TENANT_A_PAYLOAD,
        payload_sha256: TENANT_A_PAYLOAD_SHA256,
        record: tenant_a_fixture().record,
    }
}

fn service_tenant_b_fixture() -> EventFixture {
    EventFixture {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6bc622",
        tenant_id: SERVICE_TENANT_B,
        payload: TENANT_B_PAYLOAD,
        payload_sha256: TENANT_B_PAYLOAD_SHA256,
        record: tenant_b_fixture().record,
    }
}

fn jwt_service_tenant_a_fixture() -> EventFixture {
    EventFixture {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6bc631",
        tenant_id: JWT_SERVICE_TENANT_A,
        payload: TENANT_A_PAYLOAD,
        payload_sha256: TENANT_A_PAYLOAD_SHA256,
        record: tenant_a_fixture().record,
    }
}

fn jwt_service_tenant_b_fixture() -> EventFixture {
    EventFixture {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6bc632",
        tenant_id: JWT_SERVICE_TENANT_B,
        payload: TENANT_B_PAYLOAD,
        payload_sha256: TENANT_B_PAYLOAD_SHA256,
        record: tenant_b_fixture().record,
    }
}

fn service_timeout_fixture() -> EventFixture {
    EventFixture {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6bc623",
        tenant_id: SERVICE_TIMEOUT_TENANT,
        payload: TENANT_A_PAYLOAD,
        payload_sha256: TENANT_A_PAYLOAD_SHA256,
        record: tenant_a_fixture().record,
    }
}

fn scope(tenant_id: &str) -> TenantScope {
    TenantScope::try_from_trusted_tenant_id(tenant_id.to_owned())
        .expect("fixed tenant scope must be valid")
}

fn request(decision_id: &str) -> Request<GetDecisionRequest> {
    Request::new(GetDecisionRequest {
        decision_id: decision_id.to_owned(),
    })
}

fn watch_request(decision_id: &str) -> WatchDecisionRequest {
    WatchDecisionRequest {
        decision_id: decision_id.to_owned(),
    }
}

fn watch_query(decision_id: &str) -> WatchDecisionQuery {
    WatchDecisionQuery::try_from(watch_request(decision_id))
        .expect("fixed replay query must be valid")
}

fn replay_page_size(value: usize) -> DecisionReplayPageSize {
    DecisionReplayPageSize::try_from(value).expect("fixed replay page size must be valid")
}

async fn next_replay_cou_id<S>(replay: &mut DecisionReplay<S>) -> String
where
    S: DecisionReplaySource,
{
    let page = replay
        .next_page()
        .await
        .expect("replay page must succeed")
        .expect("replay page must exist");
    assert_eq!(page.events().len(), 1);
    page.events()[0]
        .decision
        .as_ref()
        .expect("replay event must contain a decision")
        .cou_id
        .clone()
}

fn authenticated_request(
    tenant_id: &'static str,
    decision_id: &str,
) -> Request<GetDecisionRequest> {
    let mut request = request(decision_id);
    request
        .extensions_mut()
        .insert(VerifiedTestTenant(tenant_id));
    request
        .metadata_mut()
        .insert("x-tenant-id", "hostile-client-tenant".parse().unwrap());
    request
}

fn jwt_authenticated_request(
    token: &str,
    hostile_tenant_id: &str,
    decision_id: &str,
    peer: SocketAddr,
) -> Request<GetDecisionRequest> {
    let mut request = request(decision_id);
    request
        .extensions_mut()
        .insert(DecisionGrpcConnectInfo::new(
            DecisionGrpcPeerKey::from_socket_addr(peer),
        ));
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
        .metadata_mut()
        .insert("x-tenant-id", hostile_tenant_id.parse().unwrap());
    request
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("integration clock must follow the Unix epoch")
        .as_secs()
}

fn assert_public_status(status: &Status, code: Code, message: &str) {
    assert_eq!(status.code(), code);
    assert_eq!(status.message(), message);
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
}

fn assert_status_does_not_reflect(status: &Status, sensitive_values: &[&str]) {
    let rendered = format!("{status:?} {status}");
    for sensitive in sensitive_values {
        assert!(!rendered.contains(sensitive));
    }
}

#[tokio::test]
async fn production_pool_preserves_startup_config_and_reuses_a_finished_session() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let pool = production_reader_pool(passwords.reader, 1, Duration::from_secs(1));

    let mut first = pool.acquire().await.expect("first lease must be acquired");
    let first_backend: i32 = first
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("first lease must be queryable")
        .get(0);
    let first_application_name: String = first
        .client()
        .query_one("SELECT pg_catalog.current_setting('application_name')", &[])
        .await
        .expect("startup application name must be queryable")
        .get(0);
    assert_eq!(first_application_name, POSTGRES_READER_APPLICATION_NAME);
    first
        .finish(PostgresReaderLeaseDisposition::Reuse)
        .expect("healthy lease must return to the pool");

    let mut second = pool.acquire().await.expect("second lease must be acquired");
    let second_backend: i32 = second
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("reused lease must be queryable")
        .get(0);
    let second_application_name: String = second
        .client()
        .query_one("SELECT pg_catalog.current_setting('application_name')", &[])
        .await
        .expect("reused startup application name must be queryable")
        .get(0);
    second
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("final lease must be discarded");

    assert_eq!(second_backend, first_backend);
    assert_eq!(second_application_name, POSTGRES_READER_APPLICATION_NAME);
    pool.close();
}

#[tokio::test]
async fn production_pool_bounds_saturated_waits_and_recovers_after_reuse() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let pool = production_reader_pool(passwords.reader, 1, Duration::from_millis(500));
    let first = pool.acquire().await.expect("first lease must be acquired");
    let wait_started = Instant::now();
    let wait_error = tokio::time::timeout(Duration::from_millis(750), pool.acquire())
        .await
        .expect("pool wait must remain bounded")
        .err();
    let wait_elapsed = wait_started.elapsed();
    assert_eq!(wait_error, Some(AcquirePostgresReaderError));
    assert!(wait_elapsed >= Duration::from_millis(450));
    assert!(wait_elapsed < Duration::from_millis(750));

    first
        .finish(PostgresReaderLeaseDisposition::Reuse)
        .expect("healthy lease must release capacity");
    let recovered = pool
        .acquire()
        .await
        .expect("released capacity must serve the next acquisition");
    recovered
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("final lease must be discarded");
    pool.close();
}

#[tokio::test]
async fn cancelled_pool_wait_does_not_consume_reader_capacity() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let pool = production_reader_pool(passwords.reader, 1, Duration::from_secs(1));
    let first = pool.acquire().await.expect("first lease must be acquired");

    assert!(
        tokio::time::timeout(Duration::from_millis(25), pool.acquire())
            .await
            .is_err()
    );

    first
        .finish(PostgresReaderLeaseDisposition::Reuse)
        .expect("healthy lease must release capacity");
    let recovered = pool
        .acquire()
        .await
        .expect("cancelled waiter must not consume capacity");
    recovered
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("final lease must be discarded");
    pool.close();
}

#[tokio::test]
async fn closing_pool_releases_a_saturated_waiter_with_a_fixed_error() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let pool = production_reader_pool(passwords.reader, 1, Duration::from_secs(1));
    let first = pool.acquire().await.expect("first lease must be acquired");
    let mut waiter = Box::pin(pool.acquire());
    assert!(
        tokio::time::timeout(Duration::from_millis(25), waiter.as_mut())
            .await
            .is_err()
    );

    pool.close();

    assert_eq!(waiter.await.err(), Some(AcquirePostgresReaderError));
    first
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("active lease must be discarded after closure");
}

#[tokio::test]
async fn production_pool_replaces_an_explicitly_discarded_session() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let pool = production_reader_pool(passwords.reader, 1, Duration::from_secs(1));
    let marker = "m23-explicit-discard";
    let mut first = pool.acquire().await.expect("first lease must be acquired");
    let first_backend: i32 = first
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("first backend identity must be queryable")
        .get(0);
    let configured: String = first
        .client()
        .query_one(
            "SELECT pg_catalog.set_config('application_name', $1, false)",
            &[&marker],
        )
        .await
        .expect("session marker must be configured")
        .get(0);
    assert_eq!(configured, marker);
    first
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("discard must remove the marked session");

    let mut replacement = pool
        .acquire()
        .await
        .expect("discarded capacity must be replaced");
    let replacement_marker: String = replacement
        .client()
        .query_one("SELECT pg_catalog.current_setting('application_name')", &[])
        .await
        .expect("replacement session must be queryable")
        .get(0);
    let replacement_backend: i32 = replacement
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("replacement backend identity must be queryable")
        .get(0);
    assert_ne!(replacement_marker, marker);
    assert_ne!(replacement_backend, first_backend);
    replacement
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("replacement must be discarded");
    pool.close();
}

#[tokio::test]
async fn production_pool_replaces_an_unfinished_reader_lease() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let pool = production_reader_pool(passwords.reader, 1, Duration::from_secs(1));
    let marker = "m23-unfinished-lease";
    let mut unfinished = pool.acquire().await.expect("lease must be acquired");
    let unfinished_backend: i32 = unfinished
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("unfinished backend identity must be queryable")
        .get(0);
    let configured: String = unfinished
        .client()
        .query_one(
            "SELECT pg_catalog.set_config('application_name', $1, false)",
            &[&marker],
        )
        .await
        .expect("session marker must be configured")
        .get(0);
    assert_eq!(configured, marker);
    drop(unfinished);

    let mut replacement = pool
        .acquire()
        .await
        .expect("abandoned capacity must be replaced");
    let replacement_marker: String = replacement
        .client()
        .query_one("SELECT pg_catalog.current_setting('application_name')", &[])
        .await
        .expect("replacement session must be queryable")
        .get(0);
    let replacement_backend: i32 = replacement
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("replacement backend identity must be queryable")
        .get(0);
    assert_ne!(replacement_marker, marker);
    assert_ne!(replacement_backend, unfinished_backend);
    replacement
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("replacement must be discarded");
    pool.close();
}

#[tokio::test]
async fn production_pool_replaces_a_closed_reader_session() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let pool = production_reader_pool(passwords.reader, 1, Duration::from_secs(1));
    let mut closed = pool.acquire().await.expect("lease must be acquired");
    let closed_backend: i32 = closed
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("backend identity must be queryable")
        .get(0);
    let _ = closed
        .client()
        .simple_query("SELECT pg_catalog.pg_terminate_backend(pg_backend_pid())")
        .await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while !closed.client().is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminated reader session must close");
    closed
        .finish(PostgresReaderLeaseDisposition::Reuse)
        .expect("closed lease must be removed instead of reused");

    let mut replacement = pool
        .acquire()
        .await
        .expect("closed capacity must be replaced");
    let replacement_backend: i32 = replacement
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("replacement backend must be queryable")
        .get(0);
    assert_ne!(replacement_backend, closed_backend);
    replacement
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("replacement must be discarded");
    pool.close();
}

#[tokio::test]
async fn production_pool_executes_concurrent_tenant_isolated_reads() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let tenant_a = pool_tenant_a_fixture();
    let tenant_b = pool_tenant_b_fixture();
    seed_event(&mut writer.client, &tenant_a).await;
    seed_event(&mut writer.client, &tenant_b).await;
    let pool = production_reader_pool(passwords.reader, 2, Duration::from_secs(1));
    let executor = PostgresGetDecisionExecutor::new(pool.clone(), event_verifier());

    let (tenant_a_response, tenant_b_response) = tokio::join!(
        get_decision(&executor, scope(POOL_TENANT_A), request(SHARED_DECISION_ID),),
        get_decision(&executor, scope(POOL_TENANT_B), request(SHARED_DECISION_ID),),
    );
    let tenant_a_response = tenant_a_response.expect("tenant A decision must be returned");
    let tenant_b_response = tenant_b_response.expect("tenant B decision must be returned");

    assert_eq!(tenant_a_response.get_ref(), &tenant_a.record);
    assert_eq!(tenant_b_response.get_ref(), &tenant_b.record);
    assert_eq!(
        tenant_a_response.get_ref().prediction_interval,
        Some(prediction_interval("0.25", "1.5"))
    );
    assert_eq!(
        tenant_a_response.get_ref().prediction_positions,
        prediction_positions()
    );

    let mut first = pool.acquire().await.expect("first clean lease must return");
    let mut second = pool
        .acquire()
        .await
        .expect("second clean lease must return");
    assert!(tenant_context_is_absent(first.client()).await);
    assert!(tenant_context_is_absent(second.client()).await);
    first
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("first lease must be discarded");
    second
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("second lease must be discarded");

    pool.close();
    writer.discard();
}

#[tokio::test]
async fn generated_service_executes_concurrent_tenant_isolated_postgres_reads() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let tenant_a = service_tenant_a_fixture();
    let tenant_b = service_tenant_b_fixture();
    seed_event(&mut writer.client, &tenant_a).await;
    seed_event(&mut writer.client, &tenant_b).await;
    let pool = production_reader_pool(passwords.reader, 2, Duration::from_secs(1));
    let service = DecisionGrpcService::new(
        TestTenantAuthenticator,
        PostgresGetDecisionExecutor::new(pool.clone(), event_verifier()),
        DecisionGrpcServiceConfig::try_new(2, Duration::from_secs(2)).unwrap(),
    );

    let (tenant_a_response, tenant_b_response) = tokio::join!(
        GeneratedDecisionService::get_decision(
            &service,
            authenticated_request(SERVICE_TENANT_A, SHARED_DECISION_ID),
        ),
        GeneratedDecisionService::get_decision(
            &service,
            authenticated_request(SERVICE_TENANT_B, SHARED_DECISION_ID),
        ),
    );

    assert_eq!(
        tenant_a_response
            .expect("tenant A service response must succeed")
            .into_inner(),
        tenant_a.record
    );
    assert_eq!(
        tenant_b_response
            .expect("tenant B service response must succeed")
            .into_inner(),
        tenant_b.record
    );

    let mut first = pool.acquire().await.expect("first clean lease must return");
    let mut second = pool
        .acquire()
        .await
        .expect("second clean lease must return");
    assert!(tenant_context_is_absent(first.client()).await);
    assert!(tenant_context_is_absent(second.client()).await);
    first
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("first lease must be discarded");
    second
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("second lease must be discarded");

    pool.close();
    writer.discard();
}

#[tokio::test]
async fn jwt_authenticated_service_executes_tenant_isolated_postgres_reads() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let tenant_a = jwt_service_tenant_a_fixture();
    let tenant_b = jwt_service_tenant_b_fixture();
    seed_event(&mut writer.client, &tenant_a).await;
    seed_event(&mut writer.client, &tenant_b).await;
    let now = unix_timestamp();
    let signing_key = IntegrationJwtKey::generate();
    let authenticator = JwtTenantAuthenticator::try_from_jwks(
        JwtTenantAuthenticatorConfig::try_new(
            JWT_ISSUER.to_owned(),
            JWT_AUDIENCE.to_owned(),
            JWT_REQUIRED_SCOPE.to_owned(),
            now + 600,
            2,
            1,
        )
        .unwrap(),
        &signing_key.jwks,
    )
    .unwrap();
    let pool = production_reader_pool(passwords.reader, 2, Duration::from_secs(1));
    let service = DecisionGrpcService::new(
        authenticator,
        PostgresGetDecisionExecutor::new(pool.clone(), event_verifier()),
        DecisionGrpcServiceConfig::try_new(2, Duration::from_secs(2)).unwrap(),
    );
    let tenant_a_token = signing_key.token(now, JWT_SERVICE_TENANT_A);
    let tenant_b_token = signing_key.token(now, JWT_SERVICE_TENANT_B);

    let (tenant_a_response, tenant_b_response) = tokio::join!(
        GeneratedDecisionService::get_decision(
            &service,
            jwt_authenticated_request(
                &tenant_a_token,
                JWT_SERVICE_TENANT_B,
                SHARED_DECISION_ID,
                "127.0.0.2:41000".parse().unwrap(),
            ),
        ),
        GeneratedDecisionService::get_decision(
            &service,
            jwt_authenticated_request(
                &tenant_b_token,
                JWT_SERVICE_TENANT_A,
                SHARED_DECISION_ID,
                "127.0.0.3:41000".parse().unwrap(),
            ),
        ),
    );

    assert_eq!(
        tenant_a_response
            .expect("tenant A JWT service response must succeed")
            .into_inner(),
        tenant_a.record
    );
    assert_eq!(
        tenant_b_response
            .expect("tenant B JWT service response must succeed")
            .into_inner(),
        tenant_b.record
    );

    let mut first = pool.acquire().await.expect("first clean lease must return");
    let mut second = pool
        .acquire()
        .await
        .expect("second clean lease must return");
    assert!(tenant_context_is_absent(first.client()).await);
    assert!(tenant_context_is_absent(second.client()).await);
    first
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("first lease must be discarded");
    second
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("second lease must be discarded");

    pool.close();
    writer.discard();
}

#[tokio::test]
async fn service_timeout_discards_an_acquired_production_lease_and_recovers() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let fixture = service_timeout_fixture();
    seed_event(&mut writer.client, &fixture).await;
    let pool = production_reader_pool(passwords.reader, 1, Duration::from_secs(1));
    let mut baseline = pool
        .acquire()
        .await
        .expect("baseline lease must be acquired");
    let baseline_backend: i32 = baseline
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("baseline backend identity must be queryable")
        .get(0);
    baseline
        .finish(PostgresReaderLeaseDisposition::Reuse)
        .expect("baseline lease must return to the pool");
    let acquired = Arc::new(AtomicUsize::new(0));
    let service = DecisionGrpcService::new(
        TestTenantAuthenticator,
        PostgresGetDecisionExecutor::new(
            DelayFirstProductionLease {
                pool: pool.clone(),
                acquired: Arc::clone(&acquired),
            },
            event_verifier(),
        ),
        DecisionGrpcServiceConfig::try_new(1, Duration::from_millis(100)).unwrap(),
    );

    let status = tokio::time::timeout(
        Duration::from_secs(1),
        GeneratedDecisionService::get_decision(
            &service,
            authenticated_request(SERVICE_TIMEOUT_TENANT, SHARED_DECISION_ID),
        ),
    )
    .await
    .expect("service timeout must remain bounded")
    .expect_err("delayed acquisition must time out");

    assert_public_status(
        &status,
        Code::DeadlineExceeded,
        "decision request deadline exceeded",
    );
    assert_eq!(acquired.load(Ordering::SeqCst), 1);

    let mut replacement = pool
        .acquire()
        .await
        .expect("discarded capacity must be replaced");
    let replacement_backend: i32 = replacement
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("replacement backend identity must be queryable")
        .get(0);
    assert_ne!(replacement_backend, baseline_backend);
    replacement
        .finish(PostgresReaderLeaseDisposition::Reuse)
        .expect("replacement lease must return to the pool");

    let response = GeneratedDecisionService::get_decision(
        &service,
        authenticated_request(SERVICE_TIMEOUT_TENANT, SHARED_DECISION_ID),
    )
    .await
    .expect("capacity must recover after service timeout");
    assert_eq!(response.into_inner(), fixture.record);

    let mut clean = pool.acquire().await.expect("clean lease must return");
    assert!(tenant_context_is_absent(clean.client()).await);
    clean
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("clean lease must be discarded");
    pool.close();
    writer.discard();
}

#[tokio::test]
async fn concurrent_scoped_reads_isolate_tenants_and_return_clean_sessions_for_reuse() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let tenant_a = tenant_a_fixture();
    let tenant_b = tenant_b_fixture();
    seed_event(&mut writer.client, &tenant_a).await;
    seed_event(&mut writer.client, &tenant_b).await;
    assert!(tenant_context_is_absent(&writer.client).await);

    let reader_a = connect(POSTGRES_READER_USER, passwords.reader.clone()).await;
    let reader_b = connect(POSTGRES_READER_USER, passwords.reader).await;
    let pool = TestReaderPool::new(vec![reader_a, reader_b]);
    let executor = PostgresGetDecisionExecutor::new(pool.clone(), event_verifier());
    let mut tenant_a_request = request(SHARED_DECISION_ID);
    tenant_a_request
        .metadata_mut()
        .insert("x-tenant-id", "attacker-tenant".parse().unwrap());

    let (tenant_a_response, tenant_b_response) = tokio::join!(
        get_decision(&executor, scope(TENANT_A), tenant_a_request),
        get_decision(&executor, scope(TENANT_B), request(SHARED_DECISION_ID)),
    );
    let tenant_a_response = tenant_a_response.expect("tenant A decision must be returned");
    let tenant_b_response = tenant_b_response.expect("tenant B decision must be returned");

    assert_eq!(tenant_a_response.get_ref(), &tenant_a.record);
    assert_eq!(tenant_a_response.get_ref().aggregate_version, u64::MAX);
    assert!(tenant_a_response.metadata().is_empty());
    assert_eq!(tenant_b_response.get_ref(), &tenant_b.record);
    assert_eq!(tenant_b_response.get_ref().aggregate_version, 7);
    assert!(tenant_b_response.metadata().is_empty());
    assert_eq!(pool.acquisitions(), 2);
    assert_eq!(pool.active(), 0);
    assert_eq!(pool.maximum_active(), 2);
    assert_eq!(
        pool.finish_requests(),
        vec![
            PostgresReaderLeaseDisposition::Reuse,
            PostgresReaderLeaseDisposition::Reuse,
        ]
    );
    assert_eq!(pool.dispositions(), pool.finish_requests());
    pool.assert_available_sessions_are_clean(2).await;

    pool.shutdown();
    writer.discard();
}

#[tokio::test]
async fn cross_tenant_and_absent_decisions_have_the_same_redacted_status() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let hidden_tenant = "tenant-grpc-postgres-hidden";
    let visible_tenant = "tenant-grpc-postgres-visible";
    let hidden_decision_id = "018f5a72-9c4b-7d31-8f6a-26f08f3fa602";
    let absent_decision_id = "018f5a72-9c4b-7d31-8f6a-26f08f3fa603";
    let hidden = EventFixture {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6bc602",
        tenant_id: hidden_tenant,
        payload: r#"{"aggregate_version":"1","cou_id":"COU-GRPC-PG-HIDDEN","decision_id":"018f5a72-9c4b-7d31-8f6a-26f08f3fa602","evidence":{"id":"ES-GRPC-PG-HIDDEN","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"rationale":["Hidden decision."],"recommendation":"defer"}"#,
        payload_sha256: "392792a5d8a222c597944ba2281f08fd71aa118e32cef28b4355da04d82af601",
        record: record(
            hidden_decision_id,
            "COU-GRPC-PG-HIDDEN",
            "ES-GRPC-PG-HIDDEN",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            Recommendation::Defer,
            "Hidden decision.",
            1,
        ),
    };
    seed_event(&mut writer.client, &hidden).await;

    let reader = connect(POSTGRES_READER_USER, passwords.reader).await;
    let pool = TestReaderPool::new(vec![reader]);
    let executor = PostgresGetDecisionExecutor::new(pool.clone(), event_verifier());
    let mut hidden_request = request(hidden_decision_id);
    hidden_request
        .metadata_mut()
        .insert("x-tenant-id", hidden_tenant.parse().unwrap());

    let hidden_status = get_decision(&executor, scope(visible_tenant), hidden_request)
        .await
        .expect_err("cross-tenant decision must appear absent");
    let absent_status = get_decision(
        &executor,
        scope(visible_tenant),
        request(absent_decision_id),
    )
    .await
    .expect_err("absent decision must return not found");

    for status in [&hidden_status, &absent_status] {
        assert_public_status(status, Code::NotFound, "decision was not found");
        assert_status_does_not_reflect(
            status,
            &[
                hidden_tenant,
                visible_tenant,
                hidden_decision_id,
                absent_decision_id,
            ],
        );
    }
    assert_eq!(pool.acquisitions(), 2);
    assert_eq!(
        pool.dispositions(),
        vec![
            PostgresReaderLeaseDisposition::Reuse,
            PostgresReaderLeaseDisposition::Reuse,
        ]
    );
    pool.assert_available_sessions_are_clean(1).await;

    pool.shutdown();
    writer.discard();
}

#[tokio::test]
async fn writer_identity_failure_is_redacted_and_returns_a_clean_reusable_lease() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let pool = TestReaderPool::new(vec![writer]);
    let executor = PostgresGetDecisionExecutor::new(pool.clone(), event_verifier());
    let submitted_tenant = "tenant-grpc-postgres-writer-role";
    let first_decision = "018f5a72-9c4b-7d31-8f6a-26f08f3fa606";
    let second_decision = "018f5a72-9c4b-7d31-8f6a-26f08f3fa608";

    let first_status = get_decision(&executor, scope(submitted_tenant), request(first_decision))
        .await
        .expect_err("writer identity must not execute a decision read");

    assert_public_status(
        &first_status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    assert_status_does_not_reflect(
        &first_status,
        &[submitted_tenant, first_decision, POSTGRES_WRITER_USER],
    );
    assert_eq!(pool.available(), 1);
    pool.assert_available_sessions_are_clean(1).await;

    let second_status = get_decision(&executor, scope(submitted_tenant), request(second_decision))
        .await
        .expect_err("clean writer session must be reusable and rejected again");

    assert_public_status(
        &second_status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    assert_status_does_not_reflect(
        &second_status,
        &[submitted_tenant, second_decision, POSTGRES_WRITER_USER],
    );
    assert_eq!(pool.acquisitions(), 2);
    assert_eq!(
        pool.finish_requests(),
        vec![
            PostgresReaderLeaseDisposition::Reuse,
            PostgresReaderLeaseDisposition::Reuse,
        ]
    );
    assert_eq!(pool.dispositions(), pool.finish_requests());
    assert_eq!(pool.active(), 0);
    pool.assert_available_sessions_are_clean(1).await;

    pool.shutdown();
}

#[tokio::test]
async fn inconsistent_stored_payload_is_redacted_and_returns_a_clean_reusable_lease() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let submitted_tenant = "tenant-grpc-postgres-corrupt";
    let submitted_decision = "018f5a72-9c4b-7d31-8f6a-26f08f3fa607";
    let corrupt_event_id = "01910d47-6f80-7a31-8c29-1d5c4f6bc607";
    let corrupt_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let corrupt = EventFixture {
        event_id: corrupt_event_id,
        tenant_id: submitted_tenant,
        payload: r#"{"aggregate_version":"2","cou_id":"COU-GRPC-PG-CORRUPT","decision_id":"018f5a72-9c4b-7d31-8f6a-26f08f3fa607","evidence":{"id":"ES-GRPC-PG-CORRUPT","sha256":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},"rationale":["Corrupt stored decision."],"recommendation":"reject"}"#,
        payload_sha256: corrupt_hash,
        record: record(
            submitted_decision,
            "COU-GRPC-PG-CORRUPT",
            "ES-GRPC-PG-CORRUPT",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            Recommendation::Reject,
            "Corrupt stored decision.",
            2,
        ),
    };
    seed_event(&mut writer.client, &corrupt).await;
    assert!(tenant_context_is_absent(&writer.client).await);

    let reader = connect(POSTGRES_READER_USER, passwords.reader).await;
    let pool = TestReaderPool::new(vec![reader]);
    let executor = PostgresGetDecisionExecutor::new(pool.clone(), event_verifier());

    let status = get_decision(
        &executor,
        scope(submitted_tenant),
        request(submitted_decision),
    )
    .await
    .expect_err("inconsistent stored state must be rejected");

    assert_public_status(
        &status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    assert_status_does_not_reflect(
        &status,
        &[
            submitted_tenant,
            submitted_decision,
            corrupt_event_id,
            corrupt_hash,
        ],
    );
    assert_eq!(pool.acquisitions(), 1);
    assert_eq!(
        pool.finish_requests(),
        vec![PostgresReaderLeaseDisposition::Reuse]
    );
    assert_eq!(pool.dispositions(), pool.finish_requests());
    assert_eq!(pool.active(), 0);
    pool.assert_available_sessions_are_clean(1).await;

    pool.shutdown();
    writer.discard();
}

#[tokio::test]
async fn closed_connection_is_redacted_and_discarded_without_reuse() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let reader_password = passwords.reader;
    let sensitive_password = reader_password.clone();
    let mut reader = connect(POSTGRES_READER_USER, reader_password).await;
    reader.disconnect().await;

    let pool = TestReaderPool::new(vec![reader]);
    let executor = PostgresGetDecisionExecutor::new(pool.clone(), event_verifier());
    let submitted_tenant = "tenant-grpc-postgres-closed";
    let submitted_decision = "018f5a72-9c4b-7d31-8f6a-26f08f3fa609";

    let status = get_decision(
        &executor,
        scope(submitted_tenant),
        request(submitted_decision),
    )
    .await
    .expect_err("closed reader connection must make the service unavailable");

    assert_public_status(
        &status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    assert_status_does_not_reflect(
        &status,
        &[
            submitted_tenant,
            submitted_decision,
            POSTGRES_READER_USER,
            &sensitive_password,
        ],
    );
    assert_eq!(pool.acquisitions(), 1);
    assert_eq!(
        pool.finish_requests(),
        vec![PostgresReaderLeaseDisposition::Discard]
    );
    assert_eq!(
        pool.dispositions(),
        vec![PostgresReaderLeaseDisposition::Discard]
    );
    assert_eq!(pool.active(), 0);
    assert_eq!(pool.available(), 0);
}

#[tokio::test]
async fn residual_tenant_context_discards_the_session_instead_of_reusing_it() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let reader = connect(POSTGRES_READER_USER, passwords.reader).await;
    let residual_tenant = "residual-sensitive-tenant";
    let configured: String = reader
        .client
        .query_one(
            "SELECT pg_catalog.set_config('bioworld.tenant_id', $1, false)",
            &[&residual_tenant],
        )
        .await
        .expect("residual tenant fixture must be configured")
        .get(0);
    assert_eq!(configured, residual_tenant);

    let pool = TestReaderPool::new(vec![reader]);
    let executor = PostgresGetDecisionExecutor::new(pool.clone(), event_verifier());
    let submitted_tenant = "tenant-grpc-postgres-cleanup";
    let submitted_decision = "018f5a72-9c4b-7d31-8f6a-26f08f3fa604";

    let status = get_decision(
        &executor,
        scope(submitted_tenant),
        request(submitted_decision),
    )
    .await
    .expect_err("unclean session must make the service unavailable");

    assert_public_status(
        &status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    assert_status_does_not_reflect(
        &status,
        &[residual_tenant, submitted_tenant, submitted_decision],
    );
    assert_eq!(
        pool.finish_requests(),
        vec![PostgresReaderLeaseDisposition::Discard]
    );
    assert_eq!(
        pool.dispositions(),
        vec![PostgresReaderLeaseDisposition::Discard]
    );
    assert_eq!(pool.active(), 0);
    assert_eq!(pool.available(), 0);
}

#[tokio::test]
async fn finish_failure_discards_the_session_and_overrides_the_application_result() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let reader = connect(POSTGRES_READER_USER, passwords.reader).await;
    let pool = TestReaderPool::new(vec![reader]);
    pool.fail_next_finish();
    let executor = PostgresGetDecisionExecutor::new(pool.clone(), event_verifier());
    let submitted_tenant = "tenant-grpc-postgres-finish";
    let submitted_decision = "018f5a72-9c4b-7d31-8f6a-26f08f3fa605";

    let status = get_decision(
        &executor,
        scope(submitted_tenant),
        request(submitted_decision),
    )
    .await
    .expect_err("failed lease finish must override not found");

    assert_public_status(
        &status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    assert_status_does_not_reflect(&status, &[submitted_tenant, submitted_decision]);
    assert_eq!(
        pool.finish_requests(),
        vec![PostgresReaderLeaseDisposition::Reuse]
    );
    assert_eq!(
        pool.dispositions(),
        vec![PostgresReaderLeaseDisposition::Discard]
    );
    assert_eq!(pool.active(), 0);
    assert_eq!(pool.available(), 0);
}

#[tokio::test]
async fn watch_executor_streams_exact_tenant_history_with_one_clean_lease_per_page() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let tenant_a = "tenant-grpc-watch-executor-a";
    let tenant_b = "tenant-grpc-watch-executor-b";
    let decision_id = "018f5a72-9c4b-7d31-8f6a-26f08f3fa801";
    let other_decision_id = "018f5a72-9c4b-7d31-8f6a-26f08f3fa802";
    let first_event_id = "01910d47-6f80-7a31-8c29-1d5c4f6ba801";
    let second_event_id = "01910d47-6f80-7a31-8c29-1d5c4f6ba802";
    let hidden_event_id = "01910d47-6f80-7a31-8c29-1d5c4f6ba803";
    let other_decision_event_id = "01910d47-6f80-7a31-8c29-1d5c4f6ba804";
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    for (event_id, tenant_id, seeded_decision_id, version, cou_id) in [
        (
            first_event_id,
            tenant_a,
            decision_id,
            1,
            "COU-WATCH-EXECUTOR-A1",
        ),
        (
            second_event_id,
            tenant_a,
            decision_id,
            2,
            "COU-WATCH-EXECUTOR-A2",
        ),
        (
            hidden_event_id,
            tenant_b,
            decision_id,
            1,
            "COU-WATCH-EXECUTOR-B1",
        ),
        (
            other_decision_event_id,
            tenant_a,
            other_decision_id,
            1,
            "COU-WATCH-EXECUTOR-A3",
        ),
    ] {
        seed_replay_event(
            &mut writer.client,
            event_id,
            tenant_id,
            seeded_decision_id,
            version,
            cou_id,
        )
        .await;
    }

    let reader = connect(POSTGRES_READER_USER, passwords.reader).await;
    let pool = TestReaderPool::new(vec![reader]);
    let executor = PostgresDecisionExecutor::new(pool.clone(), event_verifier());
    let response = watch_decision(
        &executor,
        scope(tenant_a),
        Request::new(watch_request(decision_id)),
    )
    .expect("valid watch request must return a replay stream");

    assert_eq!(pool.acquisitions(), 0);
    assert_eq!(pool.active(), 0);
    let mut stream = response.into_inner();
    let first = stream
        .next()
        .await
        .expect("first tenant event must exist")
        .expect("first tenant event must succeed");
    assert_eq!(first.event_id, first_event_id);
    assert_eq!(
        first
            .decision
            .as_ref()
            .expect("first replay event must contain a decision")
            .cou_id,
        "COU-WATCH-EXECUTOR-A1"
    );
    assert_eq!(pool.acquisitions(), 1);
    assert_eq!(pool.active(), 0);
    assert_eq!(pool.available(), 1);
    pool.assert_available_sessions_are_clean(1).await;

    let second = stream
        .next()
        .await
        .expect("second tenant event must exist")
        .expect("second tenant event must succeed");
    assert_eq!(second.event_id, second_event_id);
    assert_eq!(
        second
            .decision
            .as_ref()
            .expect("second replay event must contain a decision")
            .cou_id,
        "COU-WATCH-EXECUTOR-A2"
    );
    assert!(stream.next().await.is_none());
    assert!(stream.next().await.is_none());

    assert_eq!(pool.acquisitions(), 2);
    assert_eq!(pool.maximum_active(), 1);
    assert_eq!(pool.active(), 0);
    assert_eq!(pool.available(), 1);
    assert_eq!(
        pool.finish_requests(),
        vec![
            PostgresReaderLeaseDisposition::Reuse,
            PostgresReaderLeaseDisposition::Reuse,
        ]
    );
    assert_eq!(pool.dispositions(), pool.finish_requests());
    pool.assert_available_sessions_are_clean(1).await;

    drop(stream);
    pool.shutdown();
    writer.discard();
}

#[tokio::test]
async fn replay_uses_one_clean_lease_per_page_and_freezes_its_horizon() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    seed_replay_event(
        &mut writer.client,
        "01910d47-6f80-7a31-8c29-1d5c4f6ba711",
        REPLAY_HORIZON_TENANT,
        REPLAY_DECISION_ID,
        1,
        "COU-REPLAY-H1",
    )
    .await;
    seed_replay_event(
        &mut writer.client,
        "01910d47-6f80-7a31-8c29-1d5c4f6ba712",
        REPLAY_HORIZON_TENANT,
        REPLAY_DECISION_ID,
        2,
        "COU-REPLAY-H2",
    )
    .await;

    let reader = connect(POSTGRES_READER_USER, passwords.reader).await;
    let pool = TestReaderPool::new(vec![reader]);
    let source = PostgresDecisionReplaySource::new(
        pool.clone(),
        scope(REPLAY_HORIZON_TENANT),
        event_verifier(),
    );
    let mut replay = DecisionReplay::try_from_request(
        source,
        watch_request(REPLAY_DECISION_ID),
        replay_page_size(1),
    )
    .expect("fixed replay request must be valid");

    let first = replay
        .next_page()
        .await
        .expect("first replay page must succeed")
        .expect("first replay page must exist");
    assert_eq!(first.events().len(), 1);
    assert_eq!(
        first.events()[0].event_id,
        "01910d47-6f80-7a31-8c29-1d5c4f6ba711"
    );
    assert_eq!(
        first.events()[0]
            .decision
            .as_ref()
            .expect("replay event must contain a decision")
            .aggregate_version,
        1
    );
    assert_eq!(pool.acquisitions(), 1);
    assert_eq!(pool.active(), 0);
    assert_eq!(pool.available(), 1);
    pool.assert_available_sessions_are_clean(1).await;

    seed_replay_event(
        &mut writer.client,
        "01910d47-6f80-7a31-8c29-1d5c4f6ba713",
        REPLAY_HORIZON_TENANT,
        REPLAY_DECISION_ID,
        3,
        "COU-REPLAY-H3",
    )
    .await;

    let second = replay
        .next_page()
        .await
        .expect("second replay page must succeed")
        .expect("second replay page must exist");
    assert_eq!(second.events().len(), 1);
    assert_eq!(
        second.events()[0]
            .decision
            .as_ref()
            .expect("replay event must contain a decision")
            .aggregate_version,
        2
    );
    assert!(
        replay
            .next_page()
            .await
            .expect("completed replay must remain successful")
            .is_none()
    );
    assert_eq!(pool.acquisitions(), 2);

    let fresh_source = PostgresDecisionReplaySource::new(
        pool.clone(),
        scope(REPLAY_HORIZON_TENANT),
        event_verifier(),
    );
    let mut fresh = DecisionReplay::try_from_request(
        fresh_source,
        watch_request(REPLAY_DECISION_ID),
        replay_page_size(16),
    )
    .expect("fixed replay request must be valid");
    let fresh_page = fresh
        .next_page()
        .await
        .expect("fresh replay page must succeed")
        .expect("fresh replay page must exist");
    let fresh_versions = fresh_page
        .events()
        .iter()
        .map(|event| {
            event
                .decision
                .as_ref()
                .expect("replay event must contain a decision")
                .aggregate_version
        })
        .collect::<Vec<_>>();
    assert_eq!(fresh_versions, vec![1, 2, 3]);
    assert!(
        fresh
            .next_page()
            .await
            .expect("completed replay must remain successful")
            .is_none()
    );
    assert_eq!(pool.acquisitions(), 3);
    assert_eq!(pool.maximum_active(), 1);
    assert_eq!(pool.active(), 0);
    assert_eq!(
        pool.finish_requests(),
        vec![
            PostgresReaderLeaseDisposition::Reuse,
            PostgresReaderLeaseDisposition::Reuse,
            PostgresReaderLeaseDisposition::Reuse,
        ]
    );
    assert_eq!(pool.dispositions(), pool.finish_requests());
    pool.assert_available_sessions_are_clean(1).await;

    drop(fresh);
    drop(replay);
    pool.shutdown();
    writer.discard();
}

#[tokio::test]
async fn replay_continuation_resumes_on_a_different_physical_session() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    seed_replay_event(
        &mut writer.client,
        "01910d47-6f80-7a31-8c29-1d5c4f6ba751",
        REPLAY_ROTATION_TENANT,
        REPLAY_DECISION_ID,
        1,
        "COU-REPLAY-R1",
    )
    .await;
    seed_replay_event(
        &mut writer.client,
        "01910d47-6f80-7a31-8c29-1d5c4f6ba752",
        REPLAY_ROTATION_TENANT,
        REPLAY_DECISION_ID,
        2,
        "COU-REPLAY-R2",
    )
    .await;

    let first_reader = connect(POSTGRES_READER_USER, passwords.reader.clone()).await;
    let first_backend: i32 = first_reader
        .client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("first replay backend identity must be queryable")
        .get(0);
    let second_reader = connect(POSTGRES_READER_USER, passwords.reader).await;
    let second_backend: i32 = second_reader
        .client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("second replay backend identity must be queryable")
        .get(0);
    assert_ne!(first_backend, second_backend);

    let pool = TestReaderPool::new(vec![first_reader, second_reader]);
    let source = PostgresDecisionReplaySource::new(
        pool.clone(),
        scope(REPLAY_ROTATION_TENANT),
        event_verifier(),
    );
    let mut replay =
        DecisionReplay::new(source, watch_query(REPLAY_DECISION_ID), replay_page_size(1));

    assert_eq!(next_replay_cou_id(&mut replay).await, "COU-REPLAY-R1");
    assert_eq!(pool.acquisitions(), 1);
    assert_eq!(pool.active(), 0);
    assert_eq!(pool.available(), 2);
    assert_eq!(next_replay_cou_id(&mut replay).await, "COU-REPLAY-R2");
    assert_eq!(pool.acquisitions(), 2);
    assert_eq!(pool.active(), 0);
    assert_eq!(pool.available(), 2);
    assert!(
        replay
            .next_page()
            .await
            .expect("rotated replay completion must succeed")
            .is_none()
    );
    assert_eq!(pool.acquisitions(), 2);
    assert_eq!(pool.maximum_active(), 1);
    assert_eq!(
        pool.finish_requests(),
        vec![
            PostgresReaderLeaseDisposition::Reuse,
            PostgresReaderLeaseDisposition::Reuse,
        ]
    );
    pool.assert_available_sessions_are_clean(2).await;

    drop(replay);
    pool.shutdown();
    writer.discard();
}

#[tokio::test]
async fn replay_isolates_tenants_and_rejects_cross_scope_continuations() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    for (tenant_id, event_suffix, cou_prefix) in [
        (REPLAY_TENANT_A, "a", "COU-REPLAY-A"),
        (REPLAY_TENANT_B, "b", "COU-REPLAY-B"),
    ] {
        seed_replay_event(
            &mut writer.client,
            &format!("01910d47-6f80-7a31-8c29-1d5c4f6ba72{event_suffix}"),
            tenant_id,
            REPLAY_DECISION_ID,
            1,
            &format!("{cou_prefix}-1"),
        )
        .await;
        seed_replay_event(
            &mut writer.client,
            &format!("01910d47-6f80-7a31-8c29-1d5c4f6ba73{event_suffix}"),
            tenant_id,
            REPLAY_DECISION_ID,
            2,
            &format!("{cou_prefix}-2"),
        )
        .await;
    }
    seed_replay_event(
        &mut writer.client,
        "01910d47-6f80-7a31-8c29-1d5c4f6ba74a",
        REPLAY_TENANT_A,
        REPLAY_HIDDEN_DECISION_ID,
        1,
        "COU-REPLAY-HIDDEN",
    )
    .await;

    let reader = connect(POSTGRES_READER_USER, passwords.reader).await;
    let pool = TestReaderPool::new(vec![reader]);
    let query = watch_query(REPLAY_DECISION_ID);
    let mut tenant_a = DecisionReplay::new(
        PostgresDecisionReplaySource::new(pool.clone(), scope(REPLAY_TENANT_A), event_verifier()),
        query,
        replay_page_size(1),
    );
    let mut tenant_b = DecisionReplay::new(
        PostgresDecisionReplaySource::new(pool.clone(), scope(REPLAY_TENANT_B), event_verifier()),
        query,
        replay_page_size(1),
    );

    assert_eq!(next_replay_cou_id(&mut tenant_a).await, "COU-REPLAY-A-1");
    assert_eq!(pool.active(), 0);
    assert_eq!(next_replay_cou_id(&mut tenant_b).await, "COU-REPLAY-B-1");
    assert_eq!(pool.active(), 0);
    assert_eq!(next_replay_cou_id(&mut tenant_a).await, "COU-REPLAY-A-2");
    assert_eq!(pool.active(), 0);
    assert_eq!(next_replay_cou_id(&mut tenant_b).await, "COU-REPLAY-B-2");
    assert_eq!(pool.active(), 0);
    assert!(
        tenant_a
            .next_page()
            .await
            .expect("tenant A replay completion must succeed")
            .is_none()
    );
    assert!(
        tenant_b
            .next_page()
            .await
            .expect("tenant B replay completion must succeed")
            .is_none()
    );
    assert_eq!(pool.acquisitions(), 4);

    let mut tenant_a_source =
        PostgresDecisionReplaySource::new(pool.clone(), scope(REPLAY_TENANT_A), event_verifier());
    let tenant_a_page = tenant_a_source
        .read_page(query, replay_page_size(1), None)
        .await
        .expect("tenant A replay page must succeed");
    let (_, tenant_a_continuation) = tenant_a_page.into_parts();
    let tenant_a_continuation =
        tenant_a_continuation.expect("tenant A replay must expose a continuation");
    assert_eq!(pool.active(), 0);
    let mut tenant_b_source =
        PostgresDecisionReplaySource::new(pool.clone(), scope(REPLAY_TENANT_B), event_verifier());
    let cross_scope = tenant_b_source
        .read_page(query, replay_page_size(1), Some(&tenant_a_continuation))
        .await;
    assert!(matches!(
        cross_scope,
        Err(DecisionReplaySourceError::StoredStateRejected)
    ));
    assert_eq!(pool.active(), 0);

    let mut hidden = DecisionReplay::new(
        PostgresDecisionReplaySource::new(pool.clone(), scope(REPLAY_TENANT_B), event_verifier()),
        watch_query(REPLAY_HIDDEN_DECISION_ID),
        replay_page_size(1),
    );
    let hidden_result = hidden.next_page().await;
    assert!(matches!(hidden_result, Ok(None)));
    assert_eq!(pool.active(), 0);
    let mut missing = DecisionReplay::new(
        PostgresDecisionReplaySource::new(pool.clone(), scope(REPLAY_TENANT_B), event_verifier()),
        watch_query(REPLAY_MISSING_DECISION_ID),
        replay_page_size(1),
    );
    let missing_result = missing.next_page().await;
    assert!(matches!(missing_result, Ok(None)));
    assert_eq!(pool.active(), 0);

    assert_eq!(pool.acquisitions(), 8);
    assert_eq!(pool.maximum_active(), 1);
    assert_eq!(pool.active(), 0);
    assert_eq!(
        pool.finish_requests(),
        vec![PostgresReaderLeaseDisposition::Reuse; 8]
    );
    assert_eq!(pool.dispositions(), pool.finish_requests());
    pool.assert_available_sessions_are_clean(1).await;

    pool.shutdown();
    writer.discard();
}

#[tokio::test]
async fn replay_rejects_a_corrupt_page_atomically_and_returns_a_clean_lease() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let mut writer = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    seed_replay_event(
        &mut writer.client,
        "01910d47-6f80-7a31-8c29-1d5c4f6ba741",
        REPLAY_CORRUPT_TENANT,
        REPLAY_DECISION_ID,
        1,
        "COU-REPLAY-VALID",
    )
    .await;
    let corrupt_event_id = "01910d47-6f80-7a31-8c29-1d5c4f6ba742";
    let corrupt_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let (corrupt_payload, _) = replay_payload(REPLAY_DECISION_ID, 2, "COU-REPLAY-CORRUPT");
    seed_raw_event(
        &mut writer.client,
        corrupt_event_id,
        REPLAY_CORRUPT_TENANT,
        REPLAY_DECISION_ID,
        2,
        &corrupt_payload,
        corrupt_hash,
    )
    .await;

    let reader = connect(POSTGRES_READER_USER, passwords.reader).await;
    let pool = TestReaderPool::new(vec![reader]);
    let source = PostgresDecisionReplaySource::new(
        pool.clone(),
        scope(REPLAY_CORRUPT_TENANT),
        event_verifier(),
    );
    let mut replay = DecisionReplay::try_from_request(
        source,
        watch_request(REPLAY_DECISION_ID),
        replay_page_size(2),
    )
    .expect("fixed replay request must be valid");

    let error = match replay.next_page().await {
        Err(error) => error,
        Ok(_) => panic!("one corrupt event must reject the complete page"),
    };
    assert_eq!(error, DecisionReplayError::StoredStateRejected);
    let rendered = format!("{error:?} {error}");
    for sensitive in [
        REPLAY_CORRUPT_TENANT,
        REPLAY_DECISION_ID,
        corrupt_event_id,
        corrupt_hash,
        "COU-REPLAY-CORRUPT",
    ] {
        assert!(!rendered.contains(sensitive));
    }
    let repeated = match replay.next_page().await {
        Err(error) => error,
        Ok(_) => panic!("rejected replay must remain terminal"),
    };
    assert_eq!(repeated, DecisionReplayError::StoredStateRejected);
    assert_eq!(pool.acquisitions(), 1);
    assert_eq!(pool.active(), 0);
    assert_eq!(
        pool.finish_requests(),
        vec![PostgresReaderLeaseDisposition::Reuse]
    );
    assert_eq!(pool.dispositions(), pool.finish_requests());
    pool.assert_available_sessions_are_clean(1).await;

    drop(replay);
    pool.shutdown();
    writer.discard();
}

#[tokio::test]
async fn replay_cleanup_and_finish_failures_override_page_results() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let residual_tenant = "residual-sensitive-replay-tenant";
    let residual_reader = connect(POSTGRES_READER_USER, passwords.reader.clone()).await;
    let configured: String = residual_reader
        .client
        .query_one(
            "SELECT pg_catalog.set_config('bioworld.tenant_id', $1, false)",
            &[&residual_tenant],
        )
        .await
        .expect("residual replay tenant fixture must be configured")
        .get(0);
    assert_eq!(configured, residual_tenant);
    let residual_pool = TestReaderPool::new(vec![residual_reader]);
    let mut residual_source = PostgresDecisionReplaySource::new(
        residual_pool.clone(),
        scope(REPLAY_CLEANUP_TENANT),
        event_verifier(),
    );

    let residual_result = residual_source
        .read_page(watch_query(REPLAY_DECISION_ID), replay_page_size(1), None)
        .await;
    assert!(matches!(
        residual_result,
        Err(DecisionReplaySourceError::Unavailable)
    ));
    assert_eq!(
        residual_pool.finish_requests(),
        vec![PostgresReaderLeaseDisposition::Discard]
    );
    assert_eq!(
        residual_pool.dispositions(),
        vec![PostgresReaderLeaseDisposition::Discard]
    );
    assert_eq!(residual_pool.active(), 0);
    assert_eq!(residual_pool.available(), 0);

    let finish_reader = connect(POSTGRES_READER_USER, passwords.reader.clone()).await;
    let finish_pool = TestReaderPool::new(vec![finish_reader]);
    finish_pool.fail_next_finish();
    let mut finish_source = PostgresDecisionReplaySource::new(
        finish_pool.clone(),
        scope(REPLAY_CLEANUP_TENANT),
        event_verifier(),
    );

    let finish_result = finish_source
        .read_page(watch_query(REPLAY_DECISION_ID), replay_page_size(1), None)
        .await;
    assert!(matches!(
        finish_result,
        Err(DecisionReplaySourceError::Unavailable)
    ));
    assert_eq!(
        finish_pool.finish_requests(),
        vec![PostgresReaderLeaseDisposition::Reuse]
    );
    assert_eq!(
        finish_pool.dispositions(),
        vec![PostgresReaderLeaseDisposition::Discard]
    );
    assert_eq!(finish_pool.active(), 0);
    assert_eq!(finish_pool.available(), 0);

    let mut closed_reader = connect(POSTGRES_READER_USER, passwords.reader).await;
    closed_reader.disconnect().await;
    let closed_pool = TestReaderPool::new(vec![closed_reader]);
    let mut closed_source = PostgresDecisionReplaySource::new(
        closed_pool.clone(),
        scope(REPLAY_CLEANUP_TENANT),
        event_verifier(),
    );

    let closed_result = closed_source
        .read_page(watch_query(REPLAY_DECISION_ID), replay_page_size(1), None)
        .await;
    assert!(matches!(
        closed_result,
        Err(DecisionReplaySourceError::Unavailable)
    ));
    assert_eq!(
        closed_pool.finish_requests(),
        vec![PostgresReaderLeaseDisposition::Discard]
    );
    assert_eq!(
        closed_pool.dispositions(),
        vec![PostgresReaderLeaseDisposition::Discard]
    );
    assert_eq!(closed_pool.active(), 0);
    assert_eq!(closed_pool.available(), 0);
}

#[tokio::test]
async fn cancelled_replay_acquisition_discards_its_lease_and_recovers_capacity() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let pool = production_reader_pool(passwords.reader, 1, Duration::from_secs(1));
    let mut baseline = pool
        .acquire()
        .await
        .expect("baseline replay lease must be acquired");
    let baseline_backend: i32 = baseline
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("baseline replay backend identity must be queryable")
        .get(0);
    baseline
        .finish(PostgresReaderLeaseDisposition::Reuse)
        .expect("baseline replay lease must return to the pool");

    let acquired = Arc::new(AtomicUsize::new(0));
    let source = PostgresDecisionReplaySource::new(
        DelayFirstProductionLease {
            pool: pool.clone(),
            acquired: Arc::clone(&acquired),
        },
        scope(REPLAY_CLEANUP_TENANT),
        event_verifier(),
    );
    let mut replay = DecisionReplay::try_from_request(
        source,
        watch_request(REPLAY_DECISION_ID),
        replay_page_size(1),
    )
    .expect("fixed replay request must be valid");
    let task = tokio::spawn(async move { replay.next_page().await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while acquired.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replay acquisition must reach the cancellation point");

    task.abort();
    let cancellation = task
        .await
        .expect_err("cancelled replay acquisition must stop its task");
    assert!(cancellation.is_cancelled());

    let mut replacement = pool
        .acquire()
        .await
        .expect("cancelled replay capacity must be replaced");
    let replacement_backend: i32 = replacement
        .client()
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("replacement replay backend identity must be queryable")
        .get(0);
    assert_ne!(replacement_backend, baseline_backend);
    replacement
        .finish(PostgresReaderLeaseDisposition::Reuse)
        .expect("replacement replay lease must return to the pool");

    let recovered_source = PostgresDecisionReplaySource::new(
        pool.clone(),
        scope(REPLAY_CLEANUP_TENANT),
        event_verifier(),
    );
    let mut recovered = DecisionReplay::try_from_request(
        recovered_source,
        watch_request(REPLAY_DECISION_ID),
        replay_page_size(1),
    )
    .expect("fixed replay request must be valid");
    let missing = recovered
        .next_page()
        .await
        .expect("recovered replay read must succeed");
    assert!(missing.is_none());

    let mut clean = pool
        .acquire()
        .await
        .expect("clean replay lease must return");
    assert!(tenant_context_is_absent(clean.client()).await);
    clean
        .finish(PostgresReaderLeaseDisposition::Discard)
        .expect("clean replay lease must be discarded");
    pool.close();
}
