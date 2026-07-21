use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use bioworld_contracts::v2::{
    DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest, Recommendation,
};
use bioworld_decision_grpc::{TenantScope, get_decision};
use bioworld_decision_grpc_postgres::{
    AcquirePostgresReaderError, AcquirePostgresReaderFuture, FinishPostgresReaderLeaseError,
    PostgresGetDecisionExecutor, PostgresReaderLease, PostgresReaderLeaseDisposition,
    PostgresReaderLeaseProvider,
};
use bioworld_event_store_contracts::{
    DECISION_AGGREGATE_TYPE, DECISION_EVENT_TYPE, DECISION_SCHEMA_VERSION,
};
use tokio::task::JoinHandle;
use tokio_postgres::Client;
use tonic::{Code, Request, Status};

const POSTGRES_HOST: &str = "127.0.0.1";
const POSTGRES_PORT: u16 = 5432;
const POSTGRES_DATABASE: &str = "bioworld_migrations";
const POSTGRES_WRITER_USER: &str = "bioworld_writer";
const POSTGRES_READER_USER: &str = "bioworld_reader";
const WRITER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_WRITER_PASSWORD";
const READER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_READER_PASSWORD";
const INTEGRATION_REQUIRED_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_INTEGRATION_REQUIRED";
const OCCURRED_AT: &str = "2026-07-21T00:00:00Z";
const SIGNATURE: &str =
    r#"{"algorithm":"Ed25519","key_id":"m22-test","value":"integration-signature"}"#;
const TENANT_CONTEXT_IS_ABSENT: &str =
    "SELECT NULLIF(pg_catalog.current_setting('bioworld.tenant_id', true), '') IS NULL";
const INSERT_EVENT: &str = "INSERT INTO public.scientific_event (event_id, event_type, schema_version, aggregate_type, aggregate_id, aggregate_version, occurred_at, tenant_id, payload, payload_sha256, signature) VALUES ($1::text::uuid, $2, $3, $4, $5, $6::text::numeric, $7::text::timestamptz, $8, $9::text::jsonb, $10, $11::text::jsonb)";

const SHARED_DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3fa601";
const TENANT_A: &str = "tenant-grpc-postgres-a";
const TENANT_B: &str = "tenant-grpc-postgres-b";
const TENANT_A_PAYLOAD: &str = r#"{"aggregate_version":"18446744073709551615","cou_id":"COU-GRPC-PG-A","decision_id":"018f5a72-9c4b-7d31-8f6a-26f08f3fa601","evidence":{"id":"ES-GRPC-PG-A","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"rationale":["Tenant A decision."],"recommendation":"promote"}"#;
const TENANT_A_PAYLOAD_SHA256: &str =
    "22735232adcac85cc4bd3d3b0fee84866ec86d41e112733a1ceeac3ef699ca0c";
const TENANT_B_PAYLOAD: &str = r#"{"aggregate_version":"7","cou_id":"COU-GRPC-PG-B","decision_id":"018f5a72-9c4b-7d31-8f6a-26f08f3fa601","evidence":{"id":"ES-GRPC-PG-B","sha256":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},"rationale":["Tenant B decision."],"recommendation":"stop_program"}"#;
const TENANT_B_PAYLOAD_SHA256: &str =
    "1b2612cd0ddf808245e6b021d4e6b21099edfaa26369edd9e8ac61495dab11a5";

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

async fn seed_event(writer: &mut Client, fixture: &EventFixture) {
    let transaction = writer
        .transaction()
        .await
        .expect("fixture transaction must begin");
    let context_is_exact: bool = transaction
        .query_one(
            "SELECT pg_catalog.set_config('bioworld.tenant_id', $1, true) = $1",
            &[&fixture.tenant_id],
        )
        .await
        .expect("fixture tenant context must be set")
        .get(0);
    assert!(context_is_exact);

    let aggregate_version = fixture.record.aggregate_version.to_string();
    transaction
        .execute(
            INSERT_EVENT,
            &[
                &fixture.event_id,
                &DECISION_EVENT_TYPE,
                &DECISION_SCHEMA_VERSION,
                &DECISION_AGGREGATE_TYPE,
                &fixture.record.decision_id.as_str(),
                &aggregate_version.as_str(),
                &OCCURRED_AT,
                &fixture.tenant_id,
                &fixture.payload,
                &fixture.payload_sha256,
                &SIGNATURE,
            ],
        )
        .await
        .expect("fixture event must be inserted");
    transaction
        .commit()
        .await
        .expect("fixture transaction must commit");
}

async fn tenant_context_is_absent(client: &Client) -> bool {
    client
        .query_one(TENANT_CONTEXT_IS_ABSENT, &[])
        .await
        .expect("tenant context reset must be queryable")
        .get(0)
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

fn scope(tenant_id: &str) -> TenantScope {
    TenantScope::try_from_trusted_tenant_id(tenant_id.to_owned())
        .expect("fixed tenant scope must be valid")
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

fn assert_status_does_not_reflect(status: &Status, sensitive_values: &[&str]) {
    let rendered = format!("{status:?} {status}");
    for sensitive in sensitive_values {
        assert!(!rendered.contains(sensitive));
    }
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
    let executor = PostgresGetDecisionExecutor::new(pool.clone());
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
    let executor = PostgresGetDecisionExecutor::new(pool.clone());
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
    let executor = PostgresGetDecisionExecutor::new(pool.clone());
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
    let executor = PostgresGetDecisionExecutor::new(pool.clone());

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
    let executor = PostgresGetDecisionExecutor::new(pool.clone());
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
    let executor = PostgresGetDecisionExecutor::new(pool.clone());
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
    let executor = PostgresGetDecisionExecutor::new(pool.clone());
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
