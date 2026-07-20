use bioworld_contracts::v2::{DecisionEvent, DecisionRecord, EvidenceSnapshotRef, Recommendation};
use bioworld_event_store_contracts::{
    DecisionEventMetadata, ScientificEventRow, project_decision_event,
};
use bioworld_event_store_postgres::{
    PostgresDecisionEventReader, PostgresDecisionEventWriter, ReadDecisionEventError,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use tokio::task::JoinHandle;
use tokio_postgres::Client;

const POSTGRES_HOST: &str = "127.0.0.1";
const POSTGRES_PORT: u16 = 5432;
const POSTGRES_DATABASE: &str = "bioworld_migrations";
const POSTGRES_USER: &str = "bioworld_writer";
const WRITER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_WRITER_PASSWORD";
const INTEGRATION_REQUIRED_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_INTEGRATION_REQUIRED";

fn occurred_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-07-20T00:00:00Z")
        .expect("fixed timestamp must parse")
        .with_timezone(&Utc)
}

#[allow(deprecated)]
fn decision_event(event_id: &str, decision_id: &str) -> DecisionEvent {
    DecisionEvent {
        event_id: event_id.to_owned(),
        decision: Some(DecisionRecord {
            decision_id: decision_id.to_owned(),
            cou_id: "COU-M11".to_owned(),
            evidence_snapshot_id: "ES-M11".to_owned(),
            recommendation: Recommendation::StopProgram as i32,
            rationale: vec!["PostgreSQL reader integration event.".to_owned()],
            aggregate_version: u64::MAX,
            evidence: Some(EvidenceSnapshotRef {
                id: "ES-M11".to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
        }),
    }
}

fn metadata(tenant_id: &str) -> DecisionEventMetadata {
    DecisionEventMetadata::try_new(
        tenant_id.to_owned(),
        occurred_at(),
        json!({"algorithm": "Ed25519", "key_id": "m11-test", "value": "test-signature"}),
    )
    .expect("fixed metadata must be valid")
}

fn integration_password() -> Option<String> {
    match std::env::var(WRITER_PASSWORD_ENVIRONMENT_VARIABLE) {
        Ok(password) if !password.is_empty() => Some(password),
        _ if std::env::var(INTEGRATION_REQUIRED_ENVIRONMENT_VARIABLE).as_deref() == Ok("1") => {
            panic!("required PostgreSQL writer credential is unavailable")
        }
        _ => None,
    }
}

async fn connect_writer(password: String) -> (Client, JoinHandle<()>) {
    let mut configuration = tokio_postgres::Config::new();
    configuration
        .host(POSTGRES_HOST)
        .port(POSTGRES_PORT)
        .dbname(POSTGRES_DATABASE)
        .user(POSTGRES_USER)
        .password(password);
    let (client, connection) = configuration
        .connect(tokio_postgres::NoTls)
        .await
        .expect("writer must connect through internal PostgreSQL TCP");
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    (client, connection_task)
}

async fn append(client: &mut Client, event: DecisionEvent, tenant_id: &str) {
    PostgresDecisionEventWriter::new(client)
        .append(event, metadata(tenant_id))
        .await
        .expect("writer must seed a valid integration event");
}

async fn tenant_context_is_absent(client: &Client) -> bool {
    client
        .query_one(
            "SELECT NULLIF(pg_catalog.current_setting('bioworld.tenant_id', true), '') IS NULL",
            &[],
        )
        .await
        .expect("tenant context reset must be queryable")
        .get(0)
}

fn projected_row(event: &DecisionEvent, tenant_id: &str) -> ScientificEventRow {
    project_decision_event(event.clone(), metadata(tenant_id)).expect("fixed event must project")
}

fn assert_redacted(error: &ReadDecisionEventError) {
    let rendered = format!("{error:?} {error}");
    for sensitive in [
        WRITER_PASSWORD_ENVIRONMENT_VARIABLE,
        "test-signature",
        "fixture-signature",
        "tenant-fixture",
        "fixture-decision",
        "00000000-0000-4000-8000-000000000001",
    ] {
        assert!(!rendered.contains(sensitive));
    }
}

#[test]
fn exposes_a_narrow_reader_api_and_redacted_errors() {
    fn constructor(client: &mut Client) -> PostgresDecisionEventReader<'_> {
        PostgresDecisionEventReader::new(client)
    }
    let _ = constructor;

    for error in [
        ReadDecisionEventError::InvalidTenantId,
        ReadDecisionEventError::ReaderIdentityRejected,
        ReadDecisionEventError::TenantContextRejected,
        ReadDecisionEventError::ReadOnlyTransactionRejected,
        ReadDecisionEventError::StoredEventRejected,
        ReadDecisionEventError::AccessDenied,
        ReadDecisionEventError::RetryableTransaction,
        ReadDecisionEventError::ConnectionUnavailable,
        ReadDecisionEventError::DatabaseRejected,
        ReadDecisionEventError::TransactionCleanupFailed,
    ] {
        assert_redacted(&error);
    }
}

#[tokio::test]
async fn reads_the_exact_decision_event_with_the_maximum_u64_version() {
    let Some(password) = integration_password() else {
        return;
    };
    let (mut client, connection_task) = connect_writer(password).await;
    let tenant_id = "tenant-m11-exact";
    let expected = decision_event(
        "01910d47-6f80-7a31-8c29-1d5c4f6b7101",
        "018f5a72-9c4b-7d31-8f6a-26f08f3fd101",
    );
    let id = projected_row(&expected, tenant_id).event_id;

    append(&mut client, expected.clone(), tenant_id).await;
    assert!(tenant_context_is_absent(&client).await);

    let actual = PostgresDecisionEventReader::new(&mut client)
        .get(tenant_id, id)
        .await
        .expect("reader must load a valid event");

    assert_eq!(actual, Some(expected));
    assert_eq!(
        actual.unwrap().decision.unwrap().aggregate_version,
        u64::MAX
    );
    assert!(tenant_context_is_absent(&client).await);
    connection_task.abort();
}

#[tokio::test]
async fn makes_cross_tenant_events_indistinguishable_from_absent_events() {
    let Some(password) = integration_password() else {
        return;
    };
    let (mut client, connection_task) = connect_writer(password).await;
    let tenant_a = "tenant-m11-hidden-a";
    let tenant_b = "tenant-m11-hidden-b";
    let hidden = decision_event(
        "01910d47-6f80-7a31-8c29-1d5c4f6b7201",
        "018f5a72-9c4b-7d31-8f6a-26f08f3fd201",
    );
    let missing = decision_event(
        "01910d47-6f80-7a31-8c29-1d5c4f6b7202",
        "018f5a72-9c4b-7d31-8f6a-26f08f3fd202",
    );
    let hidden_id = projected_row(&hidden, tenant_b).event_id;
    let missing_id = projected_row(&missing, tenant_a).event_id;

    append(&mut client, hidden, tenant_b).await;

    let cross_tenant = PostgresDecisionEventReader::new(&mut client)
        .get(tenant_a, hidden_id)
        .await
        .expect("cross-tenant lookup must not disclose an error");
    assert!(tenant_context_is_absent(&client).await);
    let absent = PostgresDecisionEventReader::new(&mut client)
        .get(tenant_a, missing_id)
        .await
        .expect("absent lookup must succeed");

    assert_eq!(cross_tenant, None);
    assert_eq!(cross_tenant, absent);
    assert!(tenant_context_is_absent(&client).await);
    connection_task.abort();
}

#[tokio::test]
#[allow(deprecated)]
async fn resolves_the_same_event_identifier_independently_for_each_tenant() {
    let Some(password) = integration_password() else {
        return;
    };
    let (mut client, connection_task) = connect_writer(password).await;
    let tenant_a = "tenant-m11-shared-a";
    let tenant_b = "tenant-m11-shared-b";
    let event_a = decision_event(
        "01910d47-6f80-7a31-8c29-1d5c4f6b7301",
        "018f5a72-9c4b-7d31-8f6a-26f08f3fd301",
    );
    let mut event_b = event_a.clone();
    let decision_b = event_b.decision.as_mut().expect("decision must exist");
    decision_b.cou_id = "COU-M11-B".to_owned();
    decision_b.evidence_snapshot_id = "ES-M11-B".to_owned();
    decision_b
        .evidence
        .as_mut()
        .expect("evidence must exist")
        .id = "ES-M11-B".to_owned();
    let shared_id = projected_row(&event_a, tenant_a).event_id;

    append(&mut client, event_a.clone(), tenant_a).await;
    append(&mut client, event_b.clone(), tenant_b).await;

    let loaded_a = PostgresDecisionEventReader::new(&mut client)
        .get(tenant_a, shared_id)
        .await
        .expect("tenant A event must be readable");
    let loaded_b = PostgresDecisionEventReader::new(&mut client)
        .get(tenant_b, shared_id)
        .await
        .expect("tenant B event must be readable");

    assert_eq!(loaded_a, Some(event_a));
    assert_eq!(loaded_b, Some(event_b));
    assert!(tenant_context_is_absent(&client).await);
    connection_task.abort();
}

#[tokio::test]
async fn rejects_a_corrupt_stored_event_without_leaking_details_or_tenant_context() {
    let Some(password) = integration_password() else {
        return;
    };
    let (mut client, connection_task) = connect_writer(password).await;
    let fixture_identity = decision_event(
        "00000000-0000-4000-8000-000000000001",
        "018f5a72-9c4b-7d31-8f6a-26f08f3fd401",
    );
    let fixture_id = projected_row(&fixture_identity, "tenant-fixture").event_id;

    let error = PostgresDecisionEventReader::new(&mut client)
        .get("tenant-fixture", fixture_id)
        .await
        .expect_err("legacy fixture is not a valid decision event");

    assert_eq!(error, ReadDecisionEventError::StoredEventRejected);
    assert_redacted(&error);
    assert!(tenant_context_is_absent(&client).await);
    connection_task.abort();
}
