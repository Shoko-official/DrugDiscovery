use bioworld_contracts::v2::{DecisionEvent, DecisionRecord, EvidenceSnapshotRef, Recommendation};
use bioworld_event_store_contracts::{
    DECISION_AGGREGATE_TYPE, DECISION_EVENT_TYPE, DECISION_SCHEMA_VERSION, DecisionEventMetadata,
    MAX_EVENT_SIGNATURE_JSON_BYTES, ScientificEventRow, project_decision_event,
};
use bioworld_event_store_postgres::{AppendDecisionEventError, PostgresDecisionEventWriter};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
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
            cou_id: "COU-M10".to_owned(),
            evidence_snapshot_id: "ES-M10".to_owned(),
            recommendation: Recommendation::StopProgram as i32,
            rationale: vec!["Integration verification event.".to_owned()],
            aggregate_version: u64::MAX,
            evidence: Some(EvidenceSnapshotRef {
                id: "ES-M10".to_owned(),
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
        json!({"algorithm": "Ed25519", "key_id": "m10-test", "value": "test-signature"}),
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

async fn append(
    client: &mut Client,
    event: DecisionEvent,
    tenant_id: &str,
) -> Result<(), AppendDecisionEventError> {
    PostgresDecisionEventWriter::new(client)
        .append(event, metadata(tenant_id))
        .await
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

async fn load_event(client: &mut Client, tenant_id: &str, event_id: &str) -> ScientificEventRow {
    let transaction = client
        .transaction()
        .await
        .expect("verification transaction must begin");
    let context_is_exact: bool = transaction
        .query_one(
            "SELECT pg_catalog.set_config('bioworld.tenant_id', $1, true) = $1",
            &[&tenant_id],
        )
        .await
        .expect("verification tenant context must be set")
        .get(0);
    assert!(context_is_exact);
    let stored = transaction
        .query_one(
            "SELECT event_id, event_type, schema_version, aggregate_type, aggregate_id, aggregate_version::text, occurred_at, tenant_id, payload, payload_sha256, signature FROM public.scientific_event WHERE tenant_id = $1 AND event_id::text = $2",
            &[&tenant_id, &event_id],
        )
        .await
        .expect("stored event must be queryable inside its tenant context");
    transaction
        .commit()
        .await
        .expect("verification transaction must commit");

    let signature: Value = stored.get(10);
    ScientificEventRow {
        event_id: stored.get(0),
        event_type: stored.get(1),
        schema_version: stored.get(2),
        aggregate_type: stored.get(3),
        aggregate_id: stored.get(4),
        aggregate_version: stored
            .get::<_, String>(5)
            .parse()
            .expect("stored aggregate version must be an exact u64"),
        occurred_at: stored.get(6),
        tenant_id: stored.get(7),
        payload: stored.get(8),
        payload_sha256: stored.get(9),
        signature: signature
            .as_object()
            .expect("stored signature must be an object")
            .clone(),
    }
}

fn assert_redacted(error: &AppendDecisionEventError) {
    let rendered = format!("{error:?} {error}");
    for sensitive in [
        WRITER_PASSWORD_ENVIRONMENT_VARIABLE,
        "test-signature",
        "tenant-m10-a",
        "COU-M10",
    ] {
        assert!(!rendered.contains(sensitive));
    }
}

#[test]
fn exposes_a_narrow_writer_api_and_redacted_errors() {
    fn constructor(client: &mut Client) -> PostgresDecisionEventWriter<'_> {
        PostgresDecisionEventWriter::new(client)
    }
    let _ = constructor;
    assert_redacted(&AppendDecisionEventError::WriterIdentityRejected);
}

#[tokio::test]
async fn appends_exact_events_and_resets_tenant_context_after_commit_and_rollback() {
    let Some(password) = integration_password() else {
        return;
    };
    let (mut client, connection_task) = connect_writer(password).await;

    let tenant_a = "tenant-m10-a";
    let tenant_b = "tenant-m10-b";
    let event_id = "01910d47-6f80-7a31-8c29-1d5c4f6b7012";
    let decision_id = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
    let event = decision_event(event_id, decision_id);
    let expected = project_decision_event(event.clone(), metadata(tenant_a))
        .expect("fixed event must project");

    append(&mut client, event.clone(), tenant_a)
        .await
        .expect("writer must append a validated event");
    assert!(tenant_context_is_absent(&client).await);
    let stored = load_event(&mut client, tenant_a, event_id).await;
    assert_eq!(stored.event_id, expected.event_id);
    assert_eq!(stored.event_type, DECISION_EVENT_TYPE);
    assert_eq!(stored.schema_version, DECISION_SCHEMA_VERSION);
    assert_eq!(stored.aggregate_type, DECISION_AGGREGATE_TYPE);
    assert_eq!(stored.aggregate_id, expected.aggregate_id);
    assert_eq!(stored.aggregate_version, u64::MAX);
    assert_eq!(stored.occurred_at, expected.occurred_at);
    assert_eq!(stored.tenant_id, tenant_a);
    assert_eq!(stored.payload, expected.payload);
    assert_eq!(stored.payload_sha256, expected.payload_sha256);
    assert_eq!(stored.signature, expected.signature);
    assert!(tenant_context_is_absent(&client).await);

    let duplicate_event = decision_event(event_id, "018f5a72-9c4b-7d31-8f6a-26f08f3f4d98");
    let error = append(&mut client, duplicate_event, tenant_a)
        .await
        .expect_err("same-tenant event identity must conflict");
    assert_eq!(error, AppendDecisionEventError::DuplicateEvent);
    assert_redacted(&error);
    assert!(tenant_context_is_absent(&client).await);

    let duplicate_stream = decision_event("01910d47-6f80-7a31-8c29-1d5c4f6b7013", decision_id);
    let error = append(&mut client, duplicate_stream, tenant_a)
        .await
        .expect_err("same-tenant aggregate version must conflict");
    assert_eq!(error, AppendDecisionEventError::DuplicateStreamVersion);
    assert_redacted(&error);
    assert!(tenant_context_is_absent(&client).await);

    append(&mut client, event, tenant_b)
        .await
        .expect("tenant-scoped identities may repeat across tenants");
    assert!(tenant_context_is_absent(&client).await);
    assert_eq!(
        load_event(&mut client, tenant_b, event_id).await.tenant_id,
        tenant_b
    );
    assert!(tenant_context_is_absent(&client).await);

    let mut invalid = decision_event(
        "01910d47-6f80-7a31-8c29-1d5c4f6b7014",
        "018f5a72-9c4b-7d31-8f6a-26f08f3f4d97",
    );
    invalid.event_id.make_ascii_uppercase();
    assert_eq!(
        append(&mut client, invalid, tenant_a).await,
        Err(AppendDecisionEventError::EventRejected),
    );
    assert!(tenant_context_is_absent(&client).await);

    let signature_overhead = serde_json::to_vec(&json!({"value": ""})).unwrap().len();
    let boundary_metadata = DecisionEventMetadata::try_new(
        tenant_a.to_owned(),
        occurred_at(),
        json!({
            "value": "s".repeat(MAX_EVENT_SIGNATURE_JSON_BYTES - signature_overhead)
        }),
    )
    .unwrap();
    PostgresDecisionEventWriter::new(&mut client)
        .append(
            decision_event(
                "01910d47-6f80-7a31-8c29-1d5c4f6b7015",
                "018f5a72-9c4b-7d31-8f6a-26f08f3f4d96",
            ),
            boundary_metadata,
        )
        .await
        .expect("signature boundary must persist");
    assert!(tenant_context_is_absent(&client).await);

    connection_task.abort();
}
