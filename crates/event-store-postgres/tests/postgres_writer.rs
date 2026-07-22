use bioworld_contracts::v2::{
    DecisionCriterion, DecisionCriterionComparator, DecisionEvent, DecisionPredictionInterval,
    DecisionPredictionPosition, DecisionRecord, EvidenceSnapshotRef, OodDetectorRef, OodStatus,
    Recommendation,
};
use bioworld_event_store_contracts::{
    DECISION_AGGREGATE_TYPE, DECISION_EVENT_TYPE, DECISION_SCHEMA_VERSION, DecisionEventMetadata,
    MAX_EVENT_SIGNATURE_JSON_BYTES, ScientificEventRow, project_decision_event,
};
use bioworld_event_store_postgres::{AppendDecisionEventError, PostgresDecisionEventWriter};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_postgres::{Client, Transaction, types::ToSql};

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

fn decision_event(event_id: &str, decision_id: &str) -> DecisionEvent {
    decision_event_at_version(event_id, decision_id, u64::MAX)
}

#[allow(deprecated)]
fn decision_event_at_version(
    event_id: &str,
    decision_id: &str,
    aggregate_version: u64,
) -> DecisionEvent {
    DecisionEvent {
        event_id: event_id.to_owned(),
        decision: Some(DecisionRecord {
            decision_id: decision_id.to_owned(),
            cou_id: "COU-M10".to_owned(),
            evidence_snapshot_id: "ES-M10".to_owned(),
            recommendation: Recommendation::Abstain as i32,
            rationale: vec!["Integration verification event.".to_owned()],
            aggregate_version,
            evidence: Some(EvidenceSnapshotRef {
                id: "ES-M10".to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
            ood_status: Some(OodStatus::OutOfDomain as i32),
            ood_detector: Some(OodDetectorRef {
                detector_id: "mahalanobis".to_owned(),
                detector_version: "model-2026.07".to_owned(),
            }),
            prediction_interval: Some(prediction_interval("0.25", "1.5")),
            prediction_positions: prediction_positions(),
            decision_criterion: Some(DecisionCriterion {
                criterion_id: "writer_policy".to_owned(),
                criterion_version: "2026.07".to_owned(),
                comparator: DecisionCriterionComparator::LessThanOrEqual as i32,
                threshold_decimal: "0.75".to_owned(),
                criterion_evidence: Some(EvidenceSnapshotRef {
                    id: "ES-M10-CRITERION".to_owned(),
                    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                }),
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

async fn backend_pid(client: &Client) -> i32 {
    client
        .query_one("SELECT pg_catalog.pg_backend_pid()", &[])
        .await
        .expect("writer backend identity must be queryable")
        .get(0)
}

async fn insert_blocking_event(
    transaction: &Transaction<'_>,
    event: DecisionEvent,
    tenant_id: &str,
) {
    let row =
        project_decision_event(event, metadata(tenant_id)).expect("blocking event must project");
    let aggregate_version = row.aggregate_version.to_string();
    let signature = Value::Object(row.signature);
    let parameters: [&(dyn ToSql + Sync); 11] = [
        &row.event_id,
        &row.event_type,
        &row.schema_version,
        &row.aggregate_type,
        &row.aggregate_id,
        &aggregate_version,
        &row.occurred_at,
        &row.tenant_id,
        &row.payload,
        &row.payload_sha256,
        &signature,
    ];
    transaction
        .execute(
            "INSERT INTO public.scientific_event (event_id, event_type, schema_version, aggregate_type, aggregate_id, aggregate_version, occurred_at, tenant_id, payload, payload_sha256, signature) VALUES ($1, $2, $3, $4, $5, $6::text::numeric, $7, $8, $9, $10, $11)",
            &parameters,
        )
        .await
        .expect("blocking event must remain uncommitted");
}

async fn wait_until_writer_is_blocked(
    observer: &Transaction<'_>,
    blocker_pid: i32,
    writer_pid: i32,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let is_blocked: bool = observer
                .query_one(
                    "SELECT $1 = ANY(pg_catalog.pg_blocking_pids($2))",
                    &[&blocker_pid, &writer_pid],
                )
                .await
                .expect("writer blocking state must be queryable")
                .get(0);
            if is_blocked {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the lock holder must reach its blocked unique check");
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

async fn event_is_stored(client: &mut Client, tenant_id: &str, event_id: &str) -> bool {
    let transaction = client
        .transaction()
        .await
        .expect("verification transaction must begin");
    transaction
        .query_one(
            "SELECT pg_catalog.set_config('bioworld.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .expect("verification tenant context must be set");
    let exists = transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM public.scientific_event WHERE tenant_id = $1 AND event_id::text = $2)",
            &[&tenant_id, &event_id],
        )
        .await
        .expect("stored event identity must be queryable")
        .get(0);
    transaction
        .commit()
        .await
        .expect("verification transaction must commit");
    exists
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
    assert_eq!(stored.payload["ood_status"], json!("out_of_domain"));
    assert_eq!(
        stored.payload["ood_detector"],
        json!({
            "detector_id": "mahalanobis",
            "detector_version": "model-2026.07"
        })
    );
    assert_eq!(
        stored.payload["prediction_interval"],
        json!({
            "target": "binding_affinity",
            "unit": "nM",
            "lower_decimal": "0.25",
            "upper_decimal": "1.5",
            "nominal_coverage_decimal": "0.95",
            "interval_method_id": "split_conformal",
            "interval_method_version": "1.0",
            "calibration_method_id": "held_out_calibration",
            "calibration_method_version": "2026.07",
            "calibration_evidence": {
                "id": "ES-CAL-001",
                "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            }
        })
    );
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

#[tokio::test]
async fn enforces_strictly_advancing_versions_per_exact_tenant_stream() {
    let Some(password) = integration_password() else {
        return;
    };
    let (mut client, connection_task) = connect_writer(password).await;

    let tenant_a = "tenant-m36-a";
    let tenant_b = "tenant-m36-b";
    let decision_a = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d90";
    let decision_b = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d91";

    for (event_id, aggregate_version) in [
        ("01910d47-6f80-7a31-8c29-1d5c4f6b7020", 7),
        ("01910d47-6f80-7a31-8c29-1d5c4f6b7021", 10),
        ("01910d47-6f80-7a31-8c29-1d5c4f6b7022", u64::MAX),
    ] {
        append(
            &mut client,
            decision_event_at_version(event_id, decision_a, aggregate_version),
            tenant_a,
        )
        .await
        .expect("first and strictly greater stream versions must persist");
        assert!(tenant_context_is_absent(&client).await);
    }

    let lower_event_id = "01910d47-6f80-7a31-8c29-1d5c4f6b7023";
    let error = append(
        &mut client,
        decision_event_at_version(lower_event_id, decision_a, 9),
        tenant_a,
    )
    .await
    .expect_err("a lower committed stream version must be rejected");
    assert_eq!(error, AppendDecisionEventError::NonMonotonicStreamVersion);
    assert_redacted(&error);
    assert!(!event_is_stored(&mut client, tenant_a, lower_event_id).await);
    assert!(tenant_context_is_absent(&client).await);

    let equal_event_id = "01910d47-6f80-7a31-8c29-1d5c4f6b7024";
    let error = append(
        &mut client,
        decision_event_at_version(equal_event_id, decision_a, u64::MAX),
        tenant_a,
    )
    .await
    .expect_err("an equal committed stream version must retain duplicate semantics");
    assert_eq!(error, AppendDecisionEventError::DuplicateStreamVersion);
    assert!(!event_is_stored(&mut client, tenant_a, equal_event_id).await);
    assert!(tenant_context_is_absent(&client).await);

    let historical_equal_event_id = "01910d47-6f80-7a31-8c29-1d5c4f6b7026";
    let error = append(
        &mut client,
        decision_event_at_version(historical_equal_event_id, decision_a, 7),
        tenant_a,
    )
    .await
    .expect_err("any existing stream version must retain duplicate semantics");
    assert_eq!(error, AppendDecisionEventError::DuplicateStreamVersion);
    assert!(!event_is_stored(&mut client, tenant_a, historical_equal_event_id).await);
    assert!(tenant_context_is_absent(&client).await);

    let existing_event_id = "01910d47-6f80-7a31-8c29-1d5c4f6b7020";
    let error = append(
        &mut client,
        decision_event_at_version(existing_event_id, decision_a, 9),
        tenant_a,
    )
    .await
    .expect_err("a visible duplicate event identity must precede stale-version rejection");
    assert_eq!(error, AppendDecisionEventError::DuplicateEvent);
    assert!(tenant_context_is_absent(&client).await);

    append(
        &mut client,
        decision_event_at_version("01910d47-6f80-7a31-8c29-1d5c4f6b7025", decision_b, 1),
        tenant_a,
    )
    .await
    .expect("another decision stream must have an independent head");
    append(
        &mut client,
        decision_event_at_version("01910d47-6f80-7a31-8c29-1d5c4f6b7020", decision_a, 1),
        tenant_b,
    )
    .await
    .expect("another tenant must have an independent head");
    assert!(tenant_context_is_absent(&client).await);

    connection_task.abort();
}

#[tokio::test]
async fn prevents_concurrent_first_appends_from_committing_an_unsafe_order() {
    let Some(password) = integration_password() else {
        return;
    };
    let (mut blocker, blocker_task) = connect_writer(password.clone()).await;
    let (writer_two, writer_two_task) = connect_writer(password.clone()).await;
    let (writer_three, writer_three_task) = connect_writer(password).await;

    let tenant_id = "tenant-m36-concurrent";
    let decision_id = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d92";
    let writer_two_pid = backend_pid(&writer_two).await;
    let writer_three_pid = backend_pid(&writer_three).await;
    let blocker_pid = backend_pid(&blocker).await;
    let blocker_transaction = blocker
        .transaction()
        .await
        .expect("blocking transaction must begin");
    blocker_transaction
        .query_one(
            "SELECT pg_catalog.set_config('bioworld.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .expect("blocking tenant context must be set");
    insert_blocking_event(
        &blocker_transaction,
        decision_event_at_version("01910d47-6f80-7a31-8c29-1d5c4f6b7030", decision_id, 2),
        tenant_id,
    )
    .await;
    insert_blocking_event(
        &blocker_transaction,
        decision_event_at_version("01910d47-6f80-7a31-8c29-1d5c4f6b7031", decision_id, 3),
        tenant_id,
    )
    .await;

    let event_two =
        decision_event_at_version("01910d47-6f80-7a31-8c29-1d5c4f6b7032", decision_id, 2);
    let event_three =
        decision_event_at_version("01910d47-6f80-7a31-8c29-1d5c4f6b7033", decision_id, 3);
    let tenant_for_two = tenant_id.to_owned();
    let tenant_for_three = tenant_id.to_owned();
    let mut writer_two_handle = tokio::spawn(async move {
        let mut client = writer_two;
        let result = append(&mut client, event_two.clone(), &tenant_for_two).await;
        (client, event_two, result)
    });
    let mut writer_three_handle = tokio::spawn(async move {
        let mut client = writer_three;
        let result = append(&mut client, event_three.clone(), &tenant_for_three).await;
        (client, event_three, result)
    });

    let (retry_is_version_two, (mut retry_client, retry_event, retry_result)) =
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                result = &mut writer_two_handle => (
                    true,
                    result.expect("version two writer task must complete"),
                ),
                result = &mut writer_three_handle => (
                    false,
                    result.expect("version three writer task must complete"),
                ),
            }
        })
        .await
        .expect("one concurrent writer must fail fast on stream lock contention");
    assert_eq!(
        retry_result,
        Err(AppendDecisionEventError::RetryableTransaction),
    );
    assert!(tenant_context_is_absent(&retry_client).await);
    let pending_pid = if retry_is_version_two {
        writer_three_pid
    } else {
        writer_two_pid
    };
    wait_until_writer_is_blocked(&blocker_transaction, blocker_pid, pending_pid).await;
    blocker_transaction
        .rollback()
        .await
        .expect("blocking transaction must roll back");
    assert!(tenant_context_is_absent(&blocker).await);

    let (mut committed_client, _, committed_result) = if retry_is_version_two {
        writer_three_handle
            .await
            .expect("version three writer task must complete")
    } else {
        writer_two_handle
            .await
            .expect("version two writer task must complete")
    };
    committed_result.expect("the stream lock holder must commit after blocker rollback");

    if retry_is_version_two {
        let error = append(&mut retry_client, retry_event, tenant_id)
            .await
            .expect_err("the lower retry must observe the committed higher version");
        assert_eq!(error, AppendDecisionEventError::NonMonotonicStreamVersion);
    } else {
        append(&mut retry_client, retry_event, tenant_id)
            .await
            .expect("the higher retry must advance the committed lower version");
    }

    assert!(tenant_context_is_absent(&retry_client).await);
    assert!(tenant_context_is_absent(&committed_client).await);
    assert!(
        event_is_stored(
            &mut committed_client,
            tenant_id,
            "01910d47-6f80-7a31-8c29-1d5c4f6b7033",
        )
        .await
    );
    assert_eq!(
        event_is_stored(
            &mut committed_client,
            tenant_id,
            "01910d47-6f80-7a31-8c29-1d5c4f6b7032",
        )
        .await,
        !retry_is_version_two,
    );

    blocker_task.abort();
    writer_two_task.abort();
    writer_three_task.abort();
}
