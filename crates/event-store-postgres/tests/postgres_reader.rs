use std::future::Future;

use bioworld_contracts::{
    VersionedDecisionRecord,
    v2::{
        DecisionCriterion, DecisionCriterionComparator, DecisionEvent, DecisionPredictionInterval,
        DecisionPredictionPosition, DecisionRecord, EvidenceSnapshotRef, OodDetectorRef, OodStatus,
        Recommendation,
    },
};
use bioworld_decision_query::{
    GetDecision, GetDecisionError, GetDecisionQuery, LatestDecisionSource,
};
use bioworld_event_store_contracts::{
    DECISION_AGGREGATE_TYPE, DECISION_EVENT_TYPE, DECISION_SCHEMA_VERSION, DecisionEventMetadata,
    ScientificEventRow, project_decision_event,
};
use bioworld_event_store_postgres::{
    AppendDecisionEventError, InvalidDecisionSourceScope, PostgresDecisionEventReader,
    PostgresDecisionEventWriter, PostgresLatestDecisionSource, ReadDecisionEventError,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use tokio::task::JoinHandle;
use tokio_postgres::{Client, types::ToSql};
use uuid::Uuid;

const POSTGRES_HOST: &str = "127.0.0.1";
const POSTGRES_PORT: u16 = 5432;
const POSTGRES_DATABASE: &str = "bioworld_migrations";
const POSTGRES_WRITER_USER: &str = "bioworld_writer";
const POSTGRES_READER_USER: &str = "bioworld_reader";
const WRITER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_WRITER_PASSWORD";
const READER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_READER_PASSWORD";
const INTEGRATION_REQUIRED_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_INTEGRATION_REQUIRED";

struct IntegrationPasswords {
    writer: String,
    reader: String,
}

fn occurred_at() -> DateTime<Utc> {
    occurred_at_value("2026-07-20T00:00:00Z")
}

fn occurred_at_value(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
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

#[allow(deprecated)]
fn decision_event(event_id: &str, decision_id: &str) -> DecisionEvent {
    decision_event_at_version(event_id, decision_id, u64::MAX)
}

#[allow(deprecated)]
fn decision_event_at_version(
    event_id: &str,
    decision_id: &str,
    aggregate_version: u64,
) -> DecisionEvent {
    decision_event_at_version_with_ood_status(
        event_id,
        decision_id,
        aggregate_version,
        OodStatus::OutOfDomain,
    )
}

#[allow(deprecated)]
fn decision_event_at_version_with_ood_status(
    event_id: &str,
    decision_id: &str,
    aggregate_version: u64,
    ood_status: OodStatus,
) -> DecisionEvent {
    DecisionEvent {
        event_id: event_id.to_owned(),
        decision: Some(DecisionRecord {
            decision_id: decision_id.to_owned(),
            cou_id: "COU-M11".to_owned(),
            evidence_snapshot_id: "ES-M11".to_owned(),
            recommendation: if ood_status == OodStatus::OutOfDomain {
                Recommendation::Abstain as i32
            } else {
                Recommendation::StopProgram as i32
            },
            rationale: vec!["PostgreSQL reader integration event.".to_owned()],
            aggregate_version,
            evidence: Some(EvidenceSnapshotRef {
                id: "ES-M11".to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
            ood_status: Some(ood_status as i32),
            ood_detector: Some(OodDetectorRef {
                detector_id: "mahalanobis".to_owned(),
                detector_version: "model-2026.07".to_owned(),
            }),
            prediction_interval: Some(prediction_interval("0.25", "1.5")),
            prediction_positions: prediction_positions(),
            decision_criterion: Some(DecisionCriterion {
                criterion_id: "reader_policy".to_owned(),
                criterion_version: "2026.07".to_owned(),
                comparator: DecisionCriterionComparator::LessThanOrEqual as i32,
                threshold_decimal: "0.75".to_owned(),
                criterion_evidence: Some(EvidenceSnapshotRef {
                    id: "ES-M11-CRITERION".to_owned(),
                    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                }),
            }),
        }),
    }
}

#[tokio::test]
async fn preserves_every_qualified_ood_status_through_postgresql_write_and_read() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let tenant_id = "tenant-qualified-ood-status";

    for (index, (ood_status, canonical_ood_status)) in [
        (OodStatus::InDomain, "in_domain"),
        (OodStatus::Borderline, "borderline"),
        (OodStatus::OutOfDomain, "out_of_domain"),
    ]
    .into_iter()
    .enumerate()
    {
        let event_id = format!("01910d47-6f80-7a31-8c29-1d5c4f6b82{:02}", index + 1);
        let decision_id = format!("018f5a72-9c4b-7d31-8f6a-26f08f3fe7{:02}", index + 1);
        let expected =
            decision_event_at_version_with_ood_status(&event_id, &decision_id, 1, ood_status);

        append(&mut writer, expected.clone(), tenant_id).await;
        assert!(tenant_context_is_absent(&writer).await);

        let stored = PostgresDecisionEventReader::new(&mut reader)
            .get(
                tenant_id,
                Uuid::parse_str(&event_id).expect("fixed event identifier must parse"),
            )
            .await
            .expect("reader must load the written event")
            .expect("written event must exist");

        assert_eq!(stored, expected);
        assert_eq!(
            stored
                .decision
                .as_ref()
                .expect("stored event must contain a decision")
                .ood_status,
            Some(ood_status as i32),
            "PostgreSQL must preserve {canonical_ood_status} exactly"
        );
        assert!(tenant_context_is_absent(&reader).await);
    }

    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
async fn reads_an_exact_historical_event_without_detector() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let tenant_id = "tenant-historical-ood-read";
    let row = historical_ood_status_row(tenant_id);
    let event_id = row.event_id;

    insert_scientific_event_row(&mut writer, row).await;
    assert!(tenant_context_is_absent(&writer).await);

    let stored = PostgresDecisionEventReader::new(&mut reader)
        .get(tenant_id, event_id)
        .await
        .expect("reader must accept the historical event")
        .expect("historical event must exist");
    let decision = stored
        .decision
        .expect("historical event must contain a decision");

    assert_eq!(decision.ood_status, Some(OodStatus::Unknown as i32));
    assert!(decision.ood_detector.is_none());
    assert!(decision.prediction_interval.is_none());
    assert_eq!(decision.recommendation, Recommendation::StopProgram as i32);
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
async fn scoped_source_returns_the_exact_latest_decision_at_maximum_version() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let tenant_id = "tenant-adapter-hit";
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fa101")
        .expect("fixed decision identifier must parse");
    let older = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6ba101",
        &decision_id.to_string(),
        1,
    );
    let latest = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6ba102",
        &decision_id.to_string(),
        u64::MAX,
    );
    let expected = VersionedDecisionRecord::try_from(
        latest
            .decision
            .clone()
            .expect("fixed event must contain a decision"),
    )
    .expect("fixed decision must satisfy the contract");

    append(&mut writer, older, tenant_id).await;
    assert!(tenant_context_is_absent(&writer).await);
    append(&mut writer, latest, tenant_id).await;
    assert!(tenant_context_is_absent(&writer).await);

    let actual = {
        let reader = PostgresDecisionEventReader::new(&mut reader);
        let source = PostgresLatestDecisionSource::try_new(reader, tenant_id)
            .expect("fixed tenant scope must be valid");
        let mut get_decision = GetDecision::new(source);
        get_decision
            .execute(GetDecisionQuery::new(decision_id))
            .await
            .expect("scoped source must read the latest decision")
            .expect("latest decision must exist")
    };

    assert_eq!(actual, expected);
    assert_eq!(actual.aggregate_version().get(), u64::MAX);
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
async fn rejects_invalid_source_scopes_at_construction_without_database_access() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;

    for invalid_scope in ["", " tenant-adapter", "tenant-adapter ", "tenant\0adapter"] {
        let error = match PostgresLatestDecisionSource::try_new(
            PostgresDecisionEventReader::new(&mut reader),
            invalid_scope,
        ) {
            Ok(_) => panic!("invalid tenant scope must be rejected"),
            Err(error) => error,
        };
        let rendered = format!("{error:?} {error}");

        assert_eq!(error, InvalidDecisionSourceScope);
        assert_eq!(format!("{error:?}"), "InvalidDecisionSourceScope");
        assert_eq!(error.to_string(), "decision source scope is invalid");
        if !invalid_scope.is_empty() {
            assert!(!rendered.contains(invalid_scope));
        }
        assert!(tenant_context_is_absent(&reader).await);
    }

    reader_task.abort();
}

#[tokio::test]
async fn scoped_source_makes_cross_tenant_and_absent_decisions_indistinguishable() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let visible_tenant = "tenant-adapter-visible";
    let hidden_tenant = "tenant-adapter-hidden";
    let hidden_decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fa201")
        .expect("fixed hidden decision identifier must parse");
    let absent_decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fa202")
        .expect("fixed absent decision identifier must parse");
    let hidden = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6ba201",
        &hidden_decision_id.to_string(),
        1,
    );

    append(&mut writer, hidden, hidden_tenant).await;
    assert!(tenant_context_is_absent(&writer).await);

    let cross_tenant = {
        let source = PostgresLatestDecisionSource::try_new(
            PostgresDecisionEventReader::new(&mut reader),
            visible_tenant,
        )
        .expect("fixed tenant scope must be valid");
        GetDecision::new(source)
            .execute(GetDecisionQuery::new(hidden_decision_id))
            .await
            .expect("cross-tenant decision must appear absent")
    };
    assert!(tenant_context_is_absent(&reader).await);

    let absent = {
        let source = PostgresLatestDecisionSource::try_new(
            PostgresDecisionEventReader::new(&mut reader),
            visible_tenant,
        )
        .expect("fixed tenant scope must be valid");
        GetDecision::new(source)
            .execute(GetDecisionQuery::new(absent_decision_id))
            .await
            .expect("absent decision lookup must succeed")
    };

    assert_eq!(cross_tenant, None);
    assert_eq!(cross_tenant, absent);
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
async fn scoped_source_rejects_a_corrupt_latest_decision_without_fallback() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let tenant_id = "tenant-adapter-corrupt";
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fa301")
        .expect("fixed decision identifier must parse");
    let valid_older = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6ba301",
        &decision_id.to_string(),
        1,
    );
    let corrupt_latest = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6ba302",
        &decision_id.to_string(),
        2,
    );

    append(&mut writer, valid_older, tenant_id).await;
    assert!(tenant_context_is_absent(&writer).await);
    insert_corrupt_event(&mut writer, corrupt_latest, tenant_id).await;
    assert!(tenant_context_is_absent(&writer).await);

    let error = {
        let source = PostgresLatestDecisionSource::try_new(
            PostgresDecisionEventReader::new(&mut reader),
            tenant_id,
        )
        .expect("fixed tenant scope must be valid");
        GetDecision::new(source)
            .execute(GetDecisionQuery::new(decision_id))
            .await
            .expect_err("corrupt latest decision must not fall back")
    };
    let rendered = format!("{error:?} {error}");

    assert_eq!(error, GetDecisionError::StoredStateRejected);
    assert_eq!(format!("{error:?}"), "StoredStateRejected");
    assert_eq!(error.to_string(), "stored decision state was rejected");
    assert!(!rendered.contains(tenant_id));
    assert!(!rendered.contains(&decision_id.to_string()));
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
async fn scoped_source_maps_writer_identity_rejection_to_source_unavailable() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let tenant_id = "tenant-adapter-wrong-reader";
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fa401")
        .expect("fixed decision identifier must parse");

    let error = {
        let source = PostgresLatestDecisionSource::try_new(
            PostgresDecisionEventReader::new(&mut writer),
            tenant_id,
        )
        .expect("fixed tenant scope must be valid");
        GetDecision::new(source)
            .execute(GetDecisionQuery::new(decision_id))
            .await
            .expect_err("writer identity must not read through the scoped source")
    };
    let rendered = format!("{error:?} {error}");

    assert_eq!(error, GetDecisionError::SourceUnavailable);
    assert_eq!(format!("{error:?}"), "SourceUnavailable");
    assert_eq!(error.to_string(), "decision source is unavailable");
    assert!(!rendered.contains(tenant_id));
    assert!(!rendered.contains(&decision_id.to_string()));
    assert!(tenant_context_is_absent(&writer).await);
    writer_task.abort();
}

#[tokio::test]
async fn scoped_source_future_is_send_and_borrows_the_source_mutably() {
    fn assert_source<T: LatestDecisionSource + Send>() {}
    fn assert_future_is_send<T: Future + Send>(future: T) -> T {
        future
    }

    assert_source::<PostgresLatestDecisionSource<'_, '_>>();

    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fa501")
        .expect("fixed decision identifier must parse");

    {
        let mut source = PostgresLatestDecisionSource::try_new(
            PostgresDecisionEventReader::new(&mut reader),
            "tenant-adapter-future",
        )
        .expect("fixed tenant scope must be valid");
        let future = assert_future_is_send(source.read_latest(GetDecisionQuery::new(decision_id)));

        assert_eq!(future.await, Ok(None));
    }

    assert!(tenant_context_is_absent(&reader).await);
    reader_task.abort();
}

#[tokio::test]
async fn returns_the_only_version_one_event_for_a_decision_stream() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let tenant_id = "tenant-m14-version-one";
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fe601")
        .expect("fixed decision identifier must parse");
    let expected = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6b8101",
        &decision_id.to_string(),
        1,
    );

    append(&mut writer, expected.clone(), tenant_id).await;
    assert!(tenant_context_is_absent(&writer).await);

    let actual = PostgresDecisionEventReader::new(&mut reader)
        .get_latest(tenant_id, decision_id)
        .await
        .expect("reader must load the only stream event");

    assert_eq!(actual, Some(expected));
    assert_eq!(
        actual
            .as_ref()
            .and_then(|event| event.decision.as_ref())
            .and_then(|decision| decision.prediction_interval.clone()),
        Some(prediction_interval("0.25", "1.5"))
    );
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
async fn returns_u64_max_when_version_one_was_inserted_and_occurred_later() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let tenant_id = "tenant-m14-latest";
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fe602")
        .expect("fixed decision identifier must parse");
    let expected = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6b8102",
        &decision_id.to_string(),
        u64::MAX,
    );
    let later_insert = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6b8103",
        &decision_id.to_string(),
        1,
    );
    let lexically_greater = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6b8107",
        &decision_id.to_string(),
        9,
    );

    append_at(
        &mut writer,
        expected.clone(),
        tenant_id,
        occurred_at_value("2026-07-19T00:00:00Z"),
    )
    .await;
    assert!(tenant_context_is_absent(&writer).await);
    append_at(
        &mut writer,
        later_insert,
        tenant_id,
        occurred_at_value("2026-07-21T00:00:00Z"),
    )
    .await;
    assert!(tenant_context_is_absent(&writer).await);
    append_at(
        &mut writer,
        lexically_greater,
        tenant_id,
        occurred_at_value("2026-07-22T00:00:00Z"),
    )
    .await;
    assert!(tenant_context_is_absent(&writer).await);

    let actual = PostgresDecisionEventReader::new(&mut reader)
        .get_latest(tenant_id, decision_id)
        .await
        .expect("reader must load the numerically latest stream event");

    assert_eq!(actual, Some(expected));
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
async fn makes_cross_tenant_and_missing_decision_streams_indistinguishable() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let tenant_a = "tenant-m14-hidden-a";
    let tenant_b = "tenant-m14-hidden-b";
    let hidden_decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fe603")
        .expect("fixed hidden decision identifier must parse");
    let missing_decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fe604")
        .expect("fixed missing decision identifier must parse");
    let hidden = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6b8104",
        &hidden_decision_id.to_string(),
        1,
    );

    append(&mut writer, hidden, tenant_b).await;
    assert!(tenant_context_is_absent(&writer).await);

    let cross_tenant = PostgresDecisionEventReader::new(&mut reader)
        .get_latest(tenant_a, hidden_decision_id)
        .await
        .expect("cross-tenant stream lookup must not disclose an error");
    assert!(tenant_context_is_absent(&reader).await);
    let absent = PostgresDecisionEventReader::new(&mut reader)
        .get_latest(tenant_a, missing_decision_id)
        .await
        .expect("absent stream lookup must succeed");

    assert_eq!(cross_tenant, None);
    assert_eq!(cross_tenant, absent);
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
async fn rejects_a_corrupt_latest_event_without_falling_back() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let tenant_id = "tenant-m14-corrupt";
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3fe605")
        .expect("fixed decision identifier must parse");
    let valid_older = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6b8105",
        &decision_id.to_string(),
        1,
    );
    let corrupt_latest = decision_event_at_version(
        "01910d47-6f80-7a31-8c29-1d5c4f6b8106",
        &decision_id.to_string(),
        2,
    );

    append(&mut writer, valid_older.clone(), tenant_id).await;
    assert!(tenant_context_is_absent(&writer).await);
    insert_corrupt_event(&mut writer, corrupt_latest, tenant_id).await;
    assert!(tenant_context_is_absent(&writer).await);

    let older_event_id = projected_row(&valid_older, tenant_id).event_id;
    let loaded_older = PostgresDecisionEventReader::new(&mut reader)
        .get(tenant_id, older_event_id)
        .await
        .expect("older stream event must remain readable");
    assert_eq!(loaded_older, Some(valid_older));
    assert!(tenant_context_is_absent(&reader).await);

    let error = PostgresDecisionEventReader::new(&mut reader)
        .get_latest(tenant_id, decision_id)
        .await
        .expect_err("corrupt latest event must not fall back to an older version");

    assert_eq!(error, ReadDecisionEventError::StoredEventRejected);
    assert_redacted(&error);
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

fn metadata(tenant_id: &str) -> DecisionEventMetadata {
    metadata_at(tenant_id, occurred_at())
}

fn metadata_at(tenant_id: &str, event_occurred_at: DateTime<Utc>) -> DecisionEventMetadata {
    DecisionEventMetadata::try_new(
        tenant_id.to_owned(),
        event_occurred_at,
        json!({"algorithm": "Ed25519", "key_id": "m11-test", "value": "test-signature"}),
    )
    .expect("fixed metadata must be valid")
}

fn historical_ood_status_row(tenant_id: &str) -> ScientificEventRow {
    ScientificEventRow {
        event_id: Uuid::parse_str("01910d47-6f80-7a31-8c29-1d5c4f6b7012")
            .expect("fixed event identifier must parse"),
        event_type: DECISION_EVENT_TYPE.to_owned(),
        schema_version: DECISION_SCHEMA_VERSION.to_owned(),
        aggregate_type: DECISION_AGGREGATE_TYPE.to_owned(),
        aggregate_id: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99".to_owned(),
        aggregate_version: u64::MAX,
        occurred_at: occurred_at(),
        tenant_id: tenant_id.to_owned(),
        payload: json!({
            "aggregate_version": "18446744073709551615",
            "cou_id": "COU-001",
            "decision_id": "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
            "evidence": {
                "id": "ES-001",
                "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            },
            "ood_status": "unknown",
            "rationale": [
                "Primary threshold was not met.",
                "Confirmatory evidence was absent.",
                "Primary threshold was not met."
            ],
            "recommendation": "stop_program"
        }),
        payload_sha256: "46bf4726814bddfc9d1005766bf2b68fd11932b41306ac85d8676ab23ac995e1"
            .to_owned(),
        signature: json!({
            "algorithm": "Ed25519",
            "key_id": "historical-ood-test",
            "value": "test-signature"
        })
        .as_object()
        .expect("fixed signature must be an object")
        .clone(),
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

async fn connect(role: &str, password: String) -> (Client, JoinHandle<()>) {
    let mut configuration = tokio_postgres::Config::new();
    configuration
        .host(POSTGRES_HOST)
        .port(POSTGRES_PORT)
        .dbname(POSTGRES_DATABASE)
        .user(role)
        .password(password);
    let (client, connection) = configuration
        .connect(tokio_postgres::NoTls)
        .await
        .expect("runtime role must connect through internal PostgreSQL TCP");
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    (client, connection_task)
}

async fn append(client: &mut Client, event: DecisionEvent, tenant_id: &str) {
    append_at(client, event, tenant_id, occurred_at()).await;
}

async fn append_at(
    client: &mut Client,
    event: DecisionEvent,
    tenant_id: &str,
    event_occurred_at: DateTime<Utc>,
) {
    PostgresDecisionEventWriter::new(client)
        .append(event, metadata_at(tenant_id, event_occurred_at))
        .await
        .expect("writer must seed a valid integration event");
}

async fn insert_corrupt_event(client: &mut Client, event: DecisionEvent, tenant_id: &str) {
    let mut row = projected_row(&event, tenant_id);
    row.payload_sha256 = "0".repeat(64);
    insert_scientific_event_row(client, row).await;
}

async fn insert_scientific_event_row(client: &mut Client, row: ScientificEventRow) {
    let tenant_id = row.tenant_id.clone();
    let aggregate_version = row.aggregate_version.to_string();
    let signature = serde_json::Value::Object(row.signature);
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
    let transaction = client
        .transaction()
        .await
        .expect("corrupt fixture transaction must begin");
    let context_is_exact: bool = transaction
        .query_one(
            "SELECT pg_catalog.set_config('bioworld.tenant_id', $1, true) = $1",
            &[&tenant_id],
        )
        .await
        .expect("corrupt fixture tenant context must be set")
        .get(0);
    assert!(context_is_exact);
    transaction
        .execute(
            "INSERT INTO public.scientific_event (event_id, event_type, schema_version, aggregate_type, aggregate_id, aggregate_version, occurred_at, tenant_id, payload, payload_sha256, signature) VALUES ($1, $2, $3, $4, $5, $6::text::numeric, $7, $8, $9, $10, $11)",
            &parameters,
        )
        .await
        .expect("corrupt fixture must be inserted");
    transaction
        .commit()
        .await
        .expect("corrupt fixture transaction must commit");
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
        READER_PASSWORD_ENVIRONMENT_VARIABLE,
        "test-signature",
        "fixture-signature",
        "tenant-fixture",
        "fixture-decision",
        "00000000-0000-4000-8000-000000000001",
        "tenant-m14-corrupt",
        "018f5a72-9c4b-7d31-8f6a-26f08f3fe605",
        "01910d47-6f80-7a31-8c29-1d5c4f6b8106",
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
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let tenant_id = "tenant-m11-exact";
    let expected = decision_event(
        "01910d47-6f80-7a31-8c29-1d5c4f6b7101",
        "018f5a72-9c4b-7d31-8f6a-26f08f3fd101",
    );
    let id = projected_row(&expected, tenant_id).event_id;

    append(&mut writer, expected.clone(), tenant_id).await;
    assert!(tenant_context_is_absent(&writer).await);

    let actual = PostgresDecisionEventReader::new(&mut reader)
        .get(tenant_id, id)
        .await
        .expect("reader must load a valid event");

    assert_eq!(actual, Some(expected));
    assert_eq!(
        actual.unwrap().decision.unwrap().aggregate_version,
        u64::MAX
    );
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
async fn makes_cross_tenant_events_indistinguishable_from_absent_events() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
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

    append(&mut writer, hidden, tenant_b).await;

    let cross_tenant = PostgresDecisionEventReader::new(&mut reader)
        .get(tenant_a, hidden_id)
        .await
        .expect("cross-tenant lookup must not disclose an error");
    assert!(tenant_context_is_absent(&reader).await);
    let absent = PostgresDecisionEventReader::new(&mut reader)
        .get(tenant_a, missing_id)
        .await
        .expect("absent lookup must succeed");

    assert_eq!(cross_tenant, None);
    assert_eq!(cross_tenant, absent);
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
#[allow(deprecated)]
async fn resolves_the_same_event_identifier_independently_for_each_tenant() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
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

    append(&mut writer, event_a.clone(), tenant_a).await;
    append(&mut writer, event_b.clone(), tenant_b).await;

    let loaded_a = PostgresDecisionEventReader::new(&mut reader)
        .get(tenant_a, shared_id)
        .await
        .expect("tenant A event must be readable");
    let loaded_b = PostgresDecisionEventReader::new(&mut reader)
        .get(tenant_b, shared_id)
        .await
        .expect("tenant B event must be readable");

    assert_eq!(loaded_a, Some(event_a));
    assert_eq!(loaded_b, Some(event_b));
    assert!(tenant_context_is_absent(&reader).await);
    writer_task.abort();
    reader_task.abort();
}

#[tokio::test]
async fn rejects_a_corrupt_stored_event_without_leaking_details_or_tenant_context() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let fixture_identity = decision_event(
        "00000000-0000-4000-8000-000000000001",
        "018f5a72-9c4b-7d31-8f6a-26f08f3fd401",
    );
    let fixture_id = projected_row(&fixture_identity, "tenant-fixture").event_id;

    let error = PostgresDecisionEventReader::new(&mut reader)
        .get("tenant-fixture", fixture_id)
        .await
        .expect_err("legacy fixture is not a valid decision event");

    assert_eq!(error, ReadDecisionEventError::StoredEventRejected);
    assert_redacted(&error);
    assert!(tenant_context_is_absent(&reader).await);
    reader_task.abort();
}

#[tokio::test]
async fn rejects_writer_for_reads_and_reader_for_appends() {
    let Some(passwords) = integration_passwords() else {
        return;
    };
    let (mut writer, writer_task) = connect(POSTGRES_WRITER_USER, passwords.writer).await;
    let (mut reader, reader_task) = connect(POSTGRES_READER_USER, passwords.reader).await;
    let tenant_id = "tenant-m13-opposite-identities";
    let event = decision_event(
        "01910d47-6f80-7a31-8c29-1d5c4f6b7401",
        "018f5a72-9c4b-7d31-8f6a-26f08f3fd501",
    );
    let event_id = projected_row(&event, tenant_id).event_id;

    let read_error = PostgresDecisionEventReader::new(&mut writer)
        .get(tenant_id, event_id)
        .await
        .expect_err("writer identity must not be accepted for reads");
    assert_eq!(read_error, ReadDecisionEventError::ReaderIdentityRejected);
    assert_redacted(&read_error);
    assert!(tenant_context_is_absent(&writer).await);

    let append_error = PostgresDecisionEventWriter::new(&mut reader)
        .append(event, metadata(tenant_id))
        .await
        .expect_err("reader identity must not be accepted for appends");
    assert_eq!(
        append_error,
        AppendDecisionEventError::WriterIdentityRejected
    );
    assert!(tenant_context_is_absent(&reader).await);

    writer_task.abort();
    reader_task.abort();
}
