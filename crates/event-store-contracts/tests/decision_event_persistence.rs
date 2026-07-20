use bioworld_contracts::{
    DecisionContractError,
    v2::{DecisionEvent, DecisionRecord, EvidenceSnapshotRef, Recommendation},
};
use bioworld_event_store_contracts::{
    DECISION_AGGREGATE_TYPE, DECISION_EVENT_TYPE, DECISION_SCHEMA_VERSION, DecisionEventMetadata,
    EventProjectionError, project_decision_event, reconstruct_decision_event,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[allow(deprecated)]
fn complete_event() -> DecisionEvent {
    DecisionEvent {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6b7012".to_owned(),
        decision: Some(DecisionRecord {
            decision_id: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99".to_owned(),
            cou_id: "COU-001".to_owned(),
            evidence_snapshot_id: "ES-001".to_owned(),
            recommendation: Recommendation::StopProgram as i32,
            rationale: vec![
                "Primary threshold was not met.".to_owned(),
                "Confirmatory evidence was absent.".to_owned(),
                "Primary threshold was not met.".to_owned(),
            ],
            aggregate_version: u64::MAX,
            evidence: Some(EvidenceSnapshotRef {
                id: "ES-001".to_owned(),
                sha256: VALID_SHA256.to_owned(),
            }),
        }),
    }
}

fn occurred_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-07-20T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn metadata() -> DecisionEventMetadata {
    DecisionEventMetadata::try_new(
        "tenant-001".to_owned(),
        occurred_at(),
        json!({
            "algorithm": "Ed25519",
            "key_id": "test-key",
            "value": "test-signature"
        }),
    )
    .unwrap()
}

fn projected_row() -> bioworld_event_store_contracts::ScientificEventRow {
    project_decision_event(complete_event(), metadata()).unwrap()
}

fn rehash_payload(row: &mut bioworld_event_store_contracts::ScientificEventRow) {
    let bytes = serde_jcs::to_vec(&row.payload).unwrap();
    row.payload_sha256 = format!("{:x}", Sha256::digest(bytes));
}

#[test]
fn projects_canonical_payload_and_round_trips_without_loss() {
    let event = complete_event();

    let row = project_decision_event(event.clone(), metadata()).unwrap();

    assert_eq!(row.event_id.to_string(), event.event_id);
    assert_eq!(row.event_type, DECISION_EVENT_TYPE);
    assert_eq!(row.schema_version, DECISION_SCHEMA_VERSION);
    assert_eq!(row.aggregate_type, DECISION_AGGREGATE_TYPE);
    assert_eq!(
        row.aggregate_id,
        event.decision.as_ref().unwrap().decision_id
    );
    assert_eq!(row.aggregate_version, u64::MAX);
    assert_eq!(row.occurred_at, occurred_at());
    assert_eq!(row.tenant_id, "tenant-001");
    assert_eq!(
        row.signature,
        json!({
            "algorithm": "Ed25519",
            "key_id": "test-key",
            "value": "test-signature"
        })
        .as_object()
        .unwrap()
        .clone()
    );
    assert_eq!(
        row.payload["aggregate_version"],
        json!(u64::MAX.to_string())
    );
    assert_eq!(
        row.payload["rationale"],
        json!([
            "Primary threshold was not met.",
            "Confirmatory evidence was absent.",
            "Primary threshold was not met."
        ]),
    );
    assert_eq!(
        row.payload_sha256,
        "4b133dc1df588e8e5149d1011d53c43c2284ada02597a7d28978a7b1f9cb94f9"
    );
    assert_eq!(reconstruct_decision_event(&row).unwrap(), event);
}

#[test]
fn rejects_missing_or_invalid_event_identity() {
    let mut missing_decision = complete_event();
    missing_decision.decision = None;
    assert!(matches!(
        project_decision_event(missing_decision, metadata()),
        Err(EventProjectionError::MissingDecision)
    ));

    let mut invalid_event_id = complete_event();
    invalid_event_id.event_id = "not-a-uuid".to_owned();
    assert!(matches!(
        project_decision_event(invalid_event_id, metadata()),
        Err(EventProjectionError::InvalidEventId)
    ));

    let mut noncanonical_event_id = complete_event();
    noncanonical_event_id.event_id.make_ascii_uppercase();
    assert!(matches!(
        project_decision_event(noncanonical_event_id, metadata()),
        Err(EventProjectionError::InvalidEventId)
    ));
}

#[test]
fn rejects_noncanonical_decision_identity_instead_of_normalizing_it() {
    let mut event = complete_event();
    event
        .decision
        .as_mut()
        .unwrap()
        .decision_id
        .make_ascii_uppercase();

    assert!(matches!(
        project_decision_event(event, metadata()),
        Err(EventProjectionError::InvalidDecision(
            DecisionContractError::InvalidDecisionId
        ))
    ));
}

#[test]
fn propagates_nested_decision_validation_errors() {
    let mut missing_cou = complete_event();
    missing_cou.decision.as_mut().unwrap().cou_id = "  ".to_owned();
    assert!(matches!(
        project_decision_event(missing_cou, metadata()),
        Err(EventProjectionError::InvalidDecision(
            DecisionContractError::MissingCouId
        ))
    ));

    let mut conflicting_evidence = complete_event();
    conflicting_evidence
        .decision
        .as_mut()
        .unwrap()
        .evidence
        .as_mut()
        .unwrap()
        .id = "ES-002".to_owned();
    assert!(matches!(
        project_decision_event(conflicting_evidence, metadata()),
        Err(EventProjectionError::InvalidDecision(
            DecisionContractError::ConflictingEvidenceIds
        ))
    ));
}

#[test]
fn validates_metadata_at_both_sides_of_the_boundary() {
    for tenant_id in [
        "",
        " tenant-001",
        "tenant-001 ",
        "tenant-001\n",
        "tenant-001\u{000b}",
        "tenant-001\u{00a0}",
        "\u{3000}tenant-001",
    ] {
        assert!(matches!(
            DecisionEventMetadata::try_new(
                tenant_id.to_owned(),
                occurred_at(),
                json!({"value": "signature"}),
            ),
            Err(EventProjectionError::InvalidTenantId)
        ));
    }

    for signature in [json!(null), json!("signature"), json!([]), json!({})] {
        assert!(matches!(
            DecisionEventMetadata::try_new("tenant-001".to_owned(), occurred_at(), signature,),
            Err(EventProjectionError::InvalidSignature)
        ));
    }

    let mut row = projected_row();
    row.tenant_id = " tenant-001".to_owned();
    assert!(matches!(
        reconstruct_decision_event(&row),
        Err(EventProjectionError::InvalidTenantId)
    ));

    let mut row = projected_row();
    row.signature.clear();
    assert!(matches!(
        reconstruct_decision_event(&row),
        Err(EventProjectionError::InvalidSignature)
    ));
}

#[test]
#[allow(deprecated)]
fn rejects_nul_bytes_that_postgresql_cannot_store() {
    assert!(
        DecisionEventMetadata::try_new(
            "tenant\0id".to_owned(),
            occurred_at(),
            json!({"value": "signature"}),
        )
        .is_err()
    );
    assert!(
        DecisionEventMetadata::try_new(
            "tenant-001".to_owned(),
            occurred_at(),
            json!({"value": "signature\0value"}),
        )
        .is_err()
    );

    let mut nul_cou = complete_event();
    nul_cou.decision.as_mut().unwrap().cou_id = "COU\0-001".to_owned();
    assert!(project_decision_event(nul_cou, metadata()).is_err());

    let mut nul_evidence = complete_event();
    let decision = nul_evidence.decision.as_mut().unwrap();
    decision.evidence_snapshot_id = "ES\0-001".to_owned();
    decision.evidence.as_mut().unwrap().id = "ES\0-001".to_owned();
    assert!(project_decision_event(nul_evidence, metadata()).is_err());

    let mut nul_rationale = complete_event();
    nul_rationale.decision.as_mut().unwrap().rationale = vec!["reason\0value".to_owned()];
    assert!(project_decision_event(nul_rationale, metadata()).is_err());
}

#[test]
fn rejects_payload_and_row_metadata_tampering() {
    let mut changed_payload = projected_row();
    changed_payload.payload["cou_id"] = json!("COU-002");
    assert!(matches!(
        reconstruct_decision_event(&changed_payload),
        Err(EventProjectionError::PayloadHashMismatch)
    ));

    let mut unknown_field = projected_row();
    unknown_field.payload["unexpected"] = json!(true);
    assert!(matches!(
        reconstruct_decision_event(&unknown_field),
        Err(EventProjectionError::InvalidPayload(_))
    ));

    let mut changed_digest = projected_row();
    changed_digest.payload_sha256.make_ascii_uppercase();
    assert!(matches!(
        reconstruct_decision_event(&changed_digest),
        Err(EventProjectionError::PayloadHashMismatch)
    ));

    let mut changed_event_type = projected_row();
    changed_event_type.event_type = "other.Event".to_owned();
    assert!(matches!(
        reconstruct_decision_event(&changed_event_type),
        Err(EventProjectionError::InvalidEventType)
    ));

    let mut changed_schema = projected_row();
    changed_schema.schema_version = "3".to_owned();
    assert!(matches!(
        reconstruct_decision_event(&changed_schema),
        Err(EventProjectionError::InvalidSchemaVersion)
    ));

    let mut changed_aggregate_type = projected_row();
    changed_aggregate_type.aggregate_type = "other.Aggregate".to_owned();
    assert!(matches!(
        reconstruct_decision_event(&changed_aggregate_type),
        Err(EventProjectionError::InvalidAggregateType)
    ));

    let mut changed_aggregate_id = projected_row();
    changed_aggregate_id.aggregate_id = Uuid::nil().to_string();
    assert!(matches!(
        reconstruct_decision_event(&changed_aggregate_id),
        Err(EventProjectionError::AggregateIdMismatch)
    ));

    let mut changed_aggregate_version = projected_row();
    changed_aggregate_version.aggregate_version = 1;
    assert!(matches!(
        reconstruct_decision_event(&changed_aggregate_version),
        Err(EventProjectionError::AggregateVersionMismatch)
    ));

    let mut noncanonical_decision_id = projected_row();
    let uppercase_id = noncanonical_decision_id.payload["decision_id"]
        .as_str()
        .unwrap()
        .to_ascii_uppercase();
    noncanonical_decision_id.payload["decision_id"] = json!(uppercase_id);
    noncanonical_decision_id.aggregate_id = uppercase_id;
    rehash_payload(&mut noncanonical_decision_id);
    assert!(matches!(
        reconstruct_decision_event(&noncanonical_decision_id),
        Err(EventProjectionError::InvalidDecision(
            DecisionContractError::InvalidDecisionId
        ))
    ));
}

#[test]
fn rejects_noncanonical_or_out_of_range_payload_versions() {
    for invalid in ["0", "01", "+1", " 1", "1.0", "18446744073709551616"] {
        let mut row = projected_row();
        row.payload["aggregate_version"] = json!(invalid);
        assert!(matches!(
            reconstruct_decision_event(&row),
            Err(EventProjectionError::InvalidAggregateVersion)
        ));
    }

    let mut numeric_version = projected_row();
    numeric_version.payload["aggregate_version"] = json!(1);
    assert!(matches!(
        reconstruct_decision_event(&numeric_version),
        Err(EventProjectionError::InvalidPayload(_))
    ));
}

#[test]
fn canonical_hash_is_independent_of_json_object_key_order() {
    let expected = projected_row();
    let reordered = serde_json::from_str(
        r#"{
            "rationale":[
                "Primary threshold was not met.",
                "Confirmatory evidence was absent.",
                "Primary threshold was not met."
            ],
            "recommendation":"stop_program",
            "evidence":{
                "sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "id":"ES-001"
            },
            "cou_id":"COU-001",
            "decision_id":"018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
            "aggregate_version":"18446744073709551615"
        }"#,
    )
    .unwrap();
    let mut row = expected.clone();
    row.payload = reordered;

    assert_eq!(reconstruct_decision_event(&row).unwrap(), complete_event());
    assert_eq!(row.payload_sha256, expected.payload_sha256);
}

#[test]
#[allow(deprecated)]
fn stores_only_nested_evidence_and_backfills_the_legacy_field() {
    let mut event = complete_event();
    event
        .decision
        .as_mut()
        .unwrap()
        .evidence_snapshot_id
        .clear();

    let row = project_decision_event(event, metadata()).unwrap();
    assert!(row.payload.get("evidence_snapshot_id").is_none());

    let reconstructed = reconstruct_decision_event(&row).unwrap();
    let decision = reconstructed.decision.unwrap();
    assert_eq!(decision.evidence_snapshot_id, "ES-001");
    assert_eq!(decision.evidence.unwrap().id, "ES-001");
}

#[test]
fn round_trips_every_supported_recommendation() {
    for recommendation in [
        Recommendation::Promote,
        Recommendation::Reject,
        Recommendation::Abstain,
        Recommendation::Defer,
        Recommendation::StopProgram,
    ] {
        let mut event = complete_event();
        event.decision.as_mut().unwrap().recommendation = recommendation as i32;

        let row = project_decision_event(event.clone(), metadata()).unwrap();
        assert_eq!(reconstruct_decision_event(&row).unwrap(), event);
    }
}
