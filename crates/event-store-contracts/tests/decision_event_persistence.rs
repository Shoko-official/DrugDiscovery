use bioworld_contracts::{
    DecisionContractError, MAX_TENANT_ID_BYTES,
    v2::{DecisionEvent, DecisionRecord, EvidenceSnapshotRef, OodStatus, Recommendation},
};
use bioworld_event_store_contracts::{
    DECISION_AGGREGATE_TYPE, DECISION_EVENT_TYPE, DECISION_SCHEMA_VERSION, DecisionEventMetadata,
    EventProjectionError, MAX_CANONICAL_DECISION_PAYLOAD_BYTES,
    MAX_CANONICAL_DECISION_PAYLOAD_DEPTH, MAX_CANONICAL_DECISION_PAYLOAD_NODES,
    MAX_EVENT_SIGNATURE_DEPTH, MAX_EVENT_SIGNATURE_JSON_BYTES, MAX_EVENT_SIGNATURE_NODES,
    MAX_STORED_EVENT_PAYLOAD_BYTES, MAX_STORED_EVENT_SIGNATURE_BYTES,
    parse_stored_decision_payload, parse_stored_event_signature, project_decision_event,
    reconstruct_decision_event,
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
            ood_status: Some(OodStatus::Unknown as i32),
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

fn nested_signature(depth: usize) -> serde_json::Value {
    let mut value = json!("signature");
    for _ in 1..depth {
        value = json!({"nested": value});
    }
    value
}

fn nested_payload(depth: usize) -> serde_json::Value {
    let mut value = json!(null);
    for _ in 1..depth {
        value = json!({"nested": value});
    }
    value
}

fn projected_row() -> bioworld_event_store_contracts::ScientificEventRow {
    project_decision_event(complete_event(), metadata()).unwrap()
}

#[test]
fn parses_valid_stored_json_without_loss() {
    let payload_text =
        r#"{"decision_id":"018f5a72-9c4b-7d31-8f6a-26f08f3f4d99","rationale":["reason"]}"#;
    let signature_text = r#"{"algorithm":"Ed25519","key_id":"test-key"}"#;

    assert_eq!(
        parse_stored_decision_payload(payload_text).unwrap(),
        serde_json::from_str::<serde_json::Value>(payload_text).unwrap()
    );
    assert_eq!(
        parse_stored_event_signature(signature_text).unwrap(),
        serde_json::from_str::<serde_json::Value>(signature_text)
            .unwrap()
            .as_object()
            .unwrap()
            .clone()
    );
}

#[test]
fn bounds_stored_json_node_count() {
    let payload_exact = serde_json::to_string(&json!({
        "values": vec![serde_json::Value::Null; MAX_CANONICAL_DECISION_PAYLOAD_NODES - 2]
    }))
    .unwrap();
    assert!(parse_stored_decision_payload(&payload_exact).is_ok());

    let payload_over = serde_json::to_string(&json!({
        "values": vec![serde_json::Value::Null; MAX_CANONICAL_DECISION_PAYLOAD_NODES - 1]
    }))
    .unwrap();
    assert!(matches!(
        parse_stored_decision_payload(&payload_over),
        Err(EventProjectionError::CanonicalPayloadStructureExceeded)
    ));

    let signature_exact = serde_json::to_string(&json!({
        "values": vec![serde_json::Value::Null; MAX_EVENT_SIGNATURE_NODES - 2]
    }))
    .unwrap();
    assert!(parse_stored_event_signature(&signature_exact).is_ok());

    let signature_over = serde_json::to_string(&json!({
        "values": vec![serde_json::Value::Null; MAX_EVENT_SIGNATURE_NODES - 1]
    }))
    .unwrap();
    assert!(matches!(
        parse_stored_event_signature(&signature_over),
        Err(EventProjectionError::SignatureStructureExceeded)
    ));
}

#[test]
fn bounds_stored_json_depth() {
    let payload_exact =
        serde_json::to_string(&nested_payload(MAX_CANONICAL_DECISION_PAYLOAD_DEPTH)).unwrap();
    assert!(parse_stored_decision_payload(&payload_exact).is_ok());

    let payload_over =
        serde_json::to_string(&nested_payload(MAX_CANONICAL_DECISION_PAYLOAD_DEPTH + 1)).unwrap();
    assert!(matches!(
        parse_stored_decision_payload(&payload_over),
        Err(EventProjectionError::CanonicalPayloadStructureExceeded)
    ));

    let signature_exact =
        serde_json::to_string(&nested_signature(MAX_EVENT_SIGNATURE_DEPTH)).unwrap();
    assert!(parse_stored_event_signature(&signature_exact).is_ok());

    let signature_over =
        serde_json::to_string(&nested_signature(MAX_EVENT_SIGNATURE_DEPTH + 1)).unwrap();
    assert!(matches!(
        parse_stored_event_signature(&signature_over),
        Err(EventProjectionError::SignatureStructureExceeded)
    ));
}

#[test]
fn bounds_stored_json_text_bytes() {
    let payload_exact = format!("\"{}\"", "p".repeat(MAX_STORED_EVENT_PAYLOAD_BYTES - 2));
    assert_eq!(payload_exact.len(), MAX_STORED_EVENT_PAYLOAD_BYTES);
    assert!(parse_stored_decision_payload(&payload_exact).is_ok());

    let payload_over = format!("\"{}\"", "p".repeat(MAX_STORED_EVENT_PAYLOAD_BYTES - 1));
    assert!(matches!(
        parse_stored_decision_payload(&payload_over),
        Err(EventProjectionError::CanonicalPayloadEnvelopeExceeded)
    ));

    let signature_overhead = r#"{"value":""}"#.len();
    let signature_exact = format!(
        r#"{{"value":"{}"}}"#,
        "s".repeat(MAX_STORED_EVENT_SIGNATURE_BYTES - signature_overhead)
    );
    assert_eq!(signature_exact.len(), MAX_STORED_EVENT_SIGNATURE_BYTES);
    assert!(parse_stored_event_signature(&signature_exact).is_ok());

    let signature_over = format!(
        r#"{{"value":"{}"}}"#,
        "s".repeat(MAX_STORED_EVENT_SIGNATURE_BYTES - signature_overhead + 1)
    );
    assert!(matches!(
        parse_stored_event_signature(&signature_over),
        Err(EventProjectionError::SignatureEnvelopeExceeded)
    ));
}

#[test]
fn rejects_nul_in_stored_json_text_keys_and_values() {
    for payload in [r#"{"value":"\u0000"}"#, "{\"value\":\"\0\"}"] {
        assert!(matches!(
            parse_stored_decision_payload(payload),
            Err(EventProjectionError::NulByteNotAllowed)
        ));
    }

    for signature in [r#"{"\u0000":"value"}"#, r#"{"value":"\u0000"}"#] {
        assert!(matches!(
            parse_stored_event_signature(signature),
            Err(EventProjectionError::NulByteNotAllowed)
        ));
    }
}

#[test]
fn rejects_trailing_stored_json_without_reflecting_input() {
    let marker = "private-marker";
    let payload_error =
        parse_stored_decision_payload(&format!(r#"{{"value":1}}{marker}"#)).unwrap_err();
    assert!(matches!(
        payload_error,
        EventProjectionError::InvalidPayload(_)
    ));
    assert!(!payload_error.to_string().contains(marker));

    let signature_error =
        parse_stored_event_signature(&format!(r#"{{"value":1}}{marker}"#)).unwrap_err();
    assert!(matches!(
        signature_error,
        EventProjectionError::InvalidSignature
    ));
    assert!(!signature_error.to_string().contains(marker));
}

#[test]
fn requires_nonempty_object_for_stored_signature() {
    for signature in ["null", r#""signature""#, "[]", "{}"] {
        assert!(matches!(
            parse_stored_event_signature(signature),
            Err(EventProjectionError::InvalidSignature)
        ));
    }
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
    assert_eq!(row.payload["ood_status"], json!("unknown"));
    assert_eq!(
        row.payload_sha256,
        "46bf4726814bddfc9d1005766bf2b68fd11932b41306ac85d8676ab23ac995e1"
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
fn bounds_tenant_id_in_bytes() {
    assert!(
        DecisionEventMetadata::try_new(
            "t".repeat(MAX_TENANT_ID_BYTES),
            occurred_at(),
            json!({"value": "signature"}),
        )
        .is_ok()
    );
    assert!(matches!(
        DecisionEventMetadata::try_new(
            "t".repeat(MAX_TENANT_ID_BYTES + 1),
            occurred_at(),
            json!({"value": "signature"}),
        ),
        Err(EventProjectionError::InvalidTenantId)
    ));
}

#[test]
fn bounds_signature_canonical_json_bytes() {
    let object_overhead = serde_jcs::to_vec(&json!({"value": ""})).unwrap().len();
    let accepted = "s".repeat(MAX_EVENT_SIGNATURE_JSON_BYTES - object_overhead);
    assert!(
        DecisionEventMetadata::try_new(
            "tenant-001".to_owned(),
            occurred_at(),
            json!({"value": accepted}),
        )
        .is_ok()
    );

    let rejected = "s".repeat(MAX_EVENT_SIGNATURE_JSON_BYTES - object_overhead + 1);
    assert!(matches!(
        DecisionEventMetadata::try_new(
            "tenant-001".to_owned(),
            occurred_at(),
            json!({"value": rejected}),
        ),
        Err(EventProjectionError::SignatureEnvelopeExceeded)
    ));
}

#[test]
fn bounds_signature_json_depth() {
    assert!(
        DecisionEventMetadata::try_new(
            "tenant-001".to_owned(),
            occurred_at(),
            nested_signature(MAX_EVENT_SIGNATURE_DEPTH),
        )
        .is_ok()
    );
    assert!(matches!(
        DecisionEventMetadata::try_new(
            "tenant-001".to_owned(),
            occurred_at(),
            nested_signature(MAX_EVENT_SIGNATURE_DEPTH + 1),
        ),
        Err(EventProjectionError::SignatureStructureExceeded)
    ));
}

#[test]
fn bounds_signature_json_nodes() {
    let accepted = json!({
        "values": vec![serde_json::Value::Null; MAX_EVENT_SIGNATURE_NODES - 2]
    });
    assert!(
        DecisionEventMetadata::try_new("tenant-001".to_owned(), occurred_at(), accepted,).is_ok()
    );

    let rejected = json!({
        "values": vec![serde_json::Value::Null; MAX_EVENT_SIGNATURE_NODES - 1]
    });
    assert!(matches!(
        DecisionEventMetadata::try_new("tenant-001".to_owned(), occurred_at(), rejected,),
        Err(EventProjectionError::SignatureStructureExceeded)
    ));
}

#[test]
fn rejects_oversized_stored_signature_before_reconstruction() {
    let object_overhead = serde_jcs::to_vec(&json!({"value": ""})).unwrap().len();
    let mut accepted = projected_row();
    accepted.signature = json!({
        "value": "s".repeat(MAX_EVENT_SIGNATURE_JSON_BYTES - object_overhead)
    })
    .as_object()
    .unwrap()
    .clone();
    assert_eq!(
        reconstruct_decision_event(&accepted).unwrap(),
        complete_event()
    );

    let mut rejected = projected_row();
    rejected.signature = json!({
        "value": "s".repeat(MAX_EVENT_SIGNATURE_JSON_BYTES - object_overhead + 1)
    })
    .as_object()
    .unwrap()
    .clone();
    assert!(matches!(
        reconstruct_decision_event(&rejected),
        Err(EventProjectionError::SignatureEnvelopeExceeded)
    ));
}

#[test]
fn rejects_structurally_unbounded_stored_signatures() {
    let mut too_deep = projected_row();
    too_deep.signature = nested_signature(MAX_EVENT_SIGNATURE_DEPTH + 1)
        .as_object()
        .unwrap()
        .clone();
    assert!(matches!(
        reconstruct_decision_event(&too_deep),
        Err(EventProjectionError::SignatureStructureExceeded)
    ));

    let mut too_many_nodes = projected_row();
    too_many_nodes.signature = json!({
        "values": vec![serde_json::Value::Null; MAX_EVENT_SIGNATURE_NODES - 1]
    })
    .as_object()
    .unwrap()
    .clone();
    assert!(matches!(
        reconstruct_decision_event(&too_many_nodes),
        Err(EventProjectionError::SignatureStructureExceeded)
    ));
}

#[test]
fn bounds_stored_canonical_payload_before_reconstruction() {
    let mut accepted = projected_row();
    accepted.payload["cou_id"] = json!("");
    let payload_overhead = serde_jcs::to_vec(&accepted.payload).unwrap().len();
    accepted.payload["cou_id"] =
        json!("c".repeat(MAX_CANONICAL_DECISION_PAYLOAD_BYTES - payload_overhead));
    rehash_payload(&mut accepted);
    assert!(matches!(
        reconstruct_decision_event(&accepted),
        Err(EventProjectionError::InvalidDecision(
            DecisionContractError::DecisionTooLarge
        ))
    ));

    let mut rejected = accepted;
    rejected.payload["cou_id"] =
        json!("c".repeat(MAX_CANONICAL_DECISION_PAYLOAD_BYTES - payload_overhead + 1));
    assert!(matches!(
        reconstruct_decision_event(&rejected),
        Err(EventProjectionError::CanonicalPayloadEnvelopeExceeded)
    ));
}

#[test]
fn bounds_stored_payload_json_depth_before_canonicalization() {
    let mut exact = projected_row();
    exact.payload = nested_payload(MAX_CANONICAL_DECISION_PAYLOAD_DEPTH);
    assert!(matches!(
        reconstruct_decision_event(&exact),
        Err(EventProjectionError::InvalidPayload(_))
    ));

    let mut oversized = projected_row();
    oversized.payload = nested_payload(MAX_CANONICAL_DECISION_PAYLOAD_DEPTH + 1);
    assert!(matches!(
        reconstruct_decision_event(&oversized),
        Err(EventProjectionError::CanonicalPayloadStructureExceeded)
    ));
}

#[test]
fn bounds_stored_payload_json_nodes_before_canonicalization() {
    let mut exact = projected_row();
    exact.payload = json!({
        "values": vec![serde_json::Value::Null; MAX_CANONICAL_DECISION_PAYLOAD_NODES - 2]
    });
    assert!(matches!(
        reconstruct_decision_event(&exact),
        Err(EventProjectionError::InvalidPayload(_))
    ));

    let mut oversized = projected_row();
    oversized.payload = json!({
        "values": vec![serde_json::Value::Null; MAX_CANONICAL_DECISION_PAYLOAD_NODES - 1]
    });
    assert!(matches!(
        reconstruct_decision_event(&oversized),
        Err(EventProjectionError::CanonicalPayloadStructureExceeded)
    ));
}

#[test]
#[allow(deprecated)]
fn rejects_nul_bytes_that_postgresql_cannot_store() {
    assert!(matches!(
        DecisionEventMetadata::try_new(
            "tenant\0id".to_owned(),
            occurred_at(),
            json!({"value": "signature"}),
        ),
        Err(EventProjectionError::NulByteNotAllowed)
    ));
    assert!(matches!(
        DecisionEventMetadata::try_new(
            "tenant-001".to_owned(),
            occurred_at(),
            json!({"value": "signature\0value"}),
        ),
        Err(EventProjectionError::NulByteNotAllowed)
    ));

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
            "ood_status":"unknown",
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

#[test]
fn round_trips_every_supported_ood_status() {
    for (ood_status, canonical_ood_status) in [
        (OodStatus::InDomain, "in_domain"),
        (OodStatus::Borderline, "borderline"),
        (OodStatus::OutOfDomain, "out_of_domain"),
        (OodStatus::Unknown, "unknown"),
    ] {
        let mut event = complete_event();
        event.decision.as_mut().unwrap().ood_status = Some(ood_status as i32);

        let row = project_decision_event(event.clone(), metadata()).unwrap();
        let canonical_payload =
            String::from_utf8(serde_jcs::to_vec(&row.payload).unwrap()).unwrap();
        let expected_payload = format!(
            r#"{{"aggregate_version":"18446744073709551615","cou_id":"COU-001","decision_id":"018f5a72-9c4b-7d31-8f6a-26f08f3f4d99","evidence":{{"id":"ES-001","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},"ood_status":"{canonical_ood_status}","rationale":["Primary threshold was not met.","Confirmatory evidence was absent.","Primary threshold was not met."],"recommendation":"stop_program"}}"#
        );

        assert_eq!(canonical_payload, expected_payload);
        assert_eq!(reconstruct_decision_event(&row).unwrap(), event);
    }
}

#[test]
fn historical_payload_without_ood_status_reconstructs_as_unknown_without_rehashing() {
    const HISTORICAL_PAYLOAD_SHA256: &str =
        "4b133dc1df588e8e5149d1011d53c43c2284ada02597a7d28978a7b1f9cb94f9";

    let mut row = projected_row();
    row.payload.as_object_mut().unwrap().remove("ood_status");
    let historical_bytes = serde_jcs::to_vec(&row.payload).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&historical_bytes)),
        HISTORICAL_PAYLOAD_SHA256
    );
    row.payload_sha256 = HISTORICAL_PAYLOAD_SHA256.to_owned();

    let reconstructed = reconstruct_decision_event(&row).unwrap();

    assert_eq!(
        reconstructed.decision.unwrap().ood_status,
        Some(OodStatus::Unknown as i32)
    );
    assert_eq!(row.payload_sha256, HISTORICAL_PAYLOAD_SHA256);
}

#[test]
fn rejects_explicit_invalid_ood_status_before_persistence() {
    for (invalid, expected) in [
        (
            Some(OodStatus::Unspecified as i32),
            DecisionContractError::UnspecifiedOodStatus,
        ),
        (
            Some(i32::MAX),
            DecisionContractError::UnknownOodStatus(i32::MAX),
        ),
    ] {
        let mut event = complete_event();
        event.decision.as_mut().unwrap().ood_status = invalid;

        match project_decision_event(event, metadata()).unwrap_err() {
            EventProjectionError::InvalidDecision(actual) => assert_eq!(actual, expected),
            other => panic!("unexpected projection error: {other:?}"),
        }
    }
}
