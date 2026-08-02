use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair as _, ParsedPublicKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bioworld_contracts::v2::{
    DecisionCriterion, DecisionCriterionComparator, DecisionEvent, DecisionPredictionInterval,
    DecisionPredictionPosition, DecisionRecord, EvidenceSnapshotRef, OodDetectorRef, OodStatus,
    Recommendation,
};
use bioworld_event_store_contracts::{
    DecisionEventMetadata, DecisionEventVerificationClock, DecisionEventVerificationError,
    DecisionEventVerifier, EventProjectionError, decision_event_signature_message,
    decision_event_signature_value, parse_stored_decision_payload, project_decision_event,
    reconstruct_decision_event, stored_decision_event_signature_message,
};
use chrono::{DateTime, Timelike as _, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};

const TENANT_ID: &str = "tenant-signature-test";
const KEY_ID: &str = "scientific-key-1";
const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn new(now: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now)))
    }

    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }

    fn set_unavailable(&self) {
        self.0.store(u64::MAX, Ordering::SeqCst);
    }
}

impl DecisionEventVerificationClock for TestClock {
    fn unix_timestamp(&self) -> Option<u64> {
        let now = self.0.load(Ordering::SeqCst);
        (now != u64::MAX).then_some(now)
    }
}

fn occurred_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-02T06:30:00.123456Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn evidence(id: &str) -> EvidenceSnapshotRef {
    EvidenceSnapshotRef {
        id: id.to_owned(),
        sha256: VALID_SHA256.to_owned(),
    }
}

fn interval(lower: &str, upper: &str) -> DecisionPredictionInterval {
    DecisionPredictionInterval {
        target: "binding_affinity".to_owned(),
        unit: "nM".to_owned(),
        lower_decimal: lower.to_owned(),
        upper_decimal: upper.to_owned(),
        nominal_coverage_decimal: "0.95".to_owned(),
        interval_method_id: "split_conformal".to_owned(),
        interval_method_version: "1.0".to_owned(),
        calibration_method_id: "held_out".to_owned(),
        calibration_method_version: "2026.08".to_owned(),
        calibration_evidence: Some(evidence("calibration")),
    }
}

#[allow(deprecated)]
fn event() -> DecisionEvent {
    DecisionEvent {
        event_id: "01910d47-6f80-7a31-8c29-1d5c4f6b7012".to_owned(),
        decision: Some(DecisionRecord {
            decision_id: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99".to_owned(),
            cou_id: "COU-SIGNATURE".to_owned(),
            evidence_snapshot_id: "decision-evidence".to_owned(),
            recommendation: Recommendation::Defer as i32,
            rationale: vec!["Recorded fixture rationale.".to_owned()],
            aggregate_version: u64::MAX,
            evidence: Some(evidence("decision-evidence")),
            ood_status: Some(OodStatus::Borderline as i32),
            ood_detector: Some(OodDetectorRef {
                detector_id: "mahalanobis".to_owned(),
                detector_version: "2026.08".to_owned(),
            }),
            prediction_interval: Some(interval("0.25", "1.5")),
            prediction_positions: vec![
                DecisionPredictionPosition {
                    source_id: "model-a".to_owned(),
                    source_version: "2026.08".to_owned(),
                    dependency_group_id: "group-a".to_owned(),
                    interval: Some(interval("0.2", "1.4")),
                    prediction_evidence: Some(evidence("prediction-a")),
                },
                DecisionPredictionPosition {
                    source_id: "model-b".to_owned(),
                    source_version: "2026.08".to_owned(),
                    dependency_group_id: "group-b".to_owned(),
                    interval: Some(interval("0.3", "1.6")),
                    prediction_evidence: Some(evidence("prediction-b")),
                },
            ],
            decision_criterion: Some(DecisionCriterion {
                criterion_id: "potency".to_owned(),
                criterion_version: "2026.08".to_owned(),
                comparator: DecisionCriterionComparator::LessThanOrEqual as i32,
                threshold_decimal: "0.75".to_owned(),
                criterion_evidence: Some(evidence("criterion")),
            }),
        }),
    }
}

fn key_pair() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32]).unwrap()
}

fn snapshot(key_pair: &Ed25519KeyPair, now: u64, status: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "version": "1",
        "valid_until": now + 60,
        "keys": [{
            "tenant_id": TENANT_ID,
            "key_id": KEY_ID,
            "algorithm": "Ed25519",
            "public_key": URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref()),
            "not_before": 1,
            "not_after": 4_102_444_800_u64,
            "status": status
        }]
    }))
    .unwrap()
}

fn snapshot_with_key_window(
    key_pair: &Ed25519KeyPair,
    now: u64,
    not_before: u64,
    not_after: u64,
) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "version": "1",
        "valid_until": now + 60,
        "keys": [{
            "tenant_id": TENANT_ID,
            "key_id": KEY_ID,
            "algorithm": "Ed25519",
            "public_key": URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref()),
            "not_before": not_before,
            "not_after": not_after,
            "status": "trusted"
        }]
    }))
    .unwrap()
}

fn signed_row(key_pair: &Ed25519KeyPair) -> bioworld_event_store_contracts::ScientificEventRow {
    let event = event();
    let message = decision_event_signature_message(
        event.clone(),
        TENANT_ID.to_owned(),
        occurred_at(),
        KEY_ID,
    )
    .unwrap();
    let signature = key_pair.sign(&message);
    let metadata = DecisionEventMetadata::try_new(
        TENANT_ID.to_owned(),
        occurred_at(),
        decision_event_signature_value(KEY_ID, signature.as_ref()).unwrap(),
    )
    .unwrap();
    project_decision_event(event, metadata).unwrap()
}

fn refresh_payload_hash(row: &mut bioworld_event_store_contracts::ScientificEventRow) {
    row.payload_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_jcs::to_vec(&row.payload).unwrap())
    );
}

#[test]
fn verifies_a_tenant_bound_event_and_freezes_the_canonical_message_shape() {
    let now = 1_800_000_000;
    let clock = TestClock::new(now);
    let key_pair = key_pair();
    let row = signed_row(&key_pair);
    let verifier = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "trusted"),
        clock,
    )
    .unwrap();

    assert_eq!(verifier.verify_and_reconstruct(&row).unwrap(), event());
    let message =
        decision_event_signature_message(event(), TENANT_ID.to_owned(), occurred_at(), KEY_ID)
            .unwrap();
    let expected = concat!(
        "bioworld.scientific-event.signature.v1\0",
        r#"{"aggregate_id":"018f5a72-9c4b-7d31-8f6a-26f08f3f4d99","aggregate_type":"bioworld.v2.DecisionRecord","aggregate_version":"18446744073709551615","algorithm":"Ed25519","event_id":"01910d47-6f80-7a31-8c29-1d5c4f6b7012","event_type":"bioworld.v2.DecisionEvent","key_id":"scientific-key-1","occurred_at_unix_micros":"1785652200123456","payload_sha256":"bb50bf7b38895355e82c9e689fb649a941589a87ef38253357c837a664f772e8","schema_version":"2","tenant_id":"tenant-signature-test"}"#,
    );
    assert_eq!(message, expected.as_bytes());
    assert_eq!(
        URL_SAFE_NO_PAD.encode(key_pair.sign(&message).as_ref()),
        "cWOkF01b2pwqOVGEx8_M48Xm3gfrIyf6m_9xWDrmxar7x1LRAnDwqN__ggSLy4Ll12OOEtOj3MqrT8fk3njyCw"
    );
    let (domain, canonical) = message.split_at(b"bioworld.scientific-event.signature.v1\0".len());
    assert_eq!(domain, b"bioworld.scientific-event.signature.v1\0");
    let canonical: serde_json::Value = serde_json::from_slice(canonical).unwrap();
    assert_eq!(canonical.as_object().unwrap().len(), 11);
    assert_eq!(canonical["algorithm"], "Ed25519");
    assert_eq!(canonical["aggregate_version"], u64::MAX.to_string());
    assert_eq!(
        canonical["occurred_at_unix_micros"],
        occurred_at().timestamp_micros().to_string()
    );
    assert_eq!(canonical["tenant_id"], TENANT_ID);
    assert_eq!(canonical["key_id"], KEY_ID);
}

#[test]
fn rejects_payload_tenant_key_and_signature_mutation() {
    let now = 1_800_000_000;
    let key_pair = key_pair();
    let verifier = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "trusted"),
        TestClock::new(now),
    )
    .unwrap();

    let mut payload = signed_row(&key_pair);
    payload.payload["cou_id"] = json!("mutated");
    assert_eq!(
        verifier.verify_and_reconstruct(&payload),
        Err(DecisionEventVerificationError::EventRejected)
    );

    let mut payload_and_hash = signed_row(&key_pair);
    payload_and_hash.payload["cou_id"] = json!("mutated-with-new-hash");
    refresh_payload_hash(&mut payload_and_hash);
    assert_eq!(
        verifier.verify_and_reconstruct(&payload_and_hash),
        Err(DecisionEventVerificationError::EventRejected)
    );

    let mut tenant = signed_row(&key_pair);
    tenant.tenant_id = "other-tenant".to_owned();
    assert_eq!(
        verifier.verify_and_reconstruct(&tenant),
        Err(DecisionEventVerificationError::EventRejected)
    );

    let mut key_id = signed_row(&key_pair);
    key_id
        .signature
        .insert("key_id".to_owned(), json!("other-key"));
    assert_eq!(
        verifier.verify_and_reconstruct(&key_id),
        Err(DecisionEventVerificationError::EventRejected)
    );

    let mut signature = signed_row(&key_pair);
    signature.signature.insert(
        "value".to_owned(),
        json!(URL_SAFE_NO_PAD.encode([0_u8; 64])),
    );
    assert_eq!(
        verifier.verify_and_reconstruct(&signature),
        Err(DecisionEventVerificationError::EventRejected)
    );
}

#[test]
fn rejects_mutation_of_each_stored_message_field() {
    let now = 1_800_000_000;
    let key_pair = key_pair();
    let verifier = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "trusted"),
        TestClock::new(now),
    )
    .unwrap();
    let rejected = |row| {
        assert_eq!(
            verifier.verify_and_reconstruct(&row),
            Err(DecisionEventVerificationError::EventRejected)
        );
    };

    let mut event_id = signed_row(&key_pair);
    event_id.event_id = "01910d47-6f80-7a31-8c29-1d5c4f6b7013".parse().unwrap();
    rejected(event_id);

    let mut event_type = signed_row(&key_pair);
    event_type.event_type = "bioworld.v2.OtherEvent".to_owned();
    rejected(event_type);

    let mut schema_version = signed_row(&key_pair);
    schema_version.schema_version = "3".to_owned();
    rejected(schema_version);

    let mut aggregate_type = signed_row(&key_pair);
    aggregate_type.aggregate_type = "bioworld.v2.OtherRecord".to_owned();
    rejected(aggregate_type);

    let mut aggregate_id = signed_row(&key_pair);
    aggregate_id.aggregate_id = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d98".to_owned();
    aggregate_id.payload["decision_id"] = json!(aggregate_id.aggregate_id.clone());
    refresh_payload_hash(&mut aggregate_id);
    rejected(aggregate_id);

    let mut aggregate_version = signed_row(&key_pair);
    aggregate_version.aggregate_version = u64::MAX - 1;
    aggregate_version.payload["aggregate_version"] =
        json!(aggregate_version.aggregate_version.to_string());
    refresh_payload_hash(&mut aggregate_version);
    rejected(aggregate_version);

    let mut occurred_at = signed_row(&key_pair);
    occurred_at.occurred_at =
        DateTime::from_timestamp_micros(occurred_at.occurred_at.timestamp_micros() + 1).unwrap();
    rejected(occurred_at);

    let mut payload_sha256 = signed_row(&key_pair);
    payload_sha256.payload_sha256 = "0".repeat(64);
    rejected(payload_sha256);
}

#[test]
fn signs_valid_historical_rows_without_reapplying_new_write_policy() {
    let now = 1_800_000_000;
    let key_pair = key_pair();
    let mut row = signed_row(&key_pair);
    let payload = row.payload.as_object_mut().unwrap();
    for field in [
        "ood_status",
        "ood_detector",
        "prediction_interval",
        "prediction_positions",
        "decision_criterion",
    ] {
        payload.remove(field);
    }
    refresh_payload_hash(&mut row);
    row.signature = json!({"placeholder":true}).as_object().unwrap().clone();
    let expected = reconstruct_decision_event(&row).unwrap();
    let message = stored_decision_event_signature_message(&row, KEY_ID).unwrap();
    row.signature = decision_event_signature_value(KEY_ID, key_pair.sign(&message).as_ref())
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    let verifier = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "trusted"),
        TestClock::new(now),
    )
    .unwrap();

    assert_eq!(verifier.verify_and_reconstruct(&row).unwrap(), expected);
}

#[test]
fn distinguishes_expired_trust_from_rejected_events() {
    let now = 1_800_000_000;
    let clock = TestClock::new(now);
    let key_pair = key_pair();
    let verifier = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "trusted"),
        clock.clone(),
    )
    .unwrap();
    let row = signed_row(&key_pair);

    clock.set(now + 60);
    assert_eq!(
        verifier.verify_and_reconstruct(&row),
        Err(DecisionEventVerificationError::TrustUnavailable)
    );

    let clock = TestClock::new(now);
    let unavailable = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "trusted"),
        clock.clone(),
    )
    .unwrap();
    clock.set_unavailable();
    assert_eq!(
        unavailable.verify_and_reconstruct(&row),
        Err(DecisionEventVerificationError::TrustUnavailable)
    );

    let revoked = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "revoked"),
        TestClock::new(now),
    )
    .unwrap();
    assert_eq!(
        revoked.verify_and_reconstruct(&row),
        Err(DecisionEventVerificationError::EventRejected)
    );
}

#[test]
fn rejects_invalid_snapshots_and_noncanonical_envelopes_without_reflection() {
    let now = 1_800_000_000;
    let key_pair = key_pair();
    let public_key = URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref());
    for invalid in [
        json!({"version":"1","valid_until":now + 60,"keys":[]}),
        json!({"version":"2","valid_until":now + 60,"keys":[{
            "tenant_id":TENANT_ID,"key_id":KEY_ID,"algorithm":"Ed25519",
            "public_key":public_key,"not_before":1,"not_after":2,"status":"trusted"
        }]}),
        json!({"version":"1","valid_until":now,"keys":[{
            "tenant_id":TENANT_ID,"key_id":KEY_ID,"algorithm":"Ed25519",
            "public_key":public_key,"not_before":1,"not_after":2,"status":"trusted"
        }]}),
        json!({"version":"1","valid_until":now + 60,"keys":[{
            "tenant_id":TENANT_ID,"key_id":KEY_ID,"algorithm":"Ed25519",
            "public_key":"AA==","not_before":1,"not_after":2,"status":"trusted"
        }]}),
    ] {
        let input = serde_json::to_vec(&invalid).unwrap();
        let error =
            DecisionEventVerifier::try_from_snapshot_with_clock(&input, TestClock::new(now))
                .unwrap_err();
        assert_eq!(format!("{error:?}"), "InvalidDecisionEventVerifier");
        assert_eq!(
            error.to_string(),
            "decision event verification configuration is invalid"
        );
    }

    let mut row = signed_row(&key_pair);
    row.signature.insert("extra".to_owned(), json!("secret"));
    let verifier = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "trusted"),
        TestClock::new(now),
    )
    .unwrap();
    let error = verifier.verify_and_reconstruct(&row).unwrap_err();
    assert_eq!(error, DecisionEventVerificationError::EventRejected);
    assert!(!error.to_string().contains("secret"));
    assert_eq!(format!("{verifier:?}"), "DecisionEventVerifier");
}

#[test]
fn enforces_snapshot_lifetime_key_windows_and_clock_availability() {
    let now = 1_800_000_000;
    let key_pair = key_pair();
    let row = signed_row(&key_pair);
    let event_second = u64::try_from(row.occurred_at.timestamp()).unwrap();

    assert!(
        DecisionEventVerifier::try_from_snapshot_with_clock(
            &snapshot_with_key_window(&key_pair, now, event_second, event_second + 1),
            TestClock::new(now),
        )
        .unwrap()
        .verify_and_reconstruct(&row)
        .is_ok()
    );
    assert_eq!(
        DecisionEventVerifier::try_from_snapshot_with_clock(
            &snapshot_with_key_window(&key_pair, now, 1, event_second),
            TestClock::new(now),
        )
        .unwrap()
        .verify_and_reconstruct(&row),
        Err(DecisionEventVerificationError::EventRejected)
    );
    assert_eq!(
        DecisionEventVerifier::try_from_snapshot_with_clock(
            &snapshot_with_key_window(&key_pair, now, event_second + 1, event_second + 2),
            TestClock::new(now),
        )
        .unwrap()
        .verify_and_reconstruct(&row),
        Err(DecisionEventVerificationError::EventRejected)
    );
    assert_eq!(
        DecisionEventVerifier::try_from_snapshot_with_clock(
            &snapshot_with_key_window(&key_pair, now, 1, event_second - 1),
            TestClock::new(now),
        )
        .unwrap()
        .verify_and_reconstruct(&row),
        Err(DecisionEventVerificationError::EventRejected)
    );

    let public_key = URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref());
    let snapshot_at = |valid_until| {
        serde_json::to_vec(&json!({
            "version": "1",
            "valid_until": valid_until,
            "keys": [{
                "tenant_id": TENANT_ID,
                "key_id": KEY_ID,
                "algorithm": "Ed25519",
                "public_key": public_key,
                "not_before": 1,
                "not_after": event_second + 1,
                "status": "trusted"
            }]
        }))
        .unwrap()
    };
    assert!(
        DecisionEventVerifier::try_from_snapshot_with_clock(
            &snapshot_at(now + 86_400),
            TestClock::new(now),
        )
        .is_ok()
    );
    assert!(
        DecisionEventVerifier::try_from_snapshot_with_clock(
            &snapshot_at(now + 86_401),
            TestClock::new(now),
        )
        .is_err()
    );
    assert!(
        DecisionEventVerifier::try_from_snapshot_with_clock(
            &snapshot_at(now + 60),
            TestClock::new(u64::MAX),
        )
        .is_err()
    );
}

#[test]
fn rejects_noncanonical_signature_encodings_and_envelope_shape() {
    let now = 1_800_000_000;
    let key_pair = key_pair();
    let verifier = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "trusted"),
        TestClock::new(now),
    )
    .unwrap();
    let canonical = signed_row(&key_pair);
    let canonical_value = canonical.signature["value"].as_str().unwrap();
    let variants = [
        json!({"version":"1","algorithm":"Ed25519","key_id":KEY_ID}),
        json!({"version":"2","algorithm":"Ed25519","key_id":KEY_ID,"value":canonical_value}),
        json!({"version":"1","algorithm":"ed25519","key_id":KEY_ID,"value":canonical_value}),
        json!({"version":"1","algorithm":"Ed25519","key_id":"-invalid","value":canonical_value}),
        json!({"version":"1","algorithm":"Ed25519","key_id":KEY_ID,"value":format!("{canonical_value}=")}),
        json!({"version":"1","algorithm":"Ed25519","key_id":KEY_ID,"value":canonical_value.replace('_', "/")}),
        json!({"version":"1","algorithm":"Ed25519","key_id":KEY_ID,"value":URL_SAFE_NO_PAD.encode([0_u8; 63])}),
        json!({"version":"1","algorithm":"Ed25519","key_id":KEY_ID,"value":URL_SAFE_NO_PAD.encode([0_u8; 65])}),
        json!({"version":"1","algorithm":"Ed25519","key_id":KEY_ID,"value":canonical_value,"extra":"rejected"}),
    ];

    for variant in variants {
        let mut row = canonical.clone();
        row.signature = variant.as_object().unwrap().clone();
        assert_eq!(
            verifier.verify_and_reconstruct(&row),
            Err(DecisionEventVerificationError::EventRejected)
        );
    }
}

#[test]
fn rejects_duplicate_key_identities_aliases_and_noncanonical_public_keys() {
    let now = 1_800_000_000;
    let first = key_pair();
    let second = Ed25519KeyPair::from_seed_unchecked(&[8_u8; 32]).unwrap();
    let entry = |tenant_id: &str, key_id: &str, key_pair: &Ed25519KeyPair| {
        json!({
            "tenant_id": tenant_id,
            "key_id": key_id,
            "algorithm": "Ed25519",
            "public_key": URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref()),
            "not_before": 1,
            "not_after": 4_102_444_800_u64,
            "status": "trusted"
        })
    };
    let candidate = |keys| {
        serde_json::to_vec(&json!({
            "version": "1",
            "valid_until": now + 60,
            "keys": keys
        }))
        .unwrap()
    };

    for keys in [
        vec![
            entry(TENANT_ID, KEY_ID, &first),
            entry(TENANT_ID, KEY_ID, &second),
        ],
        vec![
            entry(TENANT_ID, KEY_ID, &first),
            entry(TENANT_ID, "alias", &first),
        ],
        vec![
            entry(TENANT_ID, KEY_ID, &first),
            entry("tenant-other", KEY_ID, &first),
        ],
    ] {
        assert!(
            DecisionEventVerifier::try_from_snapshot_with_clock(
                &candidate(keys),
                TestClock::new(now),
            )
            .is_err()
        );
    }

    for public_key in [
        URL_SAFE_NO_PAD.encode([0_u8; 31]),
        URL_SAFE_NO_PAD.encode([0_u8; 33]),
        format!("{}=", URL_SAFE_NO_PAD.encode(first.public_key().as_ref())),
    ] {
        let invalid = json!({
            "version": "1",
            "valid_until": now + 60,
            "keys": [{
                "tenant_id": TENANT_ID,
                "key_id": KEY_ID,
                "algorithm": "Ed25519",
                "public_key": public_key,
                "not_before": 1,
                "not_after": 2,
                "status": "trusted"
            }]
        });
        assert!(
            DecisionEventVerifier::try_from_snapshot_with_clock(
                &serde_json::to_vec(&invalid).unwrap(),
                TestClock::new(now),
            )
            .is_err()
        );
    }
}

#[test]
fn enforces_snapshot_size_key_count_and_schema_bounds() {
    let now = 1_800_000_000;
    let key_pair = key_pair();
    let mut maximum_bytes = snapshot(&key_pair, now, "trusted");
    maximum_bytes.resize(65_536, b' ');
    assert!(
        DecisionEventVerifier::try_from_snapshot_with_clock(&maximum_bytes, TestClock::new(now),)
            .is_ok()
    );
    maximum_bytes.push(b' ');
    assert!(
        DecisionEventVerifier::try_from_snapshot_with_clock(&maximum_bytes, TestClock::new(now),)
            .is_err()
    );

    let entries = (0_u8..33)
        .map(|index| {
            let key = Ed25519KeyPair::from_seed_unchecked(&[index; 32]).unwrap();
            json!({
                "tenant_id": format!("tenant-{index}"),
                "key_id": KEY_ID,
                "algorithm": "Ed25519",
                "public_key": URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
                "not_before": 1,
                "not_after": 4_102_444_800_u64,
                "status": "trusted"
            })
        })
        .collect::<Vec<_>>();
    let encoded = |keys: &[serde_json::Value]| {
        serde_json::to_vec(&json!({
            "version": "1",
            "valid_until": now + 60,
            "keys": keys
        }))
        .unwrap()
    };
    assert!(
        DecisionEventVerifier::try_from_snapshot_with_clock(
            &encoded(&entries[..32]),
            TestClock::new(now),
        )
        .is_ok()
    );
    assert!(
        DecisionEventVerifier::try_from_snapshot_with_clock(
            &encoded(&entries),
            TestClock::new(now),
        )
        .is_err()
    );

    let public_key = URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref());
    for invalid in [
        json!({
            "version":"1","valid_until":now + 60,"unexpected":true,"keys":[{
                "tenant_id":TENANT_ID,"key_id":KEY_ID,"algorithm":"Ed25519",
                "public_key":public_key,"not_before":1,"not_after":2,"status":"trusted"
            }]
        }),
        json!({
            "version":"1","valid_until":now + 60,"keys":[{
                "tenant_id":TENANT_ID,"key_id":KEY_ID,"algorithm":"Ed25519",
                "public_key":public_key,"not_before":1,"not_after":2,"status":"trusted",
                "unexpected":true
            }]
        }),
        json!({
            "version":"1","valid_until":now + 60,"keys":[{
                "tenant_id":TENANT_ID,"key_id":KEY_ID,"algorithm":"ed25519",
                "public_key":public_key,"not_before":1,"not_after":2,"status":"trusted"
            }]
        }),
        json!({
            "version":"1","valid_until":now + 60,"keys":[{
                "tenant_id":TENANT_ID,"key_id":KEY_ID,"algorithm":"Ed25519",
                "public_key":public_key,"not_before":1,"not_after":2,"status":"active"
            }]
        }),
        json!({
            "version":"1","valid_until":now + 60,"keys":[{
                "tenant_id":TENANT_ID,"key_id":KEY_ID,"algorithm":"Ed25519",
                "public_key":public_key,"not_before":2,"not_after":2,"status":"trusted"
            }]
        }),
    ] {
        assert!(
            DecisionEventVerifier::try_from_snapshot_with_clock(
                &serde_json::to_vec(&invalid).unwrap(),
                TestClock::new(now),
            )
            .is_err()
        );
    }
}

#[test]
fn enforces_key_id_boundaries_and_accepts_canonical_payload_reordering() {
    let valid_key_id = format!("A._-{}", "x".repeat(60));
    let invalid_key_id = format!("A{}", "x".repeat(64));
    assert_eq!(valid_key_id.len(), 64);
    assert_eq!(invalid_key_id.len(), 65);
    assert!(decision_event_signature_value(&valid_key_id, &[0_u8; 64]).is_ok());
    for invalid in [
        invalid_key_id.as_str(),
        "-leading",
        ".leading",
        "white space",
        "é",
    ] {
        assert!(decision_event_signature_value(invalid, &[0_u8; 64]).is_err());
    }

    let now = 1_800_000_000;
    let key_pair = key_pair();
    let verifier = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "trusted"),
        TestClock::new(now),
    )
    .unwrap();
    let mut row = signed_row(&key_pair);
    let object = row.payload.as_object().unwrap();
    let reordered = object
        .iter()
        .rev()
        .map(|(key, value)| {
            format!(
                "{}:{}",
                serde_json::to_string(key).unwrap(),
                serde_json::to_string(value).unwrap()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    row.payload = parse_stored_decision_payload(&format!("{{{reordered}}}")).unwrap();
    assert_eq!(verifier.verify_and_reconstruct(&row).unwrap(), event());
}

#[test]
fn rejects_sub_microsecond_timestamps_before_projection() {
    let timestamp = occurred_at().with_nanosecond(123_456_789).unwrap();
    assert!(matches!(
        DecisionEventMetadata::try_new(
            TENANT_ID.to_owned(),
            timestamp,
            json!({"value":"placeholder"}),
        ),
        Err(EventProjectionError::InvalidOccurredAt)
    ));

    let before_epoch = DateTime::from_timestamp(-1, 0).unwrap();
    assert!(matches!(
        DecisionEventMetadata::try_new(
            TENANT_ID.to_owned(),
            before_epoch,
            json!({"value":"placeholder"}),
        ),
        Err(EventProjectionError::InvalidOccurredAt)
    ));

    let now = 1_800_000_000;
    let key_pair = key_pair();
    let verifier = DecisionEventVerifier::try_from_snapshot_with_clock(
        &snapshot(&key_pair, now, "trusted"),
        TestClock::new(now),
    )
    .unwrap();
    let mut row = signed_row(&key_pair);
    row.occurred_at = before_epoch;
    assert_eq!(
        verifier.verify_and_reconstruct(&row),
        Err(DecisionEventVerificationError::EventRejected)
    );
}

#[test]
fn aws_lc_matches_the_rfc_8032_single_byte_vector() {
    let public_key = decode_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    let signature = decode_hex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );
    ParsedPublicKey::new(&ED25519, public_key)
        .unwrap()
        .verify_sig(&[0x72], &signature)
        .unwrap();
}

fn decode_hex(input: &str) -> Vec<u8> {
    let input: String = input
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect();
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}
