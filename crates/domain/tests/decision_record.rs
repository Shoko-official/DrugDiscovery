use bioworld_domain::{DecisionRecord, EvidenceSnapshotRef, Recommendation};
use uuid::Uuid;

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn constructs_valid_decision_record() {
    let decision_id = Uuid::now_v7();
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let record = DecisionRecord::try_new(
        decision_id,
        "COU-001".to_owned(),
        Recommendation::Abstain,
        evidence.clone(),
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();

    assert_eq!(record.id(), decision_id);
    assert_eq!(record.cou_id(), "COU-001");
    assert_eq!(record.recommendation(), &Recommendation::Abstain);
    assert_eq!(record.evidence(), &evidence);
    assert_eq!(record.rationale(), ["Evidence coverage is incomplete."]);
    assert_eq!(record.validate(), Ok(()));
}

#[test]
fn rejects_invalid_evidence_digests() {
    let invalid_digests = [
        "a".repeat(63),
        "a".repeat(65),
        format!("{}A", "a".repeat(63)),
        format!("{}g", "a".repeat(63)),
    ];

    for digest in invalid_digests {
        assert_eq!(
            EvidenceSnapshotRef::try_new("ES-001".to_owned(), digest),
            Err(bioworld_domain::DomainError::InvalidEvidenceDigest),
        );
    }
}

#[test]
fn rejects_decision_without_rationale() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();

    assert_eq!(
        DecisionRecord::try_new(
            Uuid::now_v7(),
            "COU-001".to_owned(),
            Recommendation::Abstain,
            evidence,
            Vec::new(),
        ),
        Err(bioworld_domain::DomainError::MissingRationale),
    );
}

#[test]
fn rejects_decision_json_with_invalid_evidence_digest() {
    let json = serde_json::json!({
        "id": Uuid::now_v7(),
        "cou_id": "COU-001",
        "recommendation": "abstain",
        "evidence": {
            "id": "ES-001",
            "sha256": "invalid"
        },
        "rationale": ["Evidence coverage is incomplete."]
    });

    let error = serde_json::from_value::<DecisionRecord>(json).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("evidence digest must be a lowercase sha256")
    );
}

#[test]
fn rejects_decision_json_without_rationale() {
    let json = serde_json::json!({
        "id": Uuid::now_v7(),
        "cou_id": "COU-001",
        "recommendation": "abstain",
        "evidence": {
            "id": "ES-001",
            "sha256": VALID_SHA256
        },
        "rationale": []
    });

    let error = serde_json::from_value::<DecisionRecord>(json).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("a qualified decision requires at least one rationale")
    );
}

#[test]
fn decision_json_round_trip_preserves_wire_shape() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let record = DecisionRecord::try_new(
        decision_id,
        "COU-001".to_owned(),
        Recommendation::Abstain,
        evidence,
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();
    let expected = serde_json::json!({
        "id": "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        "cou_id": "COU-001",
        "recommendation": "abstain",
        "evidence": {
            "id": "ES-001",
            "sha256": VALID_SHA256
        },
        "rationale": ["Evidence coverage is incomplete."]
    });

    let serialized = serde_json::to_value(&record).unwrap();
    let deserialized: DecisionRecord = serde_json::from_value(serialized.clone()).unwrap();

    assert_eq!(serialized, expected);
    assert_eq!(deserialized, record);
}
