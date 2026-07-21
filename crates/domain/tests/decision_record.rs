use bioworld_domain::{
    DecisionRecord, DomainError, EvidenceSnapshotRef, MAX_DECISION_IDENTIFIER_BYTES,
    MAX_DECISION_IDENTIFIER_CHARS, MAX_DECISION_RATIONALE_ITEM_BYTES, MAX_DECISION_RATIONALE_ITEMS,
    MAX_DECISION_RATIONALE_TOTAL_BYTES, OodStatus, Recommendation,
};
use uuid::Uuid;

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn constructs_decision_with_explicit_ood_status() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let record = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Borderline,
        evidence,
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();

    assert_eq!(record.ood_status(), &OodStatus::Borderline);
}

#[test]
fn historical_decision_json_without_ood_status_maps_to_unknown() {
    let historical = serde_json::json!({
        "id": Uuid::now_v7(),
        "cou_id": "COU-001",
        "recommendation": "abstain",
        "evidence": {
            "id": "ES-001",
            "sha256": VALID_SHA256
        },
        "rationale": ["Evidence coverage is incomplete."]
    });

    let record: DecisionRecord = serde_json::from_value(historical).unwrap();
    let current = serde_json::to_value(&record).unwrap();

    assert_eq!(record.ood_status(), &OodStatus::Unknown);
    assert_eq!(current["ood_status"], "unknown");
}

#[test]
fn bounds_cou_identifiers() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let exact_id = "\u{10000}".repeat(MAX_DECISION_IDENTIFIER_CHARS);

    let exact = DecisionRecord::try_new(
        Uuid::now_v7(),
        exact_id.clone(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence.clone(),
        vec!["Bounded rationale.".to_owned()],
    );
    let oversized = DecisionRecord::try_new(
        Uuid::now_v7(),
        format!("{exact_id}x"),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence,
        vec!["Bounded rationale.".to_owned()],
    );

    assert_eq!(exact_id.len(), MAX_DECISION_IDENTIFIER_BYTES);
    assert!(exact.is_ok());
    assert_eq!(oversized, Err(DomainError::InvalidCouId));
}

#[test]
fn rejects_identifier_character_count_plus_one() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();

    let exact = DecisionRecord::try_new(
        Uuid::now_v7(),
        "c".repeat(MAX_DECISION_IDENTIFIER_CHARS),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence.clone(),
        vec!["Bounded rationale.".to_owned()],
    );
    let oversized = DecisionRecord::try_new(
        Uuid::now_v7(),
        "c".repeat(MAX_DECISION_IDENTIFIER_CHARS + 1),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence,
        vec!["Bounded rationale.".to_owned()],
    );

    assert!(exact.is_ok());
    assert_eq!(oversized, Err(DomainError::InvalidCouId));
}

#[test]
fn bounds_evidence_identifiers_in_bytes() {
    let exact_id = "\u{10000}".repeat(MAX_DECISION_IDENTIFIER_CHARS);
    let exact = EvidenceSnapshotRef::try_new(exact_id.clone(), VALID_SHA256.to_owned());
    let oversized = EvidenceSnapshotRef::try_new(format!("{exact_id}x"), VALID_SHA256.to_owned());

    assert_eq!(exact_id.len(), MAX_DECISION_IDENTIFIER_BYTES);
    assert!(exact.is_ok());
    assert_eq!(oversized, Err(DomainError::InvalidEvidenceId));
}

#[test]
fn rejects_noncanonical_decision_identifiers() {
    for identifier in ["", " ", " leading", "trailing ", "nul\0byte"] {
        let evidence =
            EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
        assert_eq!(
            DecisionRecord::try_new(
                Uuid::now_v7(),
                identifier.to_owned(),
                Recommendation::Abstain,
                OodStatus::Unknown,
                evidence,
                vec!["Bounded rationale.".to_owned()],
            ),
            Err(DomainError::InvalidCouId),
        );
        assert_eq!(
            EvidenceSnapshotRef::try_new(identifier.to_owned(), VALID_SHA256.to_owned()),
            Err(DomainError::InvalidEvidenceId),
        );
    }
}

#[test]
fn bounds_rationale_item_count() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let rationale = vec!["r".to_owned(); MAX_DECISION_RATIONALE_ITEMS];

    let exact = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence.clone(),
        rationale.clone(),
    );
    let oversized = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence,
        [rationale, vec!["r".to_owned()]].concat(),
    );

    assert!(exact.is_ok());
    assert_eq!(oversized, Err(DomainError::TooManyRationales));
}

#[test]
fn bounds_each_rationale_in_bytes() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();

    let exact = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence.clone(),
        vec!["r".repeat(MAX_DECISION_RATIONALE_ITEM_BYTES)],
    );
    let oversized = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence,
        vec!["r".repeat(MAX_DECISION_RATIONALE_ITEM_BYTES + 1)],
    );

    assert!(exact.is_ok());
    assert_eq!(oversized, Err(DomainError::RationaleTooLarge));
}

#[test]
fn rejects_nul_in_rationales() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();

    let result = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence,
        vec!["invalid\0rationale".to_owned()],
    );

    assert_eq!(result, Err(DomainError::InvalidRationale));
}

#[test]
fn bounds_total_rationale_bytes() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let item_count = MAX_DECISION_RATIONALE_TOTAL_BYTES / MAX_DECISION_RATIONALE_ITEM_BYTES;
    let rationale = vec!["r".repeat(MAX_DECISION_RATIONALE_ITEM_BYTES); item_count];

    let exact = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence.clone(),
        rationale.clone(),
    );
    let oversized = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence,
        [rationale, vec!["r".to_owned()]].concat(),
    );

    assert!(exact.is_ok());
    assert_eq!(oversized, Err(DomainError::RationaleBudgetExceeded));
}

#[test]
fn counts_blank_rationales_without_normalizing_them() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let mut rationale = vec![" ".repeat(MAX_DECISION_RATIONALE_ITEM_BYTES); 8];
    rationale[0] = "r".repeat(MAX_DECISION_RATIONALE_ITEM_BYTES);

    let exact = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence.clone(),
        rationale.clone(),
    )
    .unwrap();
    let oversized = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence,
        [rationale.clone(), vec![" ".to_owned()]].concat(),
    );

    assert_eq!(exact.rationale(), rationale);
    assert_eq!(oversized, Err(DomainError::RationaleBudgetExceeded));
}

#[test]
fn constructs_valid_decision_record() {
    let decision_id = Uuid::now_v7();
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let record = DecisionRecord::try_new(
        decision_id,
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence.clone(),
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();

    assert_eq!(record.id(), decision_id);
    assert_eq!(record.cou_id(), "COU-001");
    assert_eq!(record.recommendation(), &Recommendation::Abstain);
    assert_eq!(record.ood_status(), &OodStatus::Unknown);
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
            OodStatus::Unknown,
            evidence,
            Vec::new(),
        ),
        Err(bioworld_domain::DomainError::MissingRationale),
    );
}

#[test]
fn rejects_decision_with_only_blank_rationale() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();

    assert_eq!(
        DecisionRecord::try_new(
            Uuid::now_v7(),
            "COU-001".to_owned(),
            Recommendation::Abstain,
            OodStatus::Unknown,
            evidence,
            vec!["  ".to_owned(), "\t".to_owned()],
        ),
        Err(bioworld_domain::DomainError::MissingRationale),
    );
}

#[test]
fn accepts_decision_with_at_least_one_nonblank_rationale() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();

    let decision = DecisionRecord::try_new(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        evidence,
        vec!["  ".to_owned(), "Evidence is incomplete.".to_owned()],
    );

    assert!(decision.is_ok());
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
fn decision_json_enforces_size_bounds() {
    let json = serde_json::json!({
        "id": Uuid::now_v7(),
        "cou_id": "c".repeat(MAX_DECISION_IDENTIFIER_CHARS + 1),
        "recommendation": "abstain",
        "evidence": {
            "id": "ES-001",
            "sha256": VALID_SHA256
        },
        "rationale": ["Evidence coverage is incomplete."]
    });

    let error = serde_json::from_value::<DecisionRecord>(json).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("context of use identifier is invalid")
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
        OodStatus::Borderline,
        evidence,
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();
    let expected = serde_json::json!({
        "id": "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        "cou_id": "COU-001",
        "recommendation": "abstain",
        "ood_status": "borderline",
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
