use bioworld_domain::{
    DecisionPredictionInterval, DecisionRecord, DomainError, EvidenceSnapshotRef,
    MAX_DECISION_IDENTIFIER_BYTES, MAX_DECISION_IDENTIFIER_CHARS,
    MAX_DECISION_RATIONALE_ITEM_BYTES, MAX_DECISION_RATIONALE_ITEMS,
    MAX_DECISION_RATIONALE_TOTAL_BYTES, MAX_OOD_DETECTOR_ID_BYTES, MAX_OOD_DETECTOR_VERSION_BYTES,
    MAX_PREDICTION_INTERVAL_DECIMAL_BYTES, MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES,
    OodDetectorRef, OodStatus, Recommendation,
};
use uuid::Uuid;

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn calibration_evidence() -> EvidenceSnapshotRef {
    EvidenceSnapshotRef::try_new("ES-CAL-001".to_owned(), VALID_SHA256.to_owned()).unwrap()
}

fn prediction_interval_values() -> [String; 9] {
    [
        "binding_affinity".to_owned(),
        "nM".to_owned(),
        "0.25".to_owned(),
        "1.5".to_owned(),
        "0.95".to_owned(),
        "split_conformal".to_owned(),
        "1.0".to_owned(),
        "held_out_calibration".to_owned(),
        "2026.07".to_owned(),
    ]
}

fn try_prediction_interval(values: [String; 9]) -> Result<DecisionPredictionInterval, DomainError> {
    let [
        target,
        unit,
        lower_decimal,
        upper_decimal,
        nominal_coverage_decimal,
        interval_method_id,
        interval_method_version,
        calibration_method_id,
        calibration_method_version,
    ] = values;
    DecisionPredictionInterval::try_new(
        target,
        unit,
        lower_decimal,
        upper_decimal,
        nominal_coverage_decimal,
        interval_method_id,
        interval_method_version,
        calibration_method_id,
        calibration_method_version,
        calibration_evidence(),
    )
}

#[test]
fn constructs_canonical_decision_prediction_interval() {
    let evidence = calibration_evidence();
    let interval = DecisionPredictionInterval::try_new(
        "binding_affinity".to_owned(),
        "nM".to_owned(),
        "0.25".to_owned(),
        "1.5".to_owned(),
        "0.95".to_owned(),
        "split_conformal".to_owned(),
        "1.0".to_owned(),
        "held_out_calibration".to_owned(),
        "2026.07".to_owned(),
        evidence.clone(),
    )
    .unwrap();

    assert_eq!(interval.target(), "binding_affinity");
    assert_eq!(interval.unit(), "nM");
    assert_eq!(interval.lower_decimal(), "0.25");
    assert_eq!(interval.upper_decimal(), "1.5");
    assert_eq!(interval.nominal_coverage_decimal(), "0.95");
    assert_eq!(interval.interval_method_id(), "split_conformal");
    assert_eq!(interval.interval_method_version(), "1.0");
    assert_eq!(interval.calibration_method_id(), "held_out_calibration");
    assert_eq!(interval.calibration_method_version(), "2026.07");
    assert_eq!(interval.calibration_evidence(), &evidence);
}

#[test]
fn validates_prediction_interval_identifiers_with_exact_byte_budgets() {
    let fields: [(usize, fn() -> DomainError); 6] = [
        (0, || DomainError::InvalidPredictionIntervalTarget),
        (1, || DomainError::InvalidPredictionIntervalUnit),
        (5, || DomainError::InvalidPredictionIntervalMethodId),
        (6, || DomainError::InvalidPredictionIntervalMethodVersion),
        (7, || {
            DomainError::InvalidPredictionIntervalCalibrationMethodId
        }),
        (8, || {
            DomainError::InvalidPredictionIntervalCalibrationMethodVersion
        }),
    ];
    let exact = "\u{10000}".repeat(MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES / 4);
    assert_eq!(exact.len(), MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES);

    for (index, expected_error) in fields {
        let mut values = prediction_interval_values();
        values[index] = exact.clone();
        assert!(try_prediction_interval(values).is_ok());

        for invalid in [
            String::new(),
            " leading".to_owned(),
            "trailing ".to_owned(),
            "embedded\0nul".to_owned(),
            format!("{exact}x"),
        ] {
            let mut values = prediction_interval_values();
            values[index] = invalid;
            assert_eq!(
                try_prediction_interval(values),
                Err(expected_error()),
                "identifier field index {index}",
            );
        }
    }
}

#[test]
fn validates_canonical_prediction_interval_bound_decimals() {
    let invalid_decimals = [
        "", " ", "+1", "-", "-0", "00", "01", "-01", ".5", "-.5", "1.", "1.0", "1.20", "0.0",
        "00.1", "-00.1", "1.a", "1e3", "1E3", "NaN", "inf", "Infinity", "1..2", " 1", "1 ", "１",
    ];

    for (index, expected_error) in [
        (2, DomainError::InvalidPredictionIntervalLowerDecimal),
        (3, DomainError::InvalidPredictionIntervalUpperDecimal),
    ] {
        for invalid in invalid_decimals {
            let mut values = prediction_interval_values();
            values[index] = invalid.to_owned();
            assert_eq!(
                try_prediction_interval(values),
                Err(match index {
                    2 => DomainError::InvalidPredictionIntervalLowerDecimal,
                    _ => DomainError::InvalidPredictionIntervalUpperDecimal,
                }),
                "decimal field index {index}: {invalid:?}",
            );
        }

        let mut values = prediction_interval_values();
        values[index] = match index {
            2 => format!("-{}", "1".repeat(MAX_PREDICTION_INTERVAL_DECIMAL_BYTES - 1)),
            _ => "1".repeat(MAX_PREDICTION_INTERVAL_DECIMAL_BYTES),
        };
        assert!(try_prediction_interval(values).is_ok());

        let mut values = prediction_interval_values();
        values[index] = match index {
            2 => format!("-{}", "1".repeat(MAX_PREDICTION_INTERVAL_DECIMAL_BYTES)),
            _ => "1".repeat(MAX_PREDICTION_INTERVAL_DECIMAL_BYTES + 1),
        };
        assert_eq!(try_prediction_interval(values), Err(expected_error));
    }

    for valid in ["0", "-12", "12", "-0.25", "0.25", "10.01", "1.5"] {
        let mut values = prediction_interval_values();
        values[2] = valid.to_owned();
        values[3] = valid.to_owned();
        assert!(try_prediction_interval(values).is_ok(), "{valid:?}");
    }
}

#[test]
fn orders_prediction_interval_bounds_with_exact_decimal_comparison() {
    for (lower, upper) in [
        ("-100", "-2"),
        ("-2.01", "-2"),
        ("-2.001", "-2.0001"),
        ("-0.25", "0"),
        ("0.001", "0.01"),
        ("1.2", "1.21"),
        ("9.999", "10"),
        ("0", "0"),
        ("-42.125", "-42.125"),
        (
            "111111111111111111111111111111111111111111111111111111111111111",
            "9999999999999999999999999999999999999999999999999999999999999999",
        ),
    ] {
        let mut values = prediction_interval_values();
        values[2] = lower.to_owned();
        values[3] = upper.to_owned();
        assert!(
            try_prediction_interval(values).is_ok(),
            "expected {lower} <= {upper}",
        );
    }

    for (lower, upper) in [
        ("2", "1"),
        ("-2", "-100"),
        ("-2.0001", "-2.001"),
        ("0.01", "0.001"),
        ("1.21", "1.2"),
        ("10", "9.999"),
        ("0", "-0.1"),
        (
            "9999999999999999999999999999999999999999999999999999999999999999",
            "111111111111111111111111111111111111111111111111111111111111111",
        ),
    ] {
        let mut values = prediction_interval_values();
        values[2] = lower.to_owned();
        values[3] = upper.to_owned();
        assert_eq!(
            try_prediction_interval(values),
            Err(DomainError::InvalidPredictionIntervalBounds),
            "expected {lower} > {upper}",
        );
    }
}

#[test]
fn constructs_decision_with_prediction_interval() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let detector =
        OodDetectorRef::try_new("mahalanobis".to_owned(), "model-2026.07".to_owned()).unwrap();
    let interval = try_prediction_interval(prediction_interval_values()).unwrap();
    let record = DecisionRecord::try_new_with_prediction_interval(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Borderline,
        Some(detector.clone()),
        Some(interval.clone()),
        evidence,
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();

    assert_eq!(record.ood_detector(), Some(&detector));
    assert_eq!(record.prediction_interval(), Some(&interval));
}

#[test]
fn validates_strict_canonical_prediction_interval_coverage() {
    for valid in [
        "0.1".to_owned(),
        "0.999".to_owned(),
        format!(
            "0.{}1",
            "0".repeat(MAX_PREDICTION_INTERVAL_DECIMAL_BYTES - 3)
        ),
    ] {
        assert!(valid.len() <= 64);
        let mut values = prediction_interval_values();
        values[4] = valid;
        assert!(try_prediction_interval(values).is_ok());
    }

    for invalid in [
        "".to_owned(),
        "0".to_owned(),
        "1".to_owned(),
        "-0.1".to_owned(),
        "1.1".to_owned(),
        "+0.5".to_owned(),
        "0.50".to_owned(),
        "5e-1".to_owned(),
        format!(
            "0.{}1",
            "0".repeat(MAX_PREDICTION_INTERVAL_DECIMAL_BYTES - 2)
        ),
    ] {
        let mut values = prediction_interval_values();
        values[4] = invalid;
        assert_eq!(
            try_prediction_interval(values),
            Err(DomainError::InvalidPredictionIntervalNominalCoverageDecimal),
        );
    }
}

#[test]
fn prediction_interval_errors_have_fixed_text() {
    for (error, expected) in [
        (
            DomainError::InvalidPredictionIntervalTarget,
            "prediction interval target is invalid",
        ),
        (
            DomainError::InvalidPredictionIntervalUnit,
            "prediction interval unit is invalid",
        ),
        (
            DomainError::InvalidPredictionIntervalMethodId,
            "prediction interval method identifier is invalid",
        ),
        (
            DomainError::InvalidPredictionIntervalMethodVersion,
            "prediction interval method version is invalid",
        ),
        (
            DomainError::InvalidPredictionIntervalCalibrationMethodId,
            "prediction interval calibration method identifier is invalid",
        ),
        (
            DomainError::InvalidPredictionIntervalCalibrationMethodVersion,
            "prediction interval calibration method version is invalid",
        ),
        (
            DomainError::InvalidPredictionIntervalLowerDecimal,
            "prediction interval lower bound is invalid",
        ),
        (
            DomainError::InvalidPredictionIntervalUpperDecimal,
            "prediction interval upper bound is invalid",
        ),
        (
            DomainError::InvalidPredictionIntervalBounds,
            "prediction interval lower bound exceeds upper bound",
        ),
        (
            DomainError::InvalidPredictionIntervalNominalCoverageDecimal,
            "prediction interval nominal coverage is invalid",
        ),
    ] {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn prediction_interval_json_enforces_domain_invariants() {
    let invalid = serde_json::json!({
        "target": "binding_affinity",
        "unit": "nM",
        "lower_decimal": "01",
        "upper_decimal": "1.5",
        "nominal_coverage_decimal": "0.95",
        "interval_method_id": "split_conformal",
        "interval_method_version": "1.0",
        "calibration_method_id": "held_out_calibration",
        "calibration_method_version": "2026.07",
        "calibration_evidence": {
            "id": "ES-CAL-001",
            "sha256": VALID_SHA256
        }
    });

    let error = serde_json::from_value::<DecisionPredictionInterval>(invalid).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("prediction interval lower bound is invalid")
    );
}

#[test]
fn decision_json_round_trip_preserves_prediction_interval() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let interval = try_prediction_interval(prediction_interval_values()).unwrap();
    let record = DecisionRecord::try_new_with_prediction_interval(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        None,
        Some(interval.clone()),
        evidence,
        vec!["Prediction interval metadata is available.".to_owned()],
    )
    .unwrap();

    let serialized = serde_json::to_value(&record).unwrap();
    let deserialized: DecisionRecord = serde_json::from_value(serialized.clone()).unwrap();

    assert_eq!(serialized["prediction_interval"]["lower_decimal"], "0.25");
    assert_eq!(deserialized.prediction_interval(), Some(&interval));
    assert_eq!(deserialized, record);
}

#[test]
fn constructs_canonical_ood_detector_reference() {
    let detector =
        OodDetectorRef::try_new("mahalanobis".to_owned(), "model-2026.07".to_owned()).unwrap();

    assert_eq!(detector.detector_id(), "mahalanobis");
    assert_eq!(detector.detector_version(), "model-2026.07");
}

#[test]
fn validates_ood_detector_id_with_an_exact_byte_budget() {
    let exact = OodDetectorRef::try_new(
        "d".repeat(MAX_OOD_DETECTOR_ID_BYTES),
        "model-2026.07".to_owned(),
    );

    assert!(exact.is_ok());
    for detector_id in [
        String::new(),
        " detector".to_owned(),
        "detector ".to_owned(),
        "detector\0id".to_owned(),
        "d".repeat(MAX_OOD_DETECTOR_ID_BYTES + 1),
    ] {
        assert_eq!(
            OodDetectorRef::try_new(detector_id, "model-2026.07".to_owned()),
            Err(DomainError::InvalidOodDetectorId),
        );
    }
}

#[test]
fn validates_ood_detector_version_with_an_exact_byte_budget() {
    let exact = OodDetectorRef::try_new(
        "mahalanobis".to_owned(),
        "v".repeat(MAX_OOD_DETECTOR_VERSION_BYTES),
    );

    assert!(exact.is_ok());
    for detector_version in [
        String::new(),
        " version".to_owned(),
        "version ".to_owned(),
        "version\0build".to_owned(),
        "v".repeat(MAX_OOD_DETECTOR_VERSION_BYTES + 1),
    ] {
        assert_eq!(
            OodDetectorRef::try_new("mahalanobis".to_owned(), detector_version),
            Err(DomainError::InvalidOodDetectorVersion),
        );
    }
}

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
    assert_eq!(record.prediction_interval(), None);
}

#[test]
fn constructs_decision_with_qualified_ood_detector_reference() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let detector =
        OodDetectorRef::try_new("mahalanobis".to_owned(), "model-2026.07".to_owned()).unwrap();
    let record = DecisionRecord::try_new_with_ood_detector(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Borderline,
        Some(detector.clone()),
        evidence,
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();

    assert_eq!(record.ood_detector(), Some(&detector));
    assert_eq!(record.prediction_interval(), None);
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
    assert_eq!(record.ood_detector(), None);
    assert_eq!(record.prediction_interval(), None);
    assert!(current.get("ood_detector").is_none());
    assert!(current.get("prediction_interval").is_none());
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
    let detector =
        OodDetectorRef::try_new("mahalanobis".to_owned(), "model-2026.07".to_owned()).unwrap();
    let record = DecisionRecord::try_new_with_ood_detector(
        decision_id,
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Borderline,
        Some(detector),
        evidence,
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();
    let expected = serde_json::json!({
        "id": "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        "cou_id": "COU-001",
        "recommendation": "abstain",
        "ood_status": "borderline",
        "ood_detector": {
            "detector_id": "mahalanobis",
            "detector_version": "model-2026.07"
        },
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
