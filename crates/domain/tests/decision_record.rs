use bioworld_domain::{
    DecisionCriterion, DecisionCriterionComparator, DecisionPredictionInterval,
    DecisionPredictionPosition, DecisionRecord, DomainError, EvidenceSnapshotRef,
    MAX_DECISION_CRITERION_DECIMAL_BYTES, MAX_DECISION_CRITERION_IDENTIFIER_BYTES,
    MAX_DECISION_IDENTIFIER_BYTES, MAX_DECISION_IDENTIFIER_CHARS,
    MAX_DECISION_RATIONALE_ITEM_BYTES, MAX_DECISION_RATIONALE_ITEMS,
    MAX_DECISION_RATIONALE_TOTAL_BYTES, MAX_OOD_DETECTOR_ID_BYTES, MAX_OOD_DETECTOR_VERSION_BYTES,
    MAX_PREDICTION_INTERVAL_DECIMAL_BYTES, MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES,
    MAX_PREDICTION_POSITION_IDENTIFIER_BYTES, OodDetectorRef, OodStatus, Recommendation,
};
use uuid::Uuid;

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn calibration_evidence() -> EvidenceSnapshotRef {
    EvidenceSnapshotRef::try_new("ES-CAL-001".to_owned(), VALID_SHA256.to_owned()).unwrap()
}

fn decision_criterion() -> DecisionCriterion {
    DecisionCriterion::try_new(
        "potency_policy".to_owned(),
        "2026.07".to_owned(),
        DecisionCriterionComparator::LessThanOrEqual,
        "0.75".to_owned(),
        EvidenceSnapshotRef::try_new("ES-CRITERION-001".to_owned(), VALID_SHA256.to_owned())
            .unwrap(),
    )
    .unwrap()
}

fn try_decision_criterion(
    criterion_id: String,
    criterion_version: String,
    threshold_decimal: String,
) -> Result<DecisionCriterion, DomainError> {
    DecisionCriterion::try_new(
        criterion_id,
        criterion_version,
        DecisionCriterionComparator::LessThanOrEqual,
        threshold_decimal,
        EvidenceSnapshotRef::try_new("ES-CRITERION-001".to_owned(), VALID_SHA256.to_owned())
            .unwrap(),
    )
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

fn prediction_position(
    source_id: &str,
    source_version: &str,
    dependency_group_id: &str,
    lower_decimal: &str,
    upper_decimal: &str,
    evidence_id: &str,
) -> DecisionPredictionPosition {
    let mut values = prediction_interval_values();
    values[2] = lower_decimal.to_owned();
    values[3] = upper_decimal.to_owned();

    DecisionPredictionPosition::try_new(
        source_id.to_owned(),
        source_version.to_owned(),
        dependency_group_id.to_owned(),
        try_prediction_interval(values).unwrap(),
        EvidenceSnapshotRef::try_new(evidence_id.to_owned(), VALID_SHA256.to_owned()).unwrap(),
    )
    .unwrap()
}

fn try_prediction_position_identifiers(
    identifiers: [String; 3],
) -> Result<DecisionPredictionPosition, DomainError> {
    let [source_id, source_version, dependency_group_id] = identifiers;

    DecisionPredictionPosition::try_new(
        source_id,
        source_version,
        dependency_group_id,
        try_prediction_interval(prediction_interval_values()).unwrap(),
        EvidenceSnapshotRef::try_new("ES-PRED-001".to_owned(), VALID_SHA256.to_owned()).unwrap(),
    )
}

fn try_decision_with_prediction_positions(
    positions: Vec<DecisionPredictionPosition>,
) -> Result<DecisionRecord, DomainError> {
    DecisionRecord::try_new_with_prediction_positions(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Borderline,
        Some(
            OodDetectorRef::try_new("mahalanobis".to_owned(), "model-2026.07".to_owned()).unwrap(),
        ),
        Some(try_prediction_interval(prediction_interval_values()).unwrap()),
        positions,
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap(),
        vec!["Evidence coverage is incomplete.".to_owned()],
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
fn constructs_decision_with_prediction_positions_in_recorded_order() {
    let evidence =
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap();
    let detector =
        OodDetectorRef::try_new("mahalanobis".to_owned(), "model-2026.07".to_owned()).unwrap();
    let interval = try_prediction_interval(prediction_interval_values()).unwrap();
    let positions = vec![
        prediction_position(
            "model-z",
            "2026.07",
            "shared-training-set",
            "0.4",
            "1.4",
            "ES-PRED-Z",
        ),
        prediction_position(
            "model-a",
            "2026.06",
            "independent-assay",
            "0.2",
            "1.2",
            "ES-PRED-A",
        ),
    ];
    let record = DecisionRecord::try_new_with_prediction_positions(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Borderline,
        Some(detector),
        Some(interval),
        positions.clone(),
        evidence,
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();

    assert_eq!(record.prediction_positions(), positions);
}

#[test]
fn constructs_decision_with_exact_recorded_criterion() {
    let interval = try_prediction_interval(prediction_interval_values()).unwrap();
    let criterion = decision_criterion();
    let record = DecisionRecord::try_new_with_decision_criterion(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Borderline,
        Some(
            OodDetectorRef::try_new("mahalanobis".to_owned(), "model-2026.07".to_owned()).unwrap(),
        ),
        Some(interval),
        Vec::new(),
        Some(criterion.clone()),
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap(),
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();

    assert_eq!(record.decision_criterion(), Some(&criterion));
    assert_eq!(criterion.criterion_id(), "potency_policy");
    assert_eq!(criterion.criterion_version(), "2026.07");
    assert_eq!(
        criterion.comparator(),
        &DecisionCriterionComparator::LessThanOrEqual
    );
    assert_eq!(criterion.threshold_decimal(), "0.75");
    assert_eq!(criterion.criterion_evidence().id(), "ES-CRITERION-001");
}

#[test]
fn validates_decision_criterion_identifiers_with_exact_byte_budgets() {
    let exact = "\u{10000}".repeat(MAX_DECISION_CRITERION_IDENTIFIER_BYTES / 4);
    assert_eq!(exact.len(), MAX_DECISION_CRITERION_IDENTIFIER_BYTES);

    for (field_index, expected) in [
        (0, DomainError::InvalidDecisionCriterionId),
        (1, DomainError::InvalidDecisionCriterionVersion),
    ] {
        let mut values = ["potency_policy".to_owned(), "2026.07".to_owned()];
        values[field_index] = exact.clone();
        assert!(
            try_decision_criterion(values[0].clone(), values[1].clone(), "0.75".to_owned()).is_ok()
        );

        for invalid in [
            String::new(),
            " ".to_owned(),
            " leading".to_owned(),
            "trailing ".to_owned(),
            "embedded\0nul".to_owned(),
            format!("{exact}x"),
        ] {
            let mut values = ["potency_policy".to_owned(), "2026.07".to_owned()];
            values[field_index] = invalid;
            assert_eq!(
                try_decision_criterion(values[0].clone(), values[1].clone(), "0.75".to_owned()),
                Err(match field_index {
                    0 => DomainError::InvalidDecisionCriterionId,
                    _ => DomainError::InvalidDecisionCriterionVersion,
                })
            );
        }

        assert_eq!(
            expected,
            match field_index {
                0 => DomainError::InvalidDecisionCriterionId,
                _ => DomainError::InvalidDecisionCriterionVersion,
            }
        );
    }
}

#[test]
fn decision_criterion_identifiers_use_unicode_whitespace_boundaries() {
    let format_character = "\u{feff}";
    let criterion = DecisionCriterion::try_new(
        format!("{format_character}potency_policy{format_character}"),
        format!("{format_character}2026.07{format_character}"),
        DecisionCriterionComparator::LessThanOrEqual,
        "0.75".to_owned(),
        EvidenceSnapshotRef::try_new(
            format!("{format_character}ES-CRITERION-001{format_character}"),
            VALID_SHA256.to_owned(),
        )
        .unwrap(),
    )
    .unwrap();

    assert_eq!(criterion.criterion_id(), "\u{feff}potency_policy\u{feff}");
    assert_eq!(
        criterion.criterion_evidence().id(),
        "\u{feff}ES-CRITERION-001\u{feff}"
    );
    assert_eq!(
        try_decision_criterion(
            "\u{2003}potency_policy".to_owned(),
            "2026.07".to_owned(),
            "0.75".to_owned(),
        ),
        Err(DomainError::InvalidDecisionCriterionId)
    );
    assert_eq!(
        EvidenceSnapshotRef::try_new(
            "ES-CRITERION-001\u{2003}".to_owned(),
            VALID_SHA256.to_owned(),
        ),
        Err(DomainError::InvalidEvidenceId)
    );
}

#[test]
fn validates_canonical_decision_criterion_threshold_decimals() {
    for valid in ["0", "-12", "12", "-0.25", "0.25", "10.01", "1.5"] {
        assert!(
            try_decision_criterion(
                "potency_policy".to_owned(),
                "2026.07".to_owned(),
                valid.to_owned(),
            )
            .is_ok()
        );
    }

    let exact = "1".repeat(MAX_DECISION_CRITERION_DECIMAL_BYTES);
    assert!(
        try_decision_criterion(
            "potency_policy".to_owned(),
            "2026.07".to_owned(),
            exact.clone(),
        )
        .is_ok()
    );

    for invalid in [
        "".to_owned(),
        " ".to_owned(),
        "+1".to_owned(),
        "-".to_owned(),
        "-0".to_owned(),
        "00".to_owned(),
        "01".to_owned(),
        ".5".to_owned(),
        "1.".to_owned(),
        "1.0".to_owned(),
        "1.20".to_owned(),
        "1e3".to_owned(),
        "NaN".to_owned(),
        "1 ".to_owned(),
        format!("{exact}1"),
    ] {
        assert_eq!(
            try_decision_criterion("potency_policy".to_owned(), "2026.07".to_owned(), invalid,),
            Err(DomainError::InvalidDecisionCriterionThresholdDecimal)
        );
    }
}

#[test]
fn rejects_decision_criterion_without_prediction_interval() {
    let result = DecisionRecord::try_new_with_decision_criterion(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Borderline,
        None,
        None,
        Vec::new(),
        Some(decision_criterion()),
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap(),
        vec!["Evidence coverage is incomplete.".to_owned()],
    );

    assert_eq!(
        result,
        Err(DomainError::MissingPredictionIntervalForCriterion)
    );
}

#[test]
fn decision_criterion_json_enforces_invariants_and_round_trips_exactly() {
    let criterion = decision_criterion();
    let serialized = serde_json::to_value(&criterion).unwrap();
    assert_eq!(serialized["comparator"], "less_than_or_equal");
    assert_eq!(serialized["threshold_decimal"], "0.75");
    assert_eq!(
        serde_json::from_value::<DecisionCriterion>(serialized.clone()).unwrap(),
        criterion
    );

    let mut invalid_decimal = serialized.clone();
    invalid_decimal["threshold_decimal"] = serde_json::Value::String("0.750".to_owned());
    assert!(
        serde_json::from_value::<DecisionCriterion>(invalid_decimal)
            .unwrap_err()
            .to_string()
            .contains("decision criterion threshold is invalid")
    );

    let mut invalid_evidence = serialized;
    invalid_evidence["criterion_evidence"]["sha256"] =
        serde_json::Value::String("invalid".to_owned());
    assert!(
        serde_json::from_value::<DecisionCriterion>(invalid_evidence)
            .unwrap_err()
            .to_string()
            .contains("evidence digest must be a lowercase sha256")
    );
}

#[test]
fn decision_json_preserves_criterion_and_omits_historical_absence() {
    let interval = try_prediction_interval(prediction_interval_values()).unwrap();
    let criterion = decision_criterion();
    let current = DecisionRecord::try_new_with_decision_criterion(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Borderline,
        None,
        Some(interval),
        Vec::new(),
        Some(criterion.clone()),
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap(),
        vec!["Evidence coverage is incomplete.".to_owned()],
    )
    .unwrap();
    let current_json = serde_json::to_value(&current).unwrap();
    let current_round_trip: DecisionRecord = serde_json::from_value(current_json.clone()).unwrap();
    assert_eq!(
        current_json["decision_criterion"]["threshold_decimal"],
        "0.75"
    );
    assert_eq!(current_round_trip.decision_criterion(), Some(&criterion));

    let historical = DecisionRecord::try_new_with_prediction_interval(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Unknown,
        None,
        Some(try_prediction_interval(prediction_interval_values()).unwrap()),
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap(),
        vec!["Historical decision.".to_owned()],
    )
    .unwrap();
    let historical_json = serde_json::to_value(&historical).unwrap();
    assert!(historical_json.get("decision_criterion").is_none());
    assert!(
        serde_json::from_value::<DecisionRecord>(historical_json)
            .unwrap()
            .decision_criterion()
            .is_none()
    );
}

#[test]
fn validates_prediction_position_identifiers_with_exact_byte_budgets() {
    let fields: [(usize, fn() -> DomainError); 3] = [
        (0, || DomainError::InvalidPredictionPositionSourceId),
        (1, || DomainError::InvalidPredictionPositionSourceVersion),
        (2, || {
            DomainError::InvalidPredictionPositionDependencyGroupId
        }),
    ];
    let exact = "\u{10000}".repeat(MAX_PREDICTION_POSITION_IDENTIFIER_BYTES / 4);
    assert_eq!(exact.len(), MAX_PREDICTION_POSITION_IDENTIFIER_BYTES);

    for (index, expected_error) in fields {
        let mut identifiers = [
            "model-a".to_owned(),
            "2026.07".to_owned(),
            "shared-training-set".to_owned(),
        ];
        identifiers[index] = exact.clone();
        assert!(try_prediction_position_identifiers(identifiers).is_ok());

        for invalid in [
            String::new(),
            " ".to_owned(),
            " leading".to_owned(),
            "trailing ".to_owned(),
            "embedded\0nul".to_owned(),
            format!("{exact}x"),
        ] {
            let mut identifiers = [
                "model-a".to_owned(),
                "2026.07".to_owned(),
                "shared-training-set".to_owned(),
            ];
            identifiers[index] = invalid;
            assert_eq!(
                try_prediction_position_identifiers(identifiers),
                Err(expected_error()),
                "identifier field index {index}",
            );
        }
    }
}

#[test]
fn validates_prediction_position_collection_bounds() {
    let positions = [
        prediction_position(
            "model-a",
            "2026.07",
            "shared-training-set",
            "0.2",
            "1.2",
            "ES-PRED-A",
        ),
        prediction_position(
            "model-b",
            "2026.07",
            "shared-training-set",
            "0.4",
            "1.4",
            "ES-PRED-B",
        ),
        prediction_position(
            "model-c",
            "2026.07",
            "independent-assay",
            "0.3",
            "1.3",
            "ES-PRED-C",
        ),
        prediction_position(
            "model-d",
            "2026.07",
            "independent-assay",
            "0.1",
            "1.1",
            "ES-PRED-D",
        ),
    ];

    assert!(try_decision_with_prediction_positions(Vec::new()).is_ok());
    assert_eq!(
        try_decision_with_prediction_positions(positions[..1].to_vec()),
        Err(DomainError::TooFewPredictionPositions),
    );
    assert!(try_decision_with_prediction_positions(positions[..2].to_vec()).is_ok());
    assert!(try_decision_with_prediction_positions(positions[..3].to_vec()).is_ok());
    assert_eq!(
        try_decision_with_prediction_positions(positions.to_vec()),
        Err(DomainError::TooManyPredictionPositions),
    );
}

#[test]
fn rejects_duplicate_prediction_position_sources() {
    let positions = vec![
        prediction_position(
            "model-a",
            "2026.07",
            "shared-training-set",
            "0.2",
            "1.2",
            "ES-PRED-A",
        ),
        prediction_position(
            "model-a",
            "2026.07",
            "independent-assay",
            "0.4",
            "1.4",
            "ES-PRED-B",
        ),
    ];

    assert_eq!(
        try_decision_with_prediction_positions(positions),
        Err(DomainError::DuplicatePredictionPositionSource),
    );
}

#[test]
fn rejects_prediction_positions_without_a_decision_interval() {
    let positions = vec![
        prediction_position(
            "model-a",
            "2026.07",
            "shared-training-set",
            "0.2",
            "1.2",
            "ES-PRED-A",
        ),
        prediction_position(
            "model-b",
            "2026.07",
            "shared-training-set",
            "0.4",
            "1.4",
            "ES-PRED-B",
        ),
    ];
    let result = DecisionRecord::try_new_with_prediction_positions(
        Uuid::now_v7(),
        "COU-001".to_owned(),
        Recommendation::Abstain,
        OodStatus::Borderline,
        Some(
            OodDetectorRef::try_new("mahalanobis".to_owned(), "model-2026.07".to_owned()).unwrap(),
        ),
        None,
        positions,
        EvidenceSnapshotRef::try_new("ES-001".to_owned(), VALID_SHA256.to_owned()).unwrap(),
        vec!["Evidence coverage is incomplete.".to_owned()],
    );

    assert_eq!(
        result,
        Err(DomainError::MissingPredictionIntervalForPositions),
    );
}

#[test]
fn requires_prediction_positions_to_match_the_decision_interval() {
    for (field_index, replacement, expected) in [
        (
            0,
            "cellular_activity",
            DomainError::IncomparablePredictionPositionTarget,
        ),
        (1, "uM", DomainError::IncomparablePredictionPositionUnit),
        (
            4,
            "0.9",
            DomainError::IncomparablePredictionPositionNominalCoverage,
        ),
    ] {
        let mut values = prediction_interval_values();
        values[field_index] = replacement.to_owned();
        let positions = vec![
            DecisionPredictionPosition::try_new(
                "model-a".to_owned(),
                "2026.07".to_owned(),
                "shared-training-set".to_owned(),
                try_prediction_interval(values).unwrap(),
                EvidenceSnapshotRef::try_new("ES-PRED-A".to_owned(), VALID_SHA256.to_owned())
                    .unwrap(),
            )
            .unwrap(),
            prediction_position(
                "model-b",
                "2026.07",
                "shared-training-set",
                "0.4",
                "1.4",
                "ES-PRED-B",
            ),
        ];

        assert_eq!(
            try_decision_with_prediction_positions(positions),
            Err(expected)
        );
    }
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
fn decision_criterion_errors_have_fixed_text() {
    for (error, expected) in [
        (
            DomainError::InvalidDecisionCriterionId,
            "decision criterion identifier is invalid",
        ),
        (
            DomainError::InvalidDecisionCriterionVersion,
            "decision criterion version is invalid",
        ),
        (
            DomainError::InvalidDecisionCriterionThresholdDecimal,
            "decision criterion threshold is invalid",
        ),
        (
            DomainError::MissingPredictionIntervalForCriterion,
            "a decision criterion requires a prediction interval",
        ),
    ] {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn prediction_position_errors_have_fixed_text() {
    for (error, expected) in [
        (
            DomainError::InvalidPredictionPositionSourceId,
            "prediction position source identifier is invalid",
        ),
        (
            DomainError::InvalidPredictionPositionSourceVersion,
            "prediction position source version is invalid",
        ),
        (
            DomainError::InvalidPredictionPositionDependencyGroupId,
            "prediction position dependency group identifier is invalid",
        ),
        (
            DomainError::TooFewPredictionPositions,
            "a decision has too few prediction positions",
        ),
        (
            DomainError::TooManyPredictionPositions,
            "a decision has too many prediction positions",
        ),
        (
            DomainError::DuplicatePredictionPositionSource,
            "prediction position source and version pairs must be unique",
        ),
        (
            DomainError::MissingPredictionIntervalForPositions,
            "prediction positions require a decision prediction interval",
        ),
        (
            DomainError::IncomparablePredictionPositionTarget,
            "prediction position target does not match the decision interval",
        ),
        (
            DomainError::IncomparablePredictionPositionUnit,
            "prediction position unit does not match the decision interval",
        ),
        (
            DomainError::IncomparablePredictionPositionNominalCoverage,
            "prediction position nominal coverage does not match the decision interval",
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
fn prediction_position_json_enforces_domain_invariants() {
    let position = prediction_position(
        "model-a",
        "2026.07",
        "shared-training-set",
        "0.2",
        "1.2",
        "ES-PRED-A",
    );
    let valid = serde_json::to_value(position).unwrap();
    let mut invalid_identifier = valid.clone();
    invalid_identifier["source_id"] = serde_json::Value::String(" model-a".to_owned());

    let error =
        serde_json::from_value::<DecisionPredictionPosition>(invalid_identifier).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("prediction position source identifier is invalid")
    );

    let mut invalid_interval = valid.clone();
    invalid_interval["interval"]["lower_decimal"] = serde_json::Value::String("01".to_owned());
    assert!(
        serde_json::from_value::<DecisionPredictionPosition>(invalid_interval)
            .unwrap_err()
            .to_string()
            .contains("prediction interval lower bound is invalid")
    );

    let mut invalid_evidence = valid;
    invalid_evidence["prediction_evidence"]["sha256"] =
        serde_json::Value::String("invalid".to_owned());
    assert!(
        serde_json::from_value::<DecisionPredictionPosition>(invalid_evidence)
            .unwrap_err()
            .to_string()
            .contains("evidence digest must be a lowercase sha256")
    );
}

#[test]
fn decision_json_round_trip_preserves_prediction_positions_in_recorded_order() {
    let positions = vec![
        prediction_position(
            "model-z",
            "2026.07",
            "shared-training-set",
            "0.4",
            "1.4",
            "ES-PRED-Z",
        ),
        prediction_position(
            "model-a",
            "2026.06",
            "independent-assay",
            "0.2",
            "1.2",
            "ES-PRED-A",
        ),
    ];
    let record = try_decision_with_prediction_positions(positions.clone()).unwrap();

    let serialized = serde_json::to_value(&record).unwrap();
    let deserialized: DecisionRecord = serde_json::from_value(serialized.clone()).unwrap();

    assert_eq!(
        serialized["prediction_positions"][0]["source_id"],
        "model-z"
    );
    assert_eq!(
        serialized["prediction_positions"][1]["source_id"],
        "model-a"
    );
    assert_eq!(deserialized.prediction_positions(), positions);
    assert_eq!(deserialized, record);
}

#[test]
fn decision_json_rejects_invalid_prediction_position_collections() {
    let record = try_decision_with_prediction_positions(vec![
        prediction_position(
            "model-a",
            "2026.07",
            "shared-training-set",
            "0.2",
            "1.2",
            "ES-PRED-A",
        ),
        prediction_position(
            "model-b",
            "2026.07",
            "shared-training-set",
            "0.4",
            "1.4",
            "ES-PRED-B",
        ),
    ])
    .unwrap();
    let valid = serde_json::to_value(record).unwrap();

    let mut too_few = valid.clone();
    too_few["prediction_positions"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    assert!(
        serde_json::from_value::<DecisionRecord>(too_few)
            .unwrap_err()
            .to_string()
            .contains("a decision has too few prediction positions")
    );

    let mut duplicate = valid.clone();
    duplicate["prediction_positions"][1]["source_id"] =
        duplicate["prediction_positions"][0]["source_id"].clone();
    duplicate["prediction_positions"][1]["source_version"] =
        duplicate["prediction_positions"][0]["source_version"].clone();
    assert!(
        serde_json::from_value::<DecisionRecord>(duplicate)
            .unwrap_err()
            .to_string()
            .contains("prediction position source and version pairs must be unique")
    );

    let mut incomparable = valid;
    incomparable["prediction_positions"][0]["interval"]["target"] =
        serde_json::Value::String("cellular_activity".to_owned());
    assert!(
        serde_json::from_value::<DecisionRecord>(incomparable)
            .unwrap_err()
            .to_string()
            .contains("prediction position target does not match the decision interval")
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
