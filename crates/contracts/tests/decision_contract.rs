use std::num::NonZeroU64;

use bioworld_contracts::{
    DecisionContractError, MAX_DECISION_WIRE_BYTES, VersionedDecisionRecord,
    v2::{
        DecisionCriterion, DecisionCriterionComparator, DecisionPredictionInterval,
        DecisionPredictionPosition, DecisionRecord, EvidenceSnapshotRef, OodDetectorRef, OodStatus,
        Recommendation,
    },
};
use bioworld_domain::{
    DomainError, MAX_DECISION_CRITERION_DECIMAL_BYTES, MAX_DECISION_CRITERION_IDENTIFIER_BYTES,
    MAX_DECISION_IDENTIFIER_BYTES, MAX_DECISION_PREDICTION_POSITIONS, MAX_DECISION_RATIONALE_ITEMS,
    MAX_DECISION_RATIONALE_TOTAL_BYTES, MAX_OOD_DETECTOR_ID_BYTES, MAX_OOD_DETECTOR_VERSION_BYTES,
    MAX_PREDICTION_INTERVAL_DECIMAL_BYTES, MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES,
    MAX_PREDICTION_POSITION_IDENTIFIER_BYTES, OodStatus as DomainOodStatus,
    Recommendation as DomainRecommendation,
};
use prost::Message;

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
type PredictionIntervalMutation = fn(&mut DecisionPredictionInterval);
type PredictionIntervalCase = (&'static str, PredictionIntervalMutation, DomainError);
type PredictionPositionMutation = fn(&mut DecisionPredictionPosition);
type PredictionPositionCase = (&'static str, PredictionPositionMutation, DomainError);
const COMPLETE_LEGACY_WIRE_WITHOUT_OOD_STATUS: &[u8] = b"\x0a\x24018f5a72-9c4b-7d31-8f6a-26f08f3f4d99\x12\x07COU-001\x1a\x06ES-001\x20\x05\x2a\x1fEvidence threshold was not met.\x30\x07\x3a\x4a\x0a\x06ES-001\x12\x400123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const M31_WIRE_WITHOUT_OOD_DETECTOR: &[u8] = b"\x0a\x24018f5a72-9c4b-7d31-8f6a-26f08f3f4d99\x12\x07COU-001\x1a\x06ES-001\x20\x05\x2a\x1fEvidence threshold was not met.\x30\x07\x3a\x4a\x0a\x06ES-001\x12\x400123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\x40\x03";
const FROZEN_WIRE_WITH_OOD_PROVENANCE_WITHOUT_INTERVAL: &[u8] = b"\x0a\x24018f5a72-9c4b-7d31-8f6a-26f08f3f4d99\x12\x07COU-001\x1a\x06ES-001\x20\x05\x2a\x1fEvidence threshold was not met.\x30\x07\x3a\x4a\x0a\x06ES-001\x12\x400123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\x40\x02\x4a\x1c\x0a\x0bmahalanobis\x12\x0dmodel-2026.07";
const FROZEN_M33_PREDICTION_INTERVAL_FIELD: &[u8] = &[
    82, 172, 1, 10, 16, 98, 105, 110, 100, 105, 110, 103, 95, 97, 102, 102, 105, 110, 105, 116,
    121, 18, 2, 110, 77, 26, 4, 48, 46, 50, 53, 34, 3, 49, 46, 53, 42, 4, 48, 46, 57, 53, 50, 15,
    115, 112, 108, 105, 116, 95, 99, 111, 110, 102, 111, 114, 109, 97, 108, 58, 3, 49, 46, 48, 66,
    20, 104, 101, 108, 100, 95, 111, 117, 116, 95, 99, 97, 108, 105, 98, 114, 97, 116, 105, 111,
    110, 74, 7, 50, 48, 50, 54, 46, 48, 55, 82, 78, 10, 10, 69, 83, 45, 67, 65, 76, 45, 48, 48, 49,
    18, 64, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 48, 49, 50, 51, 52,
    53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98,
    99, 100, 101, 102, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102,
];
const FROZEN_M34_PREDICTION_POSITIONS_FIELD: &[u8] = b"\x5a\xa5\x02\x0a\x07\x6d\x6f\x64\x65\x6c\x2d\x7a\x12\x07\x32\x30\x32\x36\x2e\x30\x37\x1a\x13\x73\x68\x61\x72\x65\x64\x2d\x74\x72\x61\x69\x6e\x69\x6e\x67\x2d\x73\x65\x74\x22\xac\x01\x0a\x10\x62\x69\x6e\x64\x69\x6e\x67\x5f\x61\x66\x66\x69\x6e\x69\x74\x79\x12\x02\x6e\x4d\x1a\x04\x30\x2e\x32\x35\x22\x03\x31\x2e\x35\x2a\x04\x30\x2e\x39\x35\x32\x0f\x73\x70\x6c\x69\x74\x5f\x63\x6f\x6e\x66\x6f\x72\x6d\x61\x6c\x3a\x03\x31\x2e\x30\x42\x14\x68\x65\x6c\x64\x5f\x6f\x75\x74\x5f\x63\x61\x6c\x69\x62\x72\x61\x74\x69\x6f\x6e\x4a\x07\x32\x30\x32\x36\x2e\x30\x37\x52\x4e\x0a\x0a\x45\x53\x2d\x43\x41\x4c\x2d\x30\x30\x31\x12\x40\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x2a\x4d\x0a\x09\x45\x53\x2d\x50\x52\x45\x44\x2d\x5a\x12\x40\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x5a\xa3\x02\x0a\x07\x6d\x6f\x64\x65\x6c\x2d\x61\x12\x07\x32\x30\x32\x36\x2e\x30\x36\x1a\x11\x69\x6e\x64\x65\x70\x65\x6e\x64\x65\x6e\x74\x2d\x61\x73\x73\x61\x79\x22\xac\x01\x0a\x10\x62\x69\x6e\x64\x69\x6e\x67\x5f\x61\x66\x66\x69\x6e\x69\x74\x79\x12\x02\x6e\x4d\x1a\x04\x30\x2e\x32\x35\x22\x03\x31\x2e\x35\x2a\x04\x30\x2e\x39\x35\x32\x0f\x73\x70\x6c\x69\x74\x5f\x63\x6f\x6e\x66\x6f\x72\x6d\x61\x6c\x3a\x03\x31\x2e\x30\x42\x14\x68\x65\x6c\x64\x5f\x6f\x75\x74\x5f\x63\x61\x6c\x69\x62\x72\x61\x74\x69\x6f\x6e\x4a\x07\x32\x30\x32\x36\x2e\x30\x37\x52\x4e\x0a\x0a\x45\x53\x2d\x43\x41\x4c\x2d\x30\x30\x31\x12\x40\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x2a\x4d\x0a\x09\x45\x53\x2d\x50\x52\x45\x44\x2d\x41\x12\x40\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66";
const FROZEN_M35_DECISION_CRITERION_FIELD: &[u8] = b"\x62\x77\x0a\x0epotency_policy\x12\x072026.07\x18\x02\x22\x040.75\x2a\x54\x0a\x10ES-CRITERION-001\x12\x400123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[allow(deprecated)]
fn complete_wire_record() -> DecisionRecord {
    DecisionRecord {
        decision_id: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99".to_owned(),
        cou_id: "COU-001".to_owned(),
        evidence_snapshot_id: "ES-001".to_owned(),
        recommendation: Recommendation::StopProgram as i32,
        rationale: vec!["Evidence threshold was not met.".to_owned()],
        aggregate_version: 7,
        evidence: Some(EvidenceSnapshotRef {
            id: "ES-001".to_owned(),
            sha256: VALID_SHA256.to_owned(),
        }),
        ood_status: Some(OodStatus::Borderline as i32),
        ood_detector: Some(OodDetectorRef {
            detector_id: "mahalanobis".to_owned(),
            detector_version: "model-2026.07".to_owned(),
        }),
        prediction_interval: None,
        prediction_positions: Vec::new(),
        decision_criterion: None,
    }
}

fn complete_prediction_interval() -> DecisionPredictionInterval {
    DecisionPredictionInterval {
        target: "binding_affinity".to_owned(),
        unit: "nM".to_owned(),
        lower_decimal: "0.25".to_owned(),
        upper_decimal: "1.5".to_owned(),
        nominal_coverage_decimal: "0.95".to_owned(),
        interval_method_id: "split_conformal".to_owned(),
        interval_method_version: "1.0".to_owned(),
        calibration_method_id: "held_out_calibration".to_owned(),
        calibration_method_version: "2026.07".to_owned(),
        calibration_evidence: Some(EvidenceSnapshotRef {
            id: "ES-CAL-001".to_owned(),
            sha256: VALID_SHA256.to_owned(),
        }),
    }
}

fn complete_prediction_position(
    source_id: &str,
    source_version: &str,
    dependency_group_id: &str,
    evidence_id: &str,
) -> DecisionPredictionPosition {
    DecisionPredictionPosition {
        source_id: source_id.to_owned(),
        source_version: source_version.to_owned(),
        dependency_group_id: dependency_group_id.to_owned(),
        interval: Some(complete_prediction_interval()),
        prediction_evidence: Some(EvidenceSnapshotRef {
            id: evidence_id.to_owned(),
            sha256: VALID_SHA256.to_owned(),
        }),
    }
}

fn complete_wire_record_with_positions() -> DecisionRecord {
    let mut record = complete_wire_record();
    record.prediction_interval = Some(complete_prediction_interval());
    record.prediction_positions = vec![
        complete_prediction_position("model-z", "2026.07", "shared-training-set", "ES-PRED-Z"),
        complete_prediction_position("model-a", "2026.06", "independent-assay", "ES-PRED-A"),
    ];
    record
}

fn complete_decision_criterion(comparator: DecisionCriterionComparator) -> DecisionCriterion {
    DecisionCriterion {
        criterion_id: "potency_policy".to_owned(),
        criterion_version: "2026.07".to_owned(),
        comparator: comparator as i32,
        threshold_decimal: "0.75".to_owned(),
        criterion_evidence: Some(EvidenceSnapshotRef {
            id: "ES-CRITERION-001".to_owned(),
            sha256: VALID_SHA256.to_owned(),
        }),
    }
}

fn record_with_encoded_len(target: usize) -> DecisionRecord {
    let mut record = complete_wire_record();
    let mut rationale_bytes = target;

    for _ in 0..4 {
        record.rationale = vec!["r".repeat(rationale_bytes)];
        match record.encoded_len().cmp(&target) {
            std::cmp::Ordering::Equal => return record,
            std::cmp::Ordering::Less => rationale_bytes += target - record.encoded_len(),
            std::cmp::Ordering::Greater => rationale_bytes -= record.encoded_len() - target,
        }
    }

    panic!("could not construct target wire size");
}

#[test]
fn bounds_decision_wire_records_before_conversion() {
    let exact = record_with_encoded_len(MAX_DECISION_WIRE_BYTES);
    let oversized = record_with_encoded_len(MAX_DECISION_WIRE_BYTES + 1);

    assert_eq!(exact.encoded_len(), MAX_DECISION_WIRE_BYTES);
    assert_eq!(oversized.encoded_len(), MAX_DECISION_WIRE_BYTES + 1);
    assert_eq!(
        VersionedDecisionRecord::try_from(exact),
        Err(DecisionContractError::InvalidDomain(
            DomainError::RationaleTooLarge,
        )),
    );
    assert_eq!(
        VersionedDecisionRecord::try_from(oversized),
        Err(DecisionContractError::DecisionTooLarge),
    );
}

#[test]
#[allow(deprecated)]
fn maximum_valid_decision_criterion_record_fits_the_wire_envelope() {
    let decision_identifier = "\u{10000}".repeat(MAX_DECISION_IDENTIFIER_BYTES / 4);
    let evidence = || EvidenceSnapshotRef {
        id: decision_identifier.clone(),
        sha256: VALID_SHA256.to_owned(),
    };
    let nominal_coverage = format!(
        "0.{}1",
        "0".repeat(MAX_PREDICTION_INTERVAL_DECIMAL_BYTES - 3)
    );
    let interval = || DecisionPredictionInterval {
        target: "t".repeat(MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES),
        unit: "u".repeat(MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES),
        lower_decimal: "1".repeat(MAX_PREDICTION_INTERVAL_DECIMAL_BYTES),
        upper_decimal: "2".repeat(MAX_PREDICTION_INTERVAL_DECIMAL_BYTES),
        nominal_coverage_decimal: nominal_coverage.clone(),
        interval_method_id: "i".repeat(MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES),
        interval_method_version: "v".repeat(MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES),
        calibration_method_id: "c".repeat(MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES),
        calibration_method_version: "m".repeat(MAX_PREDICTION_INTERVAL_IDENTIFIER_BYTES),
        calibration_evidence: Some(evidence()),
    };

    let mut record = complete_wire_record();
    record.cou_id = decision_identifier.clone();
    record.evidence_snapshot_id = decision_identifier.clone();
    record.aggregate_version = u64::MAX;
    record.evidence = Some(evidence());
    record.ood_detector = Some(OodDetectorRef {
        detector_id: "d".repeat(MAX_OOD_DETECTOR_ID_BYTES),
        detector_version: "v".repeat(MAX_OOD_DETECTOR_VERSION_BYTES),
    });
    record.prediction_interval = Some(interval());
    record.prediction_positions = (0..MAX_DECISION_PREDICTION_POSITIONS)
        .map(|index| DecisionPredictionPosition {
            source_id: format!(
                "{index}{}",
                "s".repeat(MAX_PREDICTION_POSITION_IDENTIFIER_BYTES - 1)
            ),
            source_version: "v".repeat(MAX_PREDICTION_POSITION_IDENTIFIER_BYTES),
            dependency_group_id: "g".repeat(MAX_PREDICTION_POSITION_IDENTIFIER_BYTES),
            interval: Some(interval()),
            prediction_evidence: Some(evidence()),
        })
        .collect();
    record.decision_criterion = Some(DecisionCriterion {
        criterion_id: "i".repeat(MAX_DECISION_CRITERION_IDENTIFIER_BYTES),
        criterion_version: "v".repeat(MAX_DECISION_CRITERION_IDENTIFIER_BYTES),
        comparator: DecisionCriterionComparator::GreaterThanOrEqual as i32,
        threshold_decimal: "9".repeat(MAX_DECISION_CRITERION_DECIMAL_BYTES),
        criterion_evidence: Some(evidence()),
    });
    record.rationale =
        vec![
            "r".repeat(MAX_DECISION_RATIONALE_TOTAL_BYTES / MAX_DECISION_RATIONALE_ITEMS);
            MAX_DECISION_RATIONALE_ITEMS
        ];

    let encoded_len = record.encoded_len();
    assert!(
        encoded_len <= MAX_DECISION_WIRE_BYTES,
        "maximum valid record uses {encoded_len} wire bytes"
    );
    let boundary = VersionedDecisionRecord::try_from(record.clone()).unwrap();
    assert_eq!(DecisionRecord::from(&boundary), record);
}

#[test]
fn generated_decision_contract_round_trips_complete_record() {
    let record = complete_wire_record();

    let encoded = record.encode_to_vec();
    let decoded = DecisionRecord::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded, record);
}

#[test]
#[allow(deprecated)]
fn decodes_legacy_wire_payload_before_requiring_evidence_resolution() {
    const LEGACY_WIRE: &[u8] = b"\x0a\x24018f5a72-9c4b-7d31-8f6a-26f08f3f4d99\x12\x07COU-001\x1a\x06ES-001\x20\x01\x2a\x1fEvidence threshold was not met.\x30\x07";

    let decoded = DecisionRecord::decode(LEGACY_WIRE).unwrap();

    assert_eq!(decoded.decision_id, "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99");
    assert_eq!(decoded.cou_id, "COU-001");
    assert_eq!(decoded.evidence_snapshot_id, "ES-001");
    assert_eq!(decoded.recommendation, Recommendation::Promote as i32);
    assert_eq!(decoded.rationale, ["Evidence threshold was not met."]);
    assert_eq!(decoded.aggregate_version, 7);
    assert_eq!(decoded.evidence, None);
    assert_eq!(
        VersionedDecisionRecord::try_from(decoded),
        Err(DecisionContractError::MissingEvidence)
    );
}

#[test]
fn converts_complete_wire_record_to_valid_domain_boundary() {
    let boundary = VersionedDecisionRecord::try_from(complete_wire_record()).unwrap();
    let decision = boundary.decision();

    assert_eq!(
        decision.id().to_string(),
        "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99"
    );
    assert_eq!(decision.cou_id(), "COU-001");
    assert_eq!(
        decision.recommendation(),
        &DomainRecommendation::StopProgram
    );
    assert_eq!(decision.evidence().id(), "ES-001");
    assert_eq!(decision.evidence().sha256(), VALID_SHA256);
    assert_eq!(decision.rationale(), ["Evidence threshold was not met."]);
    assert_eq!(decision.ood_status(), &DomainOodStatus::Borderline);
    let detector = decision.ood_detector().unwrap();
    assert_eq!(detector.detector_id(), "mahalanobis");
    assert_eq!(detector.detector_version(), "model-2026.07");
    assert_eq!(boundary.aggregate_version(), NonZeroU64::new(7).unwrap());
}

#[test]
fn decision_boundary_round_trips_without_data_loss() {
    let expected = complete_wire_record();
    let boundary = VersionedDecisionRecord::try_from(expected.clone()).unwrap();
    let emitted = DecisionRecord::from(&boundary);
    let encoded = emitted.encode_to_vec();
    let decoded = DecisionRecord::decode(encoded.as_slice()).unwrap();

    assert_eq!(decoded, expected);
}

#[test]
fn prediction_interval_round_trips_without_data_loss() {
    let mut expected = complete_wire_record();
    expected.prediction_interval = Some(complete_prediction_interval());

    let boundary = VersionedDecisionRecord::try_from(expected.clone()).unwrap();
    let interval = boundary.decision().prediction_interval().unwrap();

    assert_eq!(interval.target(), "binding_affinity");
    assert_eq!(interval.unit(), "nM");
    assert_eq!(interval.lower_decimal(), "0.25");
    assert_eq!(interval.upper_decimal(), "1.5");
    assert_eq!(interval.nominal_coverage_decimal(), "0.95");
    assert_eq!(interval.interval_method_id(), "split_conformal");
    assert_eq!(interval.interval_method_version(), "1.0");
    assert_eq!(interval.calibration_method_id(), "held_out_calibration");
    assert_eq!(interval.calibration_method_version(), "2026.07");
    assert_eq!(interval.calibration_evidence().id(), "ES-CAL-001");
    assert_eq!(interval.calibration_evidence().sha256(), VALID_SHA256);
    assert_eq!(DecisionRecord::from(&boundary), expected);
}

#[test]
fn prediction_positions_round_trip_without_data_loss() {
    let expected = complete_wire_record_with_positions();

    let boundary = VersionedDecisionRecord::try_from(expected.clone()).unwrap();
    let positions = boundary.decision().prediction_positions();

    assert_eq!(positions[0].source_id(), "model-z");
    assert_eq!(positions[0].source_version(), "2026.07");
    assert_eq!(positions[0].dependency_group_id(), "shared-training-set");
    assert_eq!(positions[0].interval().lower_decimal(), "0.25");
    assert_eq!(positions[0].prediction_evidence().id(), "ES-PRED-Z");
    assert_eq!(positions[1].source_id(), "model-a");
    assert_eq!(DecisionRecord::from(&boundary), expected);
}

#[test]
fn decision_criterion_round_trips_without_data_loss() {
    let mut expected = complete_wire_record_with_positions();
    expected.decision_criterion = Some(complete_decision_criterion(
        DecisionCriterionComparator::LessThanOrEqual,
    ));

    let boundary = VersionedDecisionRecord::try_from(expected.clone()).unwrap();
    let criterion = boundary.decision().decision_criterion().unwrap();

    assert_eq!(criterion.criterion_id(), "potency_policy");
    assert_eq!(criterion.criterion_version(), "2026.07");
    assert_eq!(criterion.threshold_decimal(), "0.75");
    assert_eq!(criterion.criterion_evidence().id(), "ES-CRITERION-001");
    assert_eq!(DecisionRecord::from(&boundary), expected);
}

#[test]
fn every_decision_criterion_comparator_round_trips_exactly() {
    for comparator in [
        DecisionCriterionComparator::LessThan,
        DecisionCriterionComparator::LessThanOrEqual,
        DecisionCriterionComparator::GreaterThan,
        DecisionCriterionComparator::GreaterThanOrEqual,
    ] {
        let mut expected = complete_wire_record_with_positions();
        expected.decision_criterion = Some(complete_decision_criterion(comparator));

        let boundary = VersionedDecisionRecord::try_from(expected.clone()).unwrap();

        assert_eq!(DecisionRecord::from(&boundary), expected);
    }
}

#[test]
fn rejects_incomplete_or_invalid_decision_criteria_from_wire() {
    let mut missing_evidence = complete_wire_record_with_positions();
    missing_evidence.decision_criterion = Some(complete_decision_criterion(
        DecisionCriterionComparator::LessThanOrEqual,
    ));
    missing_evidence
        .decision_criterion
        .as_mut()
        .unwrap()
        .criterion_evidence = None;
    assert_eq!(
        VersionedDecisionRecord::try_from(missing_evidence),
        Err(DecisionContractError::MissingDecisionCriterionEvidence)
    );

    for (name, mutate, expected) in [
        (
            "identifier",
            (|criterion: &mut DecisionCriterion| criterion.criterion_id = " policy".to_owned())
                as fn(&mut DecisionCriterion),
            DomainError::InvalidDecisionCriterionId,
        ),
        (
            "version",
            |criterion: &mut DecisionCriterion| criterion.criterion_version.clear(),
            DomainError::InvalidDecisionCriterionVersion,
        ),
        (
            "threshold",
            |criterion: &mut DecisionCriterion| criterion.threshold_decimal = "0.750".to_owned(),
            DomainError::InvalidDecisionCriterionThresholdDecimal,
        ),
        (
            "evidence",
            |criterion: &mut DecisionCriterion| {
                criterion.criterion_evidence.as_mut().unwrap().sha256 = "invalid".to_owned();
            },
            DomainError::InvalidEvidenceDigest,
        ),
    ] {
        let mut wire = complete_wire_record_with_positions();
        wire.decision_criterion = Some(complete_decision_criterion(
            DecisionCriterionComparator::LessThanOrEqual,
        ));
        mutate(wire.decision_criterion.as_mut().unwrap());

        assert_eq!(
            VersionedDecisionRecord::try_from(wire),
            Err(DecisionContractError::InvalidDomain(expected)),
            "{name}"
        );
    }
}

#[test]
fn rejects_unspecified_and_unknown_decision_criterion_comparators() {
    let mut unspecified = complete_wire_record_with_positions();
    unspecified.decision_criterion = Some(complete_decision_criterion(
        DecisionCriterionComparator::Unspecified,
    ));
    let mut unknown = complete_wire_record_with_positions();
    unknown.decision_criterion = Some(complete_decision_criterion(
        DecisionCriterionComparator::LessThan,
    ));
    unknown.decision_criterion.as_mut().unwrap().comparator = 99;

    assert_eq!(
        VersionedDecisionRecord::try_from(unspecified),
        Err(DecisionContractError::UnspecifiedDecisionCriterionComparator)
    );
    assert_eq!(
        VersionedDecisionRecord::try_from(unknown),
        Err(DecisionContractError::UnknownDecisionCriterionComparator(
            99
        ))
    );
}

#[test]
fn rejects_decision_criterion_without_prediction_interval() {
    let mut wire = complete_wire_record();
    wire.decision_criterion = Some(complete_decision_criterion(
        DecisionCriterionComparator::LessThan,
    ));

    assert_eq!(
        VersionedDecisionRecord::try_from(wire),
        Err(DecisionContractError::InvalidDomain(
            DomainError::MissingPredictionIntervalForCriterion
        ))
    );
}

#[test]
fn decision_criterion_contract_errors_have_fixed_text() {
    assert_eq!(
        DecisionContractError::MissingDecisionCriterionEvidence.to_string(),
        "decision criterion evidence is required"
    );
    assert_eq!(
        DecisionContractError::UnspecifiedDecisionCriterionComparator.to_string(),
        "decision criterion comparator must not be unspecified"
    );
    assert_eq!(
        DecisionContractError::UnknownDecisionCriterionComparator(99).to_string(),
        "decision criterion comparator value 99 is unknown"
    );
}

#[test]
fn prediction_position_contract_errors_have_fixed_text() {
    assert_eq!(
        DecisionContractError::MissingPredictionPositionInterval.to_string(),
        "prediction position interval is required",
    );
    assert_eq!(
        DecisionContractError::MissingPredictionPositionEvidence.to_string(),
        "prediction position evidence is required",
    );
}

#[test]
fn rejects_prediction_positions_with_missing_nested_messages() {
    let mut missing_interval = complete_wire_record_with_positions();
    missing_interval.prediction_positions[0].interval = None;
    assert_eq!(
        VersionedDecisionRecord::try_from(missing_interval),
        Err(DecisionContractError::MissingPredictionPositionInterval),
    );

    let mut missing_calibration_evidence = complete_wire_record_with_positions();
    missing_calibration_evidence.prediction_positions[0]
        .interval
        .as_mut()
        .unwrap()
        .calibration_evidence = None;
    assert_eq!(
        VersionedDecisionRecord::try_from(missing_calibration_evidence),
        Err(DecisionContractError::MissingPredictionIntervalCalibrationEvidence),
    );

    let mut missing_prediction_evidence = complete_wire_record_with_positions();
    missing_prediction_evidence.prediction_positions[0].prediction_evidence = None;
    assert_eq!(
        VersionedDecisionRecord::try_from(missing_prediction_evidence),
        Err(DecisionContractError::MissingPredictionPositionEvidence),
    );
}

#[test]
fn rejects_invalid_prediction_position_identifiers_from_wire() {
    let cases: [PredictionPositionCase; 3] = [
        (
            "source id",
            |position| position.source_id = " model-a".to_owned(),
            DomainError::InvalidPredictionPositionSourceId,
        ),
        (
            "source version",
            |position| position.source_version.clear(),
            DomainError::InvalidPredictionPositionSourceVersion,
        ),
        (
            "dependency group id",
            |position| position.dependency_group_id = "group\0id".to_owned(),
            DomainError::InvalidPredictionPositionDependencyGroupId,
        ),
    ];

    for (name, make_invalid, expected) in cases {
        let mut wire = complete_wire_record_with_positions();
        make_invalid(&mut wire.prediction_positions[0]);

        assert_eq!(
            VersionedDecisionRecord::try_from(wire),
            Err(DecisionContractError::InvalidDomain(expected)),
            "{name}",
        );
    }
}

#[test]
fn rejects_invalid_prediction_position_evidence_from_wire() {
    let mut wire = complete_wire_record_with_positions();
    wire.prediction_positions[0]
        .prediction_evidence
        .as_mut()
        .unwrap()
        .sha256 = "invalid".to_owned();

    assert_eq!(
        VersionedDecisionRecord::try_from(wire),
        Err(DecisionContractError::InvalidDomain(
            DomainError::InvalidEvidenceDigest,
        )),
    );
}

#[test]
fn rejects_invalid_prediction_position_collection_shapes_from_wire() {
    let mut too_few = complete_wire_record_with_positions();
    too_few.prediction_positions.truncate(1);
    assert_eq!(
        VersionedDecisionRecord::try_from(too_few),
        Err(DecisionContractError::InvalidDomain(
            DomainError::TooFewPredictionPositions,
        )),
    );

    let mut too_many = complete_wire_record_with_positions();
    too_many.prediction_positions.extend([
        complete_prediction_position("model-b", "2026.07", "shared-training-set", "ES-PRED-B"),
        complete_prediction_position("model-c", "2026.07", "independent-assay", "ES-PRED-C"),
    ]);
    assert_eq!(
        VersionedDecisionRecord::try_from(too_many),
        Err(DecisionContractError::InvalidDomain(
            DomainError::TooManyPredictionPositions,
        )),
    );

    let mut missing_decision_interval = complete_wire_record_with_positions();
    missing_decision_interval.prediction_interval = None;
    assert_eq!(
        VersionedDecisionRecord::try_from(missing_decision_interval),
        Err(DecisionContractError::InvalidDomain(
            DomainError::MissingPredictionIntervalForPositions,
        )),
    );

    let mut duplicate = complete_wire_record_with_positions();
    duplicate.prediction_positions[1].source_id =
        duplicate.prediction_positions[0].source_id.clone();
    duplicate.prediction_positions[1].source_version =
        duplicate.prediction_positions[0].source_version.clone();
    assert_eq!(
        VersionedDecisionRecord::try_from(duplicate),
        Err(DecisionContractError::InvalidDomain(
            DomainError::DuplicatePredictionPositionSource,
        )),
    );
}

#[test]
fn accepts_matching_source_ids_with_distinct_versions() {
    let mut wire = complete_wire_record_with_positions();
    wire.prediction_positions[1].source_id = wire.prediction_positions[0].source_id.clone();

    let boundary = VersionedDecisionRecord::try_from(wire.clone()).unwrap();

    assert_eq!(
        boundary.decision().prediction_positions()[0].source_id(),
        "model-z"
    );
    assert_eq!(
        boundary.decision().prediction_positions()[1].source_id(),
        "model-z"
    );
    assert_eq!(DecisionRecord::from(&boundary), wire);
}

#[test]
fn rejects_incomparable_prediction_positions_from_wire() {
    let cases: [PredictionIntervalCase; 3] = [
        (
            "target",
            |interval| interval.target = "cellular_activity".to_owned(),
            DomainError::IncomparablePredictionPositionTarget,
        ),
        (
            "unit",
            |interval| interval.unit = "uM".to_owned(),
            DomainError::IncomparablePredictionPositionUnit,
        ),
        (
            "nominal coverage",
            |interval| interval.nominal_coverage_decimal = "0.9".to_owned(),
            DomainError::IncomparablePredictionPositionNominalCoverage,
        ),
    ];

    for (name, make_incomparable, expected) in cases {
        let mut wire = complete_wire_record_with_positions();
        make_incomparable(wire.prediction_positions[0].interval.as_mut().unwrap());

        assert_eq!(
            VersionedDecisionRecord::try_from(wire),
            Err(DecisionContractError::InvalidDomain(expected)),
            "{name}",
        );
    }
}

#[test]
fn rejects_prediction_interval_without_calibration_evidence() {
    let mut interval = complete_prediction_interval();
    interval.calibration_evidence = None;
    let mut wire = complete_wire_record();
    wire.prediction_interval = Some(interval);

    assert_eq!(
        VersionedDecisionRecord::try_from(wire),
        Err(DecisionContractError::MissingPredictionIntervalCalibrationEvidence),
    );
}

#[test]
fn rejects_partial_prediction_intervals_with_specific_domain_errors() {
    let cases: [PredictionIntervalCase; 9] = [
        (
            "target",
            |interval| interval.target.clear(),
            DomainError::InvalidPredictionIntervalTarget,
        ),
        (
            "unit",
            |interval| interval.unit.clear(),
            DomainError::InvalidPredictionIntervalUnit,
        ),
        (
            "lower decimal",
            |interval| interval.lower_decimal.clear(),
            DomainError::InvalidPredictionIntervalLowerDecimal,
        ),
        (
            "upper decimal",
            |interval| interval.upper_decimal.clear(),
            DomainError::InvalidPredictionIntervalUpperDecimal,
        ),
        (
            "nominal coverage decimal",
            |interval| interval.nominal_coverage_decimal.clear(),
            DomainError::InvalidPredictionIntervalNominalCoverageDecimal,
        ),
        (
            "interval method id",
            |interval| interval.interval_method_id.clear(),
            DomainError::InvalidPredictionIntervalMethodId,
        ),
        (
            "interval method version",
            |interval| interval.interval_method_version.clear(),
            DomainError::InvalidPredictionIntervalMethodVersion,
        ),
        (
            "calibration method id",
            |interval| interval.calibration_method_id.clear(),
            DomainError::InvalidPredictionIntervalCalibrationMethodId,
        ),
        (
            "calibration method version",
            |interval| interval.calibration_method_version.clear(),
            DomainError::InvalidPredictionIntervalCalibrationMethodVersion,
        ),
    ];

    for (name, make_partial, expected) in cases {
        let mut interval = complete_prediction_interval();
        make_partial(&mut interval);
        let mut wire = complete_wire_record();
        wire.prediction_interval = Some(interval);

        assert_eq!(
            VersionedDecisionRecord::try_from(wire),
            Err(DecisionContractError::InvalidDomain(expected)),
            "{name}",
        );
    }
}

#[test]
#[allow(deprecated)]
fn rejects_invalid_wire_records_with_specific_errors() {
    let mut cases = Vec::new();

    let mut invalid_id = complete_wire_record();
    invalid_id.decision_id = "not-a-uuid".to_owned();
    cases.push((
        "invalid decision id",
        invalid_id,
        DecisionContractError::InvalidDecisionId,
    ));

    let mut missing_cou = complete_wire_record();
    missing_cou.cou_id = "  ".to_owned();
    cases.push((
        "missing COU",
        missing_cou,
        DecisionContractError::MissingCouId,
    ));

    let mut missing_evidence = complete_wire_record();
    missing_evidence.evidence = None;
    cases.push((
        "missing evidence",
        missing_evidence,
        DecisionContractError::MissingEvidence,
    ));

    let mut missing_evidence_id = complete_wire_record();
    missing_evidence_id.evidence_snapshot_id.clear();
    missing_evidence_id.evidence.as_mut().unwrap().id = "  ".to_owned();
    cases.push((
        "missing evidence id",
        missing_evidence_id,
        DecisionContractError::MissingEvidenceId,
    ));

    let mut conflicting_evidence_ids = complete_wire_record();
    conflicting_evidence_ids.evidence.as_mut().unwrap().id = "ES-002".to_owned();
    cases.push((
        "conflicting evidence ids",
        conflicting_evidence_ids,
        DecisionContractError::ConflictingEvidenceIds,
    ));

    let mut invalid_digest = complete_wire_record();
    invalid_digest.evidence.as_mut().unwrap().sha256 = "invalid".to_owned();
    cases.push((
        "invalid evidence digest",
        invalid_digest,
        DecisionContractError::InvalidDomain(DomainError::InvalidEvidenceDigest),
    ));

    let mut invalid_detector_id = complete_wire_record();
    invalid_detector_id
        .ood_detector
        .as_mut()
        .unwrap()
        .detector_id = " detector".to_owned();
    cases.push((
        "invalid OOD detector id",
        invalid_detector_id,
        DecisionContractError::InvalidDomain(DomainError::InvalidOodDetectorId),
    ));

    let mut invalid_detector_version = complete_wire_record();
    invalid_detector_version
        .ood_detector
        .as_mut()
        .unwrap()
        .detector_version = "v".repeat(MAX_OOD_DETECTOR_VERSION_BYTES + 1);
    cases.push((
        "invalid OOD detector version",
        invalid_detector_version,
        DecisionContractError::InvalidDomain(DomainError::InvalidOodDetectorVersion),
    ));

    let mut missing_rationale = complete_wire_record();
    missing_rationale.rationale.clear();
    cases.push((
        "missing rationale",
        missing_rationale,
        DecisionContractError::InvalidDomain(DomainError::MissingRationale),
    ));

    let mut blank_rationale = complete_wire_record();
    blank_rationale.rationale = vec!["  ".to_owned(), "\t".to_owned()];
    cases.push((
        "blank rationale",
        blank_rationale,
        DecisionContractError::InvalidDomain(DomainError::MissingRationale),
    ));

    let mut excessive_rationales = complete_wire_record();
    excessive_rationales.rationale = vec!["r".to_owned(); MAX_DECISION_RATIONALE_ITEMS + 1];
    cases.push((
        "excessive rationales",
        excessive_rationales,
        DecisionContractError::InvalidDomain(DomainError::TooManyRationales),
    ));

    let mut zero_version = complete_wire_record();
    zero_version.aggregate_version = 0;
    cases.push((
        "zero aggregate version",
        zero_version,
        DecisionContractError::InvalidAggregateVersion,
    ));

    let mut unspecified_recommendation = complete_wire_record();
    unspecified_recommendation.recommendation = Recommendation::Unspecified as i32;
    cases.push((
        "unspecified recommendation",
        unspecified_recommendation,
        DecisionContractError::UnspecifiedRecommendation,
    ));

    let mut unknown_recommendation = complete_wire_record();
    unknown_recommendation.recommendation = 99;
    cases.push((
        "unknown recommendation",
        unknown_recommendation,
        DecisionContractError::UnknownRecommendation(99),
    ));

    for (name, wire, expected) in cases {
        assert_eq!(
            VersionedDecisionRecord::try_from(wire),
            Err(expected),
            "{name}"
        );
    }
}

#[test]
fn maps_every_supported_recommendation_without_loss() {
    let cases = [
        (Recommendation::Promote, DomainRecommendation::Promote),
        (Recommendation::Reject, DomainRecommendation::Reject),
        (Recommendation::Abstain, DomainRecommendation::Abstain),
        (Recommendation::Defer, DomainRecommendation::Defer),
        (
            Recommendation::StopProgram,
            DomainRecommendation::StopProgram,
        ),
    ];

    for (wire_recommendation, domain_recommendation) in cases {
        let mut wire = complete_wire_record();
        wire.recommendation = wire_recommendation as i32;

        let boundary = VersionedDecisionRecord::try_from(wire).unwrap();
        let emitted = DecisionRecord::from(&boundary);

        assert_eq!(boundary.decision().recommendation(), &domain_recommendation);
        assert_eq!(emitted.recommendation, wire_recommendation as i32);
    }
}

#[test]
fn maps_every_supported_ood_status_without_loss() {
    let cases = [
        (OodStatus::InDomain, DomainOodStatus::InDomain),
        (OodStatus::Borderline, DomainOodStatus::Borderline),
        (OodStatus::OutOfDomain, DomainOodStatus::OutOfDomain),
        (OodStatus::Unknown, DomainOodStatus::Unknown),
    ];

    for (wire_status, domain_status) in cases {
        let mut wire = complete_wire_record();
        wire.ood_status = Some(wire_status as i32);

        let boundary = VersionedDecisionRecord::try_from(wire).unwrap();
        let emitted = DecisionRecord::from(&boundary);

        assert_eq!(boundary.decision().ood_status(), &domain_status);
        assert_eq!(emitted.ood_status, Some(wire_status as i32));
    }
}

#[test]
#[allow(deprecated)]
fn maps_frozen_historical_wire_without_ood_status_to_explicit_unknown() {
    let historical = DecisionRecord::decode(COMPLETE_LEGACY_WIRE_WITHOUT_OOD_STATUS).unwrap();

    assert_eq!(historical.evidence_snapshot_id, "ES-001");
    assert_eq!(historical.evidence.as_ref().unwrap().id, "ES-001");
    assert_eq!(historical.ood_status, None);
    assert_eq!(historical.ood_detector, None);
    assert_eq!(historical.prediction_interval, None);

    let boundary = VersionedDecisionRecord::try_from(historical).unwrap();
    let emitted = DecisionRecord::from(&boundary);

    assert_eq!(boundary.decision().ood_status(), &DomainOodStatus::Unknown);
    assert_eq!(emitted.ood_status, Some(OodStatus::Unknown as i32));
    assert_eq!(boundary.decision().ood_detector(), None);
    assert_eq!(emitted.ood_detector, None);
    assert_eq!(boundary.decision().prediction_interval(), None);
    assert_eq!(emitted.prediction_interval, None);
}

#[test]
fn maps_frozen_m31_wire_without_detector_metadata_without_backfill() {
    let historical = DecisionRecord::decode(M31_WIRE_WITHOUT_OOD_DETECTOR).unwrap();

    assert_eq!(historical.ood_status, Some(OodStatus::OutOfDomain as i32));
    assert_eq!(historical.ood_detector, None);

    let boundary = VersionedDecisionRecord::try_from(historical).unwrap();
    let emitted = DecisionRecord::from(&boundary);

    assert_eq!(
        boundary.decision().ood_status(),
        &DomainOodStatus::OutOfDomain
    );
    assert_eq!(boundary.decision().ood_detector(), None);
    assert_eq!(emitted.ood_status, Some(OodStatus::OutOfDomain as i32));
    assert_eq!(emitted.ood_detector, None);
}

#[test]
fn preserves_frozen_ood_provenance_wire_without_interval_backfill() {
    let historical =
        DecisionRecord::decode(FROZEN_WIRE_WITH_OOD_PROVENANCE_WITHOUT_INTERVAL).unwrap();

    assert_eq!(historical.ood_status, Some(OodStatus::Borderline as i32));
    assert_eq!(
        historical.ood_detector,
        Some(OodDetectorRef {
            detector_id: "mahalanobis".to_owned(),
            detector_version: "model-2026.07".to_owned(),
        })
    );
    assert_eq!(historical.prediction_interval, None);
    assert_eq!(
        historical.encode_to_vec(),
        FROZEN_WIRE_WITH_OOD_PROVENANCE_WITHOUT_INTERVAL
    );

    let boundary = VersionedDecisionRecord::try_from(historical).unwrap();
    let emitted = DecisionRecord::from(&boundary);

    assert_eq!(boundary.decision().prediction_interval(), None);
    assert_eq!(emitted.prediction_interval, None);
    assert_eq!(
        emitted.encode_to_vec(),
        FROZEN_WIRE_WITH_OOD_PROVENANCE_WITHOUT_INTERVAL
    );
}

#[test]
fn preserves_frozen_m33_interval_wire_without_position_backfill() {
    let frozen = [
        FROZEN_WIRE_WITH_OOD_PROVENANCE_WITHOUT_INTERVAL,
        FROZEN_M33_PREDICTION_INTERVAL_FIELD,
    ]
    .concat();
    let mut expected = complete_wire_record();
    expected.prediction_interval = Some(complete_prediction_interval());
    assert_eq!(expected.encode_to_vec(), frozen);

    let historical = DecisionRecord::decode(frozen.as_slice()).unwrap();

    assert!(historical.prediction_interval.is_some());
    assert!(historical.prediction_positions.is_empty());
    assert_eq!(historical.encode_to_vec(), frozen);

    let boundary = VersionedDecisionRecord::try_from(historical).unwrap();
    let emitted = DecisionRecord::from(&boundary);

    assert!(boundary.decision().prediction_interval().is_some());
    assert!(boundary.decision().prediction_positions().is_empty());
    assert!(emitted.prediction_interval.is_some());
    assert!(emitted.prediction_positions.is_empty());
    assert_eq!(emitted.encode_to_vec(), frozen);
}

#[test]
fn preserves_frozen_m34_position_wire_without_criterion_backfill() {
    let frozen = [
        FROZEN_WIRE_WITH_OOD_PROVENANCE_WITHOUT_INTERVAL,
        FROZEN_M33_PREDICTION_INTERVAL_FIELD,
        FROZEN_M34_PREDICTION_POSITIONS_FIELD,
    ]
    .concat();
    let historical = DecisionRecord::decode(frozen.as_slice()).unwrap();

    assert_eq!(historical.decision_criterion, None);
    assert_eq!(historical.encode_to_vec(), frozen);

    let boundary = VersionedDecisionRecord::try_from(historical).unwrap();
    let emitted = DecisionRecord::from(&boundary);

    assert!(boundary.decision().decision_criterion().is_none());
    assert_eq!(emitted.decision_criterion, None);
    assert_eq!(emitted.encode_to_vec(), frozen);
}

#[test]
fn preserves_frozen_m35_wire_with_decision_criterion() {
    let frozen = [
        FROZEN_WIRE_WITH_OOD_PROVENANCE_WITHOUT_INTERVAL,
        FROZEN_M33_PREDICTION_INTERVAL_FIELD,
        FROZEN_M34_PREDICTION_POSITIONS_FIELD,
        FROZEN_M35_DECISION_CRITERION_FIELD,
    ]
    .concat();
    let current = DecisionRecord::decode(frozen.as_slice()).unwrap();

    assert_eq!(
        current.decision_criterion,
        Some(complete_decision_criterion(
            DecisionCriterionComparator::LessThanOrEqual,
        )),
    );
    assert_eq!(current.encode_to_vec(), frozen);

    let boundary = VersionedDecisionRecord::try_from(current).unwrap();
    let emitted = DecisionRecord::from(&boundary);

    assert_eq!(emitted.encode_to_vec(), frozen);
}

#[test]
fn rejects_unspecified_and_unknown_ood_statuses_distinctly() {
    let mut unspecified = complete_wire_record();
    unspecified.ood_status = Some(OodStatus::Unspecified as i32);
    let mut unknown = complete_wire_record();
    unknown.ood_status = Some(99);

    assert_eq!(
        VersionedDecisionRecord::try_from(unspecified),
        Err(DecisionContractError::UnspecifiedOodStatus),
    );
    assert_eq!(
        VersionedDecisionRecord::try_from(unknown),
        Err(DecisionContractError::UnknownOodStatus(99)),
    );
}

#[test]
#[allow(deprecated)]
fn backfills_legacy_evidence_id_when_emitting_new_records() {
    let mut wire = complete_wire_record();
    wire.evidence_snapshot_id.clear();

    let boundary = VersionedDecisionRecord::try_from(wire).unwrap();
    let emitted = DecisionRecord::from(&boundary);

    assert_eq!(emitted.evidence_snapshot_id, "ES-001");
    assert_eq!(emitted.evidence.unwrap().id, "ES-001");
}
