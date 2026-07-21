use std::num::NonZeroU64;

use bioworld_contracts::{
    DecisionContractError, MAX_DECISION_WIRE_BYTES, VersionedDecisionRecord,
    v2::{DecisionRecord, EvidenceSnapshotRef, OodStatus, Recommendation},
};
use bioworld_domain::{
    DomainError, MAX_DECISION_RATIONALE_ITEMS, OodStatus as DomainOodStatus,
    Recommendation as DomainRecommendation,
};
use prost::Message;

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const COMPLETE_LEGACY_WIRE_WITHOUT_OOD_STATUS: &[u8] = b"\x0a\x24018f5a72-9c4b-7d31-8f6a-26f08f3f4d99\x12\x07COU-001\x1a\x06ES-001\x20\x05\x2a\x1fEvidence threshold was not met.\x30\x07\x3a\x4a\x0a\x06ES-001\x12\x400123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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

    let boundary = VersionedDecisionRecord::try_from(historical).unwrap();
    let emitted = DecisionRecord::from(&boundary);

    assert_eq!(boundary.decision().ood_status(), &DomainOodStatus::Unknown);
    assert_eq!(emitted.ood_status, Some(OodStatus::Unknown as i32));
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
