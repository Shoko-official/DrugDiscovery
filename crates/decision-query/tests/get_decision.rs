use std::{
    future::Future,
    pin::pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bioworld_contracts::{
    VersionedDecisionRecord,
    v2::{
        DecisionPredictionInterval, DecisionPredictionPosition, DecisionRecord,
        EvidenceSnapshotRef, GetDecisionRequest, OodDetectorRef, OodStatus, Recommendation,
    },
};
use bioworld_decision_query::{
    GetDecision, GetDecisionError, GetDecisionQuery, GetDecisionRequestError,
    GetDecisionRequestExecutionError, LatestDecisionFuture, LatestDecisionSource,
    LatestDecisionSourceError,
};
use uuid::Uuid;

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly remained pending"),
    }
}

#[test]
fn converts_each_canonical_request_into_the_exact_typed_query() {
    let canonical_identifiers = [
        "00000000-0000-0000-0000-000000000000",
        "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ];

    for decision_id in canonical_identifiers {
        let request = GetDecisionRequest {
            decision_id: decision_id.to_owned(),
        };

        let query =
            GetDecisionQuery::try_from(request).expect("canonical request must be accepted");

        assert_eq!(query.decision_id(), Uuid::parse_str(decision_id).unwrap());
    }
}

#[test]
fn rejects_every_non_canonical_request_identifier() {
    let canonical = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
    let invalid_identifiers = [
        "",
        "invalid-decision-id",
        "018F5A72-9C4B-7D31-8F6A-26F08F3F4D99",
        "018f5a72-9C4B-7d31-8f6a-26f08f3f4d99",
        "018f5a729c4b7d318f6a26f08f3f4d99",
        "{018f5a72-9c4b-7d31-8f6a-26f08f3f4d99}",
        "urn:uuid:018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        "   ",
        " 018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99 ",
    ];

    for decision_id in invalid_identifiers {
        let result = GetDecisionQuery::try_from(GetDecisionRequest {
            decision_id: decision_id.to_owned(),
        });
        let error = result.err().expect("non-canonical request must fail");
        let rendered = format!("{error:?} {error}");

        assert_eq!(error, GetDecisionRequestError::InvalidDecisionId);
        if !decision_id.is_empty() {
            assert!(!rendered.contains(decision_id));
        }
        assert!(!rendered.contains(canonical));
    }
}

#[test]
fn request_error_is_fixed_redacted_and_thread_safe() {
    fn assert_error<T: std::error::Error + Send + Sync + Copy>() {}

    assert_error::<GetDecisionRequestError>();

    let submitted = "sensitive-invalid-decision-id";
    let result = GetDecisionQuery::try_from(GetDecisionRequest {
        decision_id: submitted.to_owned(),
    });
    let error = result.err().expect("invalid request must fail");
    let rendered = format!("{error:?} {error}");

    assert_eq!(error, GetDecisionRequestError::InvalidDecisionId);
    assert_eq!(error.to_string(), "decision request identifier is invalid");
    assert_eq!(format!("{error:?}"), "InvalidDecisionId");
    assert!(!rendered.contains(submitted));
}

struct RecordingSource {
    calls: Arc<AtomicUsize>,
    query: Arc<Mutex<Option<GetDecisionQuery>>>,
    result: Result<Option<DecisionRecord>, LatestDecisionSourceError>,
}

impl LatestDecisionSource for RecordingSource {
    fn read_latest(&mut self, query: GetDecisionQuery) -> LatestDecisionFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.query.lock().expect("query recorder must be usable") = Some(query);
        let result = self.result.clone();
        Box::pin(async move { result })
    }
}

struct BorrowingSource {
    calls: usize,
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

impl LatestDecisionSource for BorrowingSource {
    fn read_latest(&mut self, _query: GetDecisionQuery) -> LatestDecisionFuture<'_> {
        Box::pin(async move {
            self.calls += 1;
            Ok(None)
        })
    }
}

#[allow(deprecated)]
fn record(decision_id: String, aggregate_version: u64) -> DecisionRecord {
    DecisionRecord {
        decision_id,
        cou_id: "COU-QUERY-001".to_owned(),
        evidence_snapshot_id: "ES-QUERY-001".to_owned(),
        recommendation: Recommendation::Abstain as i32,
        rationale: vec!["Evidence remains incomplete.".to_owned()],
        aggregate_version,
        evidence: Some(EvidenceSnapshotRef {
            id: "ES-QUERY-001".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        }),
        ood_status: Some(OodStatus::OutOfDomain as i32),
        ood_detector: Some(OodDetectorRef {
            detector_id: "query-domain-detector".to_owned(),
            detector_version: "2026.07".to_owned(),
        }),
        prediction_interval: Some(prediction_interval("0.25", "1.5")),
        prediction_positions: prediction_positions(),
    }
}

#[test]
#[allow(deprecated)]
fn executes_a_canonical_request_once_and_returns_a_canonical_record() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let mut stored = record(decision_id.to_string(), u64::MAX);
    stored.evidence_snapshot_id.clear();
    let boundary = VersionedDecisionRecord::try_from(stored.clone()).unwrap();
    let expected = DecisionRecord::from(&boundary);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_query = Arc::new(Mutex::new(None));
    let mut get_decision = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        query: Arc::clone(&observed_query),
        result: Ok(Some(stored)),
    });

    let actual = block_on_ready(get_decision.execute_request(GetDecisionRequest {
        decision_id: decision_id.to_string(),
    }))
    .unwrap();

    assert_eq!(actual, expected);
    assert_eq!(actual.aggregate_version, u64::MAX);
    assert_eq!(actual.ood_status, Some(OodStatus::OutOfDomain as i32));
    assert_eq!(
        actual.prediction_interval,
        Some(prediction_interval("0.25", "1.5"))
    );
    assert_eq!(actual.prediction_positions, prediction_positions());
    assert_eq!(actual.evidence_snapshot_id, "ES-QUERY-001");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let observed_decision_id = observed_query
        .lock()
        .expect("query recorder must be usable")
        .as_ref()
        .map(|query| query.decision_id());
    assert_eq!(observed_decision_id, Some(decision_id));
}

#[test]
fn executes_a_prevalidated_query_once_and_returns_a_canonical_record() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let stored = record(decision_id.to_string(), u64::MAX);
    let expected =
        DecisionRecord::from(&VersionedDecisionRecord::try_from(stored.clone()).unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut get_decision = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        query: Arc::new(Mutex::new(None)),
        result: Ok(Some(stored)),
    });

    let actual =
        block_on_ready(get_decision.execute_validated(GetDecisionQuery::new(decision_id))).unwrap();

    assert_eq!(actual, expected);
    assert_eq!(actual.aggregate_version, u64::MAX);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn rejects_an_invalid_request_before_source_access() {
    let submitted = "sensitive-invalid-decision-id";
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_query = Arc::new(Mutex::new(None));
    let mut get_decision = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        query: Arc::clone(&observed_query),
        result: Ok(Some(record(
            "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99".to_owned(),
            1,
        ))),
    });

    let result = block_on_ready(get_decision.execute_request(GetDecisionRequest {
        decision_id: submitted.to_owned(),
    }));
    let error = result.expect_err("invalid request must fail");
    let rendered = format!("{error:?} {error}");

    assert_eq!(error, GetDecisionRequestExecutionError::InvalidRequest);
    assert!(!rendered.contains(submitted));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        observed_query
            .lock()
            .expect("query recorder must be usable")
            .is_none()
    );
}

#[test]
fn maps_an_absent_decision_to_not_found_after_one_read() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut get_decision = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        query: Arc::new(Mutex::new(None)),
        result: Ok(None),
    });

    let result = block_on_ready(get_decision.execute_request(GetDecisionRequest {
        decision_id: decision_id.to_string(),
    }));

    assert_eq!(result, Err(GetDecisionRequestExecutionError::NotFound));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn preserves_each_fixed_query_failure_after_one_read() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let cases = [
        (
            LatestDecisionSourceError::Unavailable,
            GetDecisionRequestExecutionError::SourceUnavailable,
        ),
        (
            LatestDecisionSourceError::StoredStateRejected,
            GetDecisionRequestExecutionError::StoredStateRejected,
        ),
    ];

    for (source_error, expected) in cases {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut get_decision = GetDecision::new(RecordingSource {
            calls: Arc::clone(&calls),
            query: Arc::new(Mutex::new(None)),
            result: Err(source_error),
        });

        let result = block_on_ready(get_decision.execute_request(GetDecisionRequest {
            decision_id: decision_id.to_string(),
        }));

        assert_eq!(result, Err(expected));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn maps_invalid_stored_state_to_a_fixed_rejected_state_error() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut get_decision = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        query: Arc::new(Mutex::new(None)),
        result: Ok(Some(record(decision_id.to_string(), 0))),
    });

    let result = block_on_ready(get_decision.execute_request(GetDecisionRequest {
        decision_id: decision_id.to_string(),
    }));

    assert_eq!(
        result,
        Err(GetDecisionRequestExecutionError::StoredStateRejected)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn request_execution_errors_are_fixed_redacted_and_thread_safe() {
    fn assert_error<T: std::error::Error + Send + Sync + Copy>() {}

    assert_error::<GetDecisionRequestExecutionError>();

    let cases = [
        (
            GetDecisionRequestExecutionError::InvalidRequest,
            "InvalidRequest",
            "decision request is invalid",
        ),
        (
            GetDecisionRequestExecutionError::NotFound,
            "NotFound",
            "decision was not found",
        ),
        (
            GetDecisionRequestExecutionError::SourceUnavailable,
            "SourceUnavailable",
            "decision source is unavailable",
        ),
        (
            GetDecisionRequestExecutionError::StoredStateRejected,
            "StoredStateRejected",
            "stored decision state was rejected",
        ),
    ];

    for (error, debug, display) in cases {
        assert_eq!(format!("{error:?}"), debug);
        assert_eq!(error.to_string(), display);
    }
}

#[test]
fn returns_the_exact_latest_decision_from_one_scoped_read() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let query = GetDecisionQuery::new(decision_id);
    let wire = record(decision_id.to_string(), u64::MAX);
    let expected = VersionedDecisionRecord::try_from(wire.clone()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_query = Arc::new(Mutex::new(None));
    let mut get_decision = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        query: Arc::clone(&observed_query),
        result: Ok(Some(wire)),
    });

    let actual = block_on_ready(get_decision.execute(query))
        .unwrap()
        .unwrap();

    assert_eq!(actual, expected);
    assert_eq!(actual.aggregate_version().get(), u64::MAX);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let observed_decision_id = observed_query
        .lock()
        .expect("query recorder must be usable")
        .as_ref()
        .map(|query| query.decision_id());
    assert_eq!(observed_decision_id, Some(decision_id));
}

#[test]
fn preserves_an_absent_latest_decision() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut get_decision = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        query: Arc::new(Mutex::new(None)),
        result: Ok(None),
    });

    let actual = block_on_ready(get_decision.execute(GetDecisionQuery::new(decision_id)));

    assert_eq!(actual, Ok(None));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn maps_source_unavailability_to_a_fixed_redacted_error() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut get_decision = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        query: Arc::new(Mutex::new(None)),
        result: Err(LatestDecisionSourceError::Unavailable),
    });

    let error = block_on_ready(get_decision.execute(GetDecisionQuery::new(decision_id)))
        .expect_err("unavailable source must fail the query");

    assert_eq!(error, GetDecisionError::SourceUnavailable);
    assert_eq!(error.to_string(), "decision source is unavailable");
    assert_eq!(format!("{error:?}"), "SourceUnavailable");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn maps_source_rejection_to_a_fixed_redacted_error() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut get_decision = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        query: Arc::new(Mutex::new(None)),
        result: Err(LatestDecisionSourceError::StoredStateRejected),
    });

    let error = block_on_ready(get_decision.execute(GetDecisionQuery::new(decision_id)))
        .expect_err("rejected stored state must fail the query");

    assert_eq!(error, GetDecisionError::StoredStateRejected);
    assert_eq!(error.to_string(), "stored decision state was rejected");
    assert_eq!(format!("{error:?}"), "StoredStateRejected");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn rejects_invalid_stored_state_after_one_read() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let canonical = decision_id.to_string();
    let version_zero = record(canonical.clone(), 0);
    let mut missing_evidence = record(canonical.clone(), 1);
    missing_evidence.evidence = None;
    let mut invalid_digest = record(canonical.clone(), 1);
    invalid_digest
        .evidence
        .as_mut()
        .expect("fixture evidence must exist")
        .sha256 = "sensitive-invalid-digest".to_owned();
    let mut unknown_recommendation = record(canonical.clone(), 1);
    unknown_recommendation.recommendation = i32::MAX;

    for invalid_record in [
        version_zero,
        missing_evidence,
        invalid_digest,
        unknown_recommendation,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut get_decision = GetDecision::new(RecordingSource {
            calls: Arc::clone(&calls),
            query: Arc::new(Mutex::new(None)),
            result: Ok(Some(invalid_record)),
        });

        let error = block_on_ready(get_decision.execute(GetDecisionQuery::new(decision_id)))
            .expect_err("invalid stored state must fail the query");
        let rendered = format!("{error:?} {error}");

        assert_eq!(error, GetDecisionError::StoredStateRejected);
        assert_eq!(error.to_string(), "stored decision state was rejected");
        assert_eq!(format!("{error:?}"), "StoredStateRejected");
        assert!(!rendered.contains(&canonical));
        assert!(!rendered.contains("sensitive-invalid-digest"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn rejects_every_non_exact_stored_decision_identity_after_one_read() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let canonical = decision_id.to_string();
    let identities = [
        "invalid-decision-id".to_owned(),
        canonical.to_ascii_uppercase(),
        canonical.replace('-', ""),
        "018f5a72-9c4b-7d31-8f6a-26f08f3f4d98".to_owned(),
    ];

    for stored_identity in identities {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut get_decision = GetDecision::new(RecordingSource {
            calls: Arc::clone(&calls),
            query: Arc::new(Mutex::new(None)),
            result: Ok(Some(record(stored_identity.clone(), 1))),
        });

        let error = block_on_ready(get_decision.execute(GetDecisionQuery::new(decision_id)))
            .expect_err("non-exact stored identity must fail the query");
        let rendered = format!("{error:?} {error}");

        assert_eq!(error, GetDecisionError::StoredStateRejected);
        assert!(!rendered.contains(&stored_identity));
        assert!(!rendered.contains(&canonical));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn query_execution_contracts_are_send() {
    fn assert_send<T: Send>() {}
    fn assert_error<T: std::error::Error + Send + Sync>() {}
    fn assert_value_is_send<T: Send>(_: T) {}

    assert_send::<GetDecisionQuery>();
    assert_send::<GetDecision<RecordingSource>>();
    assert_error::<GetDecisionError>();
    assert_error::<GetDecisionRequestExecutionError>();
    assert_error::<LatestDecisionSourceError>();

    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let mut source = RecordingSource {
        calls: Arc::new(AtomicUsize::new(0)),
        query: Arc::new(Mutex::new(None)),
        result: Ok(None),
    };
    assert_value_is_send(source.read_latest(GetDecisionQuery::new(decision_id)));

    let mut get_decision = GetDecision::new(RecordingSource {
        calls: Arc::new(AtomicUsize::new(0)),
        query: Arc::new(Mutex::new(None)),
        result: Ok(None),
    });
    assert_value_is_send(get_decision.execute_request(GetDecisionRequest {
        decision_id: decision_id.to_string(),
    }));
}

#[test]
fn source_future_can_borrow_mutable_source_state() {
    fn assert_value_is_send<T: Send>(value: T) -> T {
        value
    }

    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let mut source = BorrowingSource { calls: 0 };
    let future = assert_value_is_send(source.read_latest(GetDecisionQuery::new(decision_id)));

    assert_eq!(block_on_ready(future), Ok(None));
    assert_eq!(source.calls, 1);
}
