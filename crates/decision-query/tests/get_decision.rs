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
    v2::{DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest, Recommendation},
};
use bioworld_decision_query::{
    GetDecision, GetDecisionError, GetDecisionQuery, GetDecisionRequestError, LatestDecisionFuture,
    LatestDecisionSource, LatestDecisionSourceError,
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
    assert_error::<LatestDecisionSourceError>();

    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let mut source = RecordingSource {
        calls: Arc::new(AtomicUsize::new(0)),
        query: Arc::new(Mutex::new(None)),
        result: Ok(None),
    };
    assert_value_is_send(source.read_latest(GetDecisionQuery::new(decision_id)));
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
