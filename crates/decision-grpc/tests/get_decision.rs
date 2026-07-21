use std::{
    future::Future,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bioworld_contracts::v2::{
    DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest, Recommendation,
};
use bioworld_decision_grpc::get_decision;
use bioworld_decision_query::{
    GetDecision, GetDecisionQuery, LatestDecisionFuture, LatestDecisionSource,
    LatestDecisionSourceError,
};
use tonic::{Code, Request, Status};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";

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

struct RecordingSource {
    calls: Arc<AtomicUsize>,
    result: Result<Option<DecisionRecord>, LatestDecisionSourceError>,
}

impl LatestDecisionSource for RecordingSource {
    fn read_latest(&mut self, _query: GetDecisionQuery) -> LatestDecisionFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self.result.clone();
        Box::pin(async move { result })
    }
}

#[allow(deprecated)]
fn record(aggregate_version: u64) -> DecisionRecord {
    DecisionRecord {
        decision_id: DECISION_ID.to_owned(),
        cou_id: "COU-GRPC-001".to_owned(),
        evidence_snapshot_id: "ES-GRPC-001".to_owned(),
        recommendation: Recommendation::Defer as i32,
        rationale: vec!["Additional evidence is required.".to_owned()],
        aggregate_version,
        evidence: Some(EvidenceSnapshotRef {
            id: "ES-GRPC-001".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        }),
    }
}

fn assert_public_status(status: &Status, code: Code, message: &str) {
    assert_eq!(status.code(), code);
    assert_eq!(status.message(), message);
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
}

#[test]
fn returns_the_exact_canonical_response_after_one_read() {
    let expected = record(u64::MAX);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handler = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        result: Ok(Some(expected.clone())),
    });
    let mut request = Request::new(GetDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    });
    request
        .metadata_mut()
        .insert("x-request-secret", "private".parse().unwrap());

    let response = block_on_ready(get_decision(&mut handler, request)).unwrap();

    assert_eq!(response.get_ref(), &expected);
    assert_eq!(response.get_ref().aggregate_version, u64::MAX);
    assert!(response.metadata().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn rejects_invalid_input_before_source_access() {
    let submitted = "sensitive-invalid-decision-id";
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handler = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        result: Ok(Some(record(1))),
    });

    let result = block_on_ready(get_decision(
        &mut handler,
        Request::new(GetDecisionRequest {
            decision_id: submitted.to_owned(),
        }),
    ));
    let status = result.expect_err("invalid request must fail");

    assert_public_status(
        &status,
        Code::InvalidArgument,
        "decision request is invalid",
    );
    assert!(!format!("{status:?} {status}").contains(submitted));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn maps_absence_to_not_found_after_one_read() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handler = GetDecision::new(RecordingSource {
        calls: Arc::clone(&calls),
        result: Ok(None),
    });

    let result = block_on_ready(get_decision(
        &mut handler,
        Request::new(GetDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        }),
    ));
    let status = result.expect_err("absent decision must fail");

    assert_public_status(&status, Code::NotFound, "decision was not found");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn coalesces_internal_failures_into_one_public_status() {
    for source_error in [
        LatestDecisionSourceError::Unavailable,
        LatestDecisionSourceError::StoredStateRejected,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handler = GetDecision::new(RecordingSource {
            calls: Arc::clone(&calls),
            result: Err(source_error),
        });

        let result = block_on_ready(get_decision(
            &mut handler,
            Request::new(GetDecisionRequest {
                decision_id: DECISION_ID.to_owned(),
            }),
        ));
        let status = result.expect_err("internal failure must fail");

        assert_public_status(
            &status,
            Code::Unavailable,
            "decision service is unavailable",
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn adapter_future_is_send() {
    fn assert_send<T: Send>(_: T) {}

    let mut handler = GetDecision::new(RecordingSource {
        calls: Arc::new(AtomicUsize::new(0)),
        result: Ok(None),
    });

    assert_send(get_decision(
        &mut handler,
        Request::new(GetDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        }),
    ));
}
