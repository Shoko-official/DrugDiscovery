use std::{
    error::Error,
    future::Future,
    pin::pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bioworld_contracts::{
    MAX_DECISION_WIRE_BYTES, MAX_TENANT_ID_BYTES,
    v2::{
        DecisionPredictionInterval, DecisionPredictionPosition, DecisionRecord,
        EvidenceSnapshotRef, GetDecisionRequest, OodDetectorRef, OodStatus, Recommendation,
    },
};
use bioworld_decision_grpc::{
    InvalidTenantScope, TenantScope, TenantScopedGetDecisionExecutor,
    TenantScopedGetDecisionFuture, get_decision,
};
use bioworld_decision_query::{GetDecisionQuery, GetDecisionRequestExecutionError};
use tonic::{Code, Request, Status};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
type ObservedExecutions = Arc<Mutex<Vec<(String, String)>>>;
type ExecutorHarness = (RecordingExecutor, Arc<AtomicUsize>, ObservedExecutions);

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

struct RecordingExecutor {
    calls: Arc<AtomicUsize>,
    observed: ObservedExecutions,
    result: Result<DecisionRecord, GetDecisionRequestExecutionError>,
}

impl TenantScopedGetDecisionExecutor for RecordingExecutor {
    fn execute_get_decision(
        &self,
        scope: TenantScope,
        query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.observed.lock().unwrap().push((
            scope.tenant_id().to_owned(),
            query.decision_id().to_string(),
        ));
        let result = self.result.clone();
        Box::pin(async move { result })
    }
}

fn executor(result: Result<DecisionRecord, GetDecisionRequestExecutionError>) -> ExecutorHarness {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    (
        RecordingExecutor {
            calls: Arc::clone(&calls),
            observed: Arc::clone(&observed),
            result,
        },
        calls,
        observed,
    )
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
        ood_status: Some(OodStatus::Borderline as i32),
        ood_detector: Some(OodDetectorRef {
            detector_id: "grpc-domain-detector".to_owned(),
            detector_version: "2026.07".to_owned(),
        }),
        prediction_interval: Some(prediction_interval("0.25", "1.5")),
        prediction_positions: prediction_positions(),
    }
}

fn request() -> Request<GetDecisionRequest> {
    Request::new(GetDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    })
}

fn scope(tenant_id: &str) -> TenantScope {
    TenantScope::try_from_trusted_tenant_id(tenant_id.to_owned()).unwrap()
}

fn assert_public_status(status: &Status, code: Code, message: &str) {
    assert_eq!(status.code(), code);
    assert_eq!(status.message(), message);
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
}

#[test]
fn passes_the_exact_scope_and_typed_query_once() {
    let expected = record(u64::MAX);
    let (executor, calls, observed) = executor(Ok(expected.clone()));
    let mut request = request();
    request
        .metadata_mut()
        .insert("x-tenant-id", "attacker-tenant".parse().unwrap());

    let response =
        block_on_ready(get_decision(&executor, scope("trusted-tenant"), request)).unwrap();

    assert_eq!(response.get_ref(), &expected);
    assert_eq!(response.get_ref().aggregate_version, u64::MAX);
    assert_eq!(
        response.get_ref().ood_status,
        Some(OodStatus::Borderline as i32)
    );
    assert_eq!(
        response.get_ref().prediction_interval,
        Some(prediction_interval("0.25", "1.5"))
    );
    assert_eq!(
        response.get_ref().prediction_positions,
        prediction_positions()
    );
    assert!(response.metadata().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *observed.lock().unwrap(),
        vec![("trusted-tenant".to_owned(), DECISION_ID.to_owned())]
    );
}

#[test]
fn rejects_invalid_request_before_executor_access() {
    let submitted = "sensitive-invalid-decision-id";
    let (executor, calls, observed) = executor(Ok(record(1)));

    let result = block_on_ready(get_decision(
        &executor,
        scope("trusted-tenant"),
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
    assert!(observed.lock().unwrap().is_empty());
}

#[test]
fn rejects_oversized_executor_responses_with_a_fixed_status() {
    let sensitive = "x".repeat(MAX_DECISION_WIRE_BYTES + 1);
    let mut response = record(1);
    response.rationale = vec![sensitive.clone()];
    let (executor, calls, _) = executor(Ok(response));

    let result = block_on_ready(get_decision(&executor, scope("trusted-tenant"), request()));
    let status = match result {
        Ok(_) => panic!("oversized executor response must fail"),
        Err(status) => status,
    };

    assert_public_status(
        &status,
        Code::Unavailable,
        "decision service is unavailable",
    );
    assert!(!format!("{status:?} {status}").contains(&sensitive));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
#[allow(deprecated)]
fn canonicalizes_valid_executor_responses() {
    let mut response = record(1);
    response.decision_id.make_ascii_uppercase();
    response.evidence_snapshot_id.clear();
    let (executor, _, _) = executor(Ok(response));

    let response = block_on_ready(get_decision(&executor, scope("trusted-tenant"), request()))
        .unwrap()
        .into_inner();

    assert_eq!(response.decision_id, DECISION_ID);
    assert_eq!(response.evidence_snapshot_id, "ES-GRPC-001");
}

#[test]
fn keeps_the_same_query_distinct_across_scopes() {
    let (executor, calls, observed) = executor(Ok(record(7)));

    block_on_ready(get_decision(&executor, scope("tenant-a"), request())).unwrap();
    block_on_ready(get_decision(&executor, scope("tenant-b"), request())).unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        *observed.lock().unwrap(),
        vec![
            ("tenant-a".to_owned(), DECISION_ID.to_owned()),
            ("tenant-b".to_owned(), DECISION_ID.to_owned()),
        ]
    );
}

#[test]
fn rejects_invalid_trusted_scopes_without_reflection() {
    fn assert_error<T: Error + Send + Sync + Copy>(_: T) {}

    for submitted in ["", " ", " tenant-a", "tenant-a ", "tenant\0secret"] {
        let error = match TenantScope::try_from_trusted_tenant_id(submitted.to_owned()) {
            Ok(_) => panic!("invalid scope must fail"),
            Err(error) => error,
        };

        assert_eq!(error, InvalidTenantScope);
        assert_eq!(format!("{error:?}"), "InvalidTenantScope");
        assert_eq!(error.to_string(), "tenant scope is invalid");
        assert_error(error);
    }
}

#[test]
fn bounds_trusted_tenant_scopes() {
    let exact = "t".repeat(MAX_TENANT_ID_BYTES);
    let oversized = "t".repeat(MAX_TENANT_ID_BYTES + 1);

    assert_eq!(
        TenantScope::try_from_trusted_tenant_id(exact)
            .unwrap()
            .tenant_id()
            .len(),
        MAX_TENANT_ID_BYTES,
    );
    assert!(TenantScope::try_from_trusted_tenant_id(oversized).is_err());
}

#[test]
fn maps_application_outcomes_to_fixed_public_statuses() {
    for (application_error, code, message) in [
        (
            GetDecisionRequestExecutionError::NotFound,
            Code::NotFound,
            "decision was not found",
        ),
        (
            GetDecisionRequestExecutionError::SourceUnavailable,
            Code::Unavailable,
            "decision service is unavailable",
        ),
        (
            GetDecisionRequestExecutionError::StoredStateRejected,
            Code::Unavailable,
            "decision service is unavailable",
        ),
    ] {
        let (executor, calls, _) = executor(Err(application_error));

        let result = block_on_ready(get_decision(&executor, scope("trusted-tenant"), request()));
        let status = result.expect_err("application error must fail");

        assert_public_status(&status, code, message);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn scoped_adapter_futures_are_send_and_executor_is_sync() {
    fn assert_send<T: Send>(_: T) {}
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<RecordingExecutor>();
    assert_send_sync::<TenantScope>();

    let (executor, _, _) = executor(Ok(record(1)));
    let tenant_a = get_decision(&executor, scope("tenant-a"), request());
    let tenant_b = get_decision(&executor, scope("tenant-b"), request());

    assert_send((tenant_a, tenant_b));
}
