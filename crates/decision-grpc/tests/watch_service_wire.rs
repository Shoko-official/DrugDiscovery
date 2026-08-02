use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bioworld_contracts::{
    VersionedDecisionRecord,
    v2::{
        DecisionCriterion, DecisionCriterionComparator, DecisionEvent, DecisionPredictionInterval,
        DecisionPredictionPosition, DecisionRecord, EvidenceSnapshotRef, OodDetectorRef, OodStatus,
        Recommendation, WatchDecisionRequest,
    },
};
use bioworld_decision_grpc::{
    AuthenticateTenantFuture, DecisionGrpcService, DecisionGrpcServiceConfig,
    DecisionGrpcWatchConfig, MAX_DECISION_EVENT_WIRE_BYTES, TenantAuthenticationContext,
    TenantAuthenticator, TenantAuthority, TenantScope, TenantScopedGetDecisionExecutor,
    TenantScopedGetDecisionFuture, TenantScopedWatchDecisionExecutor,
};
use bioworld_decision_query::{
    DecisionReplay, DecisionReplayPageSize, DecisionReplaySource, DecisionReplaySourceFuture,
    DecisionReplaySourcePage, GetDecisionQuery, GetDecisionRequestExecutionError,
    WatchDecisionQuery,
};
use http_body_util::{BodyExt, Full};
use prost::Message;
use tokio::time::Instant;
use tonic::codegen::{Bytes, Service, http};

const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
const EVENT_ID: &str = "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba";
const SENSITIVE_OVERSIZED_MARKER: &str = "sensitive-oversized-watch-event";
const MAXIMAL_VALID_DECISION_WIRE_BYTES: usize = 50_769;
const MAXIMAL_VALID_EVENT_WIRE_BYTES: usize = 50_811;

struct StaticAuthenticator;

impl TenantAuthenticator for StaticAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        _context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        Box::pin(async {
            Ok(TenantAuthority::try_new(
                "trusted-tenant".to_owned(),
                Instant::now() + Duration::from_secs(60),
            )
            .expect("test authority must be valid"))
        })
    }
}

struct SingleEventSource {
    event: Option<DecisionEvent>,
    reads: Arc<AtomicUsize>,
}

impl DecisionReplaySource for SingleEventSource {
    type Continuation = ();

    fn read_page<'a>(
        &'a mut self,
        _query: WatchDecisionQuery,
        _page_size: DecisionReplayPageSize,
        _continuation: Option<&'a Self::Continuation>,
    ) -> DecisionReplaySourceFuture<'a, Self::Continuation> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let event = self
            .event
            .take()
            .expect("single-event source must be read once");
        Box::pin(async move { Ok(DecisionReplaySourcePage::new(vec![event], None::<()>)) })
    }
}

struct WireExecutor {
    source: Mutex<Option<SingleEventSource>>,
}

impl TenantScopedGetDecisionExecutor for WireExecutor {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        Box::pin(async { Err(GetDecisionRequestExecutionError::NotFound) })
    }
}

impl TenantScopedWatchDecisionExecutor for WireExecutor {
    type Source = SingleEventSource;

    fn execute_watch_decision(
        &self,
        _scope: TenantScope,
        query: WatchDecisionQuery,
        page_size: DecisionReplayPageSize,
    ) -> DecisionReplay<Self::Source> {
        let source = self
            .source
            .lock()
            .unwrap()
            .take()
            .expect("Watch executor must be called once");
        DecisionReplay::new(source, query, page_size)
    }
}

fn maximal_evidence() -> EvidenceSnapshotRef {
    EvidenceSnapshotRef {
        id: "🧬".repeat(200),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
    }
}

fn maximal_interval() -> DecisionPredictionInterval {
    DecisionPredictionInterval {
        target: "t".repeat(200),
        unit: "u".repeat(200),
        lower_decimal: format!("-{}", "9".repeat(63)),
        upper_decimal: "9".repeat(64),
        nominal_coverage_decimal: format!("0.{}", "1".repeat(62)),
        interval_method_id: "i".repeat(200),
        interval_method_version: "v".repeat(200),
        calibration_method_id: "c".repeat(200),
        calibration_method_version: "m".repeat(200),
        calibration_evidence: Some(maximal_evidence()),
    }
}

fn maximal_position(suffix: char) -> DecisionPredictionPosition {
    DecisionPredictionPosition {
        source_id: format!("{}{suffix}", "s".repeat(199)),
        source_version: "v".repeat(200),
        dependency_group_id: "g".repeat(200),
        interval: Some(maximal_interval()),
        prediction_evidence: Some(maximal_evidence()),
    }
}

#[allow(deprecated)]
fn maximal_valid_event() -> DecisionEvent {
    let evidence = maximal_evidence();
    DecisionEvent {
        decision: Some(DecisionRecord {
            decision_id: DECISION_ID.to_owned(),
            cou_id: "🧬".repeat(200),
            evidence_snapshot_id: evidence.id.clone(),
            recommendation: Recommendation::StopProgram as i32,
            rationale: (0..32).map(|_| "r".repeat(1_024)).collect(),
            aggregate_version: u64::MAX,
            evidence: Some(evidence),
            ood_status: Some(OodStatus::Unknown as i32),
            ood_detector: Some(OodDetectorRef {
                detector_id: "d".repeat(200),
                detector_version: "v".repeat(200),
            }),
            prediction_interval: Some(maximal_interval()),
            prediction_positions: ['a', 'b', 'c'].into_iter().map(maximal_position).collect(),
            decision_criterion: Some(DecisionCriterion {
                criterion_id: "c".repeat(200),
                criterion_version: "v".repeat(200),
                comparator: DecisionCriterionComparator::GreaterThanOrEqual as i32,
                threshold_decimal: "9".repeat(64),
                criterion_evidence: Some(maximal_evidence()),
            }),
        }),
        event_id: EVENT_ID.to_owned(),
    }
}

#[allow(deprecated)]
fn oversized_event_with_encoded_len(target: usize, marker: &str) -> DecisionEvent {
    let mut event = DecisionEvent {
        decision: Some(DecisionRecord {
            decision_id: DECISION_ID.to_owned(),
            cou_id: "COU-WATCH-WIRE-001".to_owned(),
            evidence_snapshot_id: String::new(),
            recommendation: Recommendation::Abstain as i32,
            rationale: Vec::new(),
            aggregate_version: 1,
            evidence: Some(EvidenceSnapshotRef {
                id: "ES-WATCH-WIRE-001".to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
            ood_status: None,
            ood_detector: None,
            prediction_interval: None,
            prediction_positions: Vec::new(),
            decision_criterion: None,
        }),
        event_id: EVENT_ID.to_owned(),
    };
    let mut padding_bytes = target;

    for _ in 0..8 {
        event.decision.as_mut().unwrap().rationale =
            vec![format!("{marker}{}", "x".repeat(padding_bytes))];
        match event.encoded_len().cmp(&target) {
            std::cmp::Ordering::Equal => return event,
            std::cmp::Ordering::Less => padding_bytes += target - event.encoded_len(),
            std::cmp::Ordering::Greater => {
                padding_bytes -= event.encoded_len() - target;
            }
        }
    }

    panic!("could not construct target event wire size");
}

fn framed_watch_request() -> http::Request<Full<Bytes>> {
    let encoded = WatchDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    }
    .encode_to_vec();
    let message_len = u32::try_from(encoded.len()).unwrap();
    let mut framed = Vec::with_capacity(encoded.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&message_len.to_be_bytes());
    framed.extend_from_slice(&encoded);

    http::Request::builder()
        .method("POST")
        .uri("/bioworld.v2.DecisionService/WatchDecision")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from(framed)))
        .unwrap()
}

struct CollectedResponse {
    headers: http::HeaderMap,
    trailers: http::HeaderMap,
    body: Bytes,
}

impl CollectedResponse {
    fn grpc_status(&self) -> &str {
        self.headers
            .get("grpc-status")
            .or_else(|| self.trailers.get("grpc-status"))
            .expect("gRPC response must contain a status")
            .to_str()
            .unwrap()
    }

    fn grpc_message(&self) -> &str {
        self.headers
            .get("grpc-message")
            .or_else(|| self.trailers.get("grpc-message"))
            .map_or("", |value| value.to_str().unwrap())
    }
}

async fn call_watch(event: DecisionEvent, reads: Arc<AtomicUsize>) -> CollectedResponse {
    let service = DecisionGrpcService::try_new_with_watch(
        StaticAuthenticator,
        WireExecutor {
            source: Mutex::new(Some(SingleEventSource {
                event: Some(event),
                reads,
            })),
        },
        DecisionGrpcServiceConfig::try_new(2, Duration::from_secs(5)).unwrap(),
        DecisionGrpcWatchConfig::try_new(1, 1).unwrap(),
    )
    .expect("test Watch configuration must be valid");
    let mut server = service.into_server();
    let response = Service::call(&mut server, framed_watch_request())
        .await
        .unwrap();
    let headers = response.headers().clone();
    let collected = response.into_body().collect().await.unwrap();
    let trailers = collected.trailers().cloned().unwrap_or_default();
    let body = collected.to_bytes();

    CollectedResponse {
        headers,
        trailers,
        body,
    }
}

#[tokio::test]
async fn generated_watch_server_emits_the_maximal_semantically_valid_event() {
    let event = maximal_valid_event();
    let decision = event
        .decision
        .as_ref()
        .expect("maximal event must contain a decision");
    assert_eq!(decision.cou_id.len(), 800);
    assert_eq!(decision.rationale.len(), 32);
    assert_eq!(
        decision.rationale.iter().map(String::len).sum::<usize>(),
        32_768
    );
    assert_eq!(decision.prediction_positions.len(), 3);
    VersionedDecisionRecord::try_from(decision.clone())
        .expect("maximal event decision must remain semantically valid");
    assert_eq!(decision.encoded_len(), MAXIMAL_VALID_DECISION_WIRE_BYTES);
    assert_eq!(event.encoded_len(), MAXIMAL_VALID_EVENT_WIRE_BYTES);
    let reads = Arc::new(AtomicUsize::new(0));

    let response = call_watch(event, Arc::clone(&reads)).await;

    assert_eq!(response.grpc_status(), "0");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(response.body.len(), MAXIMAL_VALID_EVENT_WIRE_BYTES + 5);
    assert_eq!(response.body[0], 0);
    assert_eq!(
        u32::from_be_bytes(response.body[1..5].try_into().unwrap()) as usize,
        MAXIMAL_VALID_EVENT_WIRE_BYTES
    );
}

#[tokio::test]
async fn generated_watch_server_redacts_an_event_one_byte_over_the_limit() {
    let event = oversized_event_with_encoded_len(
        MAX_DECISION_EVENT_WIRE_BYTES + 1,
        SENSITIVE_OVERSIZED_MARKER,
    );
    assert_eq!(event.encoded_len(), MAX_DECISION_EVENT_WIRE_BYTES + 1);
    let reads = Arc::new(AtomicUsize::new(0));

    let response = call_watch(event, Arc::clone(&reads)).await;

    assert_eq!(response.grpc_status(), "14");
    assert_eq!(
        response.grpc_message(),
        "decision%20service%20is%20unavailable"
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(response.body.is_empty());
    for value in response.headers.values().chain(response.trailers.values()) {
        assert!(
            !value
                .as_bytes()
                .windows(SENSITIVE_OVERSIZED_MARKER.len())
                .any(|window| window == SENSITIVE_OVERSIZED_MARKER.as_bytes())
        );
    }
}
