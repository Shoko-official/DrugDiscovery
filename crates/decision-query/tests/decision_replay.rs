use std::{
    collections::VecDeque,
    future::Future,
    pin::pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bioworld_contracts::v2::{
    DecisionCriterion, DecisionCriterionComparator, DecisionEvent, DecisionPredictionInterval,
    DecisionPredictionPosition, DecisionRecord, EvidenceSnapshotRef, OodDetectorRef, OodStatus,
    Recommendation, WatchDecisionRequest,
};
use bioworld_decision_query::{
    DecisionReplay, DecisionReplayError, DecisionReplayPageSize, DecisionReplaySource,
    DecisionReplaySourceError, DecisionReplaySourceFuture, DecisionReplaySourcePage,
    InvalidDecisionReplayPageSize, MAX_DECISION_REPLAY_PAGE_EVENTS, WatchDecisionQuery,
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

#[derive(Debug, Eq, PartialEq)]
struct Cursor(u64);

struct ScriptedSource {
    calls: Arc<AtomicUsize>,
    responses: VecDeque<Result<DecisionReplaySourcePage<Cursor>, DecisionReplaySourceError>>,
}

enum PolledResponse {
    Ready(Result<DecisionReplaySourcePage<Cursor>, DecisionReplaySourceError>),
    Pending,
}

#[derive(Debug, Eq, PartialEq)]
struct ObservedRead {
    decision_id: Uuid,
    page_size: usize,
    continuation: Option<u64>,
}

struct PolledSource {
    observations: Arc<Mutex<Vec<ObservedRead>>>,
    responses: VecDeque<PolledResponse>,
}

impl DecisionReplaySource for PolledSource {
    type Continuation = Cursor;

    fn read_page<'a>(
        &'a mut self,
        query: WatchDecisionQuery,
        page_size: DecisionReplayPageSize,
        continuation: Option<&'a Self::Continuation>,
    ) -> DecisionReplaySourceFuture<'a, Self::Continuation> {
        self.observations
            .lock()
            .expect("observation recorder must be usable")
            .push(ObservedRead {
                decision_id: query.decision_id(),
                page_size: page_size.get(),
                continuation: continuation.map(|cursor| cursor.0),
            });

        match self
            .responses
            .pop_front()
            .expect("polled replay response must exist")
        {
            PolledResponse::Ready(response) => Box::pin(async move { response }),
            PolledResponse::Pending => Box::pin(std::future::pending()),
        }
    }
}

impl DecisionReplaySource for ScriptedSource {
    type Continuation = Cursor;

    fn read_page<'a>(
        &'a mut self,
        _query: WatchDecisionQuery,
        _page_size: DecisionReplayPageSize,
        _continuation: Option<&'a Self::Continuation>,
    ) -> DecisionReplaySourceFuture<'a, Self::Continuation> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let response = self
            .responses
            .pop_front()
            .expect("scripted replay response must exist");
        Box::pin(async move { response })
    }
}

fn page_size(value: usize) -> DecisionReplayPageSize {
    DecisionReplayPageSize::try_from(value).expect("fixture page size must be valid")
}

#[allow(deprecated)]
fn event(decision_id: Uuid, event_id: &str, aggregate_version: u64) -> DecisionEvent {
    DecisionEvent {
        decision: Some(DecisionRecord {
            decision_id: decision_id.to_string(),
            cou_id: "COU-REPLAY-001".to_owned(),
            evidence_snapshot_id: String::new(),
            recommendation: Recommendation::Abstain as i32,
            rationale: vec!["Evidence remains incomplete.".to_owned()],
            aggregate_version,
            evidence: Some(EvidenceSnapshotRef {
                id: "ES-REPLAY-001".to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
            ood_status: None,
            ood_detector: None,
            prediction_interval: None,
            prediction_positions: Vec::new(),
            decision_criterion: None,
        }),
        event_id: event_id.to_owned(),
    }
}

#[test]
fn accepts_only_bounded_decision_replay_page_sizes() {
    for value in 1..=MAX_DECISION_REPLAY_PAGE_EVENTS {
        let page_size = DecisionReplayPageSize::try_from(value)
            .expect("bounded replay page size must be accepted");

        assert_eq!(page_size.get(), value);
    }

    for value in [0, MAX_DECISION_REPLAY_PAGE_EVENTS + 1, usize::MAX] {
        assert_eq!(
            DecisionReplayPageSize::try_from(value),
            Err(InvalidDecisionReplayPageSize)
        );
    }
}

#[test]
fn returns_an_exact_valid_final_page_then_stays_complete_without_more_source_reads() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let original = event(
        decision_id,
        "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba",
        u64::MAX,
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let source = ScriptedSource {
        calls: Arc::clone(&calls),
        responses: VecDeque::from([Ok(DecisionReplaySourcePage::new(
            vec![original.clone()],
            None,
        ))]),
    };
    let mut replay =
        DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(16));

    let page = block_on_ready(replay.next_page())
        .expect("valid final page must succeed")
        .expect("valid final page must be returned");

    assert_eq!(page.events(), &[original]);
    assert!(block_on_ready(replay.next_page()).unwrap().is_none());
    assert!(block_on_ready(replay.next_page()).unwrap().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn rejects_a_complete_page_with_any_non_canonical_event_id_and_stays_rejected() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let invalid_event_ids = [
        "",
        "sensitive-invalid-event-id",
        "0193A72E-71CC-7D40-B59C-F6EB4F0BF6BA",
        "0193a72e71cc7d40b59cf6eb4f0bf6ba",
        "{0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba}",
    ];

    for invalid_event_id in invalid_event_ids {
        for invalid_first in [false, true] {
            let valid = event(
                decision_id,
                "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba",
                if invalid_first { 2 } else { 1 },
            );
            let invalid = event(
                decision_id,
                invalid_event_id,
                if invalid_first { 1 } else { 2 },
            );
            let events = if invalid_first {
                vec![invalid, valid]
            } else {
                vec![valid, invalid]
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let source = ScriptedSource {
                calls: Arc::clone(&calls),
                responses: VecDeque::from([Ok(DecisionReplaySourcePage::new(events, None))]),
            };
            let mut replay =
                DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(2));

            let first_error = block_on_ready(replay.next_page())
                .expect_err("invalid event identity must reject the entire page");
            let rendered = format!("{first_error:?} {first_error}");

            assert_eq!(first_error, DecisionReplayError::StoredStateRejected);
            if !invalid_event_id.is_empty() {
                assert!(!rendered.contains(invalid_event_id));
            }
            assert_eq!(
                block_on_ready(replay.next_page()).err(),
                Some(DecisionReplayError::StoredStateRejected)
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn rejects_missing_invalid_or_non_exact_decisions_before_exposing_the_page() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let event_id = "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba";
    let mut missing_decision = event(decision_id, event_id, 1);
    missing_decision.decision = None;
    let mut different_decision = event(decision_id, event_id, 1);
    different_decision.decision.as_mut().unwrap().decision_id =
        "018f5a72-9c4b-7d31-8f6a-26f08f3f4d98".to_owned();
    let mut non_canonical_decision = event(decision_id, event_id, 1);
    non_canonical_decision
        .decision
        .as_mut()
        .unwrap()
        .decision_id = decision_id.to_string().to_ascii_uppercase();
    let mut zero_version = event(decision_id, event_id, 0);
    zero_version.decision.as_mut().unwrap().cou_id = "sensitive-zero-version".to_owned();
    let mut missing_evidence = event(decision_id, event_id, 1);
    missing_evidence.decision.as_mut().unwrap().evidence = None;

    for invalid_event in [
        missing_decision,
        different_decision,
        non_canonical_decision,
        zero_version,
        missing_evidence,
    ] {
        let source = ScriptedSource {
            calls: Arc::new(AtomicUsize::new(0)),
            responses: VecDeque::from([Ok(DecisionReplaySourcePage::new(
                vec![invalid_event],
                None,
            ))]),
        };
        let mut replay =
            DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(1));

        let error = block_on_ready(replay.next_page())
            .expect_err("invalid stored decision must reject the page");
        let rendered = format!("{error:?} {error}");

        assert_eq!(error, DecisionReplayError::StoredStateRejected);
        assert!(!rendered.contains(&decision_id.to_string()));
        assert!(!rendered.contains("sensitive-zero-version"));
    }
}

#[test]
fn rejects_a_source_page_larger_than_the_requested_bound() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let source = ScriptedSource {
        calls: Arc::new(AtomicUsize::new(0)),
        responses: VecDeque::from([Ok(DecisionReplaySourcePage::new(
            vec![
                event(decision_id, "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba", 1),
                event(decision_id, "0193a72e-71cc-7d40-b59c-f6eb4f0bf6bb", 2),
            ],
            None,
        ))]),
    };
    let mut replay =
        DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(1));

    assert_eq!(
        block_on_ready(replay.next_page()).err(),
        Some(DecisionReplayError::StoredStateRejected)
    );
}

#[test]
fn treats_an_initial_empty_page_without_continuation_as_fused_completion() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let source = ScriptedSource {
        calls: Arc::clone(&calls),
        responses: VecDeque::from([Ok(DecisionReplaySourcePage::new(Vec::new(), None))]),
    };
    let mut replay =
        DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(16));

    assert!(block_on_ready(replay.next_page()).unwrap().is_none());
    assert!(block_on_ready(replay.next_page()).unwrap().is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn rejects_an_empty_page_that_claims_a_continuation() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let source = ScriptedSource {
        calls: Arc::new(AtomicUsize::new(0)),
        responses: VecDeque::from([Ok(DecisionReplaySourcePage::new(
            Vec::new(),
            Some(Cursor(1)),
        ))]),
    };
    let mut replay =
        DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(16));

    assert_eq!(
        block_on_ready(replay.next_page()).err(),
        Some(DecisionReplayError::StoredStateRejected)
    );
}

#[test]
fn rejects_an_empty_page_after_replay_has_advanced() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let source = ScriptedSource {
        calls: Arc::new(AtomicUsize::new(0)),
        responses: VecDeque::from([
            Ok(DecisionReplaySourcePage::new(
                vec![event(
                    decision_id,
                    "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba",
                    1,
                )],
                Some(Cursor(1)),
            )),
            Ok(DecisionReplaySourcePage::new(Vec::new(), None)),
        ]),
    };
    let mut replay =
        DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(1));

    assert!(block_on_ready(replay.next_page()).unwrap().is_some());
    assert_eq!(
        block_on_ready(replay.next_page()).err(),
        Some(DecisionReplayError::StoredStateRejected)
    );
}

#[test]
fn rejects_duplicate_or_descending_versions_within_and_across_pages() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let first_event_id = "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba";
    let second_event_id = "0193a72e-71cc-7d40-b59c-f6eb4f0bf6bb";

    for versions in [[1, 1], [2, 1]] {
        let source = ScriptedSource {
            calls: Arc::new(AtomicUsize::new(0)),
            responses: VecDeque::from([Ok(DecisionReplaySourcePage::new(
                vec![
                    event(decision_id, first_event_id, versions[0]),
                    event(decision_id, second_event_id, versions[1]),
                ],
                None,
            ))]),
        };
        let mut replay =
            DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(2));

        assert_eq!(
            block_on_ready(replay.next_page()).err(),
            Some(DecisionReplayError::StoredStateRejected)
        );
    }

    for versions in [[1, 1], [2, 1]] {
        let source = ScriptedSource {
            calls: Arc::new(AtomicUsize::new(0)),
            responses: VecDeque::from([
                Ok(DecisionReplaySourcePage::new(
                    vec![event(decision_id, first_event_id, versions[0])],
                    Some(Cursor(versions[0])),
                )),
                Ok(DecisionReplaySourcePage::new(
                    vec![event(decision_id, second_event_id, versions[1])],
                    None,
                )),
            ]),
        };
        let mut replay =
            DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(1));

        assert!(block_on_ready(replay.next_page()).unwrap().is_some());
        assert_eq!(
            block_on_ready(replay.next_page()).err(),
            Some(DecisionReplayError::StoredStateRejected)
        );
    }
}

#[test]
fn retries_unavailability_from_the_same_opaque_cursor_and_accepts_version_gaps() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let first = event(decision_id, "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba", 3);
    let final_event = event(
        decision_id,
        "0193a72e-71cc-7d40-b59c-f6eb4f0bf6bb",
        u64::MAX,
    );
    let observations = Arc::new(Mutex::new(Vec::new()));
    let source = PolledSource {
        observations: Arc::clone(&observations),
        responses: VecDeque::from([
            PolledResponse::Ready(Ok(DecisionReplaySourcePage::new(
                vec![first.clone()],
                Some(Cursor(73)),
            ))),
            PolledResponse::Ready(Err(DecisionReplaySourceError::Unavailable)),
            PolledResponse::Ready(Ok(DecisionReplaySourcePage::new(
                vec![final_event.clone()],
                None,
            ))),
        ]),
    };
    let mut replay =
        DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(16));

    assert_eq!(
        block_on_ready(replay.next_page())
            .unwrap()
            .unwrap()
            .events(),
        &[first]
    );
    assert_eq!(
        block_on_ready(replay.next_page()).err(),
        Some(DecisionReplayError::SourceUnavailable)
    );
    assert_eq!(
        block_on_ready(replay.next_page())
            .unwrap()
            .unwrap()
            .events(),
        &[final_event]
    );

    assert_eq!(
        *observations
            .lock()
            .expect("observation recorder must be usable"),
        [
            ObservedRead {
                decision_id,
                page_size: 16,
                continuation: None,
            },
            ObservedRead {
                decision_id,
                page_size: 16,
                continuation: Some(73),
            },
            ObservedRead {
                decision_id,
                page_size: 16,
                continuation: Some(73),
            },
        ]
    );
}

#[test]
fn rejects_a_continuation_after_the_maximum_aggregate_version() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let source = ScriptedSource {
        calls: Arc::clone(&calls),
        responses: VecDeque::from([Ok(DecisionReplaySourcePage::new(
            vec![event(
                decision_id,
                "0193a72e-71cc-7d40-b59c-f6eb4f0bf6bd",
                u64::MAX,
            )],
            Some(Cursor(u64::MAX)),
        ))]),
    };
    let mut replay =
        DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(1));

    assert_eq!(
        block_on_ready(replay.next_page()).err(),
        Some(DecisionReplayError::StoredStateRejected)
    );
    assert_eq!(
        block_on_ready(replay.next_page()).err(),
        Some(DecisionReplayError::StoredStateRejected)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn dropping_a_pending_page_read_retries_from_the_unchanged_cursor() {
    fn assert_send<T: Send>(value: T) -> T {
        value
    }

    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let observations = Arc::new(Mutex::new(Vec::new()));
    let source = PolledSource {
        observations: Arc::clone(&observations),
        responses: VecDeque::from([
            PolledResponse::Ready(Ok(DecisionReplaySourcePage::new(
                vec![event(
                    decision_id,
                    "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba",
                    1,
                )],
                Some(Cursor(91)),
            ))),
            PolledResponse::Pending,
            PolledResponse::Ready(Ok(DecisionReplaySourcePage::new(
                vec![event(
                    decision_id,
                    "0193a72e-71cc-7d40-b59c-f6eb4f0bf6bb",
                    2,
                )],
                None,
            ))),
        ]),
    };
    let mut replay =
        DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(1));

    assert!(block_on_ready(replay.next_page()).unwrap().is_some());
    let mut cancelled = Box::pin(assert_send(replay.next_page()));
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    assert!(cancelled.as_mut().poll(&mut context).is_pending());
    drop(cancelled);

    assert!(block_on_ready(replay.next_page()).unwrap().is_some());
    assert_eq!(
        observations
            .lock()
            .expect("observation recorder must be usable")
            .iter()
            .map(|read| read.continuation)
            .collect::<Vec<_>>(),
        [None, Some(91), Some(91)]
    );
}

#[test]
fn source_rejection_is_terminal_and_all_diagnostics_are_fixed() {
    fn assert_error<T: std::error::Error + Send + Sync + Copy>() {}

    assert_error::<DecisionReplayError>();
    assert_error::<DecisionReplaySourceError>();
    assert_error::<InvalidDecisionReplayPageSize>();

    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let source = ScriptedSource {
        calls: Arc::clone(&calls),
        responses: VecDeque::from([Err(DecisionReplaySourceError::StoredStateRejected)]),
    };
    let mut replay =
        DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(1));

    for _ in 0..2 {
        let error = block_on_ready(replay.next_page())
            .expect_err("stored-state rejection must remain terminal");
        assert_eq!(
            format!("{error:?}|{error}"),
            "StoredStateRejected|stored decision replay state was rejected"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let replay_errors = [
        (
            DecisionReplayError::SourceUnavailable,
            "SourceUnavailable|decision replay source is unavailable",
        ),
        (
            DecisionReplayError::StoredStateRejected,
            "StoredStateRejected|stored decision replay state was rejected",
        ),
    ];
    for (error, expected) in replay_errors {
        assert_eq!(format!("{error:?}|{error}"), expected);
    }

    let source_errors = [
        (
            DecisionReplaySourceError::Unavailable,
            "Unavailable|decision replay source is unavailable",
        ),
        (
            DecisionReplaySourceError::StoredStateRejected,
            "StoredStateRejected|decision replay source rejected stored state",
        ),
    ];
    for (error, expected) in source_errors {
        assert_eq!(format!("{error:?}|{error}"), expected);
    }
    assert_eq!(
        InvalidDecisionReplayPageSize.to_string(),
        "decision replay page size is invalid"
    );
}

#[test]
fn rejects_an_invalid_watch_request_before_reading_the_source() {
    let submitted = "sensitive-invalid-replay-decision-id";
    let calls = Arc::new(AtomicUsize::new(0));
    let source = ScriptedSource {
        calls: Arc::clone(&calls),
        responses: VecDeque::new(),
    };

    let result = DecisionReplay::try_from_request(
        source,
        WatchDecisionRequest {
            decision_id: submitted.to_owned(),
        },
        page_size(1),
    );
    let error = result
        .err()
        .expect("invalid watch request must fail before source access");
    let rendered = format!("{error:?} {error}");

    assert_eq!(
        error,
        bioworld_decision_query::WatchDecisionRequestError::InvalidDecisionId
    );
    assert!(!rendered.contains(submitted));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn transfers_a_maximum_valid_page_without_reallocating_its_event_vector() {
    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let events = (1..=MAX_DECISION_REPLAY_PAGE_EVENTS)
        .map(|version| {
            event(
                decision_id,
                &Uuid::from_u128(0x0193_a72e_71cc_7d40_b59c_f6eb_4f0b_f600 + version as u128)
                    .to_string(),
                version as u64,
            )
        })
        .collect::<Vec<_>>();
    let original_events_address = events.as_ptr();
    let source = ScriptedSource {
        calls: Arc::new(AtomicUsize::new(0)),
        responses: VecDeque::from([Ok(DecisionReplaySourcePage::new(events, None))]),
    };
    let mut replay = DecisionReplay::new(
        source,
        WatchDecisionQuery::new(decision_id),
        page_size(MAX_DECISION_REPLAY_PAGE_EVENTS),
    );

    let page = block_on_ready(replay.next_page())
        .unwrap()
        .expect("maximum valid page must be returned");

    assert_eq!(page.events().len(), MAX_DECISION_REPLAY_PAGE_EVENTS);
    assert_eq!(page.events().as_ptr(), original_events_address);
    let events = page.into_events();
    assert_eq!(events.as_ptr(), original_events_address);
}

#[test]
fn preserves_recorded_scientific_fields_without_deriving_a_verdict() {
    fn interval(lower: &str, upper: &str, evidence_id: &str) -> DecisionPredictionInterval {
        DecisionPredictionInterval {
            target: "binding_affinity".to_owned(),
            unit: "nM".to_owned(),
            lower_decimal: lower.to_owned(),
            upper_decimal: upper.to_owned(),
            nominal_coverage_decimal: "0.95".to_owned(),
            interval_method_id: "split_conformal".to_owned(),
            interval_method_version: "1.0".to_owned(),
            calibration_method_id: "held_out_calibration".to_owned(),
            calibration_method_version: "2026.07".to_owned(),
            calibration_evidence: Some(EvidenceSnapshotRef {
                id: evidence_id.to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
        }
    }

    let decision_id = Uuid::parse_str("018f5a72-9c4b-7d31-8f6a-26f08f3f4d99").unwrap();
    let mut original = event(decision_id, "0193a72e-71cc-7d40-b59c-f6eb4f0bf6bc", 7);
    let decision = original
        .decision
        .as_mut()
        .expect("fixture replay event must contain a decision");
    decision.recommendation = Recommendation::StopProgram as i32;
    decision.rationale = vec![
        "Recorded rationale Z.".to_owned(),
        "Recorded rationale A.".to_owned(),
        "Recorded rationale Z.".to_owned(),
    ];
    decision.ood_status = Some(OodStatus::OutOfDomain as i32);
    decision.ood_detector = Some(OodDetectorRef {
        detector_id: "replay-domain-detector".to_owned(),
        detector_version: "2026.07".to_owned(),
    });
    decision.prediction_interval = Some(interval("0.25", "1.5", "ES-REPLAY-CAL"));
    decision.prediction_positions = [
        (
            "model-z",
            "2026.07",
            "shared-training-set",
            "0.2",
            "1.2",
            "ES-REPLAY-POS-Z",
        ),
        (
            "model-a",
            "2026.06",
            "independent-assay",
            "0.4",
            "1.4",
            "ES-REPLAY-POS-A",
        ),
    ]
    .into_iter()
    .map(
        |(source_id, source_version, dependency_group_id, lower, upper, evidence_id)| {
            DecisionPredictionPosition {
                source_id: source_id.to_owned(),
                source_version: source_version.to_owned(),
                dependency_group_id: dependency_group_id.to_owned(),
                interval: Some(interval(lower, upper, evidence_id)),
                prediction_evidence: Some(EvidenceSnapshotRef {
                    id: evidence_id.to_owned(),
                    sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                        .to_owned(),
                }),
            }
        },
    )
    .collect();
    decision.decision_criterion = Some(DecisionCriterion {
        criterion_id: "replay_recorded_policy".to_owned(),
        criterion_version: "2026.07".to_owned(),
        comparator: DecisionCriterionComparator::LessThanOrEqual as i32,
        threshold_decimal: "0.1".to_owned(),
        criterion_evidence: Some(EvidenceSnapshotRef {
            id: "ES-REPLAY-CRITERION".to_owned(),
            sha256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_owned(),
        }),
    });
    let expected = original.clone();
    let source = ScriptedSource {
        calls: Arc::new(AtomicUsize::new(0)),
        responses: VecDeque::from([Ok(DecisionReplaySourcePage::new(vec![original], None))]),
    };
    let mut replay =
        DecisionReplay::new(source, WatchDecisionQuery::new(decision_id), page_size(1));

    let actual = block_on_ready(replay.next_page())
        .expect("recorded scientific replay page must succeed")
        .expect("recorded scientific replay page must exist")
        .into_events();

    assert_eq!(actual, vec![expected]);
}
