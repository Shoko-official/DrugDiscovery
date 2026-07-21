use std::{
    future::Future,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bioworld_contracts::v2::{DecisionRecord, Recommendation};
use bioworld_desktop_core::{
    CurrentDecisionSource, DecisionProvenance, DecisionReadFuture, DecisionRuntime,
    DecisionRuntimeError, SourcedDecision,
};

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

#[derive(Clone)]
struct CountingSource {
    calls: Arc<AtomicUsize>,
    result: Result<Option<SourcedDecision>, DecisionRuntimeError>,
}

impl CurrentDecisionSource for CountingSource {
    fn read_current_decision(&self) -> DecisionReadFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self.result.clone();
        Box::pin(async move { result })
    }
}

#[allow(deprecated)]
fn record() -> DecisionRecord {
    DecisionRecord {
        decision_id: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99".to_owned(),
        cou_id: "COU-M15".to_owned(),
        evidence_snapshot_id: String::new(),
        recommendation: Recommendation::Abstain as i32,
        rationale: vec!["Core source boundary.".to_owned()],
        aggregate_version: 1,
        evidence: None,
    }
}

#[test]
fn calls_the_source_once_and_returns_the_exact_result() {
    let calls = Arc::new(AtomicUsize::new(0));
    let expected = SourcedDecision::new(record(), DecisionProvenance::BundledSample);
    let runtime = DecisionRuntime::from_source(Arc::new(CountingSource {
        calls: calls.clone(),
        result: Ok(Some(expected.clone())),
    }));

    let actual = block_on_ready(runtime.read_current_decision());

    assert_eq!(actual, Ok(Some(expected)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn preserves_an_absent_decision() {
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime = DecisionRuntime::from_source(Arc::new(CountingSource {
        calls: calls.clone(),
        result: Ok(None),
    }));

    let actual = block_on_ready(runtime.read_current_decision());

    assert_eq!(actual, Ok(None));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn preserves_the_exact_source_error() {
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime = DecisionRuntime::from_source(Arc::new(CountingSource {
        calls: Arc::clone(&calls),
        result: Err(DecisionRuntimeError),
    }));

    let actual = block_on_ready(runtime.read_current_decision());

    assert_eq!(actual, Err(DecisionRuntimeError));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn clones_share_the_same_source_and_counter() {
    let calls = Arc::new(AtomicUsize::new(0));
    let runtime = DecisionRuntime::from_source(Arc::new(CountingSource {
        calls: Arc::clone(&calls),
        result: Ok(None),
    }));
    let cloned_runtime = runtime.clone();

    assert_eq!(block_on_ready(runtime.read_current_decision()), Ok(None));
    assert_eq!(
        block_on_ready(cloned_runtime.read_current_decision()),
        Ok(None)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn runtime_is_clone_send_and_sync() {
    fn assert_traits<T: Clone + Send + Sync>() {}

    assert_traits::<DecisionRuntime>();
}
