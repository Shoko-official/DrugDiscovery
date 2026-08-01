use std::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
    vec,
};

use bioworld_contracts::{
    MAX_DECISION_WIRE_BYTES,
    v2::{DecisionEvent, WatchDecisionRequest},
};
use bioworld_decision_query::{
    DecisionReplay, DecisionReplayError, DecisionReplayPage, DecisionReplayPageSize,
    DecisionReplaySource, WatchDecisionQuery,
};
use prost::Message;
use tonic::{
    Request, Response, Status,
    codegen::{BoxStream, tokio_stream::Stream},
};

use crate::TenantScope;

const DECISION_REPLAY_PAGE_EVENTS: usize = 1;
const DECISION_EVENT_ENVELOPE_WIRE_BYTES: usize = 42;

/// Maximum Prost-encoded decision event payload accepted by the adapter.
pub const MAX_DECISION_EVENT_WIRE_BYTES: usize =
    MAX_DECISION_WIRE_BYTES + DECISION_EVENT_ENVELOPE_WIRE_BYTES;

/// Builds a tenant-scoped typed replay for one validated watch request.
pub trait TenantScopedWatchDecisionExecutor: Send + Sync {
    type Source: DecisionReplaySource + 'static;

    fn execute_watch_decision(
        &self,
        scope: TenantScope,
        query: WatchDecisionQuery,
        page_size: DecisionReplayPageSize,
    ) -> DecisionReplay<Self::Source>;
}

/// Adapts a finite typed replay into a demand-driven Tonic response stream.
pub fn watch_decision<E>(
    executor: &E,
    scope: TenantScope,
    request: Request<WatchDecisionRequest>,
) -> Result<Response<BoxStream<DecisionEvent>>, Status>
where
    E: TenantScopedWatchDecisionExecutor + ?Sized,
    <E::Source as DecisionReplaySource>::Continuation: 'static,
{
    let query = WatchDecisionQuery::try_from(request.into_inner())
        .map_err(|_| Status::invalid_argument("decision request is invalid"))?;
    let page_size = DecisionReplayPageSize::try_from(DECISION_REPLAY_PAGE_EVENTS)
        .map_err(|_| unavailable_status())?;
    let replay = executor.execute_watch_decision(scope, query, page_size);
    if replay.page_size() != page_size {
        return Err(unavailable_status());
    }

    let stream: BoxStream<DecisionEvent> = Box::pin(DecisionReplayEventStream::new(replay));
    Ok(Response::new(stream))
}

enum WatchState<S>
where
    S: DecisionReplaySource,
{
    Idle(DecisionReplay<S>),
    Reading(PendingPageRead<S>),
    Buffered {
        replay: DecisionReplay<S>,
        events: vec::IntoIter<DecisionEvent>,
    },
    Fused,
}

struct PageRead<S>
where
    S: DecisionReplaySource,
{
    replay: DecisionReplay<S>,
    result: Result<Option<DecisionReplayPage>, DecisionReplayError>,
}

struct PendingPageRead<S>
where
    S: DecisionReplaySource,
{
    future: Pin<Box<dyn Future<Output = PageRead<S>> + Send + 'static>>,
}

struct DecisionReplayEventStream<S>
where
    S: DecisionReplaySource,
{
    state: Box<WatchState<S>>,
}

impl<S> DecisionReplayEventStream<S>
where
    S: DecisionReplaySource,
{
    fn new(replay: DecisionReplay<S>) -> Self {
        Self {
            state: Box::new(WatchState::Idle(replay)),
        }
    }
}

impl<S> Stream for DecisionReplayEventStream<S>
where
    S: DecisionReplaySource + 'static,
    S::Continuation: 'static,
{
    type Item = Result<DecisionEvent, Status>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            match mem::replace(this.state.as_mut(), WatchState::Fused) {
                WatchState::Idle(mut replay) => {
                    let read = PendingPageRead {
                        future: Box::pin(async move {
                            let result = replay.next_page().await;
                            PageRead { replay, result }
                        }),
                    };
                    *this.state = WatchState::Reading(read);
                }
                WatchState::Reading(mut read) => match read.future.as_mut().poll(context) {
                    Poll::Pending => {
                        *this.state = WatchState::Reading(read);
                        return Poll::Pending;
                    }
                    Poll::Ready(PageRead {
                        replay,
                        result: Ok(Some(page)),
                    }) => {
                        let events = page.into_events();
                        if !page_is_within_wire_limit(&events) {
                            return Poll::Ready(Some(Err(unavailable_status())));
                        }
                        *this.state = WatchState::Buffered {
                            replay,
                            events: events.into_iter(),
                        };
                    }
                    Poll::Ready(PageRead {
                        replay: _replay,
                        result: Ok(None),
                    }) => return Poll::Ready(None),
                    Poll::Ready(PageRead {
                        replay: _replay,
                        result: Err(error),
                    }) => {
                        return Poll::Ready(Some(Err(map_replay_status(error))));
                    }
                },
                WatchState::Buffered { replay, mut events } => match events.next() {
                    Some(event) => {
                        *this.state = WatchState::Buffered { replay, events };
                        return Poll::Ready(Some(Ok(event)));
                    }
                    None => {
                        *this.state = WatchState::Idle(replay);
                    }
                },
                WatchState::Fused => return Poll::Ready(None),
            }
        }
    }
}

fn page_is_within_wire_limit(events: &[DecisionEvent]) -> bool {
    events
        .iter()
        .all(|event| event.encoded_len() <= MAX_DECISION_EVENT_WIRE_BYTES)
}

fn map_replay_status(error: DecisionReplayError) -> Status {
    match error {
        DecisionReplayError::SourceUnavailable | DecisionReplayError::StoredStateRejected => {
            unavailable_status()
        }
    }
}

fn unavailable_status() -> Status {
    Status::unavailable("decision service is unavailable")
}

#[cfg(test)]
mod tests {
    use bioworld_contracts::v2::{DecisionEvent, DecisionRecord};
    use prost::Message;

    use super::{MAX_DECISION_EVENT_WIRE_BYTES, page_is_within_wire_limit};

    fn event_with_encoded_len(target: usize) -> DecisionEvent {
        let mut event = DecisionEvent {
            decision: Some(DecisionRecord::default()),
            event_id: "0193a72e-71cc-7d40-b59c-f6eb4f0bf6ba".to_owned(),
        };
        let mut rationale_bytes = target;

        for _ in 0..4 {
            event.decision.as_mut().unwrap().rationale = vec!["r".repeat(rationale_bytes)];
            match event.encoded_len().cmp(&target) {
                std::cmp::Ordering::Equal => return event,
                std::cmp::Ordering::Less => rationale_bytes += target - event.encoded_len(),
                std::cmp::Ordering::Greater => rationale_bytes -= event.encoded_len() - target,
            }
        }

        panic!("could not construct target event wire size");
    }

    #[test]
    fn accepts_the_exact_event_wire_limit_and_rejects_an_oversized_page_atomically() {
        let exact = event_with_encoded_len(MAX_DECISION_EVENT_WIRE_BYTES);
        let oversized = event_with_encoded_len(MAX_DECISION_EVENT_WIRE_BYTES + 1);

        assert_eq!(exact.encoded_len(), MAX_DECISION_EVENT_WIRE_BYTES);
        assert_eq!(oversized.encoded_len(), MAX_DECISION_EVENT_WIRE_BYTES + 1);
        assert!(page_is_within_wire_limit(std::slice::from_ref(&exact)));
        assert!(!page_is_within_wire_limit(std::slice::from_ref(&oversized)));
        assert!(!page_is_within_wire_limit(&[exact, oversized]));
    }
}
