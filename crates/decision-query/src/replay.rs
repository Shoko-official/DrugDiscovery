use std::{future::Future, pin::Pin};

use bioworld_contracts::{VersionedDecisionRecord, v2};
use thiserror::Error;

use crate::{WatchDecisionQuery, WatchDecisionRequestError, parse_canonical_uuid};

pub const MAX_DECISION_REPLAY_PAGE_EVENTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionReplayPageSize(u8);

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("decision replay page size is invalid")]
pub struct InvalidDecisionReplayPageSize;

impl TryFrom<usize> for DecisionReplayPageSize {
    type Error = InvalidDecisionReplayPageSize;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if !(1..=MAX_DECISION_REPLAY_PAGE_EVENTS).contains(&value) {
            return Err(InvalidDecisionReplayPageSize);
        }

        let value = u8::try_from(value).map_err(|_| InvalidDecisionReplayPageSize)?;
        Ok(Self(value))
    }
}

impl DecisionReplayPageSize {
    pub fn get(self) -> usize {
        usize::from(self.0)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DecisionReplaySourceError {
    #[error("decision replay source is unavailable")]
    Unavailable,
    #[error("decision replay source rejected stored state")]
    StoredStateRejected,
}

pub struct DecisionReplaySourcePage<C> {
    events: Vec<v2::DecisionEvent>,
    continuation: Option<C>,
}

impl<C> DecisionReplaySourcePage<C> {
    pub fn new(events: Vec<v2::DecisionEvent>, continuation: Option<C>) -> Self {
        Self {
            events,
            continuation,
        }
    }

    pub fn into_parts(self) -> (Vec<v2::DecisionEvent>, Option<C>) {
        (self.events, self.continuation)
    }
}

pub type DecisionReplaySourceFuture<'a, C> = Pin<
    Box<
        dyn Future<Output = Result<DecisionReplaySourcePage<C>, DecisionReplaySourceError>>
            + Send
            + 'a,
    >,
>;

pub trait DecisionReplaySource: Send {
    type Continuation: Send + Sync;

    fn read_page<'a>(
        &'a mut self,
        query: WatchDecisionQuery,
        page_size: DecisionReplayPageSize,
        continuation: Option<&'a Self::Continuation>,
    ) -> DecisionReplaySourceFuture<'a, Self::Continuation>;
}

#[derive(Debug)]
pub struct DecisionReplayPage {
    events: Vec<v2::DecisionEvent>,
}

impl DecisionReplayPage {
    pub fn events(&self) -> &[v2::DecisionEvent] {
        &self.events
    }

    pub fn into_events(self) -> Vec<v2::DecisionEvent> {
        self.events
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DecisionReplayError {
    #[error("decision replay source is unavailable")]
    SourceUnavailable,
    #[error("stored decision replay state was rejected")]
    StoredStateRejected,
}

pub struct DecisionReplay<S>
where
    S: DecisionReplaySource,
{
    source: S,
    query: WatchDecisionQuery,
    page_size: DecisionReplayPageSize,
    continuation: Option<S::Continuation>,
    last_version: Option<u64>,
    state: DecisionReplayState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DecisionReplayState {
    Active,
    Complete,
    Rejected,
}

impl<S> DecisionReplay<S>
where
    S: DecisionReplaySource,
{
    pub fn new(source: S, query: WatchDecisionQuery, page_size: DecisionReplayPageSize) -> Self {
        Self {
            source,
            query,
            page_size,
            continuation: None,
            last_version: None,
            state: DecisionReplayState::Active,
        }
    }

    pub fn page_size(&self) -> DecisionReplayPageSize {
        self.page_size
    }

    pub fn try_from_request(
        source: S,
        request: v2::WatchDecisionRequest,
        page_size: DecisionReplayPageSize,
    ) -> Result<Self, WatchDecisionRequestError> {
        WatchDecisionQuery::try_from(request).map(|query| Self::new(source, query, page_size))
    }

    pub async fn next_page(&mut self) -> Result<Option<DecisionReplayPage>, DecisionReplayError> {
        match self.state {
            DecisionReplayState::Complete => return Ok(None),
            DecisionReplayState::Rejected => {
                return Err(DecisionReplayError::StoredStateRejected);
            }
            DecisionReplayState::Active => {}
        }

        let source_page = match self
            .source
            .read_page(self.query, self.page_size, self.continuation.as_ref())
            .await
        {
            Ok(page) => page,
            Err(DecisionReplaySourceError::Unavailable) => {
                return Err(DecisionReplayError::SourceUnavailable);
            }
            Err(DecisionReplaySourceError::StoredStateRejected) => {
                self.state = DecisionReplayState::Rejected;
                return Err(DecisionReplayError::StoredStateRejected);
            }
        };
        let (events, continuation) = source_page.into_parts();
        let expected_decision_id = self.query.decision_id().to_string();
        if events.is_empty() && continuation.is_none() && self.continuation.is_none() {
            self.state = DecisionReplayState::Complete;
            return Ok(None);
        }
        let empty_active_page =
            events.is_empty() && (continuation.is_some() || self.continuation.is_some());
        let exceeds_requested_bound = events.len() > self.page_size.get();
        if empty_active_page || exceeds_requested_bound {
            self.state = DecisionReplayState::Rejected;
            return Err(DecisionReplayError::StoredStateRejected);
        }
        let next_last_version =
            match validate_page_versions(&events, &expected_decision_id, self.last_version) {
                Ok(version) if continuation.is_none() || version != u64::MAX => version,
                Ok(_) | Err(()) => {
                    self.state = DecisionReplayState::Rejected;
                    return Err(DecisionReplayError::StoredStateRejected);
                }
            };

        self.state = if continuation.is_none() {
            DecisionReplayState::Complete
        } else {
            DecisionReplayState::Active
        };
        self.continuation = continuation;
        self.last_version = Some(next_last_version);

        Ok(Some(DecisionReplayPage { events }))
    }
}

fn validated_version(event: &v2::DecisionEvent, expected_decision_id: &str) -> Option<u64> {
    parse_canonical_uuid(&event.event_id)?;
    let decision = event.decision.as_ref()?;
    if decision.decision_id != expected_decision_id {
        return None;
    }

    // Contract validation consumes a record, while replay must preserve its original wire form.
    VersionedDecisionRecord::try_from(decision.clone())
        .ok()
        .map(|decision| decision.aggregate_version().get())
}

fn validate_page_versions(
    events: &[v2::DecisionEvent],
    expected_decision_id: &str,
    mut last_version: Option<u64>,
) -> Result<u64, ()> {
    for event in events {
        let version = validated_version(event, expected_decision_id).ok_or(())?;
        if last_version.is_some_and(|previous| version <= previous) {
            return Err(());
        }
        last_version = Some(version);
    }

    last_version.ok_or(())
}
