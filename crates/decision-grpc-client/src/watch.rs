use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};

use bioworld_contracts::{
    MAX_DECISION_EVENT_WIRE_BYTES, MAX_DECISION_WIRE_BYTES, VersionedDecisionRecord,
    v2::{DecisionEvent, WatchDecisionRequest, decision_service_client::DecisionServiceClient},
};
use bioworld_decision_query::{WatchDecisionQuery, WatchDecisionRequestError};
use prost::Message;
use tokio::{
    sync::{
        OwnedSemaphorePermit, Semaphore, mpsc, oneshot,
        watch::{self, Receiver, Sender},
    },
    task::JoinHandle,
    time::{Instant, sleep_until},
};
use tonic::Streaming;
use uuid::Uuid;

use crate::{
    AccessTokenProvider, CANONICAL_DECISION_ID_BYTES, DecisionGrpcClient, DecisionGrpcClientError,
    DecisionGrpcWatchLimits, authenticated_request, complete_before_deadline, map_status,
};

#[derive(Debug)]
pub struct DecisionGrpcWatchEvent {
    event_id: Uuid,
    decision: VersionedDecisionRecord,
}

impl DecisionGrpcWatchEvent {
    pub fn event_id(&self) -> Uuid {
        self.event_id
    }

    pub fn decision(&self) -> &VersionedDecisionRecord {
        &self.decision
    }

    pub fn into_parts(self) -> (Uuid, VersionedDecisionRecord) {
        (self.event_id, self.decision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchTerminal {
    Running,
    Complete,
    Cancelled,
    Error(DecisionGrpcClientError),
}

const TERMINATION_RUNNING: u8 = 0;
const TERMINATION_PENDING: u8 = 1;
const TERMINATION_COMPLETE: u8 = 2;

pub(crate) struct WatchCleanup {
    pending: AtomicUsize,
    generation: Sender<u64>,
}

impl WatchCleanup {
    pub(crate) fn new() -> Self {
        let (generation, _receiver) = watch::channel(0);
        Self {
            pending: AtomicUsize::new(0),
            generation,
        }
    }

    fn signal(&self) {
        self.generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

struct WatchTermination {
    cleanup: Arc<WatchCleanup>,
    state: AtomicU8,
}

impl WatchTermination {
    fn new(cleanup: Arc<WatchCleanup>) -> Arc<Self> {
        Arc::new(Self {
            cleanup,
            state: AtomicU8::new(TERMINATION_RUNNING),
        })
    }

    fn mark_pending(&self) {
        self.cleanup.pending.fetch_add(1, Ordering::AcqRel);
        if self
            .state
            .compare_exchange(
                TERMINATION_RUNNING,
                TERMINATION_PENDING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.cleanup.pending.fetch_sub(1, Ordering::AcqRel);
            self.cleanup.signal();
        }
    }

    fn complete(&self) {
        if self.state.swap(TERMINATION_COMPLETE, Ordering::AcqRel) == TERMINATION_PENDING {
            self.cleanup.pending.fetch_sub(1, Ordering::AcqRel);
            self.cleanup.signal();
        }
    }
}

struct TerminalState {
    sender: Sender<WatchTerminal>,
}

impl TerminalState {
    fn new() -> (Arc<Self>, Receiver<WatchTerminal>) {
        let (sender, receiver) = watch::channel(WatchTerminal::Running);
        (Arc::new(Self { sender }), receiver)
    }

    fn current(&self) -> WatchTerminal {
        *self.sender.borrow()
    }

    fn finish(&self, terminal: WatchTerminal) {
        self.sender.send_if_modified(|current| {
            if *current != WatchTerminal::Running {
                return false;
            }
            *current = terminal;
            true
        });
    }
}

#[derive(Clone, Copy)]
enum WatchCancellation {
    Dropped,
    Finish(WatchTerminal),
}

enum WorkerPoll<T> {
    Deadline,
    Cancelled(Option<WatchCancellation>),
    Value(T),
}

struct WatchResources {
    stream: Streaming<DecisionEvent>,
    _global_permit: OwnedSemaphorePermit,
    _watch_permit: OwnedSemaphorePermit,
    seen_event_ids: HashSet<Uuid>,
    last_version: Option<u64>,
    emitted: usize,
}

struct WatchWorker {
    resources: Option<WatchResources>,
    demand_rx: mpsc::Receiver<()>,
    output_tx: mpsc::Sender<DecisionGrpcWatchEvent>,
    cancel_rx: oneshot::Receiver<WatchCancellation>,
    terminal: Arc<TerminalState>,
    termination: Arc<WatchTermination>,
    deadline: Instant,
    expected_decision_id: String,
    max_events: usize,
}

impl WatchWorker {
    async fn run(mut self) {
        loop {
            let demand = {
                let deadline = self.deadline;
                let cancel_rx = &mut self.cancel_rx;
                let demand_rx = &mut self.demand_rx;
                tokio::select! {
                    biased;
                    _ = sleep_until(deadline) => WorkerPoll::Deadline,
                    cancellation = cancel_rx => WorkerPoll::Cancelled(cancellation.ok()),
                    demand = demand_rx.recv() => WorkerPoll::Value(demand),
                }
            };
            match demand {
                WorkerPoll::Deadline => {
                    self.finish(WatchTerminal::Error(
                        DecisionGrpcClientError::DeadlineExceeded,
                    ));
                    return;
                }
                WorkerPoll::Cancelled(cancellation) => {
                    self.finish(cancellation_terminal(cancellation));
                    return;
                }
                WorkerPoll::Value(Some(())) => {}
                WorkerPoll::Value(None) => {
                    self.finish(WatchTerminal::Cancelled);
                    return;
                }
            }

            let message = {
                let deadline = self.deadline;
                let cancel_rx = &mut self.cancel_rx;
                let stream = &mut self
                    .resources
                    .as_mut()
                    .expect("Watch resources must exist while the worker is running")
                    .stream;
                tokio::select! {
                    biased;
                    _ = sleep_until(deadline) => WorkerPoll::Deadline,
                    cancellation = cancel_rx => WorkerPoll::Cancelled(cancellation.ok()),
                    message = stream.message() => WorkerPoll::Value(message),
                }
            };

            let event = match message {
                WorkerPoll::Deadline => {
                    self.finish(WatchTerminal::Error(
                        DecisionGrpcClientError::DeadlineExceeded,
                    ));
                    return;
                }
                WorkerPoll::Cancelled(cancellation) => {
                    self.finish(cancellation_terminal(cancellation));
                    return;
                }
                WorkerPoll::Value(Ok(Some(event))) => match self.validate_event(event) {
                    Ok(event) => event,
                    Err(error) => {
                        self.finish(WatchTerminal::Error(error));
                        return;
                    }
                },
                WorkerPoll::Value(Ok(None)) => {
                    self.finish(WatchTerminal::Complete);
                    return;
                }
                WorkerPoll::Value(Err(status)) => {
                    self.finish(WatchTerminal::Error(map_status(status)));
                    return;
                }
            };

            let output = {
                let deadline = self.deadline;
                let cancel_rx = &mut self.cancel_rx;
                let output_tx = &self.output_tx;
                tokio::select! {
                    biased;
                    _ = sleep_until(deadline) => WorkerPoll::Deadline,
                    cancellation = cancel_rx => WorkerPoll::Cancelled(cancellation.ok()),
                    result = output_tx.send(event) => WorkerPoll::Value(result),
                }
            };
            match output {
                WorkerPoll::Deadline => {
                    self.finish(WatchTerminal::Error(
                        DecisionGrpcClientError::DeadlineExceeded,
                    ));
                    return;
                }
                WorkerPoll::Cancelled(cancellation) => {
                    self.finish(cancellation_terminal(cancellation));
                    return;
                }
                WorkerPoll::Value(Ok(())) => {}
                WorkerPoll::Value(Err(_event)) => {
                    self.finish(WatchTerminal::Cancelled);
                    return;
                }
            }
        }
    }

    fn validate_event(
        &mut self,
        event: DecisionEvent,
    ) -> Result<DecisionGrpcWatchEvent, DecisionGrpcClientError> {
        let resources = self
            .resources
            .as_mut()
            .expect("Watch resources must exist while the worker is running");
        if resources.emitted >= self.max_events
            || event.encoded_len() > MAX_DECISION_EVENT_WIRE_BYTES
        {
            return Err(DecisionGrpcClientError::InvalidResponse);
        }
        let event_id = parse_canonical_uuid(&event.event_id)
            .ok_or(DecisionGrpcClientError::InvalidResponse)?;
        if resources.seen_event_ids.contains(&event_id) {
            return Err(DecisionGrpcClientError::InvalidResponse);
        }
        let decision = event
            .decision
            .ok_or(DecisionGrpcClientError::InvalidResponse)?;
        if decision.decision_id != self.expected_decision_id {
            return Err(DecisionGrpcClientError::InvalidResponse);
        }
        let decision = VersionedDecisionRecord::try_from(decision)
            .map_err(|_| DecisionGrpcClientError::InvalidResponse)?;
        let version = decision.aggregate_version().get();
        if resources
            .last_version
            .is_some_and(|last_version| version <= last_version)
        {
            return Err(DecisionGrpcClientError::InvalidResponse);
        }

        resources.seen_event_ids.insert(event_id);
        resources.last_version = Some(version);
        resources.emitted += 1;

        Ok(DecisionGrpcWatchEvent { event_id, decision })
    }

    fn finish(&mut self, terminal: WatchTerminal) {
        drop(self.resources.take());
        self.termination.complete();
        self.terminal.finish(terminal);
    }
}

impl Drop for WatchWorker {
    fn drop(&mut self) {
        self.finish(WatchTerminal::Error(DecisionGrpcClientError::Unavailable));
    }
}

fn cancellation_terminal(cancellation: Option<WatchCancellation>) -> WatchTerminal {
    match cancellation {
        Some(WatchCancellation::Finish(terminal)) => terminal,
        Some(WatchCancellation::Dropped) | None => WatchTerminal::Cancelled,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DemandState {
    Idle,
    Outstanding,
    Stopping,
    Fused,
}

pub struct DecisionGrpcWatch {
    demand_tx: Option<mpsc::Sender<()>>,
    output_rx: mpsc::Receiver<DecisionGrpcWatchEvent>,
    terminal_rx: Receiver<WatchTerminal>,
    terminal: Arc<TerminalState>,
    termination: Arc<WatchTermination>,
    cancel_tx: Option<oneshot::Sender<WatchCancellation>>,
    worker: JoinHandle<()>,
    deadline: Instant,
    state: DemandState,
}

impl DecisionGrpcWatch {
    pub async fn next_event(
        &mut self,
    ) -> Result<Option<DecisionGrpcWatchEvent>, DecisionGrpcClientError> {
        if self.state == DemandState::Fused {
            return Ok(None);
        }
        if self.state == DemandState::Stopping {
            return self.await_worker_terminal().await;
        }
        if let Some(terminal) = self.consume_terminal() {
            return terminal;
        }
        if Instant::now() >= self.deadline {
            return self.expire().await;
        }

        if self.state == DemandState::Idle {
            let demand = self
                .demand_tx
                .as_ref()
                .ok_or(DecisionGrpcClientError::Unavailable)?
                .try_send(());
            if demand.is_err() {
                if let Some(terminal) = self.consume_terminal() {
                    return terminal;
                }
                return self
                    .stop_with(WatchTerminal::Error(DecisionGrpcClientError::Unavailable))
                    .await;
            }
            self.state = DemandState::Outstanding;
        }

        loop {
            tokio::select! {
                biased;
                _ = sleep_until(self.deadline) => return self.expire().await,
                changed = self.terminal_rx.changed() => {
                    if changed.is_err() && self.terminal.current() == WatchTerminal::Running {
                        return self
                            .stop_with(WatchTerminal::Error(
                                DecisionGrpcClientError::Unavailable,
                            ))
                            .await;
                    }
                    if let Some(terminal) = self.consume_terminal() {
                        return terminal;
                    }
                }
                output = self.output_rx.recv() => {
                    let Some(event) = output else {
                        if let Some(terminal) = self.consume_terminal() {
                            return terminal;
                        }
                        return self
                            .stop_with(WatchTerminal::Error(
                                DecisionGrpcClientError::Unavailable,
                            ))
                            .await;
                    };
                    if let Some(terminal) = self.consume_terminal() {
                        return terminal;
                    }
                    if Instant::now() >= self.deadline {
                        return self.expire().await;
                    }
                    self.state = DemandState::Idle;
                    return Ok(Some(event));
                }
            }
        }
    }

    fn consume_terminal(
        &mut self,
    ) -> Option<Result<Option<DecisionGrpcWatchEvent>, DecisionGrpcClientError>> {
        match self.terminal.current() {
            WatchTerminal::Running => None,
            WatchTerminal::Complete | WatchTerminal::Cancelled => {
                self.state = DemandState::Fused;
                Some(Ok(None))
            }
            WatchTerminal::Error(error) => {
                self.state = DemandState::Fused;
                Some(Err(error))
            }
        }
    }

    async fn expire(&mut self) -> Result<Option<DecisionGrpcWatchEvent>, DecisionGrpcClientError> {
        self.stop_with(WatchTerminal::Error(
            DecisionGrpcClientError::DeadlineExceeded,
        ))
        .await
    }

    async fn stop_with(
        &mut self,
        terminal: WatchTerminal,
    ) -> Result<Option<DecisionGrpcWatchEvent>, DecisionGrpcClientError> {
        self.state = DemandState::Stopping;
        self.termination.mark_pending();
        if let Some(cancel_tx) = self.cancel_tx.take() {
            let _ = cancel_tx.send(WatchCancellation::Finish(terminal));
        }
        self.demand_tx.take();
        self.await_worker_terminal().await
    }

    async fn await_worker_terminal(
        &mut self,
    ) -> Result<Option<DecisionGrpcWatchEvent>, DecisionGrpcClientError> {
        let _ = (&mut self.worker).await;
        if self.terminal.current() == WatchTerminal::Running {
            self.terminal
                .finish(WatchTerminal::Error(DecisionGrpcClientError::Unavailable));
        }
        self.consume_terminal()
            .unwrap_or(Err(DecisionGrpcClientError::Unavailable))
    }

    fn cancel_worker(&mut self) {
        self.termination.mark_pending();
        if let Some(cancel_tx) = self.cancel_tx.take() {
            let _ = cancel_tx.send(WatchCancellation::Dropped);
        }
        self.demand_tx.take();
    }
}

impl Drop for DecisionGrpcWatch {
    fn drop(&mut self) {
        self.cancel_worker();
    }
}

impl<P> DecisionGrpcClient<P>
where
    P: AccessTokenProvider,
{
    pub async fn watch_decision(
        &self,
        decision_id: &str,
        limits: DecisionGrpcWatchLimits,
    ) -> Result<DecisionGrpcWatch, DecisionGrpcClientError> {
        if decision_id.len() != CANONICAL_DECISION_ID_BYTES {
            return Err(DecisionGrpcClientError::InvalidDecisionId);
        }
        let query = WatchDecisionQuery::try_from(WatchDecisionRequest {
            decision_id: decision_id.to_owned(),
        })
        .map_err(map_watch_request_error)?;
        let expected_decision_id = query.decision_id().to_string();
        let start = Instant::now();
        let watch_deadline = start + limits.timeout();
        let setup_deadline = watch_deadline.min(start + self.request_timeout);
        let watch_permit = acquire_watch_permit(
            Arc::clone(&self.watch_admission),
            self.watch_cleanup.as_ref(),
            setup_deadline,
        )
        .await?;
        let global_permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| DecisionGrpcClientError::CapacityExhausted)?;
        let request = authenticated_request(
            self.token_provider.as_ref(),
            WatchDecisionRequest {
                decision_id: expected_decision_id.clone(),
            },
            setup_deadline,
            watch_deadline,
        )
        .await?;
        let mut client = DecisionServiceClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_DECISION_EVENT_WIRE_BYTES)
            .max_encoding_message_size(MAX_DECISION_WIRE_BYTES);
        if Instant::now() >= setup_deadline {
            return Err(DecisionGrpcClientError::DeadlineExceeded);
        }
        let stream = complete_before_deadline(setup_deadline, client.watch_decision(request))
            .await
            .ok_or(DecisionGrpcClientError::DeadlineExceeded)?
            .map_err(map_status)?
            .into_inner();

        let (demand_tx, demand_rx) = mpsc::channel(1);
        let (output_tx, output_rx) = mpsc::channel(1);
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let (terminal, terminal_rx) = TerminalState::new();
        let termination = WatchTermination::new(Arc::clone(&self.watch_cleanup));
        let worker = WatchWorker {
            resources: Some(WatchResources {
                stream,
                _global_permit: global_permit,
                _watch_permit: watch_permit,
                seen_event_ids: HashSet::new(),
                last_version: None,
                emitted: 0,
            }),
            demand_rx,
            output_tx,
            cancel_rx,
            terminal: Arc::clone(&terminal),
            termination: Arc::clone(&termination),
            deadline: watch_deadline,
            expected_decision_id,
            max_events: limits.max_events(),
        };
        let worker = tokio::spawn(worker.run());

        Ok(DecisionGrpcWatch {
            demand_tx: Some(demand_tx),
            output_rx,
            terminal_rx,
            terminal,
            termination,
            cancel_tx: Some(cancel_tx),
            worker,
            deadline: watch_deadline,
            state: DemandState::Idle,
        })
    }
}

async fn acquire_watch_permit(
    admission: Arc<Semaphore>,
    cleanup: &WatchCleanup,
    deadline: Instant,
) -> Result<OwnedSemaphorePermit, DecisionGrpcClientError> {
    let mut cleanup_rx = cleanup.generation.subscribe();
    loop {
        if Instant::now() >= deadline {
            return Err(DecisionGrpcClientError::DeadlineExceeded);
        }
        if let Ok(permit) = Arc::clone(&admission).try_acquire_owned() {
            return Ok(permit);
        }
        if cleanup.pending.load(Ordering::Acquire) == 0 {
            return Err(DecisionGrpcClientError::CapacityExhausted);
        }
        complete_before_deadline(deadline, cleanup_rx.changed())
            .await
            .ok_or(DecisionGrpcClientError::DeadlineExceeded)?
            .map_err(|_| DecisionGrpcClientError::Unavailable)?;
    }
}

fn parse_canonical_uuid(value: &str) -> Option<Uuid> {
    let parsed = Uuid::parse_str(value).ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn map_watch_request_error(_error: WatchDecisionRequestError) -> DecisionGrpcClientError {
    DecisionGrpcClientError::InvalidDecisionId
}
