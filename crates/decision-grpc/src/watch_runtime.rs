use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll},
};

use bioworld_contracts::v2::DecisionEvent;
use bioworld_decision_query::{DecisionReplaySource, WatchDecisionQuery};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::AbortHandle;
use tokio::time::Instant;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tonic::{Status, codegen::tokio_stream::Stream};

use crate::{
    DECISION_GRPC_REQUEST_DEADLINE_MESSAGE, DecisionGrpcWatchConfig, TenantScope,
    TenantScopedWatchDecisionExecutor,
    watch::{MAX_DECISION_EVENT_WIRE_BYTES, watch_decision_query},
};

const DECISION_SERVICE_UNAVAILABLE_MESSAGE: &str = "decision service is unavailable";
const DECISION_SERVICE_CAPACITY_MESSAGE: &str = "decision service is at capacity";
const AUTHENTICATION_REQUIRED_MESSAGE: &str = "authentication is required";

trait ErasedWatchDecisionExecutor: Send + Sync {
    fn execute(
        &self,
        scope: TenantScope,
        query: WatchDecisionQuery,
    ) -> Result<tonic::codegen::BoxStream<DecisionEvent>, Status>;
}

struct TypedWatchDecisionExecutor<E> {
    executor: Arc<E>,
}

impl<E> ErasedWatchDecisionExecutor for TypedWatchDecisionExecutor<E>
where
    E: TenantScopedWatchDecisionExecutor + 'static,
    <E::Source as DecisionReplaySource>::Continuation: 'static,
{
    fn execute(
        &self,
        scope: TenantScope,
        query: WatchDecisionQuery,
    ) -> Result<tonic::codegen::BoxStream<DecisionEvent>, Status> {
        watch_decision_query(self.executor.as_ref(), scope, query)
    }
}

pub(crate) struct DecisionGrpcWatchRuntime {
    supervisor: Arc<WatchSupervisor>,
}

impl DecisionGrpcWatchRuntime {
    pub(crate) fn new<E>(executor: Arc<E>, config: DecisionGrpcWatchConfig) -> Self
    where
        E: TenantScopedWatchDecisionExecutor + 'static,
        <E::Source as DecisionReplaySource>::Continuation: 'static,
    {
        let executor: Arc<dyn ErasedWatchDecisionExecutor> =
            Arc::new(TypedWatchDecisionExecutor { executor });
        Self {
            supervisor: Arc::new(WatchSupervisor::new(executor, config)),
        }
    }

    pub(crate) fn try_acquire_global(&self) -> Result<OwnedSemaphorePermit, Status> {
        Arc::clone(&self.supervisor.global_admission)
            .try_acquire_owned()
            .map_err(|_| capacity_status())
    }

    pub(crate) fn try_acquire_tenant(&self, tenant_id: &str) -> Result<TenantPermit, Status> {
        TenantPermit::try_acquire(
            Arc::clone(&self.supervisor.tenant_admission),
            tenant_id,
            self.supervisor.max_in_flight_per_tenant,
        )
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.supervisor.root_cancellation.is_cancelled()
    }

    pub(crate) async fn cancelled(&self) {
        self.supervisor.root_cancellation.cancelled().await;
    }

    pub(crate) fn start(
        &self,
        scope: TenantScope,
        query: WatchDecisionQuery,
        deadline: WorkerDeadline,
        service_permit: OwnedSemaphorePermit,
        global_permit: OwnedSemaphorePermit,
        tenant_permit: TenantPermit,
    ) -> Result<tonic::codegen::BoxStream<DecisionEvent>, Status> {
        self.supervisor.start(
            scope,
            query,
            deadline,
            WorkerGuards {
                _service: service_permit,
                _global: global_permit,
                _tenant: tenant_permit,
            },
        )
    }

    pub(crate) fn lifecycle(&self) -> DecisionGrpcWatchLifecycle {
        DecisionGrpcWatchLifecycle {
            supervisor: Arc::clone(&self.supervisor),
        }
    }
}

#[derive(Clone)]
pub struct DecisionGrpcWatchLifecycle {
    supervisor: Arc<WatchSupervisor>,
}

impl DecisionGrpcWatchLifecycle {
    /// Closes Watch registration and requests cooperative cancellation.
    pub fn begin_shutdown(&self) {
        self.supervisor.begin_shutdown();
    }

    /// Waits until every registered Watch worker has released its resources.
    pub async fn wait(&self) {
        self.supervisor.tracker.wait().await;
    }

    /// Returns the current number of supervised Watch workers.
    pub fn active_workers(&self) -> usize {
        self.supervisor.tracker.len()
    }

    /// Aborts every remaining Watch worker through its bounded registry.
    pub fn abort_workers(&self) {
        self.supervisor.abort_workers();
    }
}

impl std::fmt::Debug for DecisionGrpcWatchLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecisionGrpcWatchLifecycle")
    }
}

struct WatchSupervisor {
    executor: Arc<dyn ErasedWatchDecisionExecutor>,
    global_admission: Arc<Semaphore>,
    tenant_admission: Arc<Mutex<HashMap<Box<str>, usize>>>,
    max_in_flight_per_tenant: usize,
    tracker: TaskTracker,
    root_cancellation: CancellationToken,
    registration: Arc<Mutex<RegistrationState>>,
}

struct RegistrationState {
    accepting: bool,
    next_worker_id: u64,
    workers: HashMap<u64, AbortHandle>,
}

impl RegistrationState {
    fn allocate_worker_id(&mut self) -> u64 {
        loop {
            let worker_id = self.next_worker_id;
            self.next_worker_id = self.next_worker_id.wrapping_add(1);
            if !self.workers.contains_key(&worker_id) {
                return worker_id;
            }
        }
    }
}

impl WatchSupervisor {
    fn new(
        executor: Arc<dyn ErasedWatchDecisionExecutor>,
        config: DecisionGrpcWatchConfig,
    ) -> Self {
        Self {
            executor,
            global_admission: Arc::new(Semaphore::new(config.max_in_flight())),
            tenant_admission: Arc::new(Mutex::new(HashMap::new())),
            max_in_flight_per_tenant: config.max_in_flight_per_tenant(),
            tracker: TaskTracker::new(),
            root_cancellation: CancellationToken::new(),
            registration: Arc::new(Mutex::new(RegistrationState {
                accepting: true,
                next_worker_id: 0,
                workers: HashMap::new(),
            })),
        }
    }

    fn start(
        &self,
        scope: TenantScope,
        query: WatchDecisionQuery,
        deadline: WorkerDeadline,
        guards: WorkerGuards,
    ) -> Result<tonic::codegen::BoxStream<DecisionEvent>, Status> {
        let mut registration = lock_unpoisoned(&self.registration);
        if !registration.accepting {
            return Err(unavailable_status());
        }
        let worker_id = registration.allocate_worker_id();

        let cancellation = self.root_cancellation.child_token();
        let stream_cancellation = cancellation.clone();
        let terminal = Arc::new(TerminalState::new());
        let stream_terminal = Arc::clone(&terminal);
        let (demand_tx, demand_rx) = mpsc::channel(1);
        let (result_tx, result_rx) = mpsc::channel(1);
        let worker = WorkerContext {
            executor: Arc::clone(&self.executor),
            scope: Some(scope),
            query,
            deadline,
            cancellation,
            terminal,
            demand_rx,
            result_tx,
            _guards: guards,
            _registration: WorkerRegistration {
                registration: Arc::clone(&self.registration),
                worker_id,
            },
        };
        let worker_task = self.tracker.spawn(run_worker(worker));
        registration
            .workers
            .insert(worker_id, worker_task.abort_handle());
        drop(worker_task);
        drop(registration);

        let stream = SupervisedWatchStream {
            state: ResponseState::Idle,
            deadline,
            cancellation: stream_cancellation,
            terminal: stream_terminal,
            demand_tx,
            result_rx,
        };
        Ok(Box::pin(stream))
    }

    fn begin_shutdown(&self) {
        let mut registration = lock_unpoisoned(&self.registration);
        if registration.accepting {
            registration.accepting = false;
            self.tracker.close();
            self.root_cancellation.cancel();
        }
    }

    fn abort_workers(&self) {
        let registration = lock_unpoisoned(&self.registration);
        for worker in registration.workers.values() {
            worker.abort();
        }
    }
}

impl Drop for WatchSupervisor {
    fn drop(&mut self) {
        self.tracker.close();
        self.root_cancellation.cancel();
    }
}

struct WorkerGuards {
    _service: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
    _tenant: TenantPermit,
}

struct WorkerRegistration {
    registration: Arc<Mutex<RegistrationState>>,
    worker_id: u64,
}

impl Drop for WorkerRegistration {
    fn drop(&mut self) {
        lock_unpoisoned(&self.registration)
            .workers
            .remove(&self.worker_id);
    }
}

pub(crate) struct TenantPermit {
    admission: Arc<Mutex<HashMap<Box<str>, usize>>>,
    tenant_id: Box<str>,
}

impl TenantPermit {
    fn try_acquire(
        admission: Arc<Mutex<HashMap<Box<str>, usize>>>,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Self, Status> {
        let mut tenants = lock_unpoisoned(&admission);
        let active = tenants.get(tenant_id).copied().unwrap_or(0);
        if active >= limit {
            return Err(capacity_status());
        }
        let tenant_id: Box<str> = tenant_id.into();
        tenants.insert(tenant_id.clone(), active + 1);
        drop(tenants);
        Ok(Self {
            admission,
            tenant_id,
        })
    }
}

impl Drop for TenantPermit {
    fn drop(&mut self) {
        let mut tenants = lock_unpoisoned(&self.admission);
        let remove = match tenants.get_mut(self.tenant_id.as_ref()) {
            Some(active) if *active > 1 => {
                *active -= 1;
                false
            }
            Some(_) => true,
            None => false,
        };
        if remove {
            tenants.remove(self.tenant_id.as_ref());
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct WorkerDeadline {
    at: Instant,
    terminal: WorkerTerminal,
}

impl WorkerDeadline {
    pub(crate) fn select(service: Instant, authority: Instant) -> Self {
        if authority < service {
            Self {
                at: authority,
                terminal: WorkerTerminal::AuthorityExpired,
            }
        } else {
            Self {
                at: service,
                terminal: WorkerTerminal::ServiceDeadline,
            }
        }
    }
}

struct WorkerContext {
    executor: Arc<dyn ErasedWatchDecisionExecutor>,
    scope: Option<TenantScope>,
    query: WatchDecisionQuery,
    deadline: WorkerDeadline,
    cancellation: CancellationToken,
    terminal: Arc<TerminalState>,
    demand_rx: mpsc::Receiver<()>,
    result_tx: mpsc::Sender<DecisionEvent>,
    _guards: WorkerGuards,
    _registration: WorkerRegistration,
}

impl WorkerContext {
    fn finish(&self, terminal: WorkerTerminal) {
        self.terminal.finish(terminal);
    }

    fn stopped_terminal(&self) -> Option<WorkerTerminal> {
        if Instant::now() >= self.deadline.at {
            Some(self.deadline.terminal)
        } else if self.cancellation.is_cancelled() {
            Some(WorkerTerminal::Shutdown)
        } else {
            None
        }
    }
}

impl Drop for WorkerContext {
    fn drop(&mut self) {
        self.terminal.finish(WorkerTerminal::Unavailable);
    }
}

async fn run_worker(mut worker: WorkerContext) {
    if let Some(terminal) = worker.stopped_terminal() {
        worker.finish(terminal);
        return;
    }
    let scope = match worker.scope.take() {
        Some(scope) => scope,
        None => {
            worker.finish(WorkerTerminal::Unavailable);
            return;
        }
    };
    let replay = match worker.executor.execute(scope, worker.query) {
        Ok(replay) => replay,
        Err(_) => {
            worker.finish(WorkerTerminal::Unavailable);
            return;
        }
    };
    if let Some(terminal) = worker.stopped_terminal() {
        worker.finish(terminal);
        return;
    }
    tokio::pin!(replay);

    loop {
        let demand = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(worker.deadline.at) => {
                worker.finish(worker.deadline.terminal);
                return;
            }
            _ = worker.cancellation.cancelled() => {
                worker.finish(WorkerTerminal::Shutdown);
                return;
            }
            demand = worker.demand_rx.recv() => demand,
        };
        if demand.is_none() {
            worker.finish(WorkerTerminal::Shutdown);
            return;
        }

        let next = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(worker.deadline.at) => {
                worker.finish(worker.deadline.terminal);
                return;
            }
            _ = worker.cancellation.cancelled() => {
                worker.finish(WorkerTerminal::Shutdown);
                return;
            }
            next = tonic::codegen::tokio_stream::StreamExt::next(&mut replay) => next,
        };
        let event = match next {
            Some(Ok(event)) => event,
            Some(Err(_)) => {
                worker.finish(WorkerTerminal::Unavailable);
                return;
            }
            None => {
                worker.finish(WorkerTerminal::Complete);
                return;
            }
        };

        let sent = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(worker.deadline.at) => {
                worker.finish(worker.deadline.terminal);
                return;
            }
            _ = worker.cancellation.cancelled() => {
                worker.finish(WorkerTerminal::Shutdown);
                return;
            }
            result = worker.result_tx.send(event) => result,
        };
        if sent.is_err() {
            worker.finish(WorkerTerminal::Shutdown);
            return;
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
enum WorkerTerminal {
    Running = 0,
    Complete = 1,
    ServiceDeadline = 2,
    AuthorityExpired = 3,
    Unavailable = 4,
    Shutdown = 5,
}

struct TerminalState {
    state: AtomicU8,
}

impl TerminalState {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(WorkerTerminal::Running as u8),
        }
    }

    fn finish(&self, terminal: WorkerTerminal) {
        let _ = self.state.compare_exchange(
            WorkerTerminal::Running as u8,
            terminal as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn load(&self) -> WorkerTerminal {
        match self.state.load(Ordering::Acquire) {
            0 => WorkerTerminal::Running,
            1 => WorkerTerminal::Complete,
            2 => WorkerTerminal::ServiceDeadline,
            3 => WorkerTerminal::AuthorityExpired,
            4 => WorkerTerminal::Unavailable,
            _ => WorkerTerminal::Shutdown,
        }
    }
}

enum ResponseState {
    Idle,
    DemandSent,
    Fused,
}

struct SupervisedWatchStream {
    state: ResponseState,
    deadline: WorkerDeadline,
    cancellation: CancellationToken,
    terminal: Arc<TerminalState>,
    demand_tx: mpsc::Sender<()>,
    result_rx: mpsc::Receiver<DecisionEvent>,
}

impl SupervisedWatchStream {
    fn terminal_poll(&mut self) -> Option<Poll<Option<Result<DecisionEvent, Status>>>> {
        if matches!(self.state, ResponseState::Fused) {
            return Some(Poll::Ready(None));
        }
        if Instant::now() >= self.deadline.at {
            self.terminal.finish(self.deadline.terminal);
            self.cancellation.cancel();
        }
        match self.terminal.load() {
            WorkerTerminal::Running => None,
            WorkerTerminal::Complete | WorkerTerminal::Shutdown => {
                self.state = ResponseState::Fused;
                Some(Poll::Ready(None))
            }
            WorkerTerminal::ServiceDeadline => {
                self.state = ResponseState::Fused;
                Some(Poll::Ready(Some(Err(Status::deadline_exceeded(
                    DECISION_GRPC_REQUEST_DEADLINE_MESSAGE,
                )))))
            }
            WorkerTerminal::AuthorityExpired => {
                self.state = ResponseState::Fused;
                Some(Poll::Ready(Some(Err(Status::unauthenticated(
                    AUTHENTICATION_REQUIRED_MESSAGE,
                )))))
            }
            WorkerTerminal::Unavailable => {
                self.state = ResponseState::Fused;
                Some(Poll::Ready(Some(Err(unavailable_status()))))
            }
        }
    }
}

impl Stream for SupervisedWatchStream {
    type Item = Result<DecisionEvent, Status>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Some(terminal) = this.terminal_poll() {
            return terminal;
        }
        if matches!(this.state, ResponseState::Idle) {
            match this.demand_tx.try_send(()) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {
                    this.state = ResponseState::DemandSent;
                }
                Err(mpsc::error::TrySendError::Closed(())) => {
                    this.terminal.finish(WorkerTerminal::Unavailable);
                    return this
                        .terminal_poll()
                        .unwrap_or(Poll::Ready(Some(Err(unavailable_status()))));
                }
            }
        }

        match this.result_rx.poll_recv(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(event)) => {
                this.state = ResponseState::Idle;
                if let Some(terminal) = this.terminal_poll() {
                    terminal
                } else {
                    Poll::Ready(Some(Ok(event)))
                }
            }
            Poll::Ready(None) => {
                if matches!(this.terminal.load(), WorkerTerminal::Running) {
                    this.terminal.finish(WorkerTerminal::Unavailable);
                }
                this.terminal_poll()
                    .unwrap_or(Poll::Ready(Some(Err(unavailable_status()))))
            }
        }
    }
}

impl Drop for SupervisedWatchStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn capacity_status() -> Status {
    Status::resource_exhausted(DECISION_SERVICE_CAPACITY_MESSAGE)
}

fn unavailable_status() -> Status {
    Status::unavailable(DECISION_SERVICE_UNAVAILABLE_MESSAGE)
}

pub(crate) const fn watch_encoding_limit() -> usize {
    MAX_DECISION_EVENT_WIRE_BYTES
}
