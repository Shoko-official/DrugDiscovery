#![deny(unsafe_code)]

use std::{error::Error, fmt, future::Future, pin::Pin};

use bioworld_decision_grpc::{
    TenantScope, TenantScopedGetDecisionExecutor, TenantScopedGetDecisionFuture,
};
use bioworld_decision_query::{GetDecision, GetDecisionQuery, GetDecisionRequestExecutionError};
use bioworld_event_store_postgres::{PostgresDecisionEventReader, PostgresLatestDecisionSource};
use tokio_postgres::Client;

const ROLLBACK_READER_SESSION: &str = "ROLLBACK";
const TENANT_CONTEXT_IS_ABSENT: &str =
    "SELECT NULLIF(pg_catalog.current_setting('bioworld.tenant_id', true), '') IS NULL";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcquirePostgresReaderError;

impl fmt::Display for AcquirePostgresReaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PostgreSQL reader acquisition failed")
    }
}

impl Error for AcquirePostgresReaderError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinishPostgresReaderLeaseError;

impl fmt::Display for FinishPostgresReaderLeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PostgreSQL reader cleanup failed")
    }
}

impl Error for FinishPostgresReaderLeaseError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresReaderLeaseDisposition {
    Reuse,
    Discard,
}

pub type AcquirePostgresReaderFuture<'a, L> =
    Pin<Box<dyn Future<Output = Result<L, AcquirePostgresReaderError>> + Send + 'a>>;

/// Provides exclusive access to one reader session.
///
/// Implementations must discard an unfinished lease when it is dropped. A failed
/// `finish` call must also discard the session rather than return it to circulation.
pub trait PostgresReaderLease: Send {
    fn client(&mut self) -> &mut Client;

    fn finish(
        self,
        disposition: PostgresReaderLeaseDisposition,
    ) -> Result<(), FinishPostgresReaderLeaseError>;
}

pub trait PostgresReaderLeaseProvider: Send + Sync {
    type Lease<'provider>: PostgresReaderLease + 'provider
    where
        Self: 'provider;

    /// Acquires a reader session without sharing it with another active lease.
    ///
    /// Once removed from circulation, a session must be returned or discarded if
    /// this future is cancelled before yielding its lease.
    fn acquire(&self) -> AcquirePostgresReaderFuture<'_, Self::Lease<'_>>;
}

pub struct PostgresGetDecisionExecutor<P> {
    provider: P,
}

impl<P> PostgresGetDecisionExecutor<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> TenantScopedGetDecisionExecutor for PostgresGetDecisionExecutor<P>
where
    P: PostgresReaderLeaseProvider,
{
    fn execute_get_decision(
        &self,
        scope: TenantScope,
        query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        Box::pin(async move {
            let lease = self
                .provider
                .acquire()
                .await
                .map_err(|_| GetDecisionRequestExecutionError::SourceUnavailable)?;
            let mut lease = ReaderLeaseGuard::new(lease);

            let result = {
                let reader = PostgresDecisionEventReader::new(lease.client());
                match PostgresLatestDecisionSource::try_new(reader, scope.tenant_id()) {
                    Ok(source) => GetDecision::new(source).execute_validated(query).await,
                    Err(_) => Err(GetDecisionRequestExecutionError::SourceUnavailable),
                }
            };

            let disposition = if reset_reader_session(lease.client()).await {
                PostgresReaderLeaseDisposition::Reuse
            } else {
                PostgresReaderLeaseDisposition::Discard
            };
            let finish_result = lease.finish(disposition);

            if disposition == PostgresReaderLeaseDisposition::Discard || finish_result.is_err() {
                Err(GetDecisionRequestExecutionError::SourceUnavailable)
            } else {
                result
            }
        })
    }
}

async fn reset_reader_session(client: &mut Client) -> bool {
    if client.batch_execute(ROLLBACK_READER_SESSION).await.is_err() {
        return false;
    }

    client
        .query_one(TENANT_CONTEXT_IS_ABSENT, &[])
        .await
        .ok()
        .and_then(|row| row.try_get::<_, bool>(0).ok())
        .unwrap_or(false)
}

struct ReaderLeaseGuard<L>
where
    L: PostgresReaderLease,
{
    lease: Option<L>,
}

impl<L> ReaderLeaseGuard<L>
where
    L: PostgresReaderLease,
{
    fn new(lease: L) -> Self {
        Self { lease: Some(lease) }
    }

    fn client(&mut self) -> &mut Client {
        self.lease
            .as_mut()
            .expect("reader lease guard must own its lease")
            .client()
    }

    fn finish(
        mut self,
        disposition: PostgresReaderLeaseDisposition,
    ) -> Result<(), FinishPostgresReaderLeaseError> {
        self.lease
            .take()
            .expect("reader lease guard must own its lease")
            .finish(disposition)
    }
}

impl<L> Drop for ReaderLeaseGuard<L>
where
    L: PostgresReaderLease,
{
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            let _ = lease.finish(PostgresReaderLeaseDisposition::Discard);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        FinishPostgresReaderLeaseError, PostgresReaderLease, PostgresReaderLeaseDisposition,
        ReaderLeaseGuard,
    };
    use tokio_postgres::Client;

    struct TrackingLease {
        disposition: Arc<Mutex<Option<PostgresReaderLeaseDisposition>>>,
    }

    impl PostgresReaderLease for TrackingLease {
        fn client(&mut self) -> &mut Client {
            panic!("drop test must not access a database client")
        }

        fn finish(
            self,
            disposition: PostgresReaderLeaseDisposition,
        ) -> Result<(), FinishPostgresReaderLeaseError> {
            *self.disposition.lock().unwrap() = Some(disposition);
            Ok(())
        }
    }

    #[test]
    fn unfinished_guard_discards_its_reader_session() {
        let disposition = Arc::new(Mutex::new(None));

        drop(ReaderLeaseGuard::new(TrackingLease {
            disposition: Arc::clone(&disposition),
        }));

        assert_eq!(
            *disposition.lock().unwrap(),
            Some(PostgresReaderLeaseDisposition::Discard)
        );
    }
}
