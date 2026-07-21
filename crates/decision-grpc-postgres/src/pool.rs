use std::{error::Error, fmt, num::NonZeroUsize, time::Duration};

use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use tokio_postgres::{
    Client, Socket,
    tls::{MakeTlsConnect, TlsConnect},
};

use crate::{
    AcquirePostgresReaderError, AcquirePostgresReaderFuture, FinishPostgresReaderLeaseError,
    PostgresReaderLease, PostgresReaderLeaseDisposition, PostgresReaderLeaseProvider,
};

// Deadpool preallocates its slot queue to the configured maximum.
const MAX_POSTGRES_READER_POOL_SIZE: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresReaderPoolConfig {
    max_size: NonZeroUsize,
    acquire_timeout: Duration,
}

impl PostgresReaderPoolConfig {
    pub fn try_new(
        max_size: usize,
        acquire_timeout: Duration,
    ) -> Result<Self, InvalidPostgresReaderPoolConfig> {
        let max_size = NonZeroUsize::new(max_size).ok_or(InvalidPostgresReaderPoolConfig)?;
        if max_size.get() > MAX_POSTGRES_READER_POOL_SIZE || acquire_timeout.is_zero() {
            return Err(InvalidPostgresReaderPoolConfig);
        }

        Ok(Self {
            max_size,
            acquire_timeout,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPostgresReaderPoolConfig;

impl fmt::Display for InvalidPostgresReaderPoolConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PostgreSQL reader pool configuration is invalid")
    }
}

impl Error for InvalidPostgresReaderPoolConfig {}

#[derive(Clone)]
pub struct PostgresReaderPool {
    pool: Pool,
}

impl PostgresReaderPool {
    /// The caller-supplied connector defines the PostgreSQL transport security boundary.
    pub fn try_new<T>(
        postgres_config: tokio_postgres::Config,
        tls: T,
        config: PostgresReaderPoolConfig,
    ) -> Result<Self, InvalidPostgresReaderPoolConfig>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let manager = Manager::from_config(
            postgres_config,
            tls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Verified,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(config.max_size.get())
            .wait_timeout(Some(config.acquire_timeout))
            .create_timeout(Some(config.acquire_timeout))
            .recycle_timeout(Some(config.acquire_timeout))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|_| InvalidPostgresReaderPoolConfig)?;

        Ok(Self { pool })
    }

    pub fn close(&self) {
        self.pool.close();
    }
}

pub struct PooledPostgresReaderLease {
    client: Option<Object>,
}

impl PostgresReaderLease for PooledPostgresReaderLease {
    fn client(&mut self) -> &mut Client {
        self.client
            .as_mut()
            .expect("pooled reader lease must own one session")
            .as_mut()
    }

    fn finish(
        mut self,
        disposition: PostgresReaderLeaseDisposition,
    ) -> Result<(), FinishPostgresReaderLeaseError> {
        let client = self
            .client
            .take()
            .expect("pooled reader lease must own one session");
        if disposition == PostgresReaderLeaseDisposition::Discard || client.is_closed() {
            discard(client);
        } else {
            drop(client);
        }

        Ok(())
    }
}

impl Drop for PooledPostgresReaderLease {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            discard(client);
        }
    }
}

impl PostgresReaderLeaseProvider for PostgresReaderPool {
    type Lease<'provider>
        = PooledPostgresReaderLease
    where
        Self: 'provider;

    fn acquire(&self) -> AcquirePostgresReaderFuture<'_, Self::Lease<'_>> {
        Box::pin(async move {
            self.pool
                .get()
                .await
                .map(|client| PooledPostgresReaderLease {
                    client: Some(client),
                })
                .map_err(|_| AcquirePostgresReaderError)
        })
    }
}

fn discard(client: Object) {
    drop(Object::take(client));
}
