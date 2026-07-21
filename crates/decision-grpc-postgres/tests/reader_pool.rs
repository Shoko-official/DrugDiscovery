use std::{error::Error, time::Duration};

use bioworld_decision_grpc_postgres::{
    AcquirePostgresReaderError, InvalidPostgresReaderPoolConfig, PostgresReaderLeaseProvider,
    PostgresReaderPool, PostgresReaderPoolConfig,
};

#[test]
fn reader_pool_configuration_rejects_unsafe_limits() {
    assert_eq!(
        PostgresReaderPoolConfig::try_new(0, Duration::from_secs(1)),
        Err(InvalidPostgresReaderPoolConfig)
    );
    assert_eq!(
        PostgresReaderPoolConfig::try_new(1, Duration::ZERO),
        Err(InvalidPostgresReaderPoolConfig)
    );
    assert_eq!(
        PostgresReaderPoolConfig::try_new(usize::MAX, Duration::from_secs(1)),
        Err(InvalidPostgresReaderPoolConfig)
    );

    let error = InvalidPostgresReaderPoolConfig;
    assert_eq!(format!("{error:?}"), "InvalidPostgresReaderPoolConfig");
    assert_eq!(
        error.to_string(),
        "PostgreSQL reader pool configuration is invalid"
    );

    fn assert_error<T: Error + Send + Sync + Copy>(_: T) {}
    assert_error(error);
}

#[test]
fn reader_pool_and_acquisition_future_are_thread_safe() {
    fn assert_send<T: Send>(_: T) {}
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<PostgresReaderPool>();

    let config = PostgresReaderPoolConfig::try_new(2, Duration::from_secs(1)).unwrap();
    let pool =
        PostgresReaderPool::try_new(tokio_postgres::Config::new(), tokio_postgres::NoTls, config)
            .unwrap();
    let acquisition = pool.acquire();
    assert_send(acquisition);
    pool.close();
}

#[tokio::test]
async fn closed_reader_pool_rejects_acquisition_with_a_fixed_error() {
    let sensitive_host = "sensitive-reader.internal.invalid";
    let sensitive_password = "sensitive-reader-password";
    let mut postgres = tokio_postgres::Config::new();
    postgres
        .host(sensitive_host)
        .user("sensitive-reader")
        .password(sensitive_password);
    let config = PostgresReaderPoolConfig::try_new(1, Duration::from_secs(1)).unwrap();
    let pool = PostgresReaderPool::try_new(postgres, tokio_postgres::NoTls, config).unwrap();
    pool.close();

    let error = pool.acquire().await.err();

    assert_eq!(error, Some(AcquirePostgresReaderError));
    let rendered = format!("{:?} {}", error.unwrap(), error.unwrap());
    assert!(!rendered.contains(sensitive_host));
    assert!(!rendered.contains(sensitive_password));
}

#[tokio::test]
async fn connection_failure_is_fixed_and_does_not_reflect_credentials() {
    let sensitive_user = "sensitive-failed-reader";
    let sensitive_password = "sensitive-failed-password";
    let mut postgres = tokio_postgres::Config::new();
    postgres
        .host("127.0.0.1")
        .port(1)
        .user(sensitive_user)
        .password(sensitive_password);
    let config = PostgresReaderPoolConfig::try_new(1, Duration::from_millis(100)).unwrap();
    let pool = PostgresReaderPool::try_new(postgres, tokio_postgres::NoTls, config).unwrap();

    let error = pool.acquire().await.err();

    assert_eq!(error, Some(AcquirePostgresReaderError));
    let rendered = format!("{:?} {}", error.unwrap(), error.unwrap());
    assert!(!rendered.contains(sensitive_user));
    assert!(!rendered.contains(sensitive_password));
    pool.close();
}
