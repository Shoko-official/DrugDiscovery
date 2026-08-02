use std::{
    collections::HashSet,
    error::Error,
    fmt,
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bioworld_decision_grpc::{DecisionGrpcService, TenantScope, TenantScopedGetDecisionExecutor};
use bioworld_decision_grpc_jwt::JwtTenantAuthenticator;
use bioworld_decision_grpc_postgres::{PostgresDecisionExecutor, PostgresReaderPool};
use bioworld_decision_grpc_server::{
    BindDecisionGrpcServerError, DecisionGrpcServer, DecisionGrpcTlsIdentity,
    MAX_DECISION_GRPC_TLS_CERTIFICATE_CHAIN_PEM_BYTES, MAX_DECISION_GRPC_TLS_PRIVATE_KEY_PEM_BYTES,
    ServeDecisionGrpcServerError,
};
use bioworld_decision_query::{GetDecisionQuery, GetDecisionRequestExecutionError};
use bioworld_event_store_contracts::{
    DecisionEventVerifier, MAX_DECISION_EVENT_VERIFICATION_SNAPSHOT_BYTES,
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject, pem::SectionKind},
};
use tokio_postgres::config::{ChannelBinding, SslMode};
use tokio_postgres_rustls::MakeRustlsConnect;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::DecisionServerConfig;
use crate::config::{DecisionServerConfigParts, PostgresRuntimeConfig};
use crate::secure_file::{SecureFile, SecureFilePolicy, read_secure_file};

const MAX_JWKS_FILE_BYTES: usize = 65_536;
const MAX_POSTGRES_CA_FILE_BYTES: usize = 65_536;
const MAX_POSTGRES_CA_CERTIFICATES: usize = 32;
const MAX_POSTGRES_PASSWORD_BYTES: usize = 1_024;
const POSTGRES_READER_ROLE: &str = "bioworld_reader";
const POSTGRES_APPLICATION_NAME: &str = "bioworld-decision-server";
const PREFLIGHT_TENANT_ID: &str = "bioworld-startup-probe";
const TRUST_DEADLINE_SAFETY_MARGIN: Duration = Duration::from_secs(1);
const TRUST_READINESS_MARGIN: Duration = Duration::from_secs(1);
const TRUST_WALL_CLOCK_RECHECK_INTERVAL: Duration = Duration::from_millis(250);

type RuntimeExecutor = PostgresDecisionExecutor<PostgresReaderPool>;
type RuntimeService = DecisionGrpcService<JwtTenantAuthenticator, RuntimeExecutor>;

/// Prepared read-only server with every dependency verified before listener use.
pub struct DecisionServerRuntime {
    server: DecisionGrpcServer,
    service: RuntimeService,
    pool: PoolCloseGuard,
    trust_deadline: RuntimeTrustDeadline,
}

impl DecisionServerRuntime {
    /// Loads sensitive inputs, verifies PostgreSQL, and binds only after preflight succeeds.
    pub async fn prepare(config: DecisionServerConfig) -> Result<Self, DecisionServerStartupError> {
        let DecisionServerConfigParts {
            server,
            server_tls,
            jwt,
            jwks_file,
            event_verification_keys_file,
            postgres,
            service: service_config,
            watch,
        } = config.into_parts();

        let certificate_chain = read_secure_file(
            &server_tls.certificate_chain,
            MAX_DECISION_GRPC_TLS_CERTIFICATE_CHAIN_PEM_BYTES,
            SecureFilePolicy::Public,
        )
        .await
        .map_err(|_| DecisionServerStartupError::SensitiveInputRejected)?;
        let private_key = read_secure_file(
            &server_tls.private_key,
            MAX_DECISION_GRPC_TLS_PRIVATE_KEY_PEM_BYTES,
            SecureFilePolicy::Secret,
        )
        .await
        .map_err(|_| DecisionServerStartupError::SensitiveInputRejected)?;
        let jwks = read_secure_file(&jwks_file, MAX_JWKS_FILE_BYTES, SecureFilePolicy::Public)
            .await
            .map_err(|_| DecisionServerStartupError::SensitiveInputRejected)?;
        let event_verification_keys = read_secure_file(
            &event_verification_keys_file,
            MAX_DECISION_EVENT_VERIFICATION_SNAPSHOT_BYTES,
            SecureFilePolicy::Public,
        )
        .await
        .map_err(|_| DecisionServerStartupError::SensitiveInputRejected)?;
        let ca_pem = read_secure_file(
            &postgres.ca_file,
            MAX_POSTGRES_CA_FILE_BYTES,
            SecureFilePolicy::Public,
        )
        .await
        .map_err(|_| DecisionServerStartupError::SensitiveInputRejected)?;
        let password = read_secure_file(
            &postgres.password_file,
            MAX_POSTGRES_PASSWORD_BYTES,
            SecureFilePolicy::Secret,
        )
        .await
        .map_err(|_| DecisionServerStartupError::SensitiveInputRejected)?;
        let mut identities = HashSet::new();
        let mut certificate_chain = unique_contents(certificate_chain, &mut identities)?;
        let mut private_key = unique_contents(private_key, &mut identities)?;
        let jwks = unique_contents(jwks, &mut identities)?;
        let event_verification_keys = unique_contents(event_verification_keys, &mut identities)?;
        let ca_pem = unique_contents(ca_pem, &mut identities)?;
        let mut password = unique_contents(password, &mut identities)?;

        let certificate_chain = std::mem::take(&mut *certificate_chain);
        let private_key = std::mem::take(&mut *private_key);
        let server_identity = DecisionGrpcTlsIdentity::try_from_pem(certificate_chain, private_key)
            .map_err(|_| DecisionServerStartupError::ServerIdentityRejected)?;

        let jwks_valid_until = jwt.jwks_valid_until();
        let authenticator = JwtTenantAuthenticator::try_from_jwks(jwt, &jwks)
            .map_err(|_| DecisionServerStartupError::IdentityConfigurationRejected)?;
        let event_verifier = DecisionEventVerifier::try_from_snapshot(&event_verification_keys)
            .map_err(|_| DecisionServerStartupError::EventVerificationConfigurationRejected)?;
        let trust_deadline = RuntimeTrustDeadline::try_from_unix_expirations(
            jwks_valid_until,
            event_verifier.snapshot_valid_until(),
        )?;
        trust_deadline.ensure_current()?;

        normalize_password(&mut password)?;
        let (postgres_config, postgres_tls) =
            build_postgres_transport(&postgres, &ca_pem, &password)?;
        let pool = PostgresReaderPool::try_new(postgres_config, postgres_tls, postgres.pool)
            .map_err(|_| DecisionServerStartupError::DatabaseConfigurationRejected)?;
        let pool = PoolCloseGuard::new(pool);
        preflight_with_deadline(
            postgres.preflight_timeout,
            preflight_reader(pool.pool(), event_verifier.clone()),
        )
        .await?;
        trust_deadline.ensure_current()?;

        let executor = PostgresDecisionExecutor::new(pool.pool().clone(), event_verifier);
        let service = match watch {
            Some(watch_config) => DecisionGrpcService::try_new_with_watch(
                authenticator,
                executor,
                service_config,
                watch_config,
            ),
            None => Ok(DecisionGrpcService::new(
                authenticator,
                executor,
                service_config,
            )),
        }
        .map_err(|_| DecisionServerStartupError::ServiceConfigurationRejected)?;
        trust_deadline.ensure_current()?;
        let server = DecisionGrpcServer::bind(server, server_identity)
            .await
            .map_err(map_bind_error)?;
        trust_deadline.ensure_current()?;

        Ok(Self {
            server,
            service,
            pool,
            trust_deadline,
        })
    }

    /// Returns the bound listener address after all startup checks succeed.
    pub fn local_addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    /// Returns the observer-verifiable Unix expiration for a bounded readiness lease.
    ///
    /// A process controller must reject the lease at or after this value.
    pub fn readiness_valid_until(&self) -> Result<u64, DecisionServerStartupError> {
        self.trust_deadline.ensure_ready()?;
        Ok(self.trust_deadline.unix_deadline.as_secs())
    }

    /// Serves until shutdown or trust expiry, drains bounded work, then closes the reader pool.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), DecisionServerServeError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let Self {
            server,
            service,
            pool,
            trust_deadline,
        } = self;
        if trust_deadline.is_expired() {
            drop(pool);
            return Err(DecisionServerServeError::TrustExpired);
        }
        let trust_expired = Arc::new(AtomicBool::new(false));
        let expiry_observed = Arc::clone(&trust_expired);
        let bounded_shutdown = async move {
            tokio::select! {
                biased;
                _ = shutdown => {}
                _ = trust_deadline.wait_until_expired() => {
                    expiry_observed.store(true, Ordering::Release);
                }
            }
        };
        let result = server
            .serve(service, bounded_shutdown)
            .await
            .map_err(DecisionServerServeError::from);
        drop(pool);
        result?;
        if trust_expired.load(Ordering::Acquire) {
            Err(DecisionServerServeError::TrustExpired)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for DecisionServerRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionServerRuntime")
    }
}

/// Fixed, redacted startup failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionServerStartupError {
    /// A bounded file could not be read as a regular file within its limit.
    SensitiveInputRejected,
    /// Server certificate or private-key input was rejected.
    ServerIdentityRejected,
    /// JWT verification policy or key snapshot was rejected.
    IdentityConfigurationRejected,
    /// Scientific event verification policy or key snapshot was rejected.
    EventVerificationConfigurationRejected,
    /// The validated service and Watch capacity relationship was rejected.
    ServiceConfigurationRejected,
    /// PostgreSQL CA, password, or connection policy was rejected.
    DatabaseConfigurationRejected,
    /// PostgreSQL availability, schema, reader identity, or tenant boundary was rejected.
    DatabaseUnavailable,
    /// The configured listener address was unavailable.
    ListenerUnavailable,
    /// JWT or scientific-event verification trust expired before readiness.
    TrustExpired,
}

impl fmt::Display for DecisionServerStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SensitiveInputRejected => {
                formatter.write_str("decision server sensitive input is rejected")
            }
            Self::ServerIdentityRejected => {
                formatter.write_str("decision server identity is rejected")
            }
            Self::IdentityConfigurationRejected => {
                formatter.write_str("decision server authentication configuration is rejected")
            }
            Self::EventVerificationConfigurationRejected => {
                formatter.write_str("decision server event verification configuration is rejected")
            }
            Self::ServiceConfigurationRejected => {
                formatter.write_str("decision server service configuration is rejected")
            }
            Self::DatabaseConfigurationRejected => {
                formatter.write_str("decision server database configuration is rejected")
            }
            Self::DatabaseUnavailable => {
                formatter.write_str("decision server database is unavailable")
            }
            Self::ListenerUnavailable => {
                formatter.write_str("decision server listener is unavailable")
            }
            Self::TrustExpired => formatter.write_str("decision server verification trust expired"),
        }
    }
}

impl Error for DecisionServerStartupError {}

/// Fixed, redacted serving failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionServerServeError {
    /// The transport stopped unexpectedly.
    TransportFailure,
    /// Graceful shutdown exceeded its validated deadline.
    ShutdownDeadlineExceeded,
    /// Service work cannot drain inside the shutdown budget.
    ServiceLimitsRejected,
    /// JWT or scientific-event verification trust reached its bounded deadline.
    TrustExpired,
}

impl fmt::Display for DecisionServerServeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportFailure => formatter.write_str("decision server transport failed"),
            Self::ShutdownDeadlineExceeded => {
                formatter.write_str("decision server shutdown deadline exceeded")
            }
            Self::ServiceLimitsRejected => {
                formatter.write_str("decision server service limits are rejected")
            }
            Self::TrustExpired => formatter.write_str("decision server verification trust expired"),
        }
    }
}

impl Error for DecisionServerServeError {}

impl From<ServeDecisionGrpcServerError> for DecisionServerServeError {
    fn from(error: ServeDecisionGrpcServerError) -> Self {
        match error {
            ServeDecisionGrpcServerError::TransportFailure => Self::TransportFailure,
            ServeDecisionGrpcServerError::ShutdownDeadlineExceeded => {
                Self::ShutdownDeadlineExceeded
            }
            ServeDecisionGrpcServerError::ServiceLimitsRejected => Self::ServiceLimitsRejected,
        }
    }
}

#[derive(Clone, Copy)]
struct RuntimeTrustDeadline {
    monotonic_deadline: tokio::time::Instant,
    unix_deadline: Duration,
}

impl RuntimeTrustDeadline {
    fn try_from_unix_expirations(
        jwks_valid_until: u64,
        event_verification_valid_until: u64,
    ) -> Result<Self, DecisionServerStartupError> {
        let sampled_at = tokio::time::Instant::now();
        let sampled_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DecisionServerStartupError::TrustExpired)?;
        Self::try_from_sample(
            jwks_valid_until,
            event_verification_valid_until,
            sampled_now,
            sampled_at,
        )
    }

    fn try_from_sample(
        jwks_valid_until: u64,
        event_verification_valid_until: u64,
        sampled_now: Duration,
        sampled_at: tokio::time::Instant,
    ) -> Result<Self, DecisionServerStartupError> {
        let unix_deadline =
            Duration::from_secs(jwks_valid_until.min(event_verification_valid_until))
                .checked_sub(TRUST_DEADLINE_SAFETY_MARGIN)
                .ok_or(DecisionServerStartupError::TrustExpired)?;
        let valid_for = unix_deadline
            .checked_sub(sampled_now)
            .filter(|duration| !duration.is_zero())
            .ok_or(DecisionServerStartupError::TrustExpired)?;
        sampled_at
            .checked_add(valid_for)
            .map(|monotonic_deadline| Self {
                monotonic_deadline,
                unix_deadline,
            })
            .ok_or(DecisionServerStartupError::TrustExpired)
    }

    fn ensure_current(self) -> Result<(), DecisionServerStartupError> {
        if self.is_expired() {
            Err(DecisionServerStartupError::TrustExpired)
        } else {
            Ok(())
        }
    }

    fn ensure_ready(self) -> Result<(), DecisionServerStartupError> {
        self.ensure_ready_at(
            tokio::time::Instant::now(),
            SystemTime::now().duration_since(UNIX_EPOCH).ok(),
        )
    }

    fn ensure_ready_at(
        self,
        monotonic_now: tokio::time::Instant,
        unix_now: Option<Duration>,
    ) -> Result<(), DecisionServerStartupError> {
        let remaining = self.remaining_at(monotonic_now, unix_now);
        if remaining.is_some_and(|remaining| remaining > TRUST_READINESS_MARGIN) {
            Ok(())
        } else {
            Err(DecisionServerStartupError::TrustExpired)
        }
    }

    fn is_expired(self) -> bool {
        self.remaining_at(
            tokio::time::Instant::now(),
            SystemTime::now().duration_since(UNIX_EPOCH).ok(),
        )
        .is_none_or(|remaining| remaining.is_zero())
    }

    fn remaining_at(
        self,
        monotonic_now: tokio::time::Instant,
        unix_now: Option<Duration>,
    ) -> Option<Duration> {
        let unix_now = unix_now?;
        Some(
            self.monotonic_deadline
                .saturating_duration_since(monotonic_now)
                .min(self.unix_deadline.saturating_sub(unix_now)),
        )
    }

    async fn wait_until_expired(self) {
        loop {
            if self.is_expired() {
                return;
            }
            let next_wall_check = tokio::time::Instant::now()
                .checked_add(TRUST_WALL_CLOCK_RECHECK_INTERVAL)
                .unwrap_or(self.monotonic_deadline)
                .min(self.monotonic_deadline);
            tokio::time::sleep_until(next_wall_check).await;
        }
    }

    #[cfg(test)]
    fn monotonic(self) -> tokio::time::Instant {
        self.monotonic_deadline
    }
}

struct PoolCloseGuard {
    pool: PostgresReaderPool,
}

impl PoolCloseGuard {
    fn new(pool: PostgresReaderPool) -> Self {
        Self { pool }
    }

    fn pool(&self) -> &PostgresReaderPool {
        &self.pool
    }
}

impl Drop for PoolCloseGuard {
    fn drop(&mut self) {
        self.pool.close();
    }
}

fn unique_contents(
    file: SecureFile,
    identities: &mut HashSet<same_file::Handle>,
) -> Result<Zeroizing<Vec<u8>>, DecisionServerStartupError> {
    let (contents, identity) = file.into_parts();
    if !identities.insert(identity) {
        return Err(DecisionServerStartupError::SensitiveInputRejected);
    }
    Ok(contents)
}

fn build_postgres_transport(
    config: &PostgresRuntimeConfig,
    ca_pem: &[u8],
    password: &[u8],
) -> Result<(tokio_postgres::Config, MakeRustlsConnect), DecisionServerStartupError> {
    let roots = parse_postgres_roots(ca_pem)?;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let client_tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| DecisionServerStartupError::DatabaseConfigurationRejected)?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut postgres = tokio_postgres::Config::new();
    postgres
        .host(&config.host)
        .port(config.port)
        .dbname(&config.database)
        .user(POSTGRES_READER_ROLE)
        .password(password)
        .application_name(POSTGRES_APPLICATION_NAME)
        .ssl_mode(SslMode::Require)
        .channel_binding(ChannelBinding::Require)
        .connect_timeout(config.connect_timeout);

    Ok((postgres, MakeRustlsConnect::new(client_tls)))
}

fn parse_postgres_roots(input: &[u8]) -> Result<RootCertStore, DecisionServerStartupError> {
    validate_certificate_pem(input)?;
    let mut roots = RootCertStore::empty();
    let mut seen = HashSet::<Vec<u8>>::new();
    let mut count = 0_usize;

    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(input) {
        let (SectionKind::Certificate, certificate) =
            item.map_err(|_| DecisionServerStartupError::DatabaseConfigurationRejected)?
        else {
            return Err(DecisionServerStartupError::DatabaseConfigurationRejected);
        };
        count = count
            .checked_add(1)
            .ok_or(DecisionServerStartupError::DatabaseConfigurationRejected)?;
        if count > MAX_POSTGRES_CA_CERTIFICATES || !seen.insert(certificate.clone()) {
            return Err(DecisionServerStartupError::DatabaseConfigurationRejected);
        }
        add_root(&mut roots, CertificateDer::from(certificate))?;
    }

    if count == 0 {
        return Err(DecisionServerStartupError::DatabaseConfigurationRejected);
    }
    Ok(roots)
}

fn validate_certificate_pem(input: &[u8]) -> Result<(), DecisionServerStartupError> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";

    let mut inside = false;
    let mut count = 0_usize;
    for raw_line in input.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.contains(&b'\r') {
            return Err(DecisionServerStartupError::DatabaseConfigurationRejected);
        }
        if inside {
            if line == END {
                inside = false;
                count = count
                    .checked_add(1)
                    .ok_or(DecisionServerStartupError::DatabaseConfigurationRejected)?;
            } else if line.is_empty()
                || !line
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
            {
                return Err(DecisionServerStartupError::DatabaseConfigurationRejected);
            }
        } else if line == BEGIN {
            inside = true;
        } else if !line.iter().all(u8::is_ascii_whitespace) {
            return Err(DecisionServerStartupError::DatabaseConfigurationRejected);
        }
    }

    if inside || count == 0 || count > MAX_POSTGRES_CA_CERTIFICATES {
        return Err(DecisionServerStartupError::DatabaseConfigurationRejected);
    }
    Ok(())
}

fn add_root(
    roots: &mut RootCertStore,
    certificate: CertificateDer<'static>,
) -> Result<(), DecisionServerStartupError> {
    roots
        .add(certificate)
        .map_err(|_| DecisionServerStartupError::DatabaseConfigurationRejected)
}

fn normalize_password(password: &mut Vec<u8>) -> Result<(), DecisionServerStartupError> {
    if password.ends_with(b"\n") {
        password.pop();
        if password.ends_with(b"\r") {
            password.pop();
        }
    }
    if password.is_empty()
        || password
            .iter()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(DecisionServerStartupError::DatabaseConfigurationRejected);
    }
    Ok(())
}

async fn preflight_reader(
    pool: &PostgresReaderPool,
    verifier: DecisionEventVerifier,
) -> Result<(), DecisionServerStartupError> {
    let executor = PostgresDecisionExecutor::new(pool.clone(), verifier);
    let scope = TenantScope::try_from_trusted_tenant_id(PREFLIGHT_TENANT_ID.to_owned())
        .map_err(|_| DecisionServerStartupError::DatabaseUnavailable)?;
    let query = GetDecisionQuery::new(Uuid::nil());
    match executor.execute_get_decision(scope, query).await {
        Ok(_) | Err(GetDecisionRequestExecutionError::NotFound) => Ok(()),
        Err(
            GetDecisionRequestExecutionError::InvalidRequest
            | GetDecisionRequestExecutionError::SourceUnavailable
            | GetDecisionRequestExecutionError::StoredStateRejected,
        ) => Err(DecisionServerStartupError::DatabaseUnavailable),
    }
}

async fn preflight_with_deadline<F>(
    deadline: Duration,
    preflight: F,
) -> Result<(), DecisionServerStartupError>
where
    F: Future<Output = Result<(), DecisionServerStartupError>>,
{
    tokio::time::timeout(deadline, preflight)
        .await
        .map_err(|_| DecisionServerStartupError::DatabaseUnavailable)?
}

fn map_bind_error(error: BindDecisionGrpcServerError) -> DecisionServerStartupError {
    match error {
        BindDecisionGrpcServerError::TlsIdentityRejected => {
            DecisionServerStartupError::ServerIdentityRejected
        }
        BindDecisionGrpcServerError::AddressUnavailable => {
            DecisionServerStartupError::ListenerUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future, time::Duration};

    use rcgen::generate_simple_self_signed;
    use tokio::time::Instant;

    use super::{
        DecisionServerStartupError, RuntimeTrustDeadline, parse_postgres_roots,
        preflight_with_deadline,
    };

    #[test]
    fn postgres_ca_input_is_strictly_certificate_pem() {
        let certificate = generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("test certificate generation")
            .cert
            .pem();

        assert!(parse_postgres_roots(certificate.as_bytes()).is_ok());
        for rejected in [
            format!("untrusted prefix\n{certificate}"),
            format!("{certificate}\nuntrusted suffix"),
            format!("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n{certificate}"),
        ] {
            assert_eq!(
                parse_postgres_roots(rejected.as_bytes()).expect_err("CA input must be rejected"),
                DecisionServerStartupError::DatabaseConfigurationRejected
            );
        }
    }

    #[tokio::test]
    async fn postgres_preflight_has_a_global_deadline() {
        let result = preflight_with_deadline(
            Duration::from_millis(1),
            future::pending::<Result<(), DecisionServerStartupError>>(),
        )
        .await;

        assert_eq!(result, Err(DecisionServerStartupError::DatabaseUnavailable));
    }

    #[test]
    fn runtime_trust_uses_the_earliest_snapshot_and_a_monotonic_deadline() {
        let sampled_at = Instant::now();
        let sampled_now = Duration::from_secs(100);
        let jwks_first = RuntimeTrustDeadline::try_from_sample(110, 120, sampled_now, sampled_at)
            .expect("bounded JWKS validity must produce a deadline");
        let events_first = RuntimeTrustDeadline::try_from_sample(120, 108, sampled_now, sampled_at)
            .expect("bounded event verification validity must produce a deadline");

        assert_eq!(jwks_first.monotonic(), sampled_at + Duration::from_secs(9));
        assert_eq!(
            events_first.monotonic(),
            sampled_at + Duration::from_secs(7)
        );
    }

    #[test]
    fn runtime_trust_rejects_expiration_inside_its_precision_reserve() {
        let sampled_at = Instant::now();

        for valid_until in [99, 100, 101] {
            assert_eq!(
                RuntimeTrustDeadline::try_from_sample(
                    valid_until,
                    valid_until,
                    Duration::from_secs(100),
                    sampled_at,
                )
                .err()
                .expect("stale trust must not produce a runtime deadline"),
                DecisionServerStartupError::TrustExpired
            );
        }
    }

    #[test]
    fn runtime_trust_rejects_readiness_after_its_monotonic_deadline() {
        let expired = RuntimeTrustDeadline {
            monotonic_deadline: Instant::now() - Duration::from_millis(1),
            unix_deadline: Duration::from_secs(u64::MAX),
        };

        assert_eq!(
            expired.ensure_current(),
            Err(DecisionServerStartupError::TrustExpired)
        );
    }

    #[test]
    fn runtime_trust_preserves_the_full_precision_safety_margin() {
        let sampled_at = Instant::now();
        let deadline = RuntimeTrustDeadline::try_from_sample(
            110,
            120,
            Duration::from_millis(100_900),
            sampled_at,
        )
        .expect("fractional wall time must produce a conservative deadline");

        assert_eq!(
            deadline.monotonic(),
            sampled_at + Duration::from_millis(8_100)
        );
    }

    #[test]
    fn runtime_trust_uses_wall_time_only_to_shorten_the_monotonic_bound() {
        let sampled_at = Instant::now();
        let deadline =
            RuntimeTrustDeadline::try_from_sample(120, 120, Duration::from_secs(100), sampled_at)
                .expect("bounded trust must produce a deadline");

        assert_eq!(
            deadline.remaining_at(
                sampled_at + Duration::from_secs(1),
                Some(Duration::from_secs(119))
            ),
            Some(Duration::ZERO)
        );
        assert_eq!(
            deadline.remaining_at(
                sampled_at + Duration::from_secs(19),
                Some(Duration::from_secs(1))
            ),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn runtime_trust_requires_a_margin_before_readiness() {
        let sampled_at = Instant::now();
        let deadline =
            RuntimeTrustDeadline::try_from_sample(103, 103, Duration::from_secs(100), sampled_at)
                .expect("bounded trust must produce a deadline");

        assert_eq!(
            deadline.ensure_ready_at(
                sampled_at + Duration::from_secs(1),
                Some(Duration::from_secs(101)),
            ),
            Err(DecisionServerStartupError::TrustExpired)
        );
        assert_eq!(
            deadline.ensure_ready_at(sampled_at, Some(Duration::from_secs(100))),
            Ok(())
        );
    }
}
