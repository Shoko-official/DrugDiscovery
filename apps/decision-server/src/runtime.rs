use std::{
    collections::HashSet, error::Error, fmt, future::Future, net::SocketAddr, sync::Arc,
    time::Duration,
};

use bioworld_decision_grpc::{DecisionGrpcService, TenantScope, TenantScopedGetDecisionExecutor};
use bioworld_decision_grpc_jwt::JwtTenantAuthenticator;
use bioworld_decision_grpc_postgres::{PostgresGetDecisionExecutor, PostgresReaderPool};
use bioworld_decision_grpc_server::{
    BindDecisionGrpcServerError, DecisionGrpcServer, DecisionGrpcTlsIdentity,
    MAX_DECISION_GRPC_TLS_CERTIFICATE_CHAIN_PEM_BYTES, MAX_DECISION_GRPC_TLS_PRIVATE_KEY_PEM_BYTES,
    ServeDecisionGrpcServerError,
};
use bioworld_decision_query::{GetDecisionQuery, GetDecisionRequestExecutionError};
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

type RuntimeExecutor = PostgresGetDecisionExecutor<PostgresReaderPool>;
type RuntimeService = DecisionGrpcService<JwtTenantAuthenticator, RuntimeExecutor>;

/// Prepared read-only server with every dependency verified before listener use.
pub struct DecisionServerRuntime {
    server: DecisionGrpcServer,
    service: RuntimeService,
    pool: PoolCloseGuard,
}

impl DecisionServerRuntime {
    /// Loads sensitive inputs, verifies PostgreSQL, and binds only after preflight succeeds.
    pub async fn prepare(config: DecisionServerConfig) -> Result<Self, DecisionServerStartupError> {
        let DecisionServerConfigParts {
            server,
            server_tls,
            jwt,
            jwks_file,
            postgres,
            service,
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
        let ca_pem = unique_contents(ca_pem, &mut identities)?;
        let mut password = unique_contents(password, &mut identities)?;

        let certificate_chain = std::mem::take(&mut *certificate_chain);
        let private_key = std::mem::take(&mut *private_key);
        let server_identity = DecisionGrpcTlsIdentity::try_from_pem(certificate_chain, private_key)
            .map_err(|_| DecisionServerStartupError::ServerIdentityRejected)?;

        let authenticator = JwtTenantAuthenticator::try_from_jwks(jwt, &jwks)
            .map_err(|_| DecisionServerStartupError::IdentityConfigurationRejected)?;

        normalize_password(&mut password)?;
        let (postgres_config, postgres_tls) =
            build_postgres_transport(&postgres, &ca_pem, &password)?;
        let pool = PostgresReaderPool::try_new(postgres_config, postgres_tls, postgres.pool)
            .map_err(|_| DecisionServerStartupError::DatabaseConfigurationRejected)?;
        let pool = PoolCloseGuard::new(pool);
        preflight_with_deadline(postgres.preflight_timeout, preflight_reader(pool.pool())).await?;

        let executor = PostgresGetDecisionExecutor::new(pool.pool().clone());
        let service = DecisionGrpcService::new(authenticator, executor, service);
        let server = DecisionGrpcServer::bind(server, server_identity)
            .await
            .map_err(map_bind_error)?;

        Ok(Self {
            server,
            service,
            pool,
        })
    }

    /// Returns the bound listener address after all startup checks succeed.
    pub fn local_addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    /// Serves until shutdown, drains bounded request work, then closes the reader pool.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), DecisionServerServeError>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let Self {
            server,
            service,
            pool,
        } = self;
        let result = server.serve(service, shutdown).await.map_err(Into::into);
        drop(pool);
        result
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
    /// PostgreSQL CA, password, or connection policy was rejected.
    DatabaseConfigurationRejected,
    /// PostgreSQL availability, schema, reader identity, or tenant boundary was rejected.
    DatabaseUnavailable,
    /// The configured listener address was unavailable.
    ListenerUnavailable,
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
            Self::DatabaseConfigurationRejected => {
                formatter.write_str("decision server database configuration is rejected")
            }
            Self::DatabaseUnavailable => {
                formatter.write_str("decision server database is unavailable")
            }
            Self::ListenerUnavailable => {
                formatter.write_str("decision server listener is unavailable")
            }
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

async fn preflight_reader(pool: &PostgresReaderPool) -> Result<(), DecisionServerStartupError> {
    let executor = PostgresGetDecisionExecutor::new(pool.clone());
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

    use super::{DecisionServerStartupError, parse_postgres_roots, preflight_with_deadline};

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
}
