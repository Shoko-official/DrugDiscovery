use std::{
    collections::HashSet,
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use bioworld_decision_grpc::DecisionGrpcServiceConfig;
use bioworld_decision_grpc_jwt::JwtTenantAuthenticatorConfig;
use bioworld_decision_grpc_postgres::PostgresReaderPoolConfig;
use bioworld_decision_grpc_server::{
    DecisionGrpcBind, DecisionGrpcServerConfig, DecisionGrpcServerLimits,
};
use serde::Deserialize;

use crate::secure_file::{SecureFilePolicy, read_secure_file};

/// Maximum accepted byte length for the non-secret runtime control document.
pub const MAX_DECISION_SERVER_CONTROL_BYTES: usize = 32_768;

const MAX_DATABASE_HOST_BYTES: usize = 253;
const MAX_DATABASE_NAME_BYTES: usize = 63;
const MAX_SENSITIVE_PATH_BYTES: usize = 4_096;
const MAX_POSTGRES_CONNECT_TIMEOUT: Duration = Duration::from_secs(300);

/// Validated non-secret control values and sensitive file locations for one server process.
pub struct DecisionServerConfig {
    server: DecisionGrpcServerConfig,
    server_tls: ServerTlsFiles,
    jwt: JwtTenantAuthenticatorConfig,
    jwks_file: PathBuf,
    postgres: PostgresRuntimeConfig,
    service: DecisionGrpcServiceConfig,
}

impl DecisionServerConfig {
    /// Reads and validates one regular control file through a fixed byte ceiling.
    pub async fn load(path: impl AsRef<Path>) -> Result<Self, InvalidDecisionServerConfig> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(InvalidDecisionServerConfig);
        }
        let input = read_secure_file(
            path,
            MAX_DECISION_SERVER_CONTROL_BYTES,
            SecureFilePolicy::Public,
        )
        .await
        .map_err(|_| InvalidDecisionServerConfig)?;
        Self::try_from_json(input.contents())
    }

    /// Parses and validates one strict, size-bounded JSON control document.
    pub fn try_from_json(input: &[u8]) -> Result<Self, InvalidDecisionServerConfig> {
        if input.is_empty() || input.len() > MAX_DECISION_SERVER_CONTROL_BYTES {
            return Err(InvalidDecisionServerConfig);
        }
        let raw: RawDecisionServerConfig =
            serde_json::from_slice(input).map_err(|_| InvalidDecisionServerConfig)?;
        raw.try_into()
    }

    pub(crate) fn into_parts(self) -> DecisionServerConfigParts {
        DecisionServerConfigParts {
            server: self.server,
            server_tls: self.server_tls,
            jwt: self.jwt,
            jwks_file: self.jwks_file,
            postgres: self.postgres,
            service: self.service,
        }
    }
}

impl fmt::Debug for DecisionServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionServerConfig")
    }
}

/// Fixed failure returned when runtime control input is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDecisionServerConfig;

impl fmt::Display for InvalidDecisionServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("decision server configuration is invalid")
    }
}

impl Error for InvalidDecisionServerConfig {}

pub(crate) struct DecisionServerConfigParts {
    pub(crate) server: DecisionGrpcServerConfig,
    pub(crate) server_tls: ServerTlsFiles,
    pub(crate) jwt: JwtTenantAuthenticatorConfig,
    pub(crate) jwks_file: PathBuf,
    pub(crate) postgres: PostgresRuntimeConfig,
    pub(crate) service: DecisionGrpcServiceConfig,
}

pub(crate) struct ServerTlsFiles {
    pub(crate) certificate_chain: PathBuf,
    pub(crate) private_key: PathBuf,
}

pub(crate) struct PostgresRuntimeConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) database: String,
    pub(crate) password_file: PathBuf,
    pub(crate) ca_file: PathBuf,
    pub(crate) pool: PostgresReaderPoolConfig,
    pub(crate) connect_timeout: Duration,
    pub(crate) preflight_timeout: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDecisionServerConfig {
    listen: RawListen,
    server_tls: RawServerTls,
    jwt: RawJwt,
    postgres: RawPostgres,
    service: RawService,
    transport: RawTransport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListen {
    address: String,
    exposure: RawExposure,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawExposure {
    Loopback,
    Exposed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerTls {
    certificate_chain_file: String,
    private_key_file: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawJwt {
    issuer: String,
    audience: String,
    required_scope: String,
    jwks_file: String,
    jwks_valid_until: u64,
    max_concurrent_verifications: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPostgres {
    host: String,
    port: u16,
    database: String,
    password_file: String,
    ca_file: String,
    pool_max_size: usize,
    acquire_timeout_seconds: u64,
    connect_timeout_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawService {
    max_in_flight: usize,
    request_timeout_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTransport {
    max_active_connections: usize,
    max_concurrent_streams_per_connection: u32,
    tls_handshake_timeout_seconds: u64,
    request_timeout_seconds: u64,
    max_connection_age_seconds: u64,
    connection_age_grace_seconds: u64,
    shutdown_grace_seconds: u64,
}

impl TryFrom<RawDecisionServerConfig> for DecisionServerConfig {
    type Error = InvalidDecisionServerConfig;

    fn try_from(raw: RawDecisionServerConfig) -> Result<Self, Self::Error> {
        let socket_addr = raw
            .listen
            .address
            .parse::<SocketAddr>()
            .map_err(|_| InvalidDecisionServerConfig)?;
        let bind = match raw.listen.exposure {
            RawExposure::Loopback => DecisionGrpcBind::loopback(socket_addr),
            RawExposure::Exposed => DecisionGrpcBind::exposed(socket_addr),
        }
        .map_err(|_| InvalidDecisionServerConfig)?;

        let transport_request_timeout = Duration::from_secs(raw.transport.request_timeout_seconds);
        let shutdown_grace = Duration::from_secs(raw.transport.shutdown_grace_seconds);
        let limits = DecisionGrpcServerLimits::try_new(
            raw.transport.max_active_connections,
            raw.transport.max_concurrent_streams_per_connection,
            Duration::from_secs(raw.transport.tls_handshake_timeout_seconds),
            transport_request_timeout,
            Duration::from_secs(raw.transport.max_connection_age_seconds),
            Duration::from_secs(raw.transport.connection_age_grace_seconds),
            shutdown_grace,
        )
        .map_err(|_| InvalidDecisionServerConfig)?;

        let request_timeout = Duration::from_secs(raw.service.request_timeout_seconds);
        let service =
            DecisionGrpcServiceConfig::try_new(raw.service.max_in_flight, request_timeout)
                .map_err(|_| InvalidDecisionServerConfig)?;
        let acquire_timeout = Duration::from_secs(raw.postgres.acquire_timeout_seconds);
        let connect_timeout = Duration::from_secs(raw.postgres.connect_timeout_seconds);
        let pool = PostgresReaderPoolConfig::try_new(raw.postgres.pool_max_size, acquire_timeout)
            .map_err(|_| InvalidDecisionServerConfig)?;

        if request_timeout >= shutdown_grace
            || transport_request_timeout >= shutdown_grace
            || raw.postgres.pool_max_size > raw.service.max_in_flight
            || acquire_timeout > request_timeout
            || connect_timeout.is_zero()
            || connect_timeout > MAX_POSTGRES_CONNECT_TIMEOUT
            || connect_timeout > acquire_timeout
            || !valid_database_host(&raw.postgres.host)
            || !valid_database_name(&raw.postgres.database)
            || raw.postgres.port == 0
        {
            return Err(InvalidDecisionServerConfig);
        }

        let server_tls = ServerTlsFiles {
            certificate_chain: validated_path(raw.server_tls.certificate_chain_file)?,
            private_key: validated_path(raw.server_tls.private_key_file)?,
        };
        let jwks_file = validated_path(raw.jwt.jwks_file)?;
        let password_file = validated_path(raw.postgres.password_file)?;
        let ca_file = validated_path(raw.postgres.ca_file)?;
        let paths = [
            &server_tls.certificate_chain,
            &server_tls.private_key,
            &jwks_file,
            &password_file,
            &ca_file,
        ];
        if paths.iter().collect::<HashSet<_>>().len() != paths.len() {
            return Err(InvalidDecisionServerConfig);
        }

        let jwt = JwtTenantAuthenticatorConfig::try_new(
            raw.jwt.issuer,
            raw.jwt.audience,
            raw.jwt.required_scope,
            raw.jwt.jwks_valid_until,
            raw.jwt.max_concurrent_verifications,
        )
        .map_err(|_| InvalidDecisionServerConfig)?;

        Ok(Self {
            server: DecisionGrpcServerConfig::new(bind, limits),
            server_tls,
            jwt,
            jwks_file,
            postgres: PostgresRuntimeConfig {
                host: raw.postgres.host,
                port: raw.postgres.port,
                database: raw.postgres.database,
                password_file,
                ca_file,
                pool,
                connect_timeout,
                preflight_timeout: request_timeout,
            },
            service,
        })
    }
}

fn validated_path(value: String) -> Result<PathBuf, InvalidDecisionServerConfig> {
    if value.is_empty() || value.len() > MAX_SENSITIVE_PATH_BYTES || value.contains('\0') {
        return Err(InvalidDecisionServerConfig);
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() || path.components().any(|part| part.as_os_str() == "..") {
        return Err(InvalidDecisionServerConfig);
    }
    Ok(path)
}

fn valid_database_host(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_DATABASE_HOST_BYTES
        || value.trim() != value
        || !value.is_ascii()
    {
        return false;
    }
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }

    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn valid_database_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DATABASE_NAME_BYTES
        && value.trim() == value
        && !value.contains('\0')
}
