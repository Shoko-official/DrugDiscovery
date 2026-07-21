use std::{collections::HashSet, error::Error, fmt, net::SocketAddr, time::Duration};

use bioworld_decision_grpc::MAX_DECISION_GRPC_IN_FLIGHT_REQUESTS;
use tonic::transport::Identity;
use zeroize::Zeroizing;

/// Hard ceiling for simultaneously accepted TCP connections.
pub const MAX_DECISION_GRPC_ACTIVE_CONNECTIONS: usize = 1_024;
/// Hard ceiling for concurrent HTTP/2 streams on one connection.
pub const MAX_DECISION_GRPC_STREAMS_PER_CONNECTION: u32 = 256;
/// Hard ceiling for aggregate pre-authentication HTTP/2 streams.
pub const MAX_DECISION_GRPC_PRE_AUTHENTICATION_STREAMS: usize =
    MAX_DECISION_GRPC_IN_FLIGHT_REQUESTS;
/// Maximum accepted PEM certificate-chain input size.
pub const MAX_DECISION_GRPC_TLS_CERTIFICATE_CHAIN_PEM_BYTES: usize = 65_536;
/// Maximum accepted unencrypted PKCS#8 private-key PEM input size.
pub const MAX_DECISION_GRPC_TLS_PRIVATE_KEY_PEM_BYTES: usize = 16_384;
/// Maximum configurable TLS handshake time.
pub const MAX_DECISION_GRPC_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum configurable transport-level request time.
pub const MAX_DECISION_GRPC_TRANSPORT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
/// Maximum configurable lifetime of one established connection.
pub const MAX_DECISION_GRPC_CONNECTION_AGE: Duration = Duration::from_secs(86_400);
/// Maximum grace after the connection-age limit is reached.
pub const MAX_DECISION_GRPC_CONNECTION_AGE_GRACE: Duration = Duration::from_secs(300);
/// Maximum grace after server shutdown begins.
pub const MAX_DECISION_GRPC_SHUTDOWN_GRACE: Duration = Duration::from_secs(330);

const DEFAULT_ACTIVE_CONNECTIONS: usize = 128;
const DEFAULT_STREAMS_PER_CONNECTION: u32 = 32;
const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_TRANSPORT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_CONNECTION_AGE: Duration = Duration::from_secs(3_600);
const DEFAULT_CONNECTION_AGE_GRACE: Duration = Duration::from_secs(30);
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(310);
const CERTIFICATE_LABEL: &str = "CERTIFICATE";
const PRIVATE_KEY_LABEL: &str = "PRIVATE KEY";

/// Validated resource limits for the TLS and HTTP/2 server transport.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DecisionGrpcServerLimits {
    max_active_connections: usize,
    max_concurrent_streams_per_connection: u32,
    tls_handshake_timeout: Duration,
    transport_request_timeout: Duration,
    max_connection_age: Duration,
    connection_age_grace: Duration,
    shutdown_grace: Duration,
}

impl DecisionGrpcServerLimits {
    /// Validates every transport and lifecycle budget as one consistent set.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        max_active_connections: usize,
        max_concurrent_streams_per_connection: u32,
        tls_handshake_timeout: Duration,
        transport_request_timeout: Duration,
        max_connection_age: Duration,
        connection_age_grace: Duration,
        shutdown_grace: Duration,
    ) -> Result<Self, InvalidDecisionGrpcServerLimits> {
        if !(1..=MAX_DECISION_GRPC_ACTIVE_CONNECTIONS).contains(&max_active_connections)
            || !(1..=MAX_DECISION_GRPC_STREAMS_PER_CONNECTION)
                .contains(&max_concurrent_streams_per_connection)
            || max_active_connections
                .checked_mul(max_concurrent_streams_per_connection as usize)
                .is_none_or(|value| value > MAX_DECISION_GRPC_PRE_AUTHENTICATION_STREAMS)
            || duration_outside(
                tls_handshake_timeout,
                MAX_DECISION_GRPC_TLS_HANDSHAKE_TIMEOUT,
            )
            || duration_outside(
                transport_request_timeout,
                MAX_DECISION_GRPC_TRANSPORT_REQUEST_TIMEOUT,
            )
            || duration_outside(max_connection_age, MAX_DECISION_GRPC_CONNECTION_AGE)
            || duration_outside(connection_age_grace, MAX_DECISION_GRPC_CONNECTION_AGE_GRACE)
            || duration_outside(shutdown_grace, MAX_DECISION_GRPC_SHUTDOWN_GRACE)
            || connection_age_grace > max_connection_age
        {
            return Err(InvalidDecisionGrpcServerLimits);
        }

        Ok(Self {
            max_active_connections,
            max_concurrent_streams_per_connection,
            tls_handshake_timeout,
            transport_request_timeout,
            max_connection_age,
            connection_age_grace,
            shutdown_grace,
        })
    }

    /// Returns the active TCP connection cap.
    pub fn max_active_connections(self) -> usize {
        self.max_active_connections
    }

    /// Returns the concurrent HTTP/2 stream cap for one connection.
    pub fn max_concurrent_streams_per_connection(self) -> u32 {
        self.max_concurrent_streams_per_connection
    }

    /// Returns the TLS handshake timeout.
    pub fn tls_handshake_timeout(self) -> Duration {
        self.tls_handshake_timeout
    }

    /// Returns the outer transport request timeout.
    pub fn transport_request_timeout(self) -> Duration {
        self.transport_request_timeout
    }

    /// Returns the maximum established connection age.
    pub fn max_connection_age(self) -> Duration {
        self.max_connection_age
    }

    /// Returns the grace applied after maximum connection age.
    pub fn connection_age_grace(self) -> Duration {
        self.connection_age_grace
    }

    /// Returns the graceful server shutdown deadline.
    pub fn shutdown_grace(self) -> Duration {
        self.shutdown_grace
    }
}

impl Default for DecisionGrpcServerLimits {
    fn default() -> Self {
        Self {
            max_active_connections: DEFAULT_ACTIVE_CONNECTIONS,
            max_concurrent_streams_per_connection: DEFAULT_STREAMS_PER_CONNECTION,
            tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
            transport_request_timeout: DEFAULT_TRANSPORT_REQUEST_TIMEOUT,
            max_connection_age: DEFAULT_CONNECTION_AGE,
            connection_age_grace: DEFAULT_CONNECTION_AGE_GRACE,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

impl fmt::Debug for DecisionGrpcServerLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionGrpcServerLimits")
    }
}

/// Fixed failure returned for an invalid transport budget set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDecisionGrpcServerLimits;

impl fmt::Display for InvalidDecisionGrpcServerLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("decision gRPC server limits are invalid")
    }
}

impl Error for InvalidDecisionGrpcServerLimits {}

/// Explicit listener exposure selection.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DecisionGrpcBind {
    socket_addr: SocketAddr,
    exposure: BindExposure,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum BindExposure {
    Loopback,
    Exposed,
}

impl DecisionGrpcBind {
    /// Selects a loopback-only address. Port zero is allowed for ephemeral local binding.
    pub fn loopback(socket_addr: SocketAddr) -> Result<Self, InvalidDecisionGrpcBind> {
        if !socket_addr.ip().is_loopback() {
            return Err(InvalidDecisionGrpcBind);
        }

        Ok(Self {
            socket_addr,
            exposure: BindExposure::Loopback,
        })
    }

    /// Selects an explicitly exposed address. Port zero is rejected.
    pub fn exposed(socket_addr: SocketAddr) -> Result<Self, InvalidDecisionGrpcBind> {
        if socket_addr.port() == 0 {
            return Err(InvalidDecisionGrpcBind);
        }

        Ok(Self {
            socket_addr,
            exposure: BindExposure::Exposed,
        })
    }

    /// Returns the selected socket address.
    pub fn socket_addr(self) -> SocketAddr {
        self.socket_addr
    }
}

impl fmt::Debug for DecisionGrpcBind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.exposure {
            BindExposure::Loopback => formatter.write_str("DecisionGrpcBind::Loopback"),
            BindExposure::Exposed => formatter.write_str("DecisionGrpcBind::Exposed"),
        }
    }
}

/// Fixed failure returned for an invalid listener exposure selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDecisionGrpcBind;

impl fmt::Display for InvalidDecisionGrpcBind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("decision gRPC server bind is invalid")
    }
}

impl Error for InvalidDecisionGrpcBind {}

/// Immutable server startup configuration.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DecisionGrpcServerConfig {
    bind: DecisionGrpcBind,
    limits: DecisionGrpcServerLimits,
}

impl DecisionGrpcServerConfig {
    /// Combines validated bind and resource-limit values.
    pub const fn new(bind: DecisionGrpcBind, limits: DecisionGrpcServerLimits) -> Self {
        Self { bind, limits }
    }

    /// Returns the explicit listener exposure selection.
    pub fn bind(self) -> DecisionGrpcBind {
        self.bind
    }

    /// Returns the validated transport resource limits.
    pub fn limits(self) -> DecisionGrpcServerLimits {
        self.limits
    }
}

impl fmt::Debug for DecisionGrpcServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionGrpcServerConfig")
    }
}

/// Owned, size-bounded server certificate chain and private key.
///
/// The private key must be one unencrypted PKCS#8 PEM block. Its transferred input
/// allocation remains in zeroizing storage until validation fails or Tonic receives it.
#[derive(Eq, PartialEq)]
pub struct DecisionGrpcTlsIdentity {
    certificate_chain_pem: Vec<u8>,
    private_key_pem: Zeroizing<Vec<u8>>,
}

impl DecisionGrpcTlsIdentity {
    /// Consumes and validates PEM framing and fixed input-size budgets.
    ///
    /// Cryptographic parsing and certificate-to-key matching occur before the listener binds.
    pub fn try_from_pem(
        certificate_chain_pem: Vec<u8>,
        private_key_pem: Vec<u8>,
    ) -> Result<Self, InvalidDecisionGrpcTlsIdentity> {
        let private_key_pem = Zeroizing::new(private_key_pem);
        if certificate_chain_pem.len() > MAX_DECISION_GRPC_TLS_CERTIFICATE_CHAIN_PEM_BYTES
            || private_key_pem.len() > MAX_DECISION_GRPC_TLS_PRIVATE_KEY_PEM_BYTES
            || !valid_certificate_chain_pem(&certificate_chain_pem)
            || !valid_private_key_pem(&private_key_pem)
        {
            return Err(InvalidDecisionGrpcTlsIdentity);
        }

        Ok(Self {
            certificate_chain_pem,
            private_key_pem,
        })
    }

    pub(crate) fn into_tonic(self) -> Identity {
        Identity::from_pem(&self.certificate_chain_pem, self.private_key_pem.as_slice())
    }
}

impl fmt::Debug for DecisionGrpcTlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionGrpcTlsIdentity")
    }
}

/// Fixed failure returned for invalid TLS identity input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDecisionGrpcTlsIdentity;

impl fmt::Display for InvalidDecisionGrpcTlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("decision gRPC TLS identity is invalid")
    }
}

impl Error for InvalidDecisionGrpcTlsIdentity {}

fn duration_outside(value: Duration, maximum: Duration) -> bool {
    value.is_zero() || value > maximum
}

fn valid_certificate_chain_pem(input: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };
    let begin = format!("-----BEGIN {CERTIFICATE_LABEL}-----");
    let end = format!("-----END {CERTIFICATE_LABEL}-----");
    let mut inside = false;
    let mut block_count = 0_usize;
    let mut payload = String::new();
    let mut seen_payloads = HashSet::new();

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if !inside {
            if line != begin {
                return false;
            }
            inside = true;
            payload.clear();
            block_count += 1;
        } else if line == end {
            if payload.is_empty() || !seen_payloads.insert(std::mem::take(&mut payload)) {
                return false;
            }
            inside = false;
        } else if line.bytes().all(is_base64_pem_byte) {
            payload.push_str(line);
        } else {
            return false;
        }
    }

    !inside && block_count > 0
}

fn valid_private_key_pem(input: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };
    let begin = format!("-----BEGIN {PRIVATE_KEY_LABEL}-----");
    let end = format!("-----END {PRIVATE_KEY_LABEL}-----");
    let mut inside = false;
    let mut completed = false;
    let mut has_payload = false;

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if completed {
            return false;
        }
        if !inside {
            if line != begin {
                return false;
            }
            inside = true;
        } else if line == end {
            if !has_payload {
                return false;
            }
            inside = false;
            completed = true;
        } else if line.bytes().all(is_base64_pem_byte) {
            has_payload = true;
        } else {
            return false;
        }
    }

    completed && !inside
}

fn is_base64_pem_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'+' | b'/' | b'=')
}
