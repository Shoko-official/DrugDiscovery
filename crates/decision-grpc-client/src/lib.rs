#![deny(unsafe_code)]

mod watch;

use watch::WatchCleanup;
pub use watch::{DecisionGrpcWatch, DecisionGrpcWatchEvent};

use std::{
    collections::HashSet, fmt, future::Future, net::IpAddr, pin::Pin, sync::Arc, time::Duration,
};

use bioworld_contracts::{
    MAX_DECISION_WIRE_BYTES, VersionedDecisionRecord,
    v2::{GetDecisionRequest, decision_service_client::DecisionServiceClient},
};
use bioworld_decision_query::GetDecisionQuery;
use http::Uri;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, pem::PemObject, pem::SectionKind},
};
use thiserror::Error;
use tokio::{
    sync::Semaphore,
    time::{Instant, sleep_until},
};
use tonic::{
    Code, Request,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};
use zeroize::Zeroizing;

pub const MAX_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_CLIENT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_CLIENT_WATCH_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_CLIENT_IN_FLIGHT: usize = 64;
pub const MAX_CLIENT_WATCH_EVENTS: usize = 65_536;
pub const MAX_DECISION_CLIENT_ENDPOINT_BYTES: usize = 2_048;
pub const MAX_TLS_CA_CERTIFICATE_BYTES: usize = 65_536;
pub const MAX_TLS_CA_CERTIFICATES: usize = 16;
pub const MAX_TLS_SERVER_NAME_BYTES: usize = 253;
pub const MAX_ACCESS_TOKEN_BYTES: usize = 8_192;
const CANONICAL_DECISION_ID_BYTES: usize = 36;
const AUTHORIZATION_PREFIX: &str = "Bearer ";
const MAX_HTTP2_HEADER_LIST_BYTES: u32 = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("access token is invalid")]
pub struct InvalidAccessToken;

pub struct AccessToken(Zeroizing<String>);

impl AccessToken {
    pub fn try_new(value: String) -> Result<Self, InvalidAccessToken> {
        let value = Zeroizing::new(value);
        if value.is_empty() || value.len() > MAX_ACCESS_TOKEN_BYTES || !valid_compact_token(&value)
        {
            return Err(InvalidAccessToken);
        }

        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccessToken([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecisionGrpcClientError {
    #[error("decision client configuration is invalid")]
    InvalidConfiguration,
    #[error("decision identifier is invalid")]
    InvalidDecisionId,
    #[error("decision authentication is unavailable")]
    AuthenticationUnavailable,
    #[error("decision client capacity is exhausted")]
    CapacityExhausted,
    #[error("decision was not found")]
    NotFound,
    #[error("decision authentication was rejected")]
    Unauthenticated,
    #[error("decision access was denied")]
    PermissionDenied,
    #[error("decision request deadline exceeded")]
    DeadlineExceeded,
    #[error("decision service is unavailable")]
    Unavailable,
    #[error("decision service response is invalid")]
    InvalidResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("access token provider is unavailable")]
pub struct AccessTokenProviderError;

pub type AccessTokenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AccessToken, AccessTokenProviderError>> + Send + 'a>>;

pub trait AccessTokenProvider: Send + Sync {
    fn access_token(&self) -> AccessTokenFuture<'_>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionGrpcClientLimits {
    connect_timeout: Duration,
    tls_handshake_timeout: Duration,
    request_timeout: Duration,
    max_in_flight: usize,
    max_active_watches: usize,
}

impl DecisionGrpcClientLimits {
    pub fn try_new(
        connect_timeout: Duration,
        tls_handshake_timeout: Duration,
        request_timeout: Duration,
        max_in_flight: usize,
    ) -> Result<Self, DecisionGrpcClientError> {
        Self::try_new_with_watch_capacity(
            connect_timeout,
            tls_handshake_timeout,
            request_timeout,
            max_in_flight,
            0,
        )
    }

    pub fn try_new_with_watch_capacity(
        connect_timeout: Duration,
        tls_handshake_timeout: Duration,
        request_timeout: Duration,
        max_in_flight: usize,
        max_active_watches: usize,
    ) -> Result<Self, DecisionGrpcClientError> {
        if connect_timeout.is_zero()
            || connect_timeout > MAX_CLIENT_CONNECT_TIMEOUT
            || tls_handshake_timeout.is_zero()
            || tls_handshake_timeout > MAX_CLIENT_TLS_HANDSHAKE_TIMEOUT
            || request_timeout.is_zero()
            || request_timeout > MAX_CLIENT_REQUEST_TIMEOUT
            || max_in_flight == 0
            || max_in_flight > MAX_CLIENT_IN_FLIGHT
            || max_active_watches >= max_in_flight
        {
            return Err(DecisionGrpcClientError::InvalidConfiguration);
        }

        Ok(Self {
            connect_timeout,
            tls_handshake_timeout,
            request_timeout,
            max_in_flight,
            max_active_watches,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DecisionGrpcWatchLimits {
    timeout: Duration,
    max_events: usize,
}

impl fmt::Debug for DecisionGrpcWatchLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecisionGrpcWatchLimits")
            .finish_non_exhaustive()
    }
}

impl DecisionGrpcWatchLimits {
    pub fn try_new(timeout: Duration, max_events: usize) -> Result<Self, DecisionGrpcClientError> {
        if timeout.is_zero()
            || timeout > MAX_CLIENT_WATCH_TIMEOUT
            || max_events == 0
            || max_events > MAX_CLIENT_WATCH_EVENTS
        {
            return Err(DecisionGrpcClientError::InvalidConfiguration);
        }

        Ok(Self {
            timeout,
            max_events,
        })
    }

    pub(crate) fn timeout(self) -> Duration {
        self.timeout
    }

    pub(crate) fn max_events(self) -> usize {
        self.max_events
    }
}

pub struct DecisionGrpcClientConfig {
    endpoint: String,
    tls_server_name: String,
    ca_certificate_pem: Vec<u8>,
    limits: DecisionGrpcClientLimits,
}

impl fmt::Debug for DecisionGrpcClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecisionGrpcClientConfig")
            .finish_non_exhaustive()
    }
}

impl DecisionGrpcClientConfig {
    pub fn try_new(
        endpoint: String,
        tls_server_name: String,
        ca_certificate_pem: Vec<u8>,
        limits: DecisionGrpcClientLimits,
    ) -> Result<Self, DecisionGrpcClientError> {
        if endpoint.is_empty()
            || endpoint.len() > MAX_DECISION_CLIENT_ENDPOINT_BYTES
            || endpoint.contains('#')
        {
            return Err(DecisionGrpcClientError::InvalidConfiguration);
        }
        let uri = endpoint
            .parse::<Uri>()
            .map_err(|_| DecisionGrpcClientError::InvalidConfiguration)?;
        let authority = uri
            .authority()
            .ok_or(DecisionGrpcClientError::InvalidConfiguration)?;
        let authority_suffix = &authority.as_str()[authority.host().len()..];
        if uri.scheme_str() != Some("https")
            || !valid_endpoint_host(authority.host())
            || authority.as_str().contains('@')
            || (!authority_suffix.is_empty()
                && (!authority_suffix.starts_with(':')
                    || authority.port_u16().is_none_or(|port| port == 0)))
            || uri.path() != "/"
            || uri.query().is_some()
        {
            return Err(DecisionGrpcClientError::InvalidConfiguration);
        }
        if !valid_tls_server_name(&tls_server_name) {
            return Err(DecisionGrpcClientError::InvalidConfiguration);
        }
        if ca_certificate_pem.is_empty()
            || ca_certificate_pem.len() > MAX_TLS_CA_CERTIFICATE_BYTES
            || !valid_ca_certificate_pem(&ca_certificate_pem)
        {
            return Err(DecisionGrpcClientError::InvalidConfiguration);
        }

        Ok(Self {
            endpoint,
            tls_server_name,
            ca_certificate_pem,
            limits,
        })
    }
}

pub struct DecisionGrpcClient<P> {
    channel: Channel,
    token_provider: Arc<P>,
    admission: Arc<Semaphore>,
    watch_admission: Arc<Semaphore>,
    watch_cleanup: Arc<WatchCleanup>,
    request_timeout: Duration,
}

impl<P> Clone for DecisionGrpcClient<P> {
    fn clone(&self) -> Self {
        Self {
            channel: self.channel.clone(),
            token_provider: Arc::clone(&self.token_provider),
            admission: Arc::clone(&self.admission),
            watch_admission: Arc::clone(&self.watch_admission),
            watch_cleanup: Arc::clone(&self.watch_cleanup),
            request_timeout: self.request_timeout,
        }
    }
}

impl<P> DecisionGrpcClient<P>
where
    P: AccessTokenProvider,
{
    pub async fn connect(
        config: DecisionGrpcClientConfig,
        token_provider: P,
    ) -> Result<Self, DecisionGrpcClientError> {
        let DecisionGrpcClientConfig {
            endpoint,
            tls_server_name,
            ca_certificate_pem,
            limits,
        } = config;
        let endpoint = Endpoint::from_shared(endpoint)
            .map_err(|_| DecisionGrpcClientError::InvalidConfiguration)?
            .connect_timeout(limits.connect_timeout)
            .concurrency_limit(limits.max_in_flight)
            .buffer_size(limits.max_in_flight)
            .http2_max_header_list_size(MAX_HTTP2_HEADER_LIST_BYTES)
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(ca_certificate_pem))
                    .domain_name(tls_server_name)
                    .timeout(limits.tls_handshake_timeout),
            )
            .map_err(|_| DecisionGrpcClientError::InvalidConfiguration)?;
        let channel = tokio::time::timeout(limits.connect_timeout, endpoint.connect())
            .await
            .map_err(|_| DecisionGrpcClientError::Unavailable)?
            .map_err(|_| DecisionGrpcClientError::Unavailable)?;

        Ok(Self {
            channel,
            token_provider: Arc::new(token_provider),
            admission: Arc::new(Semaphore::new(limits.max_in_flight)),
            watch_admission: Arc::new(Semaphore::new(limits.max_active_watches)),
            watch_cleanup: Arc::new(WatchCleanup::new()),
            request_timeout: limits.request_timeout,
        })
    }

    pub async fn get_decision(
        &self,
        decision_id: &str,
    ) -> Result<VersionedDecisionRecord, DecisionGrpcClientError> {
        if decision_id.len() != CANONICAL_DECISION_ID_BYTES {
            return Err(DecisionGrpcClientError::InvalidDecisionId);
        }
        let query = GetDecisionQuery::try_from(GetDecisionRequest {
            decision_id: decision_id.to_owned(),
        })
        .map_err(|_| DecisionGrpcClientError::InvalidDecisionId)?;
        let expected_decision_id = query.decision_id().to_string();
        let _permit = Arc::clone(&self.admission)
            .try_acquire_owned()
            .map_err(|_| DecisionGrpcClientError::CapacityExhausted)?;
        let deadline = Instant::now() + self.request_timeout;
        let operation = async {
            let request = authenticated_request(
                self.token_provider.as_ref(),
                GetDecisionRequest {
                    decision_id: expected_decision_id.clone(),
                },
                deadline,
                deadline,
            )
            .await?;
            let mut client = DecisionServiceClient::new(self.channel.clone())
                .max_decoding_message_size(MAX_DECISION_WIRE_BYTES)
                .max_encoding_message_size(MAX_DECISION_WIRE_BYTES);
            let response = client
                .get_decision(request)
                .await
                .map_err(map_status)?
                .into_inner();
            if response.decision_id != expected_decision_id {
                return Err(DecisionGrpcClientError::InvalidResponse);
            }

            VersionedDecisionRecord::try_from(response)
                .map_err(|_| DecisionGrpcClientError::InvalidResponse)
        };

        complete_before_deadline(deadline, operation)
            .await
            .ok_or(DecisionGrpcClientError::DeadlineExceeded)?
    }
}

pub(crate) async fn complete_before_deadline<F>(deadline: Instant, future: F) -> Option<F::Output>
where
    F: Future,
{
    tokio::pin!(future);
    tokio::select! {
        biased;
        _ = sleep_until(deadline) => None,
        output = &mut future => Some(output),
    }
}

pub(crate) async fn authenticated_request<P, M>(
    token_provider: &P,
    message: M,
    credential_deadline: Instant,
    request_deadline: Instant,
) -> Result<Request<M>, DecisionGrpcClientError>
where
    P: AccessTokenProvider + ?Sized,
{
    let credential_deadline = credential_deadline.min(request_deadline);
    let token = complete_before_deadline(credential_deadline, token_provider.access_token())
        .await
        .ok_or(DecisionGrpcClientError::DeadlineExceeded)?
        .map_err(|_| DecisionGrpcClientError::AuthenticationUnavailable)?;
    if Instant::now() >= credential_deadline {
        return Err(DecisionGrpcClientError::DeadlineExceeded);
    }
    let mut bearer = Zeroizing::new(String::with_capacity(
        AUTHORIZATION_PREFIX.len() + token.as_str().len(),
    ));
    bearer.push_str(AUTHORIZATION_PREFIX);
    bearer.push_str(token.as_str());
    let mut authorization = MetadataValue::try_from(bearer.as_str())
        .map_err(|_| DecisionGrpcClientError::AuthenticationUnavailable)?;
    authorization.set_sensitive(true);
    drop(bearer);
    drop(token);

    if Instant::now() >= credential_deadline {
        return Err(DecisionGrpcClientError::DeadlineExceeded);
    }
    let remaining = request_deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(DecisionGrpcClientError::DeadlineExceeded)?;
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", authorization);
    request.set_timeout(remaining);

    Ok(request)
}

fn valid_tls_server_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_TLS_SERVER_NAME_BYTES
        || !value.is_ascii()
        || value.parse::<IpAddr>().is_ok()
    {
        return false;
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

fn valid_endpoint_host(value: &str) -> bool {
    if let Some(ipv6) = value
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return ipv6
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_ipv6());
    }

    value.parse::<IpAddr>().is_ok() || valid_tls_server_name(value)
}

fn valid_compact_token(value: &str) -> bool {
    let mut parts = value.split('.');
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };

    parts.next().is_some_and(valid_part)
        && parts.next().is_some_and(valid_part)
        && parts.next().is_some_and(valid_part)
        && parts.next().is_none()
}

fn valid_ca_certificate_pem(input: &[u8]) -> bool {
    if !strict_certificate_pem_shape(input) {
        return false;
    }
    let mut roots = RootCertStore::empty();
    let mut seen = HashSet::<Vec<u8>>::new();
    let mut count = 0_usize;

    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(input) {
        let Ok((SectionKind::Certificate, certificate)) = item else {
            return false;
        };
        count += 1;
        if count > MAX_TLS_CA_CERTIFICATES || !seen.insert(certificate.clone()) {
            return false;
        }
        if roots.add(CertificateDer::from(certificate)).is_err() {
            return false;
        }
    }

    count > 0
}

fn strict_certificate_pem_shape(input: &[u8]) -> bool {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";

    let mut inside = false;
    let mut count = 0_usize;
    for raw_line in input.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.contains(&b'\r') {
            return false;
        }
        if inside {
            if line == END {
                inside = false;
                count += 1;
            } else if line.is_empty()
                || !line
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
            {
                return false;
            }
        } else if line == BEGIN {
            inside = true;
        } else if !line.iter().all(u8::is_ascii_whitespace) {
            return false;
        }
    }

    !inside && count > 0 && count <= MAX_TLS_CA_CERTIFICATES
}

pub(crate) fn map_status(status: tonic::Status) -> DecisionGrpcClientError {
    match status.code() {
        Code::NotFound => DecisionGrpcClientError::NotFound,
        Code::Unauthenticated => DecisionGrpcClientError::Unauthenticated,
        Code::PermissionDenied => DecisionGrpcClientError::PermissionDenied,
        Code::ResourceExhausted => DecisionGrpcClientError::CapacityExhausted,
        Code::DeadlineExceeded | Code::Cancelled => DecisionGrpcClientError::DeadlineExceeded,
        Code::Unavailable | Code::Unknown | Code::Aborted => DecisionGrpcClientError::Unavailable,
        Code::Ok
        | Code::InvalidArgument
        | Code::AlreadyExists
        | Code::FailedPrecondition
        | Code::OutOfRange
        | Code::Unimplemented
        | Code::Internal
        | Code::DataLoss => DecisionGrpcClientError::InvalidResponse,
    }
}
