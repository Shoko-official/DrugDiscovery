#![deny(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    num::NonZeroUsize,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bioworld_decision_grpc::{
    AuthenticateTenantError, AuthenticateTenantFuture, TenantAuthenticationContext,
    TenantAuthenticator,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::{
    runtime::Handle,
    sync::Semaphore,
    task::{JoinError, JoinHandle},
};

/// Collision-resistant claim that binds a verified principal to one BioWorld tenant.
pub const BIOWORLD_TENANT_CLAIM: &str =
    "https://github.com/Shoko-official/DrugDiscovery/claims/tenant_id";

const MAX_AUDIENCE_BYTES: usize = 512;
const MAX_CONCURRENT_VERIFICATIONS: usize = 64;
const MAX_ISSUER_BYTES: usize = 2_048;
const MAX_JWKS_BYTES: usize = 65_536;
const MAX_JWKS_KEYS: usize = 32;
const MAX_JWKS_SNAPSHOT_LIFETIME_SECONDS: u64 = 86_400;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_SCOPE_BYTES: usize = 1_024;
const MAX_TOKEN_BYTES: usize = 8_192;
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 900;
const MAX_VALUE_BYTES: usize = 1_024;
const MIN_REMAINING_VALIDITY_SECONDS: u64 = 5;
const TENANT_ID_MAX_BYTES: usize = 128;
const TOKEN_CLOCK_SKEW_SECONDS: u64 = 30;

#[derive(Clone)]
/// Immutable verification policy for one issuer, audience, scope, and key snapshot.
pub struct JwtTenantAuthenticatorConfig {
    issuer: Box<str>,
    audience: Box<str>,
    required_scope: Box<str>,
    jwks_valid_until: u64,
    max_concurrent_verifications: NonZeroUsize,
}

impl JwtTenantAuthenticatorConfig {
    /// Builds a bounded single-issuer RS256 access-token policy.
    ///
    /// The issuer must be an HTTPS identifier. The key snapshot expiry is checked
    /// against the authenticator clock during construction and may be at most 24
    /// hours in the future. Verification concurrency must be between 1 and 64.
    pub fn try_new(
        issuer: String,
        audience: String,
        required_scope: String,
        jwks_valid_until: u64,
        max_concurrent_verifications: usize,
    ) -> Result<Self, InvalidJwtTenantAuthenticatorConfig> {
        let max_concurrent_verifications = NonZeroUsize::new(max_concurrent_verifications)
            .filter(|value| value.get() <= MAX_CONCURRENT_VERIFICATIONS)
            .ok_or(InvalidJwtTenantAuthenticatorConfig)?;
        if !valid_https_identifier(&issuer, MAX_ISSUER_BYTES)
            || !valid_identifier(&audience, MAX_AUDIENCE_BYTES)
            || !valid_scope_token(&required_scope)
            || jwks_valid_until == 0
        {
            return Err(InvalidJwtTenantAuthenticatorConfig);
        }

        Ok(Self {
            issuer: issuer.into_boxed_str(),
            audience: audience.into_boxed_str(),
            required_scope: required_scope.into_boxed_str(),
            jwks_valid_until,
            max_concurrent_verifications,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Fixed construction error that never reflects configuration or key material.
pub struct InvalidJwtTenantAuthenticatorConfig;

impl fmt::Display for InvalidJwtTenantAuthenticatorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JWT tenant authenticator configuration is invalid")
    }
}

impl Error for InvalidJwtTenantAuthenticatorConfig {}

/// Trusted wall-clock source used for token and key-snapshot validation.
pub trait JwtClock: Send + Sync {
    /// Returns the current Unix timestamp, or `None` when the clock is unavailable.
    fn unix_timestamp(&self) -> Option<u64>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Wall clock backed by [`SystemTime`].
pub struct SystemJwtClock;

impl JwtClock for SystemJwtClock {
    fn unix_timestamp(&self) -> Option<u64> {
        unix_timestamp()
    }
}

#[derive(Clone)]
/// Bounded RFC 9068 RS256 tenant authenticator for Tonic request metadata.
///
/// Tokens are limited to 8 KiB, a 15-minute lifetime, 30 seconds of clock skew,
/// and at least 5 seconds of remaining validity. Signature verification runs on
/// Tokio blocking capacity guarded by a fail-fast semaphore.
pub struct JwtTenantAuthenticator {
    verifier: Arc<JwtVerifier>,
    admission: Arc<Semaphore>,
}

impl JwtTenantAuthenticator {
    /// Builds an authenticator from a normalized public RS256 JWK snapshot.
    ///
    /// The snapshot is limited to 64 KiB and 32 unique RSA keys. Every key must
    /// be an RS256 verification key with a 2048 to 4096 bit modulus and exponent
    /// 65537. Mixed-algorithm sets and additional JWK fields are rejected.
    pub fn try_from_jwks(
        config: JwtTenantAuthenticatorConfig,
        jwks: &[u8],
    ) -> Result<Self, InvalidJwtTenantAuthenticatorConfig> {
        Self::try_from_jwks_with_clock(config, jwks, SystemJwtClock)
    }

    /// Builds an authenticator with an explicit trusted clock.
    ///
    /// This constructor supports deterministic composition tests and deployments
    /// that provide a hardened time source. A clock failure after construction is
    /// reported as authentication-service unavailability.
    pub fn try_from_jwks_with_clock<C>(
        config: JwtTenantAuthenticatorConfig,
        jwks: &[u8],
        clock: C,
    ) -> Result<Self, InvalidJwtTenantAuthenticatorConfig>
    where
        C: JwtClock + 'static,
    {
        let now = clock
            .unix_timestamp()
            .ok_or(InvalidJwtTenantAuthenticatorConfig)?;
        if config.jwks_valid_until <= now
            || config.jwks_valid_until > now.saturating_add(MAX_JWKS_SNAPSHOT_LIFETIME_SECONDS)
        {
            return Err(InvalidJwtTenantAuthenticatorConfig);
        }
        let keys = parse_jwks(jwks)?;
        let admission = Arc::new(Semaphore::new(config.max_concurrent_verifications.get()));

        Ok(Self {
            verifier: Arc::new(JwtVerifier {
                config,
                keys,
                clock: Arc::new(clock),
            }),
            admission,
        })
    }
}

impl TenantAuthenticator for JwtTenantAuthenticator {
    fn authenticate_tenant<'a>(
        &'a self,
        context: TenantAuthenticationContext<'a>,
    ) -> AuthenticateTenantFuture<'a> {
        let token = match bearer_token(context) {
            Ok(token) => token,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let permit = match Arc::clone(&self.admission).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Box::pin(async { Err(AuthenticateTenantError::capacity_exhausted()) });
            }
        };
        let verifier = Arc::clone(&self.verifier);
        let runtime = match Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => return Box::pin(async { Err(AuthenticateTenantError::unavailable()) }),
        };

        Box::pin(async move {
            AbortOnDropTask::new(runtime.spawn_blocking(move || {
                let _permit = permit;
                verifier.verify(&token)
            }))
            .join()
            .await
            .unwrap_or_else(|_| Err(AuthenticateTenantError::unavailable()))
        })
    }
}

struct AbortOnDropTask<T> {
    handle: JoinHandle<T>,
    completed: bool,
}

impl<T> AbortOnDropTask<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self {
            handle,
            completed: false,
        }
    }

    async fn join(mut self) -> Result<T, JoinError> {
        let result = (&mut self.handle).await;
        self.completed = true;
        result
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        if !self.completed {
            self.handle.abort();
        }
    }
}

struct JwtVerifier {
    config: JwtTenantAuthenticatorConfig,
    keys: HashMap<Box<str>, DecodingKey>,
    clock: Arc<dyn JwtClock>,
}

impl JwtVerifier {
    fn verify(&self, token: &str) -> Result<String, AuthenticateTenantError> {
        let now = self
            .clock
            .unix_timestamp()
            .ok_or_else(AuthenticateTenantError::unavailable)?;
        if now >= self.config.jwks_valid_until {
            return Err(AuthenticateTenantError::unavailable());
        }

        let header = decode_header(token).map_err(|_| AuthenticateTenantError::rejected())?;
        if header.alg != Algorithm::RS256
            || !header.typ.as_deref().is_some_and(valid_access_token_type)
            || header.cty.is_some()
            || header.jku.is_some()
            || header.jwk.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
            || header.x5t.is_some()
            || header.x5t_s256.is_some()
            || header.crit.is_some()
            || header.enc.is_some()
            || header.zip.is_some()
            || header.url.is_some()
            || header.nonce.is_some()
            || !header.extras.is_empty()
        {
            return Err(AuthenticateTenantError::rejected());
        }
        let key_id = header
            .kid
            .as_deref()
            .filter(|key_id| valid_key_id(key_id))
            .ok_or_else(AuthenticateTenantError::rejected)?;
        let key = self
            .keys
            .get(key_id)
            .ok_or_else(AuthenticateTenantError::rejected)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 0;
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.set_required_spec_claims(&["iss", "aud", "sub"]);
        validation.set_issuer(&[self.config.issuer.as_ref()]);
        validation.set_audience(&[self.config.audience.as_ref()]);
        let claims = decode::<AccessTokenClaims>(token, key, &validation)
            .map_err(|_| AuthenticateTenantError::rejected())?
            .claims;

        self.validate_claims(claims, now)
    }

    fn validate_claims(
        &self,
        claims: AccessTokenClaims,
        now: u64,
    ) -> Result<String, AuthenticateTenantError> {
        if claims.issuer != self.config.issuer.as_ref()
            || !claims.audience.contains(self.config.audience.as_ref())
            || !valid_claim_value(&claims.subject)
            || !valid_claim_value(&claims.client_id)
            || !valid_claim_value(&claims.jwt_id)
            || !valid_scope_set(&claims.scope, self.config.required_scope.as_ref())
            || !valid_tenant_id(&claims.tenant_id)
            || claims.expiration <= now
            || claims.expiration <= claims.issued_at
            || claims.expiration - claims.issued_at > MAX_TOKEN_LIFETIME_SECONDS
            || claims.issued_at > now.saturating_add(TOKEN_CLOCK_SKEW_SECONDS)
            || claims
                .not_before
                .is_some_and(|not_before| not_before > now.saturating_add(TOKEN_CLOCK_SKEW_SECONDS))
            || claims
                .not_before
                .is_some_and(|not_before| not_before >= claims.expiration)
            || claims.expiration.saturating_sub(now) < MIN_REMAINING_VALIDITY_SECONDS
        {
            return Err(AuthenticateTenantError::rejected());
        }

        Ok(claims.tenant_id)
    }
}

#[derive(Deserialize)]
struct AccessTokenClaims {
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "aud")]
    audience: Audience,
    #[serde(rename = "exp")]
    expiration: u64,
    #[serde(rename = "sub")]
    subject: String,
    client_id: String,
    #[serde(rename = "iat")]
    issued_at: u64,
    #[serde(rename = "jti")]
    jwt_id: String,
    scope: String,
    #[serde(rename = "https://github.com/Shoko-official/DrugDiscovery/claims/tenant_id")]
    tenant_id: String,
    #[serde(default, rename = "nbf")]
    not_before: Option<u64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(audience) => audience == expected,
            Self::Many(audiences) => {
                !audiences.is_empty()
                    && audiences.len() <= 8
                    && audiences
                        .iter()
                        .all(|audience| valid_identifier(audience, MAX_AUDIENCE_BYTES))
                    && audiences.iter().any(|audience| audience == expected)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonWebKeySet {
    keys: Vec<RsaJsonWebKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RsaJsonWebKey {
    kty: String,
    #[serde(rename = "use")]
    intended_use: Option<String>,
    key_ops: Option<Vec<String>>,
    alg: String,
    kid: String,
    n: String,
    e: String,
}

fn parse_jwks(
    input: &[u8],
) -> Result<HashMap<Box<str>, DecodingKey>, InvalidJwtTenantAuthenticatorConfig> {
    if input.is_empty() || input.len() > MAX_JWKS_BYTES {
        return Err(InvalidJwtTenantAuthenticatorConfig);
    }
    let jwks: JsonWebKeySet =
        serde_json::from_slice(input).map_err(|_| InvalidJwtTenantAuthenticatorConfig)?;
    if jwks.keys.is_empty() || jwks.keys.len() > MAX_JWKS_KEYS {
        return Err(InvalidJwtTenantAuthenticatorConfig);
    }

    let mut keys = HashMap::with_capacity(jwks.keys.len());
    for jwk in jwks.keys {
        if jwk.kty != "RSA"
            || jwk.alg != "RS256"
            || !valid_key_id(&jwk.kid)
            || (jwk.intended_use.is_some() && jwk.key_ops.is_some())
            || jwk
                .intended_use
                .as_deref()
                .is_some_and(|value| value != "sig")
            || !valid_key_operations(jwk.key_ops.as_deref())
            || !valid_rsa_modulus(&jwk.n)
            || jwk.e != "AQAB"
        {
            return Err(InvalidJwtTenantAuthenticatorConfig);
        }
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|_| InvalidJwtTenantAuthenticatorConfig)?;
        if keys
            .insert(jwk.kid.into_boxed_str(), decoding_key)
            .is_some()
        {
            return Err(InvalidJwtTenantAuthenticatorConfig);
        }
    }

    Ok(keys)
}

fn bearer_token(
    context: TenantAuthenticationContext<'_>,
) -> Result<String, AuthenticateTenantError> {
    if context.metadata().get_bin("authorization-bin").is_some() {
        return Err(AuthenticateTenantError::rejected());
    }
    let mut values = context.metadata().get_all("authorization").iter();
    let value = values
        .next()
        .ok_or_else(AuthenticateTenantError::rejected)?;
    if values.next().is_some() {
        return Err(AuthenticateTenantError::rejected());
    }
    let value = value
        .to_str()
        .map_err(|_| AuthenticateTenantError::rejected())?;
    if value.len() <= 7 || !value[..6].eq_ignore_ascii_case("Bearer") || value.as_bytes()[6] != b' '
    {
        return Err(AuthenticateTenantError::rejected());
    }
    let token = &value[7..];
    if token.len() > MAX_TOKEN_BYTES || !valid_compact_jwt(token) {
        return Err(AuthenticateTenantError::rejected());
    }

    Ok(token.to_owned())
}

fn valid_compact_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
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

fn valid_access_token_type(value: &str) -> bool {
    value.eq_ignore_ascii_case("at+jwt") || value.eq_ignore_ascii_case("application/at+jwt")
}

fn valid_https_identifier(value: &str, max_bytes: usize) -> bool {
    if !valid_identifier(value, max_bytes) || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return false;
    }
    let Ok(identifier) = value.parse::<http::Uri>() else {
        return false;
    };

    identifier.scheme_str() == Some("https")
        && identifier.authority().is_some_and(|authority| {
            !authority.as_str().contains('@')
                && !authority.host().is_empty()
                && (authority.as_str().len() == authority.host().len()
                    || authority.port().is_some())
        })
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_ID_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_key_operations(operations: Option<&[String]>) -> bool {
    operations.is_none_or(|operations| {
        operations.len() == 1
            && operations
                .first()
                .is_some_and(|operation| operation == "verify")
    })
}

fn valid_rsa_modulus(value: &str) -> bool {
    let Ok(modulus) = URL_SAFE_NO_PAD.decode(value) else {
        return false;
    };
    let Some(first) = modulus.first().filter(|byte| **byte != 0) else {
        return false;
    };
    if modulus.len() > 512 {
        return false;
    }
    let bits = modulus.len() * 8 - first.leading_zeros() as usize;

    (2_048..=4_096).contains(&bits)
}

fn valid_claim_value(value: &str) -> bool {
    valid_identifier(value, MAX_VALUE_BYTES)
}

fn valid_scope_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn valid_scope_set(value: &str, required: &str) -> bool {
    if value.is_empty() || value.len() > MAX_SCOPE_BYTES {
        return false;
    }
    let mut matched = false;
    let mut scopes = HashSet::new();
    for scope in value.split(' ') {
        if !valid_scope_token(scope) || !scopes.insert(scope) {
            return false;
        }
        matched |= scope == required;
    }

    matched
}

fn valid_tenant_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };

    value.len() <= TENANT_ID_MAX_BYTES
        && first.is_ascii_alphanumeric()
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':' | b'_'))
}

fn unix_timestamp() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}
