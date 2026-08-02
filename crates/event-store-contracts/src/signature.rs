use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::signature::{ED25519, ParsedPublicKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bioworld_contracts::{tenant_id_is_valid, v2::DecisionEvent};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::decision_event::{
    DecisionEventMetadata, EventProjectionError, ScientificEventRow, project_decision_event,
    reconstruct_decision_event,
};

const SIGNATURE_ALGORITHM: &str = "Ed25519";
const SIGNATURE_DOMAIN: &[u8] = b"bioworld.scientific-event.signature.v1\0";
const SIGNATURE_VERSION: &str = "1";
const SNAPSHOT_VERSION: &str = "1";
const MAX_KEY_ID_BYTES: usize = 64;
pub const MAX_DECISION_EVENT_VERIFICATION_SNAPSHOT_BYTES: usize = 65_536;
const MAX_VERIFICATION_KEYS: usize = 32;
const MAX_SNAPSHOT_LIFETIME_SECONDS: u64 = 86_400;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionEventSignatureError;

impl fmt::Display for DecisionEventSignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("decision event signature is invalid")
    }
}

impl Error for DecisionEventSignatureError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDecisionEventVerifier;

impl fmt::Display for InvalidDecisionEventVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("decision event verification configuration is invalid")
    }
}

impl Error for InvalidDecisionEventVerifier {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionEventVerificationError {
    TrustUnavailable,
    EventRejected,
}

impl fmt::Display for DecisionEventVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrustUnavailable => {
                formatter.write_str("decision event verification trust is unavailable")
            }
            Self::EventRejected => formatter.write_str("decision event signature was rejected"),
        }
    }
}

impl Error for DecisionEventVerificationError {}

pub trait DecisionEventVerificationClock: Send + Sync {
    fn unix_timestamp(&self) -> Option<u64>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemDecisionEventVerificationClock;

impl DecisionEventVerificationClock for SystemDecisionEventVerificationClock {
    fn unix_timestamp(&self) -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
    }
}

#[derive(Clone)]
pub struct DecisionEventVerifier {
    valid_until: u64,
    tenants: Arc<TenantVerificationKeys>,
    clock: Arc<dyn DecisionEventVerificationClock>,
}

impl DecisionEventVerifier {
    pub fn try_from_snapshot(input: &[u8]) -> Result<Self, InvalidDecisionEventVerifier> {
        Self::try_from_snapshot_with_clock(input, SystemDecisionEventVerificationClock)
    }

    pub fn try_from_snapshot_with_clock<C>(
        input: &[u8],
        clock: C,
    ) -> Result<Self, InvalidDecisionEventVerifier>
    where
        C: DecisionEventVerificationClock + 'static,
    {
        if input.is_empty() || input.len() > MAX_DECISION_EVENT_VERIFICATION_SNAPSHOT_BYTES {
            return Err(InvalidDecisionEventVerifier);
        }
        let now = clock.unix_timestamp().ok_or(InvalidDecisionEventVerifier)?;
        let snapshot: VerificationSnapshot =
            serde_json::from_slice(input).map_err(|_| InvalidDecisionEventVerifier)?;
        if snapshot.version != SNAPSHOT_VERSION
            || snapshot.keys.is_empty()
            || snapshot.keys.len() > MAX_VERIFICATION_KEYS
            || snapshot.valid_until <= now
            || snapshot.valid_until > now.saturating_add(MAX_SNAPSHOT_LIFETIME_SECONDS)
        {
            return Err(InvalidDecisionEventVerifier);
        }

        let mut tenants = TenantVerificationKeys::new();
        let mut public_keys = HashSet::<[u8; ED25519_PUBLIC_KEY_BYTES]>::new();
        for raw in snapshot.keys {
            if !tenant_id_is_valid(&raw.tenant_id)
                || !valid_key_id(&raw.key_id)
                || raw.algorithm != SIGNATURE_ALGORITHM
                || raw.not_before >= raw.not_after
            {
                return Err(InvalidDecisionEventVerifier);
            }
            let public_key = decode_canonical::<ED25519_PUBLIC_KEY_BYTES>(&raw.public_key)
                .map_err(|_| InvalidDecisionEventVerifier)?;
            if !public_keys.insert(public_key) {
                return Err(InvalidDecisionEventVerifier);
            }
            let public_key = ParsedPublicKey::new(&ED25519, public_key)
                .map_err(|_| InvalidDecisionEventVerifier)?;
            let keys = tenants.entry(raw.tenant_id.into_boxed_str()).or_default();
            if keys
                .insert(
                    raw.key_id.into_boxed_str(),
                    VerificationKey {
                        public_key,
                        not_before: raw.not_before,
                        not_after: raw.not_after,
                        revoked: raw.status == VerificationKeyStatus::Revoked,
                    },
                )
                .is_some()
            {
                return Err(InvalidDecisionEventVerifier);
            }
        }

        Ok(Self {
            valid_until: snapshot.valid_until,
            tenants: Arc::new(tenants),
            clock: Arc::new(clock),
        })
    }

    pub fn verify_and_reconstruct(
        &self,
        row: &ScientificEventRow,
    ) -> Result<DecisionEvent, DecisionEventVerificationError> {
        let signature = parse_signature(&row.signature)
            .map_err(|_| DecisionEventVerificationError::EventRejected)?;
        let now = self
            .clock
            .unix_timestamp()
            .ok_or(DecisionEventVerificationError::TrustUnavailable)?;
        if now >= self.valid_until {
            return Err(DecisionEventVerificationError::TrustUnavailable);
        }
        let key = self
            .tenants
            .get(row.tenant_id.as_str())
            .and_then(|keys| keys.get(signature.key_id.as_str()))
            .ok_or(DecisionEventVerificationError::EventRejected)?;
        if key.revoked {
            return Err(DecisionEventVerificationError::EventRejected);
        }

        let event = reconstruct_decision_event(row)
            .map_err(|_| DecisionEventVerificationError::EventRejected)?;
        let occurred_at = u64::try_from(row.occurred_at.timestamp())
            .map_err(|_| DecisionEventVerificationError::EventRejected)?;
        if occurred_at < key.not_before || occurred_at >= key.not_after {
            return Err(DecisionEventVerificationError::EventRejected);
        }
        let message = signature_message(row, &signature.key_id)
            .map_err(|_| DecisionEventVerificationError::EventRejected)?;
        key.public_key
            .verify_sig(&message, &signature.value)
            .map_err(|_| DecisionEventVerificationError::EventRejected)?;

        Ok(event)
    }
}

impl fmt::Debug for DecisionEventVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionEventVerifier")
    }
}

pub fn decision_event_signature_message(
    event: DecisionEvent,
    tenant_id: String,
    occurred_at: DateTime<Utc>,
    key_id: &str,
) -> Result<Vec<u8>, EventProjectionError> {
    if !valid_key_id(key_id) {
        return Err(EventProjectionError::InvalidSignature);
    }
    let metadata =
        DecisionEventMetadata::try_new(tenant_id, occurred_at, json!({"placeholder": true}))?;
    let row = project_decision_event(event, metadata)?;
    signature_message(&row, key_id).map_err(|_| EventProjectionError::InvalidSignature)
}

pub fn decision_event_signature_value(
    key_id: &str,
    signature: &[u8],
) -> Result<Value, DecisionEventSignatureError> {
    if !valid_key_id(key_id) || signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(DecisionEventSignatureError);
    }
    Ok(json!({
        "version": SIGNATURE_VERSION,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "value": URL_SAFE_NO_PAD.encode(signature),
    }))
}

fn signature_message(
    row: &ScientificEventRow,
    key_id: &str,
) -> Result<Vec<u8>, DecisionEventSignatureError> {
    if !valid_key_id(key_id)
        || !row
            .occurred_at
            .timestamp_subsec_nanos()
            .is_multiple_of(1_000)
    {
        return Err(DecisionEventSignatureError);
    }
    let occurred_at_unix_micros =
        canonical_unix_micros(row.occurred_at).ok_or(DecisionEventSignatureError)?;
    let payload = SignatureMessage {
        algorithm: SIGNATURE_ALGORITHM,
        aggregate_id: &row.aggregate_id,
        aggregate_type: &row.aggregate_type,
        aggregate_version: row.aggregate_version.to_string(),
        event_id: row.event_id.to_string(),
        event_type: &row.event_type,
        key_id,
        occurred_at_unix_micros,
        payload_sha256: &row.payload_sha256,
        schema_version: &row.schema_version,
        tenant_id: &row.tenant_id,
    };
    let canonical = serde_jcs::to_vec(&payload).map_err(|_| DecisionEventSignatureError)?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len().saturating_add(canonical.len()));
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&canonical);
    Ok(message)
}

fn parse_signature(
    value: &Map<String, Value>,
) -> Result<ParsedSignature, DecisionEventSignatureError> {
    if value.len() != 4 {
        return Err(DecisionEventSignatureError);
    }
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .ok_or(DecisionEventSignatureError)?;
    let algorithm = value
        .get("algorithm")
        .and_then(Value::as_str)
        .ok_or(DecisionEventSignatureError)?;
    let key_id = value
        .get("key_id")
        .and_then(Value::as_str)
        .ok_or(DecisionEventSignatureError)?;
    let signature = value
        .get("value")
        .and_then(Value::as_str)
        .ok_or(DecisionEventSignatureError)?;
    if version != SIGNATURE_VERSION || algorithm != SIGNATURE_ALGORITHM || !valid_key_id(key_id) {
        return Err(DecisionEventSignatureError);
    }
    let value = decode_canonical::<ED25519_SIGNATURE_BYTES>(signature)?;
    Ok(ParsedSignature {
        key_id: key_id.to_owned(),
        value,
    })
}

fn decode_canonical<const N: usize>(input: &str) -> Result<[u8; N], DecisionEventSignatureError> {
    let expected_length = (N / 3)
        .checked_mul(4)
        .and_then(|length| {
            length.checked_add(match N % 3 {
                0 => 0,
                1 => 2,
                _ => 3,
            })
        })
        .ok_or(DecisionEventSignatureError)?;
    if input.len() != expected_length {
        return Err(DecisionEventSignatureError);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| DecisionEventSignatureError)?;
    if decoded.len() != N || URL_SAFE_NO_PAD.encode(&decoded) != input {
        return Err(DecisionEventSignatureError);
    }
    decoded.try_into().map_err(|_| DecisionEventSignatureError)
}

fn valid_key_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_KEY_ID_BYTES
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn canonical_unix_micros(value: DateTime<Utc>) -> Option<String> {
    let seconds = u64::try_from(value.timestamp()).ok()?;
    seconds
        .checked_mul(1_000_000)?
        .checked_add(u64::from(value.timestamp_subsec_micros()))
        .map(|value| value.to_string())
}

struct VerificationKey {
    public_key: ParsedPublicKey,
    not_before: u64,
    not_after: u64,
    revoked: bool,
}

type TenantVerificationKeys = HashMap<Box<str>, HashMap<Box<str>, VerificationKey>>;

struct ParsedSignature {
    key_id: String,
    value: [u8; ED25519_SIGNATURE_BYTES],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationSnapshot {
    version: String,
    valid_until: u64,
    keys: Vec<VerificationKeyInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationKeyInput {
    tenant_id: String,
    key_id: String,
    algorithm: String,
    public_key: String,
    not_before: u64,
    not_after: u64,
    status: VerificationKeyStatus,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum VerificationKeyStatus {
    Trusted,
    Revoked,
}

#[derive(Serialize)]
struct SignatureMessage<'a> {
    algorithm: &'static str,
    aggregate_id: &'a str,
    aggregate_type: &'a str,
    aggregate_version: String,
    event_id: String,
    event_type: &'a str,
    key_id: &'a str,
    occurred_at_unix_micros: String,
    payload_sha256: &'a str,
    schema_version: &'a str,
    tenant_id: &'a str,
}
