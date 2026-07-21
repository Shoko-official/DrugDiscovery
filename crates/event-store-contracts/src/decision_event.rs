use bioworld_contracts::{
    DecisionContractError, MAX_TENANT_ID_BYTES, VersionedDecisionRecord, tenant_id_is_valid,
    v2::{self, DecisionEvent, EvidenceSnapshotRef},
};
use chrono::{DateTime, Utc};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

pub const DECISION_EVENT_TYPE: &str = "bioworld.v2.DecisionEvent";
pub const DECISION_SCHEMA_VERSION: &str = "2";
pub const DECISION_AGGREGATE_TYPE: &str = "bioworld.v2.DecisionRecord";
pub const MAX_CANONICAL_DECISION_PAYLOAD_BYTES: usize = 262_144;
pub const MAX_CANONICAL_DECISION_PAYLOAD_DEPTH: usize = 8;
pub const MAX_CANONICAL_DECISION_PAYLOAD_NODES: usize = 128;
pub const MAX_EVENT_SIGNATURE_JSON_BYTES: usize = 16_384;
pub const MAX_EVENT_SIGNATURE_DEPTH: usize = 16;
pub const MAX_EVENT_SIGNATURE_NODES: usize = 256;
pub const MAX_STORED_EVENT_PAYLOAD_BYTES: usize = 524_288;
pub const MAX_STORED_EVENT_SIGNATURE_BYTES: usize = 20_480;
pub const MAX_STORED_EVENT_IDENTIFIER_CHARS: usize = 200;
pub const MAX_STORED_EVENT_IDENTIFIER_BYTES: usize = 800;

#[derive(Debug, Clone, PartialEq)]
pub struct DecisionEventMetadata {
    tenant_id: String,
    occurred_at: DateTime<Utc>,
    signature: Map<String, Value>,
}

impl DecisionEventMetadata {
    pub fn try_new(
        tenant_id: String,
        occurred_at: DateTime<Utc>,
        signature: Value,
    ) -> Result<Self, EventProjectionError> {
        validate_tenant_id(&tenant_id)?;
        let signature = signature
            .as_object()
            .filter(|value| !value.is_empty())
            .ok_or(EventProjectionError::InvalidSignature)?;
        validate_signature_object(signature)?;
        validate_signature_size(signature)?;
        let signature = signature.clone();

        Ok(Self {
            tenant_id,
            occurred_at,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScientificEventRow {
    pub event_id: Uuid,
    pub event_type: String,
    pub schema_version: String,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub aggregate_version: u64,
    pub occurred_at: DateTime<Utc>,
    pub tenant_id: String,
    pub payload: Value,
    pub payload_sha256: String,
    pub signature: Map<String, Value>,
}

#[derive(Debug, Error)]
pub enum EventProjectionError {
    #[error("decision event is missing its decision")]
    MissingDecision,
    #[error("new decision events require an explicit ood_status")]
    MissingOodStatus,
    #[error("new decision events require a qualified ood_status")]
    UnqualifiedOodStatus,
    #[error("new decision events require an OOD detector reference")]
    MissingOodDetector,
    #[error("out-of-domain decisions must abstain")]
    OutOfDomainRequiresAbstain,
    #[error("event_id must be a canonical UUID")]
    InvalidEventId,
    #[error("tenant_id must be non-empty, at most 128 bytes, and have no surrounding whitespace")]
    InvalidTenantId,
    #[error("signature must be a non-empty JSON object")]
    InvalidSignature,
    #[error("signature exceeds the accepted JSON envelope")]
    SignatureEnvelopeExceeded,
    #[error("signature exceeds the accepted JSON structure")]
    SignatureStructureExceeded,
    #[error("PostgreSQL text and jsonb values must not contain NUL bytes")]
    NulByteNotAllowed,
    #[error("decision contract is invalid: {0}")]
    InvalidDecision(#[from] DecisionContractError),
    #[error("canonical payload could not be serialized: {0}")]
    Canonicalization(#[source] serde_json::Error),
    #[error("stored payload is invalid: {0}")]
    InvalidPayload(#[source] serde_json::Error),
    #[error("canonical decision payload exceeds the accepted JSON envelope")]
    CanonicalPayloadEnvelopeExceeded,
    #[error("canonical decision payload exceeds the accepted JSON structure")]
    CanonicalPayloadStructureExceeded,
    #[error("stored event type does not match the decision event contract")]
    InvalidEventType,
    #[error("stored schema version does not match the decision event contract")]
    InvalidSchemaVersion,
    #[error("stored aggregate type does not match the decision event contract")]
    InvalidAggregateType,
    #[error("stored aggregate id conflicts with the payload")]
    AggregateIdMismatch,
    #[error("stored aggregate version conflicts with the payload")]
    AggregateVersionMismatch,
    #[error("stored aggregate version is not a canonical positive u64")]
    InvalidAggregateVersion,
    #[error("stored payload digest does not match its canonical form")]
    PayloadHashMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalDecisionPayload {
    decision_id: String,
    cou_id: String,
    recommendation: CanonicalRecommendation,
    #[serde(default)]
    ood_status: CanonicalOodStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ood_detector: Option<CanonicalOodDetector>,
    evidence: CanonicalEvidence,
    rationale: Vec<String>,
    aggregate_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalEvidence {
    id: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalOodDetector {
    detector_id: String,
    detector_version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CanonicalRecommendation {
    Promote,
    Reject,
    Abstain,
    Defer,
    StopProgram,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CanonicalOodStatus {
    InDomain,
    Borderline,
    OutOfDomain,
    #[default]
    Unknown,
}

pub fn project_decision_event(
    event: DecisionEvent,
    metadata: DecisionEventMetadata,
) -> Result<ScientificEventRow, EventProjectionError> {
    let event_id = canonical_uuid(&event.event_id).ok_or(EventProjectionError::InvalidEventId)?;
    let decision = event
        .decision
        .ok_or(EventProjectionError::MissingDecision)?;
    if canonical_uuid(&decision.decision_id).is_none() {
        return Err(DecisionContractError::InvalidDecisionId.into());
    }
    validate_new_ood_metadata(&decision)?;
    let boundary = VersionedDecisionRecord::try_from(decision)?;
    let decision = v2::DecisionRecord::from(&boundary);
    if decision.ood_status == Some(v2::OodStatus::OutOfDomain as i32)
        && decision.recommendation != v2::Recommendation::Abstain as i32
    {
        return Err(EventProjectionError::OutOfDomainRequiresAbstain);
    }
    let payload = CanonicalDecisionPayload::from_wire(&decision)?;
    let (payload, payload_sha256) = canonical_payload(&payload)?;

    Ok(ScientificEventRow {
        event_id,
        event_type: DECISION_EVENT_TYPE.to_owned(),
        schema_version: DECISION_SCHEMA_VERSION.to_owned(),
        aggregate_type: DECISION_AGGREGATE_TYPE.to_owned(),
        aggregate_id: decision.decision_id,
        aggregate_version: decision.aggregate_version,
        occurred_at: metadata.occurred_at,
        tenant_id: metadata.tenant_id,
        payload,
        payload_sha256,
        signature: metadata.signature,
    })
}

pub fn reconstruct_decision_event(
    row: &ScientificEventRow,
) -> Result<DecisionEvent, EventProjectionError> {
    validate_row_metadata(row)?;

    validate_payload_json(&row.payload)?;
    let payload_bytes = canonical_payload_bytes(&row.payload)?;
    let payload: CanonicalDecisionPayload =
        serde_json::from_slice(&payload_bytes).map_err(EventProjectionError::InvalidPayload)?;
    if canonical_uuid(&payload.decision_id).is_none() {
        return Err(DecisionContractError::InvalidDecisionId.into());
    }
    let aggregate_version = parse_aggregate_version(&payload.aggregate_version)?;

    if row.aggregate_id != payload.decision_id {
        return Err(EventProjectionError::AggregateIdMismatch);
    }
    if row.aggregate_version != aggregate_version {
        return Err(EventProjectionError::AggregateVersionMismatch);
    }

    let expected_hash = format!("{:x}", Sha256::digest(&payload_bytes));
    if row.payload_sha256 != expected_hash {
        return Err(EventProjectionError::PayloadHashMismatch);
    }

    let decision = payload.into_wire(aggregate_version);
    let boundary = VersionedDecisionRecord::try_from(decision)?;

    Ok(DecisionEvent {
        event_id: row.event_id.to_string(),
        decision: Some(v2::DecisionRecord::from(&boundary)),
    })
}

pub fn parse_stored_decision_payload(input: &str) -> Result<Value, EventProjectionError> {
    parse_bounded_json(
        input,
        MAX_STORED_EVENT_PAYLOAD_BYTES,
        MAX_CANONICAL_DECISION_PAYLOAD_DEPTH,
        MAX_CANONICAL_DECISION_PAYLOAD_NODES,
        StoredJsonKind::Payload,
    )
}

pub fn parse_stored_event_signature(
    input: &str,
) -> Result<Map<String, Value>, EventProjectionError> {
    let value = parse_bounded_json(
        input,
        MAX_STORED_EVENT_SIGNATURE_BYTES,
        MAX_EVENT_SIGNATURE_DEPTH,
        MAX_EVENT_SIGNATURE_NODES,
        StoredJsonKind::Signature,
    )?;
    match value {
        Value::Object(value) if !value.is_empty() => Ok(value),
        _ => Err(EventProjectionError::InvalidSignature),
    }
}

impl CanonicalDecisionPayload {
    fn from_wire(value: &v2::DecisionRecord) -> Result<Self, EventProjectionError> {
        let evidence = value
            .evidence
            .as_ref()
            .ok_or(DecisionContractError::MissingEvidence)?;

        Ok(Self {
            decision_id: value.decision_id.clone(),
            cou_id: value.cou_id.clone(),
            recommendation: CanonicalRecommendation::try_from(value.recommendation)?,
            ood_status: CanonicalOodStatus::try_from(value.ood_status)?,
            ood_detector: value
                .ood_detector
                .as_ref()
                .map(|detector| CanonicalOodDetector {
                    detector_id: detector.detector_id.clone(),
                    detector_version: detector.detector_version.clone(),
                }),
            evidence: CanonicalEvidence {
                id: evidence.id.clone(),
                sha256: evidence.sha256.clone(),
            },
            rationale: value.rationale.clone(),
            aggregate_version: value.aggregate_version.to_string(),
        })
    }

    #[allow(deprecated)]
    fn into_wire(self, aggregate_version: u64) -> v2::DecisionRecord {
        let evidence = EvidenceSnapshotRef {
            id: self.evidence.id,
            sha256: self.evidence.sha256,
        };

        v2::DecisionRecord {
            decision_id: self.decision_id,
            cou_id: self.cou_id,
            evidence_snapshot_id: evidence.id.clone(),
            recommendation: self.recommendation.to_wire() as i32,
            rationale: self.rationale,
            aggregate_version,
            evidence: Some(evidence),
            ood_status: Some(self.ood_status.to_wire() as i32),
            ood_detector: self.ood_detector.map(|detector| v2::OodDetectorRef {
                detector_id: detector.detector_id,
                detector_version: detector.detector_version,
            }),
        }
    }
}

fn validate_new_ood_metadata(value: &v2::DecisionRecord) -> Result<(), EventProjectionError> {
    let Some(status) = value.ood_status else {
        return Err(EventProjectionError::MissingOodStatus);
    };
    match v2::OodStatus::try_from(status) {
        Ok(v2::OodStatus::InDomain | v2::OodStatus::Borderline | v2::OodStatus::OutOfDomain) => {}
        Ok(v2::OodStatus::Unspecified | v2::OodStatus::Unknown) | Err(_) => {
            return Err(EventProjectionError::UnqualifiedOodStatus);
        }
    }
    if value.ood_detector.is_none() {
        return Err(EventProjectionError::MissingOodDetector);
    }
    Ok(())
}

impl TryFrom<i32> for CanonicalRecommendation {
    type Error = EventProjectionError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match v2::Recommendation::try_from(value)
            .map_err(|_| DecisionContractError::UnknownRecommendation(value))?
        {
            v2::Recommendation::Unspecified => {
                Err(DecisionContractError::UnspecifiedRecommendation.into())
            }
            v2::Recommendation::Promote => Ok(Self::Promote),
            v2::Recommendation::Reject => Ok(Self::Reject),
            v2::Recommendation::Abstain => Ok(Self::Abstain),
            v2::Recommendation::Defer => Ok(Self::Defer),
            v2::Recommendation::StopProgram => Ok(Self::StopProgram),
        }
    }
}

impl CanonicalRecommendation {
    fn to_wire(self) -> v2::Recommendation {
        match self {
            Self::Promote => v2::Recommendation::Promote,
            Self::Reject => v2::Recommendation::Reject,
            Self::Abstain => v2::Recommendation::Abstain,
            Self::Defer => v2::Recommendation::Defer,
            Self::StopProgram => v2::Recommendation::StopProgram,
        }
    }
}

impl TryFrom<Option<i32>> for CanonicalOodStatus {
    type Error = EventProjectionError;

    fn try_from(value: Option<i32>) -> Result<Self, Self::Error> {
        let Some(value) = value else {
            return Ok(Self::Unknown);
        };

        match v2::OodStatus::try_from(value)
            .map_err(|_| DecisionContractError::UnknownOodStatus(value))?
        {
            v2::OodStatus::Unspecified => Err(DecisionContractError::UnspecifiedOodStatus.into()),
            v2::OodStatus::InDomain => Ok(Self::InDomain),
            v2::OodStatus::Borderline => Ok(Self::Borderline),
            v2::OodStatus::OutOfDomain => Ok(Self::OutOfDomain),
            v2::OodStatus::Unknown => Ok(Self::Unknown),
        }
    }
}

impl CanonicalOodStatus {
    fn to_wire(self) -> v2::OodStatus {
        match self {
            Self::InDomain => v2::OodStatus::InDomain,
            Self::Borderline => v2::OodStatus::Borderline,
            Self::OutOfDomain => v2::OodStatus::OutOfDomain,
            Self::Unknown => v2::OodStatus::Unknown,
        }
    }
}

fn validate_row_metadata(row: &ScientificEventRow) -> Result<(), EventProjectionError> {
    if row.event_type != DECISION_EVENT_TYPE {
        return Err(EventProjectionError::InvalidEventType);
    }
    if row.schema_version != DECISION_SCHEMA_VERSION {
        return Err(EventProjectionError::InvalidSchemaVersion);
    }
    if row.aggregate_type != DECISION_AGGREGATE_TYPE {
        return Err(EventProjectionError::InvalidAggregateType);
    }
    validate_tenant_id(&row.tenant_id)?;
    if row.signature.is_empty() {
        return Err(EventProjectionError::InvalidSignature);
    }
    validate_signature_object(&row.signature)?;
    validate_signature_size(&row.signature)?;
    Ok(())
}

fn validate_tenant_id(tenant_id: &str) -> Result<(), EventProjectionError> {
    if tenant_id.len() <= MAX_TENANT_ID_BYTES && tenant_id.contains('\0') {
        return Err(EventProjectionError::NulByteNotAllowed);
    }
    if !tenant_id_is_valid(tenant_id) {
        return Err(EventProjectionError::InvalidTenantId);
    }
    Ok(())
}

fn canonical_uuid(value: &str) -> Option<Uuid> {
    let parsed = Uuid::parse_str(value).ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn parse_aggregate_version(value: &str) -> Result<u64, EventProjectionError> {
    let parsed = value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(EventProjectionError::InvalidAggregateVersion)?;
    if parsed.to_string() != value {
        return Err(EventProjectionError::InvalidAggregateVersion);
    }
    Ok(parsed)
}

fn canonical_payload<T: Serialize>(value: &T) -> Result<(Value, String), EventProjectionError> {
    let bytes = canonical_payload_bytes(value)?;
    let payload = serde_json::from_slice(&bytes).map_err(EventProjectionError::Canonicalization)?;
    validate_payload_json(&payload)?;
    let payload_sha256 = format!("{:x}", Sha256::digest(&bytes));
    Ok((payload, payload_sha256))
}

fn canonical_payload_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, EventProjectionError> {
    let bytes = serde_jcs::to_vec(value).map_err(EventProjectionError::Canonicalization)?;
    if bytes.len() > MAX_CANONICAL_DECISION_PAYLOAD_BYTES {
        return Err(EventProjectionError::CanonicalPayloadEnvelopeExceeded);
    }
    Ok(bytes)
}

fn validate_signature_size<T: Serialize>(value: &T) -> Result<(), EventProjectionError> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| EventProjectionError::InvalidSignature)?;
    if bytes.len() > MAX_EVENT_SIGNATURE_JSON_BYTES {
        return Err(EventProjectionError::SignatureEnvelopeExceeded);
    }
    Ok(())
}

fn validate_signature_object(value: &Map<String, Value>) -> Result<(), EventProjectionError> {
    validate_json_object_envelope(
        value,
        MAX_EVENT_SIGNATURE_DEPTH,
        MAX_EVENT_SIGNATURE_NODES,
        MAX_EVENT_SIGNATURE_JSON_BYTES,
    )
    .map_err(|violation| match violation {
        JsonEnvelopeViolation::Size => EventProjectionError::SignatureEnvelopeExceeded,
        JsonEnvelopeViolation::Structure => EventProjectionError::SignatureStructureExceeded,
        JsonEnvelopeViolation::NulByte => EventProjectionError::NulByteNotAllowed,
    })
}

fn validate_payload_json(value: &Value) -> Result<(), EventProjectionError> {
    validate_json_value_envelope(
        value,
        MAX_CANONICAL_DECISION_PAYLOAD_DEPTH,
        MAX_CANONICAL_DECISION_PAYLOAD_NODES,
        MAX_CANONICAL_DECISION_PAYLOAD_BYTES,
    )
    .map_err(|violation| match violation {
        JsonEnvelopeViolation::Size => EventProjectionError::CanonicalPayloadEnvelopeExceeded,
        JsonEnvelopeViolation::Structure => EventProjectionError::CanonicalPayloadStructureExceeded,
        JsonEnvelopeViolation::NulByte => EventProjectionError::NulByteNotAllowed,
    })
}

#[derive(Clone, Copy)]
enum JsonEnvelopeViolation {
    Size,
    Structure,
    NulByte,
}

fn validate_json_value_envelope(
    value: &Value,
    max_depth: usize,
    max_nodes: usize,
    max_text_bytes: usize,
) -> Result<(), JsonEnvelopeViolation> {
    match value {
        Value::Object(value) => {
            validate_json_object_envelope(value, max_depth, max_nodes, max_text_bytes)
        }
        _ => validate_json_nodes(
            std::iter::once((value, 1_usize)),
            0,
            0,
            max_depth,
            max_nodes,
            max_text_bytes,
        ),
    }
}

fn validate_json_object_envelope(
    value: &Map<String, Value>,
    max_depth: usize,
    max_nodes: usize,
    max_text_bytes: usize,
) -> Result<(), JsonEnvelopeViolation> {
    if value.len() > max_nodes.saturating_sub(1) {
        return Err(JsonEnvelopeViolation::Structure);
    }
    let mut text_bytes = 0_usize;
    let mut pending = Vec::with_capacity(value.len().min(max_nodes));
    for (key, value) in value {
        add_json_text(key, &mut text_bytes, max_text_bytes)?;
        pending.push((value, 2_usize));
    }
    validate_json_nodes(pending, 1, text_bytes, max_depth, max_nodes, max_text_bytes)
}

fn validate_json_nodes<'value>(
    values: impl IntoIterator<Item = (&'value Value, usize)>,
    initial_nodes: usize,
    initial_text_bytes: usize,
    max_depth: usize,
    max_nodes: usize,
    max_text_bytes: usize,
) -> Result<(), JsonEnvelopeViolation> {
    let mut pending: Vec<_> = values.into_iter().collect();
    let mut nodes = initial_nodes;
    let mut text_bytes = initial_text_bytes;
    while let Some((current, depth)) = pending.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or(JsonEnvelopeViolation::Structure)?;
        if nodes > max_nodes || depth > max_depth {
            return Err(JsonEnvelopeViolation::Structure);
        }
        match current {
            Value::String(value) => add_json_text(value, &mut text_bytes, max_text_bytes)?,
            Value::Array(values) => {
                if values.len() > max_nodes.saturating_sub(nodes + pending.len()) {
                    return Err(JsonEnvelopeViolation::Structure);
                }
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.len() > max_nodes.saturating_sub(nodes + pending.len()) {
                    return Err(JsonEnvelopeViolation::Structure);
                }
                for (key, value) in values {
                    add_json_text(key, &mut text_bytes, max_text_bytes)?;
                    pending.push((value, depth + 1));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(())
}

fn add_json_text(
    value: &str,
    text_bytes: &mut usize,
    max_text_bytes: usize,
) -> Result<(), JsonEnvelopeViolation> {
    *text_bytes = text_bytes
        .checked_add(value.len())
        .ok_or(JsonEnvelopeViolation::Size)?;
    if *text_bytes > max_text_bytes {
        return Err(JsonEnvelopeViolation::Size);
    }
    if value.contains('\0') {
        return Err(JsonEnvelopeViolation::NulByte);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum StoredJsonKind {
    Payload,
    Signature,
}

fn parse_bounded_json(
    input: &str,
    max_bytes: usize,
    max_depth: usize,
    max_nodes: usize,
    kind: StoredJsonKind,
) -> Result<Value, EventProjectionError> {
    if input.len() > max_bytes {
        return Err(kind.envelope_error());
    }
    if input.contains('\0') {
        return Err(EventProjectionError::NulByteNotAllowed);
    }

    let mut budget = StoredJsonBudget {
        max_depth,
        max_nodes,
        nodes: 0,
        violation: None,
    };
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let result = BoundedValueSeed {
        budget: &mut budget,
        depth: 1,
    }
    .deserialize(&mut deserializer);

    let value = match result {
        Ok(value) => value,
        Err(error) => return Err(kind.parse_error(error, budget.violation)),
    };
    deserializer
        .end()
        .map_err(|error| kind.parse_error(error, budget.violation))?;
    Ok(value)
}

impl StoredJsonKind {
    fn envelope_error(self) -> EventProjectionError {
        match self {
            Self::Payload => EventProjectionError::CanonicalPayloadEnvelopeExceeded,
            Self::Signature => EventProjectionError::SignatureEnvelopeExceeded,
        }
    }

    fn structure_error(self) -> EventProjectionError {
        match self {
            Self::Payload => EventProjectionError::CanonicalPayloadStructureExceeded,
            Self::Signature => EventProjectionError::SignatureStructureExceeded,
        }
    }

    fn parse_error(
        self,
        error: serde_json::Error,
        violation: Option<StoredJsonViolation>,
    ) -> EventProjectionError {
        match violation {
            Some(StoredJsonViolation::Structure) => self.structure_error(),
            Some(StoredJsonViolation::NulByte) => EventProjectionError::NulByteNotAllowed,
            None => match self {
                Self::Payload => EventProjectionError::InvalidPayload(error),
                Self::Signature => EventProjectionError::InvalidSignature,
            },
        }
    }
}

#[derive(Clone, Copy)]
enum StoredJsonViolation {
    Structure,
    NulByte,
}

struct StoredJsonBudget {
    max_depth: usize,
    max_nodes: usize,
    nodes: usize,
    violation: Option<StoredJsonViolation>,
}

impl StoredJsonBudget {
    fn enter<E: de::Error>(&mut self, depth: usize) -> Result<(), E> {
        self.nodes = self.nodes.saturating_add(1);
        if depth > self.max_depth || self.nodes > self.max_nodes {
            self.violation = Some(StoredJsonViolation::Structure);
            return Err(E::custom("stored JSON exceeds accepted structure"));
        }
        Ok(())
    }

    fn reject_nul<E: de::Error>(&mut self, value: &str) -> Result<(), E> {
        if value.contains('\0') {
            self.violation = Some(StoredJsonViolation::NulByte);
            return Err(E::custom("stored JSON contains a NUL byte"));
        }
        Ok(())
    }
}

struct BoundedValueSeed<'budget> {
    budget: &'budget mut StoredJsonBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedValueSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.budget.enter(self.depth)?;
        deserializer.deserialize_any(BoundedValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct BoundedValueVisitor<'budget> {
    budget: &'budget mut StoredJsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for BoundedValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value within the stored envelope")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.reject_nul(value)?;
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.reject_nul(&value)?;
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(BoundedValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            self.budget.reject_nul(&key)?;
            let value = object.next_value_seed(BoundedValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
