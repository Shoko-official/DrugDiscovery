use bioworld_contracts::{
    DecisionContractError, VersionedDecisionRecord,
    v2::{self, DecisionEvent, EvidenceSnapshotRef},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const DECISION_EVENT_TYPE: &str = "bioworld.v2.DecisionEvent";
pub const DECISION_SCHEMA_VERSION: &str = "2";
pub const DECISION_AGGREGATE_TYPE: &str = "bioworld.v2.DecisionRecord";

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
        validate_json_value(&signature)?;
        let signature = signature
            .as_object()
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or(EventProjectionError::InvalidSignature)?;

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
    #[error("event_id must be a canonical UUID")]
    InvalidEventId,
    #[error("tenant_id must be non-empty and have no surrounding whitespace")]
    InvalidTenantId,
    #[error("signature must be a non-empty JSON object")]
    InvalidSignature,
    #[error("PostgreSQL text and jsonb values must not contain NUL bytes")]
    NulByteNotAllowed,
    #[error("decision contract is invalid: {0}")]
    InvalidDecision(#[from] DecisionContractError),
    #[error("canonical payload could not be serialized: {0}")]
    Canonicalization(#[source] serde_json::Error),
    #[error("stored payload is invalid: {0}")]
    InvalidPayload(#[source] serde_json::Error),
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CanonicalRecommendation {
    Promote,
    Reject,
    Abstain,
    Defer,
    StopProgram,
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
    let boundary = VersionedDecisionRecord::try_from(decision)?;
    let decision = v2::DecisionRecord::from(&boundary);
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

    let payload: CanonicalDecisionPayload = serde_json::from_value(row.payload.clone())
        .map_err(EventProjectionError::InvalidPayload)?;
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

    let (_, expected_hash) = canonical_payload(&payload)?;
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
        }
    }
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
    validate_json_object(&row.signature)?;
    Ok(())
}

fn validate_tenant_id(tenant_id: &str) -> Result<(), EventProjectionError> {
    validate_text(tenant_id)?;
    if tenant_id.is_empty() || tenant_id.trim() != tenant_id {
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
    let bytes = serde_jcs::to_vec(value).map_err(EventProjectionError::Canonicalization)?;
    let payload = serde_json::from_slice(&bytes).map_err(EventProjectionError::Canonicalization)?;
    validate_json_value(&payload)?;
    let payload_sha256 = format!("{:x}", Sha256::digest(&bytes));
    Ok((payload, payload_sha256))
}

fn validate_text(value: &str) -> Result<(), EventProjectionError> {
    if value.contains('\0') {
        return Err(EventProjectionError::NulByteNotAllowed);
    }
    Ok(())
}

fn validate_json_object(value: &Map<String, Value>) -> Result<(), EventProjectionError> {
    for (key, value) in value {
        validate_text(key)?;
        validate_json_value(value)?;
    }
    Ok(())
}

fn validate_json_value(value: &Value) -> Result<(), EventProjectionError> {
    match value {
        Value::String(value) => validate_text(value),
        Value::Array(values) => values.iter().try_for_each(validate_json_value),
        Value::Object(value) => validate_json_object(value),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}
