#![deny(unsafe_code)]

mod decision_event;
mod signature;

pub use decision_event::{
    DECISION_AGGREGATE_TYPE, DECISION_EVENT_TYPE, DECISION_SCHEMA_VERSION, DecisionEventMetadata,
    EventProjectionError, MAX_CANONICAL_DECISION_PAYLOAD_BYTES,
    MAX_CANONICAL_DECISION_PAYLOAD_DEPTH, MAX_CANONICAL_DECISION_PAYLOAD_NODES,
    MAX_EVENT_SIGNATURE_DEPTH, MAX_EVENT_SIGNATURE_JSON_BYTES, MAX_EVENT_SIGNATURE_NODES,
    MAX_STORED_EVENT_IDENTIFIER_BYTES, MAX_STORED_EVENT_IDENTIFIER_CHARS,
    MAX_STORED_EVENT_PAYLOAD_BYTES, MAX_STORED_EVENT_SIGNATURE_BYTES, ScientificEventRow,
    parse_stored_decision_payload, parse_stored_event_signature, project_decision_event,
    reconstruct_decision_event,
};
pub use signature::{
    DecisionEventSignatureError, DecisionEventVerificationClock, DecisionEventVerificationError,
    DecisionEventVerifier, InvalidDecisionEventVerifier,
    MAX_DECISION_EVENT_VERIFICATION_SNAPSHOT_BYTES, SystemDecisionEventVerificationClock,
    decision_event_signature_message, decision_event_signature_value,
    stored_decision_event_signature_message,
};
