#![deny(unsafe_code)]

mod decision_event;

pub use decision_event::{
    DECISION_AGGREGATE_TYPE, DECISION_EVENT_TYPE, DECISION_SCHEMA_VERSION, DecisionEventMetadata,
    EventProjectionError, ScientificEventRow, project_decision_event, reconstruct_decision_event,
};
