#![deny(unsafe_code)]

mod decision;
mod tenant;

pub use decision::{DecisionContractError, MAX_DECISION_WIRE_BYTES, VersionedDecisionRecord};
pub use tenant::{MAX_TENANT_ID_BYTES, tenant_id_is_valid};

pub mod v2 {
    tonic::include_proto!("bioworld.v2");
}
