#![deny(unsafe_code)]

mod decision;

pub use decision::{DecisionContractError, VersionedDecisionRecord};

pub mod v2 {
    tonic::include_proto!("bioworld.v2");
}
