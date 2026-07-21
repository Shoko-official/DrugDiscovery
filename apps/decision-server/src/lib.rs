#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Runnable composition root for the read-only BioWorld decision service.

mod config;
mod runtime;
mod secure_file;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_acl;

pub use config::{
    DecisionServerConfig, InvalidDecisionServerConfig, MAX_DECISION_SERVER_CONTROL_BYTES,
};
pub use runtime::{DecisionServerRuntime, DecisionServerServeError, DecisionServerStartupError};
