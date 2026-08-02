#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Runnable composition root for the read-only BioWorld decision service.

use std::{
    io::{self, Write},
    panic,
};

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

/// Replaces the process panic hook with one fixed message that omits panic payloads.
pub fn install_redacted_panic_hook() {
    panic::set_hook(Box::new(|_| {
        let mut output = io::stderr().lock();
        let _ = writeln!(output, "decision_server panicked");
        let _ = output.flush();
    }));
}
