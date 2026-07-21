#![deny(unsafe_code)]
#![deny(missing_docs)]

//! TLS-only network transport for the authenticated BioWorld decision gRPC service.

mod config;
mod server;

pub use config::{
    DecisionGrpcBind, DecisionGrpcServerConfig, DecisionGrpcServerLimits, DecisionGrpcTlsIdentity,
    InvalidDecisionGrpcBind, InvalidDecisionGrpcServerLimits, InvalidDecisionGrpcTlsIdentity,
    MAX_DECISION_GRPC_ACTIVE_CONNECTIONS, MAX_DECISION_GRPC_CONNECTION_AGE,
    MAX_DECISION_GRPC_CONNECTION_AGE_GRACE, MAX_DECISION_GRPC_PRE_AUTHENTICATION_STREAMS,
    MAX_DECISION_GRPC_SHUTDOWN_GRACE, MAX_DECISION_GRPC_STREAMS_PER_CONNECTION,
    MAX_DECISION_GRPC_TLS_CERTIFICATE_CHAIN_PEM_BYTES, MAX_DECISION_GRPC_TLS_HANDSHAKE_TIMEOUT,
    MAX_DECISION_GRPC_TLS_PRIVATE_KEY_PEM_BYTES, MAX_DECISION_GRPC_TRANSPORT_REQUEST_TIMEOUT,
};
pub use server::{BindDecisionGrpcServerError, DecisionGrpcServer, ServeDecisionGrpcServerError};
