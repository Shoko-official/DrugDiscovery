use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use bioworld_decision_grpc_server::{
    BindDecisionGrpcServerError, DecisionGrpcBind, DecisionGrpcServerConfig,
    DecisionGrpcServerLimits, DecisionGrpcTlsIdentity, InvalidDecisionGrpcBind,
    InvalidDecisionGrpcServerLimits, InvalidDecisionGrpcTlsIdentity,
    MAX_DECISION_GRPC_ACTIVE_CONNECTIONS, MAX_DECISION_GRPC_CONNECTION_AGE,
    MAX_DECISION_GRPC_CONNECTION_AGE_GRACE, MAX_DECISION_GRPC_PRE_AUTHENTICATION_STREAMS,
    MAX_DECISION_GRPC_SHUTDOWN_GRACE, MAX_DECISION_GRPC_STREAMS_PER_CONNECTION,
    MAX_DECISION_GRPC_TLS_CERTIFICATE_CHAIN_PEM_BYTES, MAX_DECISION_GRPC_TLS_HANDSHAKE_TIMEOUT,
    MAX_DECISION_GRPC_TLS_PRIVATE_KEY_PEM_BYTES, MAX_DECISION_GRPC_TRANSPORT_REQUEST_TIMEOUT,
    ServeDecisionGrpcServerError,
};

const CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const CERT_END: &str = "-----END CERTIFICATE-----";
const KEY_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const KEY_END: &str = "-----END PRIVATE KEY-----";

fn pem_with_len(begin: &str, end: &str, len: usize) -> Vec<u8> {
    let framing = begin.len() + end.len() + 2;
    assert!(len >= framing);
    let mut value = String::with_capacity(len);
    value.push_str(begin);
    value.push('\n');
    value.extend(std::iter::repeat_n('A', len - framing));
    value.push('\n');
    value.push_str(end);
    assert_eq!(value.len(), len);
    value.into_bytes()
}

fn valid_shape_identity() -> DecisionGrpcTlsIdentity {
    DecisionGrpcTlsIdentity::try_from_pem(
        pem_with_len(CERT_BEGIN, CERT_END, 128),
        pem_with_len(KEY_BEGIN, KEY_END, 128),
    )
    .unwrap()
}

#[test]
fn accepts_exact_server_limit_boundaries() {
    let limits = DecisionGrpcServerLimits::try_new(
        MAX_DECISION_GRPC_ACTIVE_CONNECTIONS,
        4,
        MAX_DECISION_GRPC_TLS_HANDSHAKE_TIMEOUT,
        MAX_DECISION_GRPC_TRANSPORT_REQUEST_TIMEOUT,
        MAX_DECISION_GRPC_CONNECTION_AGE,
        MAX_DECISION_GRPC_CONNECTION_AGE_GRACE,
        MAX_DECISION_GRPC_SHUTDOWN_GRACE,
    )
    .unwrap();

    assert_eq!(
        limits.max_active_connections(),
        MAX_DECISION_GRPC_ACTIVE_CONNECTIONS
    );
    assert_eq!(limits.max_concurrent_streams_per_connection(), 4);
    assert_eq!(
        limits.tls_handshake_timeout(),
        MAX_DECISION_GRPC_TLS_HANDSHAKE_TIMEOUT
    );
    assert_eq!(
        limits.transport_request_timeout(),
        MAX_DECISION_GRPC_TRANSPORT_REQUEST_TIMEOUT
    );
    assert_eq!(
        limits.max_connection_age(),
        MAX_DECISION_GRPC_CONNECTION_AGE
    );
    assert_eq!(
        limits.connection_age_grace(),
        MAX_DECISION_GRPC_CONNECTION_AGE_GRACE
    );
    assert_eq!(limits.shutdown_grace(), MAX_DECISION_GRPC_SHUTDOWN_GRACE);

    let stream_limits = DecisionGrpcServerLimits::try_new(
        16,
        MAX_DECISION_GRPC_STREAMS_PER_CONNECTION,
        MAX_DECISION_GRPC_TLS_HANDSHAKE_TIMEOUT,
        MAX_DECISION_GRPC_TRANSPORT_REQUEST_TIMEOUT,
        MAX_DECISION_GRPC_CONNECTION_AGE,
        MAX_DECISION_GRPC_CONNECTION_AGE_GRACE,
        MAX_DECISION_GRPC_SHUTDOWN_GRACE,
    )
    .unwrap();
    assert_eq!(
        stream_limits.max_concurrent_streams_per_connection(),
        MAX_DECISION_GRPC_STREAMS_PER_CONNECTION
    );
}

#[test]
fn rejects_unsafe_server_limits_with_a_fixed_error() {
    let invalid = [
        DecisionGrpcServerLimits::try_new(
            0,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            MAX_DECISION_GRPC_ACTIVE_CONNECTIONS + 1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            0,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            MAX_DECISION_GRPC_STREAMS_PER_CONNECTION + 1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            129,
            32,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(3),
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            1,
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            1,
            MAX_DECISION_GRPC_TLS_HANDSHAKE_TIMEOUT + Duration::from_nanos(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            1,
            Duration::from_secs(1),
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            1,
            Duration::from_secs(1),
            MAX_DECISION_GRPC_TRANSPORT_REQUEST_TIMEOUT + Duration::from_nanos(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_DECISION_GRPC_SHUTDOWN_GRACE,
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_DECISION_GRPC_CONNECTION_AGE + Duration::from_nanos(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::ZERO,
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_DECISION_GRPC_CONNECTION_AGE_GRACE + Duration::from_nanos(1),
            Duration::from_secs(2),
        ),
        DecisionGrpcServerLimits::try_new(
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_DECISION_GRPC_SHUTDOWN_GRACE + Duration::from_nanos(1),
        ),
    ];

    assert!(
        invalid
            .into_iter()
            .all(|result| { result == Err(InvalidDecisionGrpcServerLimits) })
    );
    let error = InvalidDecisionGrpcServerLimits;
    assert_eq!(format!("{error:?}"), "InvalidDecisionGrpcServerLimits");
    assert_eq!(error.to_string(), "decision gRPC server limits are invalid");
}

#[test]
fn defaults_are_secure_and_in_range() {
    let limits = DecisionGrpcServerLimits::default();

    assert!(limits.max_active_connections() <= MAX_DECISION_GRPC_ACTIVE_CONNECTIONS);
    assert!(
        limits.max_concurrent_streams_per_connection() <= MAX_DECISION_GRPC_STREAMS_PER_CONNECTION
    );
    assert!(limits.tls_handshake_timeout() <= MAX_DECISION_GRPC_TLS_HANDSHAKE_TIMEOUT);
    assert!(limits.transport_request_timeout() <= MAX_DECISION_GRPC_TRANSPORT_REQUEST_TIMEOUT);
    assert!(limits.max_connection_age() <= MAX_DECISION_GRPC_CONNECTION_AGE);
    assert!(limits.connection_age_grace() <= MAX_DECISION_GRPC_CONNECTION_AGE_GRACE);
    assert!(limits.shutdown_grace() <= MAX_DECISION_GRPC_SHUTDOWN_GRACE);
    assert!(
        limits.max_active_connections() * limits.max_concurrent_streams_per_connection() as usize
            <= MAX_DECISION_GRPC_PRE_AUTHENTICATION_STREAMS
    );
}

#[test]
fn allows_shutdown_to_force_a_request_before_its_outer_timeout() {
    let limits = DecisionGrpcServerLimits::try_new(
        1,
        1,
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(30),
        Duration::from_secs(1),
        Duration::from_millis(100),
    )
    .unwrap();

    assert!(limits.shutdown_grace() < limits.transport_request_timeout());
}

#[test]
fn requires_explicit_and_valid_bind_exposure() {
    let loopback_address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let loopback = DecisionGrpcBind::loopback(loopback_address).unwrap();
    assert_eq!(loopback.socket_addr(), loopback_address);

    let exposed_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8443));
    let exposed = DecisionGrpcBind::exposed(exposed_address).unwrap();
    assert_eq!(exposed.socket_addr(), exposed_address);

    for result in [
        DecisionGrpcBind::loopback(exposed_address),
        DecisionGrpcBind::exposed(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
    ] {
        assert_eq!(result, Err(InvalidDecisionGrpcBind));
    }

    let error = InvalidDecisionGrpcBind;
    assert_eq!(format!("{error:?}"), "InvalidDecisionGrpcBind");
    assert_eq!(error.to_string(), "decision gRPC server bind is invalid");

    let config = DecisionGrpcServerConfig::new(loopback, DecisionGrpcServerLimits::default());
    assert_eq!(config.bind().socket_addr(), loopback_address);
}

#[test]
fn bounds_and_redacts_tls_identity_input() {
    let exact = DecisionGrpcTlsIdentity::try_from_pem(
        pem_with_len(
            CERT_BEGIN,
            CERT_END,
            MAX_DECISION_GRPC_TLS_CERTIFICATE_CHAIN_PEM_BYTES,
        ),
        pem_with_len(
            KEY_BEGIN,
            KEY_END,
            MAX_DECISION_GRPC_TLS_PRIVATE_KEY_PEM_BYTES,
        ),
    )
    .unwrap();
    assert_eq!(format!("{exact:?}"), "DecisionGrpcTlsIdentity");

    let sensitive_marker = "sensitive-private-key-marker";
    let certificate_block = String::from_utf8(pem_with_len(CERT_BEGIN, CERT_END, 128)).unwrap();
    let invalid = [
        DecisionGrpcTlsIdentity::try_from_pem(Vec::new(), Vec::new()),
        DecisionGrpcTlsIdentity::try_from_pem(
            pem_with_len(
                CERT_BEGIN,
                CERT_END,
                MAX_DECISION_GRPC_TLS_CERTIFICATE_CHAIN_PEM_BYTES + 1,
            ),
            pem_with_len(KEY_BEGIN, KEY_END, 128),
        ),
        DecisionGrpcTlsIdentity::try_from_pem(
            pem_with_len(CERT_BEGIN, CERT_END, 128),
            pem_with_len(
                KEY_BEGIN,
                KEY_END,
                MAX_DECISION_GRPC_TLS_PRIVATE_KEY_PEM_BYTES + 1,
            ),
        ),
        DecisionGrpcTlsIdentity::try_from_pem(
            pem_with_len(CERT_BEGIN, CERT_END, 128),
            format!("{KEY_BEGIN}\n{sensitive_marker}\n{KEY_END}\n{KEY_BEGIN}\nAA\n{KEY_END}")
                .into_bytes(),
        ),
        DecisionGrpcTlsIdentity::try_from_pem(
            pem_with_len(CERT_BEGIN, CERT_END, 128),
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA\n-----END ENCRYPTED PRIVATE KEY-----"
                .to_vec(),
        ),
        DecisionGrpcTlsIdentity::try_from_pem(
            format!("{certificate_block}\n{certificate_block}").into_bytes(),
            pem_with_len(KEY_BEGIN, KEY_END, 128),
        ),
    ];

    assert!(
        invalid
            .into_iter()
            .all(|result| { result == Err(InvalidDecisionGrpcTlsIdentity) })
    );
    let error = InvalidDecisionGrpcTlsIdentity;
    let rendered = format!("{error:?} {error}");
    assert_eq!(
        rendered,
        "InvalidDecisionGrpcTlsIdentity decision gRPC TLS identity is invalid"
    );
    assert!(!rendered.contains(sensitive_marker));

    let identity = valid_shape_identity();
    assert!(!format!("{identity:?}").contains(KEY_BEGIN));
}

#[test]
fn transport_errors_are_fixed_and_redacted() {
    let sensitive_marker = "sensitive-transport-detail";
    let rendered = [
        format!(
            "{:?} {}",
            BindDecisionGrpcServerError::TlsIdentityRejected,
            BindDecisionGrpcServerError::TlsIdentityRejected
        ),
        format!(
            "{:?} {}",
            BindDecisionGrpcServerError::AddressUnavailable,
            BindDecisionGrpcServerError::AddressUnavailable
        ),
        format!(
            "{:?} {}",
            ServeDecisionGrpcServerError::TransportFailure,
            ServeDecisionGrpcServerError::TransportFailure
        ),
        format!(
            "{:?} {}",
            ServeDecisionGrpcServerError::ShutdownDeadlineExceeded,
            ServeDecisionGrpcServerError::ShutdownDeadlineExceeded
        ),
        format!(
            "{:?} {}",
            ServeDecisionGrpcServerError::ServiceLimitsRejected,
            ServeDecisionGrpcServerError::ServiceLimitsRejected
        ),
    ];

    assert_eq!(
        rendered,
        [
            "TlsIdentityRejected decision gRPC server TLS identity is rejected",
            "AddressUnavailable decision gRPC server address is unavailable",
            "TransportFailure decision gRPC server transport failed",
            "ShutdownDeadlineExceeded decision gRPC server shutdown deadline exceeded",
            "ServiceLimitsRejected decision gRPC server service limits are rejected",
        ]
    );
    assert!(
        rendered
            .iter()
            .all(|value| !value.contains(sensitive_marker))
    );

    fn assert_error<T: std::error::Error + Send + Sync + Copy>(_: T) {}
    assert_error(BindDecisionGrpcServerError::TlsIdentityRejected);
    assert_error(ServeDecisionGrpcServerError::TransportFailure);
}
