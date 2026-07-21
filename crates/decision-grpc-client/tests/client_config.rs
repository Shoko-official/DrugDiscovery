use std::time::Duration;

use bioworld_decision_grpc_client::{
    DecisionGrpcClientConfig, DecisionGrpcClientError, DecisionGrpcClientLimits,
    MAX_CLIENT_CONNECT_TIMEOUT, MAX_CLIENT_IN_FLIGHT, MAX_CLIENT_REQUEST_TIMEOUT,
    MAX_CLIENT_TLS_HANDSHAKE_TIMEOUT, MAX_DECISION_CLIENT_ENDPOINT_BYTES,
    MAX_TLS_CA_CERTIFICATE_BYTES, MAX_TLS_CA_CERTIFICATES, MAX_TLS_SERVER_NAME_BYTES,
};
use rcgen::generate_simple_self_signed;

fn test_ca() -> Vec<u8> {
    generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("test CA must be generated")
        .cert
        .pem()
        .into_bytes()
}

fn limits() -> DecisionGrpcClientLimits {
    DecisionGrpcClientLimits::try_new(
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(5),
        4,
    )
    .expect("test limits must be valid")
}

#[test]
fn rejects_plaintext_endpoints_without_reflecting_the_input() {
    let endpoint = "http://private.internal:50051";
    let error = DecisionGrpcClientConfig::try_new(
        endpoint.to_owned(),
        "private.internal".to_owned(),
        test_ca(),
        limits(),
    )
    .expect_err("plaintext endpoint must fail");

    assert_eq!(error, DecisionGrpcClientError::InvalidConfiguration);
    assert_eq!(
        error.to_string(),
        "decision client configuration is invalid"
    );
    assert!(!format!("{error:?}").contains(endpoint));
}

#[test]
fn rejects_zero_or_excessive_client_limits() {
    let invalid = [
        (
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
        ),
        (
            MAX_CLIENT_CONNECT_TIMEOUT + Duration::from_nanos(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
        ),
        (
            Duration::from_secs(1),
            Duration::ZERO,
            Duration::from_secs(1),
            1,
        ),
        (
            Duration::from_secs(1),
            MAX_CLIENT_TLS_HANDSHAKE_TIMEOUT + Duration::from_nanos(1),
            Duration::from_secs(1),
            1,
        ),
        (
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::ZERO,
            1,
        ),
        (
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_CLIENT_REQUEST_TIMEOUT + Duration::from_nanos(1),
            1,
        ),
        (
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            0,
        ),
        (
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_CLIENT_IN_FLIGHT + 1,
        ),
    ];

    for (connect, handshake, request, in_flight) in invalid {
        assert_eq!(
            DecisionGrpcClientLimits::try_new(connect, handshake, request, in_flight),
            Err(DecisionGrpcClientError::InvalidConfiguration),
        );
    }
}

#[test]
fn accepts_the_exact_client_limit_ceilings() {
    assert!(
        DecisionGrpcClientLimits::try_new(
            MAX_CLIENT_CONNECT_TIMEOUT,
            MAX_CLIENT_TLS_HANDSHAKE_TIMEOUT,
            MAX_CLIENT_REQUEST_TIMEOUT,
            MAX_CLIENT_IN_FLIGHT,
        )
        .is_ok()
    );
}

#[test]
fn rejects_https_endpoints_that_are_not_bounded_origins() {
    let invalid = [
        "https://".to_owned(),
        "https://:443".to_owned(),
        "https://user@example.com".to_owned(),
        "https://example.com/path".to_owned(),
        "https://example.com?query=1".to_owned(),
        "https://example.com/#fragment".to_owned(),
        "https://example.com:invalid".to_owned(),
        "https://example.com:0".to_owned(),
        "https://private_name".to_owned(),
        "https://example%2ecom".to_owned(),
        format!("https://{}", "a".repeat(MAX_DECISION_CLIENT_ENDPOINT_BYTES)),
    ];

    for endpoint in invalid {
        let error = DecisionGrpcClientConfig::try_new(
            endpoint.clone(),
            "example.com".to_owned(),
            test_ca(),
            limits(),
        )
        .err()
        .unwrap_or_else(|| panic!("non-origin endpoint must fail: {endpoint}"));

        assert_eq!(error, DecisionGrpcClientError::InvalidConfiguration);
        assert!(!error.to_string().contains(&endpoint));
        assert!(!format!("{error:?}").contains(&endpoint));
    }
}

#[test]
fn rejects_non_dns_or_noncanonical_tls_server_names() {
    let oversized_label = format!("{}.example", "a".repeat(64));
    let oversized_name = "a".repeat(MAX_TLS_SERVER_NAME_BYTES + 1);
    let invalid = [
        "".to_owned(),
        "127.0.0.1".to_owned(),
        "[::1]".to_owned(),
        "*.example.com".to_owned(),
        "-example.com".to_owned(),
        "example-.com".to_owned(),
        "example..com".to_owned(),
        "example.com.".to_owned(),
        "private_name".to_owned(),
        "tést.example".to_owned(),
        oversized_label,
        oversized_name,
    ];

    for server_name in invalid {
        let error = DecisionGrpcClientConfig::try_new(
            "https://127.0.0.1:50051".to_owned(),
            server_name.clone(),
            test_ca(),
            limits(),
        )
        .expect_err("invalid TLS server name must fail");

        assert_eq!(error, DecisionGrpcClientError::InvalidConfiguration);
        if !server_name.is_empty() {
            assert!(!error.to_string().contains(&server_name));
            assert!(!format!("{error:?}").contains(&server_name));
        }
    }
}

#[test]
fn rejects_empty_or_oversized_ca_certificate_inputs() {
    for ca_certificate_pem in [Vec::new(), vec![b'x'; MAX_TLS_CA_CERTIFICATE_BYTES + 1]] {
        assert_eq!(
            DecisionGrpcClientConfig::try_new(
                "https://127.0.0.1:50051".to_owned(),
                "localhost".to_owned(),
                ca_certificate_pem,
                limits(),
            )
            .err(),
            Some(DecisionGrpcClientError::InvalidConfiguration),
        );
    }
}

#[test]
fn redacts_all_configuration_values_from_debug_output() {
    let endpoint = "https://private.internal:50051";
    let server_name = "private.internal";
    let certificate = test_ca();
    let config = DecisionGrpcClientConfig::try_new(
        endpoint.to_owned(),
        server_name.to_owned(),
        certificate,
        limits(),
    )
    .expect("bounded TLS configuration must be accepted");

    let rendered = format!("{config:?}");
    assert_eq!(rendered, "DecisionGrpcClientConfig { .. }");
    assert!(!rendered.contains(endpoint));
    assert!(!rendered.contains(server_name));
    assert!(!rendered.contains("BEGIN CERTIFICATE"));
}

#[test]
fn rejects_duplicate_or_excessive_ca_anchors() {
    let certificate = test_ca();
    let duplicate = [certificate.as_slice(), certificate.as_slice()].concat();
    assert_eq!(
        DecisionGrpcClientConfig::try_new(
            "https://localhost:50051".to_owned(),
            "localhost".to_owned(),
            duplicate,
            limits(),
        )
        .err(),
        Some(DecisionGrpcClientError::InvalidConfiguration),
    );

    let excessive = (0..=MAX_TLS_CA_CERTIFICATES)
        .flat_map(|_| test_ca())
        .collect::<Vec<_>>();
    assert_eq!(
        DecisionGrpcClientConfig::try_new(
            "https://localhost:50051".to_owned(),
            "localhost".to_owned(),
            excessive,
            limits(),
        )
        .err(),
        Some(DecisionGrpcClientError::InvalidConfiguration),
    );
}
