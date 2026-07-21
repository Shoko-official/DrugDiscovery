use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener},
    time::Duration,
};

use bioworld_decision_grpc_server::{
    BindDecisionGrpcServerError, DecisionGrpcBind, DecisionGrpcServer, DecisionGrpcServerConfig,
    DecisionGrpcServerLimits, DecisionGrpcTlsIdentity,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};

fn tls_identity() -> DecisionGrpcTlsIdentity {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    DecisionGrpcTlsIdentity::try_from_pem(
        cert.pem().into_bytes(),
        signing_key.serialize_pem().into_bytes(),
    )
    .unwrap()
}

fn limits() -> DecisionGrpcServerLimits {
    DecisionGrpcServerLimits::try_new(
        4,
        4,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(30),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .unwrap()
}

fn config(socket_addr: SocketAddr) -> DecisionGrpcServerConfig {
    DecisionGrpcServerConfig::new(DecisionGrpcBind::loopback(socket_addr).unwrap(), limits())
}

#[tokio::test]
async fn binds_valid_tls_before_reporting_readiness() {
    let server = DecisionGrpcServer::bind(
        config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        tls_identity(),
    )
    .await
    .unwrap();
    let local_addr = server.local_addr();

    assert_eq!(local_addr.ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(local_addr.port(), 0);
    assert_eq!(format!("{server:?}"), "DecisionGrpcServer");
    assert!(TcpListener::bind(local_addr).is_err());

    drop(server);
    TcpListener::bind(local_addr).unwrap();
}

#[tokio::test]
async fn rejects_invalid_or_mismatched_tls_before_bind() {
    let invalid = DecisionGrpcTlsIdentity::try_from_pem(
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----".to_vec(),
        b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----".to_vec(),
    )
    .unwrap();
    let result =
        DecisionGrpcServer::bind(config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))), invalid).await;
    assert_eq!(
        result.unwrap_err(),
        BindDecisionGrpcServerError::TlsIdentityRejected
    );

    let CertifiedKey {
        cert,
        signing_key: _,
    } = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let CertifiedKey {
        cert: _,
        signing_key,
    } = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mismatched = DecisionGrpcTlsIdentity::try_from_pem(
        cert.pem().into_bytes(),
        signing_key.serialize_pem().into_bytes(),
    )
    .unwrap();
    let result = DecisionGrpcServer::bind(
        config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        mismatched,
    )
    .await;
    assert_eq!(
        result.unwrap_err(),
        BindDecisionGrpcServerError::TlsIdentityRejected
    );
}

#[tokio::test]
async fn reports_bind_conflict_without_address_or_identity_detail() {
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let occupied_addr = occupied.local_addr().unwrap();
    let result = DecisionGrpcServer::bind(config(occupied_addr), tls_identity()).await;

    let error = result.unwrap_err();
    assert_eq!(error, BindDecisionGrpcServerError::AddressUnavailable);
    let rendered = format!("{error:?} {error}");
    assert_eq!(
        rendered,
        "AddressUnavailable decision gRPC server address is unavailable"
    );
    assert!(!rendered.contains(&occupied_addr.to_string()));
    assert!(!rendered.contains("PRIVATE KEY"));
}
