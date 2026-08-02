use std::time::Duration;

use bioworld_decision_grpc::{
    DecisionGrpcServiceConfig, DecisionGrpcWatchConfig, InvalidDecisionGrpcWatchConfig,
    MAX_DECISION_GRPC_WATCH_IN_FLIGHT_REQUESTS,
};

#[test]
fn watch_configuration_is_bounded_and_redacted() {
    for (global, per_tenant) in [
        (0, 1),
        (1, 0),
        (1, 2),
        (MAX_DECISION_GRPC_WATCH_IN_FLIGHT_REQUESTS + 1, 1),
    ] {
        assert_eq!(
            DecisionGrpcWatchConfig::try_new(global, per_tenant),
            Err(InvalidDecisionGrpcWatchConfig)
        );
    }

    let error = InvalidDecisionGrpcWatchConfig;
    assert_eq!(format!("{error:?}"), "InvalidDecisionGrpcWatchConfig");
    assert_eq!(
        error.to_string(),
        "gRPC decision Watch configuration is invalid"
    );

    fn assert_error<T: std::error::Error + Send + Sync + Copy>(_: T) {}
    assert_error(error);
}

#[test]
fn watch_capacity_must_reserve_total_service_capacity() {
    let service = DecisionGrpcServiceConfig::try_new(4, Duration::from_secs(1)).unwrap();
    let watch = DecisionGrpcWatchConfig::try_new(4, 1).unwrap();

    assert_eq!(
        watch.validate_for_service(service),
        Err(InvalidDecisionGrpcWatchConfig)
    );
    assert!(
        DecisionGrpcWatchConfig::try_new(3, 1)
            .unwrap()
            .validate_for_service(service)
            .is_ok()
    );
}
