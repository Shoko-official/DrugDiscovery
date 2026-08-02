use std::time::Duration;

use bioworld_decision_grpc_client::{
    DecisionGrpcClientError, DecisionGrpcClientLimits, DecisionGrpcWatchLimits,
    MAX_CLIENT_IN_FLIGHT, MAX_CLIENT_WATCH_EVENTS, MAX_CLIENT_WATCH_TIMEOUT,
};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(1);

#[test]
fn accepts_the_exact_watch_limit_ceilings() {
    assert!(
        DecisionGrpcWatchLimits::try_new(MAX_CLIENT_WATCH_TIMEOUT, MAX_CLIENT_WATCH_EVENTS,)
            .is_ok()
    );
}

#[test]
fn rejects_zero_or_excessive_watch_limits() {
    let invalid = [
        (Duration::ZERO, 1),
        (MAX_CLIENT_WATCH_TIMEOUT + Duration::from_nanos(1), 1),
        (Duration::from_secs(1), 0),
        (Duration::from_secs(1), MAX_CLIENT_WATCH_EVENTS + 1),
    ];

    for (timeout, max_events) in invalid {
        assert_eq!(
            DecisionGrpcWatchLimits::try_new(timeout, max_events).err(),
            Some(DecisionGrpcClientError::InvalidConfiguration),
        );
    }
}

#[test]
fn accepts_the_exact_watch_limit_minima() {
    assert!(DecisionGrpcWatchLimits::try_new(Duration::from_millis(1), 1).is_ok());
}

#[test]
fn redacts_watch_limit_values_from_debug_output() {
    let limits = DecisionGrpcWatchLimits::try_new(Duration::from_secs(173), 41)
        .expect("bounded Watch limits must be accepted");

    assert_eq!(format!("{limits:?}"), "DecisionGrpcWatchLimits { .. }");
}

#[test]
fn accepts_explicit_bounded_or_get_only_watch_capacity() {
    for (max_in_flight, max_active_watches) in [(2, 1), (1, 0), (2, 0)] {
        assert!(
            DecisionGrpcClientLimits::try_new_with_watch_capacity(
                CLIENT_TIMEOUT,
                CLIENT_TIMEOUT,
                CLIENT_TIMEOUT,
                max_in_flight,
                max_active_watches,
            )
            .is_ok()
        );
    }
}

#[test]
fn rejects_watch_capacity_without_a_reserved_non_watch_slot() {
    for max_active_watches in [2, 3] {
        assert_eq!(
            DecisionGrpcClientLimits::try_new_with_watch_capacity(
                CLIENT_TIMEOUT,
                CLIENT_TIMEOUT,
                CLIENT_TIMEOUT,
                2,
                max_active_watches,
            )
            .err(),
            Some(DecisionGrpcClientError::InvalidConfiguration),
        );
    }
}

#[test]
fn accepts_the_exact_global_and_watch_capacity_ceilings() {
    assert!(
        DecisionGrpcClientLimits::try_new_with_watch_capacity(
            CLIENT_TIMEOUT,
            CLIENT_TIMEOUT,
            CLIENT_TIMEOUT,
            MAX_CLIENT_IN_FLIGHT,
            MAX_CLIENT_IN_FLIGHT - 1,
        )
        .is_ok()
    );
}
