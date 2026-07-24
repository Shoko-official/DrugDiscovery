use bioworld_contracts::v2::WatchDecisionRequest;
use bioworld_decision_query::{
    GetDecisionQuery, GetDecisionRequestError, WatchDecisionQuery, WatchDecisionRequestError,
};
use uuid::Uuid;

#[test]
fn converts_each_canonical_watch_request_into_the_exact_typed_query() {
    let canonical_identifiers = [
        "00000000-0000-0000-0000-000000000000",
        "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ];

    for decision_id in canonical_identifiers {
        let request = WatchDecisionRequest {
            decision_id: decision_id.to_owned(),
        };

        let query = WatchDecisionQuery::try_from(request)
            .expect("canonical watch request must be accepted");

        assert_eq!(query.decision_id(), Uuid::parse_str(decision_id).unwrap());
    }
}

#[test]
fn rejects_every_non_canonical_watch_request_identifier() {
    let invalid_identifiers = [
        "",
        "invalid-decision-id",
        "018F5A72-9C4B-7D31-8F6A-26F08F3F4D99",
        "018f5a72-9C4B-7d31-8f6a-26f08f3f4d99",
        "018f5a729c4b7d318f6a26f08f3f4d99",
        "{018f5a72-9c4b-7d31-8f6a-26f08f3f4d99}",
        "urn:uuid:018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        "   ",
        " 018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99 ",
    ];

    for decision_id in invalid_identifiers {
        let result = WatchDecisionQuery::try_from(WatchDecisionRequest {
            decision_id: decision_id.to_owned(),
        });

        assert_eq!(
            result.err(),
            Some(WatchDecisionRequestError::InvalidDecisionId)
        );
    }
}

#[test]
fn watch_request_contract_is_fixed_redacted_and_distinct() {
    fn assert_query<T: Send + Sync + Copy>() {}
    fn assert_error<T: std::error::Error + Send + Sync + Copy>() {}

    assert_query::<WatchDecisionQuery>();
    assert_error::<WatchDecisionRequestError>();
    assert_ne!(
        std::any::TypeId::of::<WatchDecisionQuery>(),
        std::any::TypeId::of::<GetDecisionQuery>()
    );
    assert_ne!(
        std::any::TypeId::of::<WatchDecisionRequestError>(),
        std::any::TypeId::of::<GetDecisionRequestError>()
    );

    let submitted = "sensitive-invalid-watch-decision-id";
    let error = WatchDecisionQuery::try_from(WatchDecisionRequest {
        decision_id: submitted.to_owned(),
    })
    .err()
    .expect("invalid watch request must fail");
    let rendered = format!("{error:?} {error}");

    assert_eq!(error, WatchDecisionRequestError::InvalidDecisionId);
    assert_eq!(
        error.to_string(),
        "watch decision request identifier is invalid"
    );
    assert_eq!(format!("{error:?}"), "InvalidDecisionId");
    assert!(!rendered.contains(submitted));
}
