use bioworld_decision_grpc_client::{AccessToken, InvalidAccessToken, MAX_ACCESS_TOKEN_BYTES};

#[test]
fn rejects_empty_oversized_or_noncompact_access_tokens() {
    let invalid = [
        "".to_owned(),
        "header.payload".to_owned(),
        "header.payload.signature.extra".to_owned(),
        "header..signature".to_owned(),
        "header.payload.sign=ature".to_owned(),
        "header.payload.sign ature".to_owned(),
        format!("{}.payload.signature", "a".repeat(MAX_ACCESS_TOKEN_BYTES)),
    ];

    for token in invalid {
        let error =
            AccessToken::try_new(token.clone()).expect_err("invalid access token must fail");

        assert_eq!(error, InvalidAccessToken);
        assert_eq!(error.to_string(), "access token is invalid");
        if !token.is_empty() {
            assert!(!error.to_string().contains(&token));
            assert!(!format!("{error:?}").contains(&token));
        }
    }
}

#[test]
fn redacts_valid_access_tokens_from_debug_output() {
    let marker = "privateHeader.privatePayload.privateSignature";
    let token = AccessToken::try_new(marker.to_owned()).expect("compact token must be valid");

    let rendered = format!("{token:?}");
    assert_eq!(rendered, "AccessToken([REDACTED])");
    assert!(!rendered.contains(marker));
}

#[test]
fn accepts_the_exact_token_budget_and_rejects_one_byte_more() {
    let exact = format!("{}.b.c", "a".repeat(MAX_ACCESS_TOKEN_BYTES - 4));
    assert_eq!(exact.len(), MAX_ACCESS_TOKEN_BYTES);
    assert!(AccessToken::try_new(exact).is_ok());

    let oversized = format!("{}.b.c", "a".repeat(MAX_ACCESS_TOKEN_BYTES - 3));
    assert_eq!(oversized.len(), MAX_ACCESS_TOKEN_BYTES + 1);
    assert_eq!(
        AccessToken::try_new(oversized).err(),
        Some(InvalidAccessToken),
    );
}
