use std::{
    collections::VecDeque,
    future::{Future, pending, poll_fn},
    net::SocketAddr,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    rand::SystemRandom,
    rsa::{KeyPair, KeySize, PublicKeyComponents},
    signature::{KeyPair as _, RSA_PKCS1_SHA256},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bioworld_contracts::v2::{
    DecisionCriterion, DecisionCriterionComparator, DecisionPredictionInterval,
    DecisionPredictionPosition, DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest,
    OodDetectorRef, OodStatus, Recommendation,
    decision_service_server::DecisionService as GeneratedDecisionService,
};
use bioworld_decision_grpc::{
    DecisionGrpcConnectInfo, DecisionGrpcPeerKey, DecisionGrpcService, DecisionGrpcServiceConfig,
    TenantScope, TenantScopedGetDecisionExecutor, TenantScopedGetDecisionFuture,
};
use bioworld_decision_grpc_jwt::{
    BIOWORLD_TENANT_CLAIM, JwtClock, JwtTenantAuthenticator, JwtTenantAuthenticatorConfig,
};
use bioworld_decision_query::GetDecisionQuery;
use jsonwebtoken::{Algorithm, Header};
use serde_json::{Value, json};
use tonic::{Code, Request, Status, metadata::MetadataValue};

const AUDIENCE: &str = "https://decision.bioworld.test";
const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99";
const ISSUER: &str = "https://identity.bioworld.test";
const KEY_ID: &str = "integration-key";
const REQUIRED_SCOPE: &str = "decision:read";
const TENANT_ID: &str = "tenant-a";

#[derive(Clone)]
struct FixedClock {
    available: Arc<AtomicBool>,
    calls: Arc<AtomicU64>,
    now: Arc<AtomicU64>,
}

impl FixedClock {
    fn new(now: u64) -> Self {
        Self {
            available: Arc::new(AtomicBool::new(true)),
            calls: Arc::new(AtomicU64::new(0)),
            now: Arc::new(AtomicU64::new(now)),
        }
    }

    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    fn fail(&self) {
        self.available.store(false, Ordering::SeqCst);
    }
}

impl JwtClock for FixedClock {
    fn unix_timestamp(&self) -> Option<u64> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.available
            .load(Ordering::SeqCst)
            .then(|| self.now.load(Ordering::SeqCst))
    }
}

#[derive(Clone)]
struct BlockingClock {
    calls: Arc<AtomicU64>,
    gate: BlockingPoolGate,
    now: u64,
}

#[derive(Clone)]
struct FirstVerificationBlockingClock {
    calls: Arc<AtomicU64>,
    gate: BlockingPoolGate,
    now: u64,
}

#[derive(Clone)]
struct PanicOnceClock {
    calls: Arc<AtomicU64>,
    now: u64,
}

impl PanicOnceClock {
    fn new(now: u64) -> Self {
        Self {
            calls: Arc::new(AtomicU64::new(0)),
            now,
        }
    }
}

impl JwtClock for PanicOnceClock {
    fn unix_timestamp(&self) -> Option<u64> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
            panic!("verification clock failed");
        }
        Some(self.now)
    }
}

impl FirstVerificationBlockingClock {
    fn new(now: u64, gate: BlockingPoolGate) -> Self {
        Self {
            calls: Arc::new(AtomicU64::new(0)),
            gate,
            now,
        }
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl JwtClock for FirstVerificationBlockingClock {
    fn unix_timestamp(&self) -> Option<u64> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
            self.gate.block();
        }
        Some(self.now)
    }
}

#[derive(Clone)]
struct SequenceClock {
    timestamps: Arc<Mutex<VecDeque<Option<u64>>>>,
}

impl SequenceClock {
    fn new(timestamps: impl IntoIterator<Item = Option<u64>>) -> Self {
        Self {
            timestamps: Arc::new(Mutex::new(timestamps.into_iter().collect())),
        }
    }

    fn remaining(&self) -> usize {
        self.timestamps.lock().unwrap().len()
    }
}

impl JwtClock for SequenceClock {
    fn unix_timestamp(&self) -> Option<u64> {
        self.timestamps
            .lock()
            .unwrap()
            .pop_front()
            .expect("test clock exhausted")
    }
}

impl BlockingClock {
    fn new(now: u64, gate: BlockingPoolGate) -> Self {
        Self {
            calls: Arc::new(AtomicU64::new(0)),
            gate,
            now,
        }
    }
}

impl JwtClock for BlockingClock {
    fn unix_timestamp(&self) -> Option<u64> {
        if self.calls.fetch_add(1, Ordering::SeqCst) > 0 {
            self.gate.block();
        }
        Some(self.now)
    }
}

#[derive(Clone)]
struct BlockingPoolGate {
    entered: Arc<AtomicBool>,
    state: Arc<(Mutex<bool>, Condvar)>,
}

impl BlockingPoolGate {
    fn new() -> Self {
        Self {
            entered: Arc::new(AtomicBool::new(false)),
            state: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    fn block(&self) {
        self.entered.store(true, Ordering::SeqCst);
        let (released, wake) = self.state.as_ref();
        let mut released = released.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
    }

    fn entered(&self) -> bool {
        self.entered.load(Ordering::SeqCst)
    }

    fn release(&self) {
        let (released, wake) = self.state.as_ref();
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
}

async fn wait_for_gate(gate: &BlockingPoolGate) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gate.entered() {
        assert!(
            Instant::now() < deadline,
            "blocking worker did not enter the test gate"
        );
        tokio::task::yield_now().await;
    }
}

async fn wait_for_clock_calls(calls: &AtomicU64, expected: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while calls.load(Ordering::SeqCst) < expected {
        assert!(
            Instant::now() < deadline,
            "blocking workers did not enter the test clock"
        );
        tokio::task::yield_now().await;
    }
}

struct GateRelease(BlockingPoolGate);

impl Drop for GateRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct TestKey {
    key_pair: KeyPair,
    key_id: String,
    jwk: Value,
}

impl TestKey {
    fn generate(key_id: &str) -> Self {
        let key_pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let components = PublicKeyComponents::<Vec<u8>>::from(key_pair.public_key());
        let jwk = json!({
            "alg": "RS256",
            "e": URL_SAFE_NO_PAD.encode(components.e),
            "kid": key_id,
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode(components.n),
            "use": "sig"
        });

        Self {
            key_pair,
            key_id: key_id.to_owned(),
            jwk,
        }
    }

    fn claims(now: u64, tenant_id: &str) -> Value {
        let mut claims = json!({
            "aud": AUDIENCE,
            "client_id": "desktop-client",
            "exp": now + 300,
            "iat": now,
            "iss": ISSUER,
            "jti": "access-token-1",
            "scope": REQUIRED_SCOPE,
            "sub": "scientist-1"
        });
        claims.as_object_mut().unwrap().insert(
            BIOWORLD_TENANT_CLAIM.to_owned(),
            Value::String(tenant_id.to_owned()),
        );

        claims
    }

    fn token(&self, now: u64, tenant_id: &str) -> String {
        self.sign(
            access_token_header(&self.key_id),
            Self::claims(now, tenant_id),
        )
    }

    fn sign(&self, header: Header, claims: Value) -> String {
        self.sign_raw(
            &serde_json::to_vec(&header).unwrap(),
            &serde_json::to_vec(&claims).unwrap(),
        )
    }

    fn sign_values(&self, header: Value, claims: Value) -> String {
        self.sign_raw(
            &serde_json::to_vec(&header).unwrap(),
            &serde_json::to_vec(&claims).unwrap(),
        )
    }

    fn sign_raw(&self, header: &[u8], claims: &[u8]) -> String {
        let encoded_header = URL_SAFE_NO_PAD.encode(header);
        let encoded_claims = URL_SAFE_NO_PAD.encode(claims);
        let message = format!("{encoded_header}.{encoded_claims}");
        let mut signature = vec![0; self.key_pair.public_modulus_len()];
        self.key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message.as_bytes(),
                &mut signature,
            )
            .unwrap();

        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))
    }
}

fn access_token_header(key_id: &str) -> Header {
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".to_owned());
    header.kid = Some(key_id.to_owned());
    header
}

struct RecordingExecutor {
    tenants: Arc<Mutex<Vec<String>>>,
}

struct ObservedPendingExecutor {
    calls: Arc<AtomicU64>,
}

impl TenantScopedGetDecisionExecutor for ObservedPendingExecutor {
    fn execute_get_decision(
        &self,
        _scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(pending())
    }
}

impl TenantScopedGetDecisionExecutor for RecordingExecutor {
    fn execute_get_decision(
        &self,
        scope: TenantScope,
        _query: GetDecisionQuery,
    ) -> TenantScopedGetDecisionFuture<'_> {
        self.tenants
            .lock()
            .unwrap()
            .push(scope.tenant_id().to_owned());
        Box::pin(async { Ok(record()) })
    }
}

fn prediction_interval(lower_decimal: &str, upper_decimal: &str) -> DecisionPredictionInterval {
    DecisionPredictionInterval {
        target: "binding_affinity".to_owned(),
        unit: "nM".to_owned(),
        lower_decimal: lower_decimal.to_owned(),
        upper_decimal: upper_decimal.to_owned(),
        nominal_coverage_decimal: "0.95".to_owned(),
        interval_method_id: "split_conformal".to_owned(),
        interval_method_version: "1.0".to_owned(),
        calibration_method_id: "held_out_calibration".to_owned(),
        calibration_method_version: "2026.07".to_owned(),
        calibration_evidence: Some(EvidenceSnapshotRef {
            id: "ES-CAL-001".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        }),
    }
}

fn prediction_positions() -> Vec<DecisionPredictionPosition> {
    [
        (
            "model-z",
            "2026.07",
            "shared-training-set",
            "0.4",
            "1.4",
            "ES-PRED-Z",
        ),
        (
            "model-a",
            "2026.06",
            "independent-assay",
            "0.2",
            "1.2",
            "ES-PRED-A",
        ),
    ]
    .into_iter()
    .map(
        |(source_id, source_version, dependency_group_id, lower, upper, evidence_id)| {
            DecisionPredictionPosition {
                source_id: source_id.to_owned(),
                source_version: source_version.to_owned(),
                dependency_group_id: dependency_group_id.to_owned(),
                interval: Some(prediction_interval(lower, upper)),
                prediction_evidence: Some(EvidenceSnapshotRef {
                    id: evidence_id.to_owned(),
                    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                }),
            }
        },
    )
    .collect()
}

#[allow(deprecated)]
fn record() -> DecisionRecord {
    DecisionRecord {
        decision_id: DECISION_ID.to_owned(),
        cou_id: "COU-JWT-001".to_owned(),
        evidence_snapshot_id: "ES-JWT-001".to_owned(),
        recommendation: Recommendation::Promote as i32,
        rationale: vec!["Signed tenant access.".to_owned()],
        aggregate_version: 1,
        evidence: Some(EvidenceSnapshotRef {
            id: "ES-JWT-001".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        }),
        ood_status: Some(OodStatus::InDomain as i32),
        ood_detector: Some(OodDetectorRef {
            detector_id: "jwt-domain-detector".to_owned(),
            detector_version: "2026.07".to_owned(),
        }),
        prediction_interval: Some(prediction_interval("0.25", "1.5")),
        prediction_positions: prediction_positions(),
        decision_criterion: Some(DecisionCriterion {
            criterion_id: "jwt_policy".to_owned(),
            criterion_version: "2026.07".to_owned(),
            comparator: DecisionCriterionComparator::LessThanOrEqual as i32,
            threshold_decimal: "0.75".to_owned(),
            criterion_evidence: Some(EvidenceSnapshotRef {
                id: "ES-JWT-CRITERION".to_owned(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            }),
        }),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn config(now: u64, max_concurrent_verifications: usize) -> JwtTenantAuthenticatorConfig {
    let max_concurrent_verifications = max_concurrent_verifications.max(2);
    JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        now + 3_600,
        max_concurrent_verifications,
        max_concurrent_verifications - 1,
    )
    .unwrap()
}

fn jwks(keys: &[&TestKey]) -> Vec<u8> {
    let keys = keys.iter().map(|key| key.jwk.clone()).collect::<Vec<_>>();
    serde_json::to_vec(&json!({ "keys": keys })).unwrap()
}

fn service(
    key: &TestKey,
    now: u64,
    max_concurrent_verifications: usize,
) -> (
    DecisionGrpcService<JwtTenantAuthenticator, RecordingExecutor>,
    Arc<Mutex<Vec<String>>>,
) {
    let authenticator = JwtTenantAuthenticator::try_from_jwks(
        config(now, max_concurrent_verifications),
        &jwks(&[key]),
    )
    .unwrap();
    service_with_authenticator(authenticator)
}

fn service_with_authenticator(
    authenticator: JwtTenantAuthenticator,
) -> (
    DecisionGrpcService<JwtTenantAuthenticator, RecordingExecutor>,
    Arc<Mutex<Vec<String>>>,
) {
    service_with_timeout(authenticator, Duration::from_secs(2))
}

fn service_with_timeout(
    authenticator: JwtTenantAuthenticator,
    request_timeout: Duration,
) -> (
    DecisionGrpcService<JwtTenantAuthenticator, RecordingExecutor>,
    Arc<Mutex<Vec<String>>>,
) {
    let tenants = Arc::new(Mutex::new(Vec::new()));
    let service = DecisionGrpcService::new(
        authenticator,
        RecordingExecutor {
            tenants: Arc::clone(&tenants),
        },
        DecisionGrpcServiceConfig::try_new(2, request_timeout).unwrap(),
    );

    (service, tenants)
}

fn request_with_token(token: &str) -> Request<GetDecisionRequest> {
    request_with_authorization(&format!("Bearer {token}"))
}

fn request_with_authorization(value: &str) -> Request<GetDecisionRequest> {
    request_with_authorization_from(value, "127.0.0.1:41000".parse().unwrap())
}

fn request_with_token_from(token: &str, peer: SocketAddr) -> Request<GetDecisionRequest> {
    request_with_authorization_from(&format!("Bearer {token}"), peer)
}

fn request_with_authorization_from(value: &str, peer: SocketAddr) -> Request<GetDecisionRequest> {
    let mut request = Request::new(GetDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    });
    request
        .metadata_mut()
        .insert("authorization", value.parse().unwrap());
    request
        .extensions_mut()
        .insert(DecisionGrpcConnectInfo::new(
            DecisionGrpcPeerKey::from_socket_addr(peer),
        ));
    request
}

fn assert_unauthenticated(status: &Status, sensitive_values: &[&str]) {
    assert_redacted_status(
        status,
        Code::Unauthenticated,
        "authentication is required",
        sensitive_values,
    );
}

fn assert_unavailable(status: &Status, sensitive_values: &[&str]) {
    assert_redacted_status(
        status,
        Code::Unavailable,
        "authentication service is unavailable",
        sensitive_values,
    );
}

fn assert_redacted_status(status: &Status, code: Code, message: &str, sensitive_values: &[&str]) {
    assert_eq!(status.code(), code);
    assert_eq!(status.message(), message);
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
    let rendered = format!("{status:?} {status}");
    for value in sensitive_values {
        assert!(!rendered.contains(value));
    }
}

#[test]
fn rejects_jwks_with_conflicting_key_use_metadata() {
    let key = TestKey::generate(KEY_ID);
    let mut jwk = key.jwk.clone();
    jwk.as_object_mut()
        .unwrap()
        .insert("key_ops".to_owned(), json!(["verify"]));
    let jwks = serde_json::to_vec(&json!({ "keys": [jwk] })).unwrap();

    let result = JwtTenantAuthenticator::try_from_jwks(config(now(), 2), &jwks);

    assert!(result.is_err());
}

#[test]
fn rejects_noncanonical_rsa_modulus_encoding() {
    let key = TestKey::generate(KEY_ID);
    let mut jwk = key.jwk.clone();
    let encoded_modulus = jwk["n"].as_str().unwrap();
    let mut modulus = URL_SAFE_NO_PAD.decode(encoded_modulus).unwrap();
    modulus.insert(0, 0);
    jwk["n"] = Value::String(URL_SAFE_NO_PAD.encode(modulus));
    let jwks = serde_json::to_vec(&json!({ "keys": [jwk] })).unwrap();

    let result = JwtTenantAuthenticator::try_from_jwks(config(now(), 2), &jwks);

    assert!(result.is_err());
}

#[test]
fn rejects_issuer_without_an_https_authority() {
    let result = JwtTenantAuthenticatorConfig::try_new(
        "https://".to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        now() + 3_600,
        2,
        1,
    );

    assert!(result.is_err());
}

#[test]
fn validated_config_preserves_jwks_snapshot_expiration() {
    const JWKS_VALID_UNTIL: u64 = 4_102_444_800;

    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        JWKS_VALID_UNTIL,
        2,
        1,
    )
    .unwrap();

    assert_eq!(config.jwks_valid_until(), JWKS_VALID_UNTIL);
}

#[test]
fn rejects_unsafe_configuration_and_jwk_sets_with_fixed_errors() {
    let now = now();
    let invalid_configs = [
        JwtTenantAuthenticatorConfig::try_new(
            String::new(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            2,
            1,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            "http://identity.bioworld.test".to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            2,
            1,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            "https://identity.bioworld.test:not-a-port".to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            2,
            1,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            String::new(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            2,
            1,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            "decision:read decision:write".to_owned(),
            now + 3_600,
            2,
            1,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            0,
            2,
            1,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            0,
            1,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            65,
            1,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            2,
            0,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            2,
            2,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            2,
            3,
        ),
    ];
    for result in invalid_configs {
        let error = match result {
            Ok(_) => panic!("unsafe authenticator config must fail"),
            Err(error) => error,
        };
        assert_eq!(format!("{error:?}"), "InvalidJwtTenantAuthenticatorConfig");
        assert_eq!(
            error.to_string(),
            "JWT tenant authenticator configuration is invalid"
        );
    }

    const FIXED_NOW: u64 = 1_000_000;
    let key = TestKey::generate(KEY_ID);
    for valid_until in [FIXED_NOW, FIXED_NOW + 86_401] {
        let config = JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            valid_until,
            2,
            1,
        )
        .unwrap();
        assert!(
            JwtTenantAuthenticator::try_from_jwks_with_clock(
                config,
                &jwks(&[&key]),
                FixedClock::new(FIXED_NOW),
            )
            .is_err()
        );
    }

    let mut invalid_jwks = vec![
        Vec::new(),
        vec![b' '; 65_537],
        b"not-json".to_vec(),
        serde_json::to_vec(&json!({ "keys": [] })).unwrap(),
        serde_json::to_vec(&json!({ "keys": vec![key.jwk.clone(); 33] })).unwrap(),
        serde_json::to_vec(&json!({ "keys": [key.jwk.clone(), key.jwk.clone()] })).unwrap(),
    ];
    for (field, value) in [
        ("kty", json!("oct")),
        ("alg", json!("RS384")),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("kid", json!("")),
        ("kid", json!("a".repeat(129))),
        ("n", json!("***")),
        ("n", json!(URL_SAFE_NO_PAD.encode([0x80; 128]))),
        ("n", json!(URL_SAFE_NO_PAD.encode([0x80; 513]))),
        ("e", json!("Aw")),
    ] {
        let mut jwk = key.jwk.clone();
        jwk[field] = value;
        invalid_jwks.push(serde_json::to_vec(&json!({ "keys": [jwk] })).unwrap());
    }
    let mut private_jwk = key.jwk.clone();
    private_jwk["d"] = json!("private-material");
    invalid_jwks.push(serde_json::to_vec(&json!({ "keys": [private_jwk] })).unwrap());
    let mut incompatible_jwk = key.jwk.clone();
    incompatible_jwk["kid"] = json!("incompatible-key");
    incompatible_jwk["alg"] = json!("RS384");
    invalid_jwks
        .push(serde_json::to_vec(&json!({ "keys": [key.jwk.clone(), incompatible_jwk] })).unwrap());
    let mut missing_kid = key.jwk.clone();
    missing_kid.as_object_mut().unwrap().remove("kid");
    invalid_jwks.push(serde_json::to_vec(&json!({ "keys": [missing_kid] })).unwrap());

    for invalid in invalid_jwks {
        assert!(JwtTenantAuthenticator::try_from_jwks(config(now, 2), &invalid).is_err());
    }

    let mut operations_only = key.jwk.clone();
    operations_only.as_object_mut().unwrap().remove("use");
    operations_only["key_ops"] = json!(["verify"]);
    assert!(
        JwtTenantAuthenticator::try_from_jwks(
            config(now, 2),
            &serde_json::to_vec(&json!({ "keys": [operations_only] })).unwrap(),
        )
        .is_ok()
    );
}

#[tokio::test]
async fn missing_trusted_peer_fails_closed_before_verification_work() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let clock = FixedClock::new(FIXED_NOW);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock.clone())
            .unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);
    let calls_before_request = clock.calls();
    let mut request = Request::new(GetDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    });
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
        .metadata_mut()
        .insert("x-forwarded-for", "127.0.0.1".parse().unwrap());

    let status = GeneratedDecisionService::get_decision(&service, request)
        .await
        .expect_err("untrusted forwarding metadata must not establish a peer");

    assert_unavailable(&status, &[&token, TENANT_ID, KEY_ID]);
    assert_eq!(clock.calls(), calls_before_request);
    assert!(tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejects_noncanonical_duplicate_scope_values() {
    let now = now();
    let key = TestKey::generate(KEY_ID);
    let mut claims = TestKey::claims(now, TENANT_ID);
    claims["scope"] = Value::String(format!("{REQUIRED_SCOPE} {REQUIRED_SCOPE}"));
    let token = key.sign(access_token_header(KEY_ID), claims);
    let (service, tenants) = service(&key, now, 2);

    let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
        .await
        .expect_err("duplicate scope values must fail authentication");

    assert_unauthenticated(&status, &[&token, TENANT_ID, KEY_ID]);
    assert!(tenants.lock().unwrap().is_empty());
}

#[test]
fn token_expiry_bounds_authorized_execution_before_the_jwks_snapshot() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let mut claims = TestKey::claims(FIXED_NOW, TENANT_ID);
    claims["exp"] = json!(FIXED_NOW + 30);
    let token = key.sign(access_token_header(KEY_ID), claims);
    let clock = FixedClock::new(FIXED_NOW);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 60,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock.clone())
            .unwrap();
    let executor_calls = Arc::new(AtomicU64::new(0));
    let service = DecisionGrpcService::new(
        authenticator,
        ObservedPendingExecutor {
            calls: Arc::clone(&executor_calls),
        },
        DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(120)).unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();

    runtime.block_on(async {
        let mut request = Box::pin(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ));
        assert!(
            poll_fn(|context| Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending)))
                .await
        );
        while clock.calls() < 3 {
            tokio::task::yield_now().await;
        }
        while executor_calls.load(Ordering::SeqCst) == 0 {
            assert!(
                poll_fn(|context| {
                    Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending))
                })
                .await
            );
            tokio::task::yield_now().await;
        }

        tokio::time::advance(Duration::from_secs(28)).await;
        assert!(
            poll_fn(|context| Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending)))
                .await
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let result = poll_fn(|context| {
            Poll::Ready(match request.as_mut().poll(context) {
                Poll::Ready(result) => Some(result),
                Poll::Pending => None,
            })
        })
        .await;
        let status = result
            .expect("token authority must conservatively expire by this instant")
            .expect_err("token authority must expire before the JWKS snapshot");
        assert_unauthenticated(&status, &[&token, TENANT_ID, KEY_ID]);
    });
}

#[test]
fn jwks_expiry_bounds_authorized_execution_before_the_token() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let clock = FixedClock::new(FIXED_NOW);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 30,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock.clone())
            .unwrap();
    let executor_calls = Arc::new(AtomicU64::new(0));
    let service = DecisionGrpcService::new(
        authenticator,
        ObservedPendingExecutor {
            calls: Arc::clone(&executor_calls),
        },
        DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(120)).unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();

    runtime.block_on(async {
        let mut request = Box::pin(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ));
        assert!(
            poll_fn(|context| Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending)))
                .await
        );
        while clock.calls() < 3 {
            tokio::task::yield_now().await;
        }
        while executor_calls.load(Ordering::SeqCst) == 0 {
            assert!(
                poll_fn(|context| {
                    Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending))
                })
                .await
            );
            tokio::task::yield_now().await;
        }

        tokio::time::advance(Duration::from_secs(28)).await;
        assert!(
            poll_fn(|context| Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending)))
                .await
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let result = poll_fn(|context| {
            Poll::Ready(match request.as_mut().poll(context) {
                Poll::Ready(result) => Some(result),
                Poll::Pending => None,
            })
        })
        .await;
        let status = result
            .expect("JWKS authority must conservatively expire by this instant")
            .expect_err("JWKS authority must expire before the token");
        assert_unauthenticated(&status, &[&token, TENANT_ID, KEY_ID]);
    });
}

#[tokio::test]
async fn rejects_a_token_that_expires_during_verification() {
    const FIXED_NOW: u64 = 1_000_000;
    const TOKEN_EXPIRY: u64 = FIXED_NOW + 300;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let clock = SequenceClock::new([Some(FIXED_NOW), Some(FIXED_NOW), Some(TOKEN_EXPIRY)]);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock).unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);

    let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
        .await
        .expect_err("token expiring during verification must be rejected");

    assert_unauthenticated(&status, &[&token, TENANT_ID, KEY_ID]);
    assert!(tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reports_a_jwks_snapshot_expiring_during_verification_as_unavailable() {
    const FIXED_NOW: u64 = 1_000_000;
    const SNAPSHOT_EXPIRY: u64 = FIXED_NOW + 60;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let clock = SequenceClock::new([Some(FIXED_NOW), Some(FIXED_NOW), Some(SNAPSHOT_EXPIRY)]);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        SNAPSHOT_EXPIRY,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock).unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);

    let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
        .await
        .expect_err("JWKS snapshot expiring during verification must stop authentication");

    assert_unavailable(&status, &[&token, TENANT_ID, KEY_ID]);
    assert!(tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reports_completion_clock_failure_as_fixed_unavailable_error() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let clock = SequenceClock::new([Some(FIXED_NOW), Some(FIXED_NOW), None]);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock).unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);

    let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
        .await
        .expect_err("completion clock failure must stop authentication");

    assert_unavailable(&status, &[&token, TENANT_ID, KEY_ID]);
    assert!(tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejects_token_authority_too_close_for_conservative_conversion() {
    const FIXED_NOW: u64 = 1_000_000;
    const TOKEN_EXPIRY: u64 = FIXED_NOW + 300;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let clock = SequenceClock::new([Some(FIXED_NOW), Some(FIXED_NOW), Some(TOKEN_EXPIRY - 1)]);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock).unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);

    let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
        .await
        .expect_err("subsecond token authority cannot be represented safely");

    assert_unauthenticated(&status, &[&token, TENANT_ID, KEY_ID]);
    assert!(tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reports_jwks_authority_too_close_for_conservative_conversion_as_unavailable() {
    const FIXED_NOW: u64 = 1_000_000;
    const SNAPSHOT_EXPIRY: u64 = FIXED_NOW + 60;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let clock = SequenceClock::new([Some(FIXED_NOW), Some(FIXED_NOW), Some(SNAPSHOT_EXPIRY - 1)]);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        SNAPSHOT_EXPIRY,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock).unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);

    let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
        .await
        .expect_err("subsecond JWKS authority cannot be represented safely");

    assert_unavailable(&status, &[&token, TENANT_ID, KEY_ID]);
    assert!(tenants.lock().unwrap().is_empty());
}

#[test]
fn a_backward_completion_clock_cannot_extend_authority() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let clock = SequenceClock::new([Some(FIXED_NOW), Some(FIXED_NOW), Some(FIXED_NOW - 100)]);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock.clone())
            .unwrap();
    let executor_calls = Arc::new(AtomicU64::new(0));
    let service = DecisionGrpcService::new(
        authenticator,
        ObservedPendingExecutor {
            calls: Arc::clone(&executor_calls),
        },
        DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(300)).unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();

    runtime.block_on(async {
        let mut request = Box::pin(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ));
        assert!(
            poll_fn(|context| Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending)))
                .await
        );
        while clock.remaining() != 0 {
            tokio::task::yield_now().await;
        }
        while executor_calls.load(Ordering::SeqCst) == 0 {
            assert!(
                poll_fn(|context| {
                    Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending))
                })
                .await
            );
            tokio::task::yield_now().await;
        }

        tokio::time::advance(Duration::from_secs(298)).await;
        assert!(
            poll_fn(|context| Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending)))
                .await
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let result = poll_fn(|context| {
            Poll::Ready(match request.as_mut().poll(context) {
                Poll::Ready(result) => Some(result),
                Poll::Pending => None,
            })
        })
        .await;
        let status = result
            .expect("initial clock sample must cap authority despite clock regression")
            .expect_err("regressed clock must not extend token authority");
        assert_unauthenticated(&status, &[&token, TENANT_ID, KEY_ID]);
    });
}

#[test]
fn a_stalled_verification_clock_cannot_pause_authority_time() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let gate = BlockingPoolGate::new();
    let release = GateRelease(gate.clone());
    let clock = BlockingClock::new(FIXED_NOW, gate.clone());
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock.clone())
            .unwrap();
    let executor_calls = Arc::new(AtomicU64::new(0));
    let service = DecisionGrpcService::new(
        authenticator,
        ObservedPendingExecutor {
            calls: Arc::clone(&executor_calls),
        },
        DecisionGrpcServiceConfig::try_new(1, Duration::from_secs(300)).unwrap(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(1)
        .start_paused(true)
        .build()
        .unwrap();

    runtime.block_on(async {
        let mut request = Box::pin(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ));
        assert!(
            poll_fn(|context| Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending)))
                .await
        );
        wait_for_gate(&gate).await;

        tokio::time::advance(Duration::from_secs(100)).await;
        release.0.release();
        while clock.calls.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
        while executor_calls.load(Ordering::SeqCst) == 0 {
            assert!(
                poll_fn(|context| {
                    Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending))
                })
                .await
            );
            tokio::task::yield_now().await;
        }

        tokio::time::advance(Duration::from_secs(198)).await;
        assert!(
            poll_fn(|context| Poll::Ready(matches!(request.as_mut().poll(context), Poll::Pending)))
                .await
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let result = poll_fn(|context| {
            Poll::Ready(match request.as_mut().poll(context) {
                Poll::Ready(result) => Some(result),
                Poll::Pending => None,
            })
        })
        .await;
        let status = result
            .expect("clock stall must consume the original monotonic authority budget")
            .expect_err("stalled clock must not extend token authority");
        assert_unauthenticated(&status, &[&token, TENANT_ID, KEY_ID]);
    });
}

#[tokio::test]
async fn rejects_a_key_snapshot_at_its_exact_expiry() {
    const FIXED_NOW: u64 = 1_000_000;
    const SNAPSHOT_EXPIRY: u64 = FIXED_NOW + 60;

    let key = TestKey::generate(KEY_ID);
    let clock = FixedClock::new(FIXED_NOW);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        SNAPSHOT_EXPIRY,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock.clone())
            .unwrap();
    let tenants = Arc::new(Mutex::new(Vec::new()));
    let service = DecisionGrpcService::new(
        authenticator,
        RecordingExecutor {
            tenants: Arc::clone(&tenants),
        },
        DecisionGrpcServiceConfig::try_new(2, Duration::from_secs(2)).unwrap(),
    );
    let token = key.token(FIXED_NOW, TENANT_ID);
    clock.set(SNAPSHOT_EXPIRY);

    let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
        .await
        .expect_err("expired key snapshot must fail authentication");

    assert_unavailable(&status, &[&token, TENANT_ID, KEY_ID]);
    assert!(tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn reports_clock_failure_as_unavailable_without_execution() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let clock = FixedClock::new(FIXED_NOW);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock.clone())
            .unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);
    let token = key.token(FIXED_NOW, TENANT_ID);
    clock.fail();

    let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
        .await
        .expect_err("clock failure must stop authentication");

    assert_unavailable(&status, &[&token, TENANT_ID, KEY_ID]);
    assert!(tenants.lock().unwrap().is_empty());
}

#[test]
fn cancelling_queued_crypto_prevents_orphan_verification() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let clock = FixedClock::new(FIXED_NOW);
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock.clone())
            .unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let gate = BlockingPoolGate::new();
    let release = GateRelease(gate.clone());

    runtime.block_on(async {
        let worker_gate = gate.clone();
        let blocker = tokio::task::spawn_blocking(move || worker_gate.block());
        wait_for_gate(&gate).await;

        let mut first = Box::pin(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ));
        let first_pending =
            poll_fn(|context| Poll::Ready(matches!(first.as_mut().poll(context), Poll::Pending)))
                .await;
        assert!(first_pending);
        drop(first);

        release.0.release();
        blocker.await.unwrap();
    });
    drop(release);
    drop(runtime);

    let retry_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    retry_runtime
        .block_on(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ))
        .expect("capacity must recover after queued crypto cancellation");

    assert_eq!(clock.calls(), 3);
    assert_eq!(*tenants.lock().unwrap(), vec![TENANT_ID.to_owned()]);
}

#[test]
fn reports_verification_saturation_as_capacity_exhaustion() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator = JwtTenantAuthenticator::try_from_jwks_with_clock(
        config,
        &jwks(&[&key]),
        FixedClock::new(FIXED_NOW),
    )
    .unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let gate = BlockingPoolGate::new();
    let release = GateRelease(gate.clone());

    runtime.block_on(async {
        let worker_gate = gate.clone();
        let blocker = tokio::task::spawn_blocking(move || worker_gate.block());
        wait_for_gate(&gate).await;
        let mut first = Box::pin(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ));
        let first_pending =
            poll_fn(|context| Poll::Ready(matches!(first.as_mut().poll(context), Poll::Pending)))
                .await;
        assert!(first_pending);

        let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
            .await
            .expect_err("saturated verification must fail immediately");
        assert_eq!(status.code(), Code::ResourceExhausted);
        assert_eq!(status.message(), "authentication service is at capacity");
        assert!(status.details().is_empty());
        assert!(status.metadata().is_empty());

        drop(first);
        release.0.release();
        blocker.await.unwrap();
    });

    assert!(tenants.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_verification_limit_bounds_distinct_peers_and_recovers() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let gate = BlockingPoolGate::new();
    let release = GateRelease(gate.clone());
    let clock = BlockingClock::new(FIXED_NOW, gate);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock.clone())
            .unwrap();
    let tenants = Arc::new(Mutex::new(Vec::new()));
    let service = Arc::new(DecisionGrpcService::new(
        authenticator,
        RecordingExecutor {
            tenants: Arc::clone(&tenants),
        },
        DecisionGrpcServiceConfig::try_new(4, Duration::from_secs(2)).unwrap(),
    ));
    let peer_a: SocketAddr = "127.0.0.2:41000".parse().unwrap();
    let peer_b: SocketAddr = "127.0.0.3:41000".parse().unwrap();
    let peer_c: SocketAddr = "127.0.0.4:41000".parse().unwrap();

    let first_service = Arc::clone(&service);
    let first_token = token.clone();
    let first = tokio::spawn(async move {
        GeneratedDecisionService::get_decision(
            first_service.as_ref(),
            request_with_token_from(&first_token, peer_a),
        )
        .await
    });
    let second_service = Arc::clone(&service);
    let second_token = token.clone();
    let second = tokio::spawn(async move {
        GeneratedDecisionService::get_decision(
            second_service.as_ref(),
            request_with_token_from(&second_token, peer_b),
        )
        .await
    });
    wait_for_clock_calls(clock.calls.as_ref(), 3).await;

    let calls_before_rejection = clock.calls.load(Ordering::SeqCst);
    let status = GeneratedDecisionService::get_decision(
        service.as_ref(),
        request_with_token_from(&token, peer_c),
    )
    .await
    .expect_err("global verification saturation must reject a distinct peer");
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(status.message(), "authentication service is at capacity");
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
    assert_eq!(clock.calls.load(Ordering::SeqCst), calls_before_rejection);

    release.0.release();
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
    GeneratedDecisionService::get_decision(
        service.as_ref(),
        request_with_token_from(&token, peer_c),
    )
    .await
    .expect("global verification capacity must recover");
    assert_eq!(tenants.lock().unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturated_verification_peer_does_not_block_another_peer() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let gate = BlockingPoolGate::new();
    let release = GateRelease(gate.clone());
    let clock = FirstVerificationBlockingClock::new(FIXED_NOW, gate.clone());
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock.clone())
            .unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);
    let service = Arc::new(service);
    let peer_a: SocketAddr = "127.0.0.2:41000".parse().unwrap();
    let peer_b: SocketAddr = "127.0.0.3:41000".parse().unwrap();
    let first_service = Arc::clone(&service);
    let first_token = token.clone();
    let first = tokio::spawn(async move {
        GeneratedDecisionService::get_decision(
            first_service.as_ref(),
            request_with_token_from(&first_token, peer_a),
        )
        .await
    });
    wait_for_gate(&gate).await;

    let calls_before_rejection = clock.calls();
    let mut same_peer_request = request_with_token_from(&token, peer_a);
    same_peer_request
        .metadata_mut()
        .insert("x-forwarded-for", "127.0.0.3".parse().unwrap());
    let status = GeneratedDecisionService::get_decision(service.as_ref(), same_peer_request)
        .await
        .expect_err("a saturated peer must fail before crypto work");
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(status.message(), "authentication service is at capacity");
    assert!(status.details().is_empty());
    assert!(status.metadata().is_empty());
    assert_eq!(clock.calls(), calls_before_rejection);
    assert!(tenants.lock().unwrap().is_empty());

    GeneratedDecisionService::get_decision(
        service.as_ref(),
        request_with_token_from(&token, peer_b),
    )
    .await
    .expect("another peer must retain verification capacity");
    assert_eq!(tenants.lock().unwrap().len(), 1);

    release.0.release();
    first.await.unwrap().unwrap();
    GeneratedDecisionService::get_decision(
        service.as_ref(),
        request_with_token_from(&token, peer_a),
    )
    .await
    .expect("peer capacity must recover after blocking verification completes");
    assert_eq!(tenants.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn blocking_worker_panic_restores_peer_and_global_capacity() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator = JwtTenantAuthenticator::try_from_jwks_with_clock(
        config,
        &jwks(&[&key]),
        PanicOnceClock::new(FIXED_NOW),
    )
    .unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);

    let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
        .await
        .expect_err("blocking worker panic must fail closed");
    assert_unavailable(&status, &[&token, TENANT_ID, KEY_ID]);
    assert!(tenants.lock().unwrap().is_empty());

    GeneratedDecisionService::get_decision(&service, request_with_token(&token))
        .await
        .expect("same peer must recover after the panicking worker exits");
    assert_eq!(*tenants.lock().unwrap(), vec![TENANT_ID.to_owned()]);
}

#[test]
fn cancelling_running_crypto_retains_capacity_until_work_ends() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let gate = BlockingPoolGate::new();
    let clock = BlockingClock::new(FIXED_NOW, gate.clone());
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock).unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);
    let token = key.token(FIXED_NOW, TENANT_ID);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let release = GateRelease(gate.clone());

    runtime.block_on(async {
        let mut active = Box::pin(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ));
        let active_pending =
            poll_fn(|context| Poll::Ready(matches!(active.as_mut().poll(context), Poll::Pending)))
                .await;
        assert!(active_pending);
        wait_for_gate(&gate).await;
        drop(active);

        let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
            .await
            .expect_err("running cancelled crypto must retain its permit");
        assert_eq!(status.code(), Code::ResourceExhausted);
        assert_eq!(status.message(), "authentication service is at capacity");

        release.0.release();
    });
    drop(release);
    drop(runtime);

    let retry_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    retry_runtime
        .block_on(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ))
        .expect("capacity must recover after running crypto ends");
    assert_eq!(*tenants.lock().unwrap(), vec![TENANT_ID.to_owned()]);
}

#[test]
fn service_timeout_keeps_running_crypto_bounded_until_completion() {
    const FIXED_NOW: u64 = 1_000_000;

    let key = TestKey::generate(KEY_ID);
    let gate = BlockingPoolGate::new();
    let clock = BlockingClock::new(FIXED_NOW, gate.clone());
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&key]), clock).unwrap();
    let (service, tenants) = service_with_timeout(authenticator, Duration::from_secs(1));
    let token = key.token(FIXED_NOW, TENANT_ID);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let release = GateRelease(gate.clone());

    runtime.block_on(async {
        let mut active = Box::pin(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ));
        let active_pending =
            poll_fn(|context| Poll::Ready(matches!(active.as_mut().poll(context), Poll::Pending)))
                .await;
        assert!(active_pending);
        wait_for_gate(&gate).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let status = active
            .await
            .expect_err("service timeout must cancel the authentication future");
        assert_eq!(status.code(), Code::DeadlineExceeded);
        assert_eq!(status.message(), "decision request deadline exceeded");

        let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
            .await
            .expect_err("timed-out running crypto must retain its permit");
        assert_eq!(status.code(), Code::ResourceExhausted);
        assert_eq!(status.message(), "authentication service is at capacity");

        release.0.release();
    });
    drop(release);
    drop(runtime);

    let retry_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    retry_runtime
        .block_on(GeneratedDecisionService::get_decision(
            &service,
            request_with_token(&token),
        ))
        .expect("capacity must recover after timed-out crypto ends");
    assert_eq!(*tenants.lock().unwrap(), vec![TENANT_ID.to_owned()]);
}

#[tokio::test]
async fn rejects_missing_or_ambiguous_bearer_metadata() {
    let now = now();
    let key = TestKey::generate(KEY_ID);
    let (service, tenants) = service(&key, now, 2);
    let valid_token = key.token(now, TENANT_ID);
    let oversized_token = format!("{}.a.a", "a".repeat(8_190));
    let mut requests = vec![
        Request::new(GetDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        }),
        request_with_authorization(""),
        request_with_authorization("Basic credential"),
        request_with_authorization("Bearer"),
        request_with_authorization("Bearer  a.a.a"),
        request_with_authorization("Bearer a.a.a "),
        request_with_authorization("Bearer a.a.a,a.a.a"),
        request_with_authorization(&format!("Bearer {oversized_token}")),
    ];
    let mut duplicate = request_with_token(&valid_token);
    duplicate.metadata_mut().append(
        "authorization",
        format!("Bearer {valid_token}").parse().unwrap(),
    );
    requests.push(duplicate);
    let mut binary = request_with_token(&valid_token);
    binary.metadata_mut().insert_bin(
        "authorization-bin",
        MetadataValue::from_bytes(b"binary-credential"),
    );
    requests.push(binary);

    for request in requests {
        let status = GeneratedDecisionService::get_decision(&service, request)
            .await
            .expect_err("ambiguous bearer metadata must fail");
        assert_unauthenticated(&status, &[&valid_token, TENANT_ID, KEY_ID]);
    }
    assert!(tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejects_forgery_algorithm_confusion_and_unsupported_jose_headers() {
    let now = now();
    let key = TestKey::generate(KEY_ID);
    let wrong_key = TestKey::generate(KEY_ID);
    let claims = TestKey::claims(now, TENANT_ID);
    let (service, tenants) = service(&key, now, 2);
    let mut tokens = vec![
        key.sign_values(
            json!({ "alg": "none", "kid": KEY_ID, "typ": "at+jwt" }),
            claims.clone(),
        ),
        key.sign_values(
            json!({ "alg": "HS256", "kid": KEY_ID, "typ": "at+jwt" }),
            claims.clone(),
        ),
        key.sign_values(
            json!({ "alg": "RS384", "kid": KEY_ID, "typ": "at+jwt" }),
            claims.clone(),
        ),
        key.sign_values(
            json!({ "alg": "PS256", "kid": KEY_ID, "typ": "at+jwt" }),
            claims.clone(),
        ),
        key.sign_values(
            json!({ "alg": "RS256", "kid": KEY_ID, "typ": "JWT" }),
            claims.clone(),
        ),
        key.sign_values(json!({ "alg": "RS256", "kid": KEY_ID }), claims.clone()),
        key.sign_values(json!({ "alg": "RS256", "typ": "at+jwt" }), claims.clone()),
        key.sign_values(
            json!({ "alg": "RS256", "kid": "unknown-key", "typ": "at+jwt" }),
            claims.clone(),
        ),
        key.sign_values(
            json!({
                "alg": "RS256",
                "jku": "https://attacker.test/jwks.json",
                "kid": KEY_ID,
                "typ": "at+jwt"
            }),
            claims.clone(),
        ),
        key.sign_values(
            json!({
                "alg": "RS256",
                "crit": ["custom"],
                "custom": "value",
                "kid": KEY_ID,
                "typ": "at+jwt"
            }),
            claims.clone(),
        ),
        key.sign_values(
            json!({
                "alg": "RS256",
                "cty": "JWT",
                "kid": KEY_ID,
                "typ": "at+jwt"
            }),
            claims.clone(),
        ),
        key.sign_values(
            json!({
                "alg": "RS256",
                "kid": KEY_ID,
                "typ": "at+jwt",
                "x5u": "https://attacker.test/key.pem"
            }),
            claims.clone(),
        ),
        key.sign_values(
            json!({
                "alg": "RS256",
                "kid": KEY_ID,
                "typ": "at+jwt",
                "unexpected": "value"
            }),
            claims.clone(),
        ),
        wrong_key.sign(access_token_header(KEY_ID), claims.clone()),
    ];
    let valid = key.token(now, TENANT_ID);
    let mut invalid_signature = valid.clone();
    let replacement = if invalid_signature.ends_with('A') {
        'B'
    } else {
        'A'
    };
    invalid_signature.pop();
    invalid_signature.push(replacement);
    tokens.push(invalid_signature);
    let mut parts = valid.split('.').map(str::to_owned).collect::<Vec<_>>();
    let mut forged_claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[1]).unwrap()).unwrap();
    forged_claims[BIOWORLD_TENANT_CLAIM] = Value::String("tenant-forged".to_owned());
    parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged_claims).unwrap());
    tokens.push(parts.join("."));
    tokens.push(key.sign_raw(
        format!(r#"{{"alg":"RS256","typ":"at+jwt","kid":"{KEY_ID}","kid":"{KEY_ID}"}}"#).as_bytes(),
        &serde_json::to_vec(&claims).unwrap(),
    ));

    for token in tokens {
        let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
            .await
            .expect_err("JOSE confusion or forgery must fail");
        assert_unauthenticated(&status, &[&token, TENANT_ID, KEY_ID]);
    }
    assert!(tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejects_invalid_required_claims_and_time_policy() {
    let now = now();
    let key = TestKey::generate(KEY_ID);
    let (service, tenants) = service(&key, now, 2);
    let base = TestKey::claims(now, TENANT_ID);
    let mut invalid_claims = Vec::new();

    for field in [
        "iss",
        "aud",
        "exp",
        "sub",
        "client_id",
        "iat",
        "jti",
        "scope",
        BIOWORLD_TENANT_CLAIM,
    ] {
        let mut claims = base.clone();
        claims.as_object_mut().unwrap().remove(field);
        invalid_claims.push(claims);
    }
    for (field, value) in [
        ("iss", json!("https://other-issuer.test")),
        ("aud", json!("https://other-audience.test")),
        ("aud", json!(42)),
        ("exp", json!(-1)),
        ("sub", json!("")),
        ("client_id", json!(" padded-client ")),
        ("jti", json!("\u{0000}")),
        ("scope", json!("decision:write")),
        ("scope", json!("decision:read  decision:write")),
        (BIOWORLD_TENANT_CLAIM, json!(42)),
    ] {
        let mut claims = base.clone();
        claims[field] = value;
        invalid_claims.push(claims);
    }
    for tenant in [
        "",
        " tenant-a",
        "tenant-a ",
        "tenant/a",
        "tenant\nvalue",
        &"a".repeat(129),
    ] {
        let mut claims = base.clone();
        claims[BIOWORLD_TENANT_CLAIM] = Value::String(tenant.to_owned());
        invalid_claims.push(claims);
    }
    for (expiration, issued_at, not_before) in [
        (now, now.saturating_sub(1), None),
        (now + 300, now + 300, None),
        (now + 901, now, None),
        (now + 300, now + 60, None),
        (now + 4, now, None),
        (now + 300, now, Some(now + 60)),
        (now + 300, now, Some(now + 300)),
    ] {
        let mut claims = base.clone();
        claims["exp"] = json!(expiration);
        claims["iat"] = json!(issued_at);
        if let Some(not_before) = not_before {
            claims["nbf"] = json!(not_before);
        }
        invalid_claims.push(claims);
    }
    let mut tokens = invalid_claims
        .into_iter()
        .map(|claims| key.sign(access_token_header(KEY_ID), claims))
        .collect::<Vec<_>>();
    let duplicate_issuer = format!(
        r#"{{"iss":"{ISSUER}","iss":"{ISSUER}","aud":"{AUDIENCE}","exp":{},"sub":"scientist-1","client_id":"desktop-client","iat":{now},"jti":"access-token-1","scope":"{REQUIRED_SCOPE}","{BIOWORLD_TENANT_CLAIM}":"{TENANT_ID}"}}"#,
        now + 300
    );
    tokens.push(key.sign_raw(
        &serde_json::to_vec(&access_token_header(KEY_ID)).unwrap(),
        duplicate_issuer.as_bytes(),
    ));
    let duplicate_tenant = format!(
        r#"{{"iss":"{ISSUER}","aud":"{AUDIENCE}","exp":{},"sub":"scientist-1","client_id":"desktop-client","iat":{now},"jti":"access-token-1","scope":"{REQUIRED_SCOPE}","{BIOWORLD_TENANT_CLAIM}":"{TENANT_ID}","{BIOWORLD_TENANT_CLAIM}":"tenant-forged"}}"#,
        now + 300
    );
    tokens.push(key.sign_raw(
        &serde_json::to_vec(&access_token_header(KEY_ID)).unwrap(),
        duplicate_tenant.as_bytes(),
    ));

    for token in tokens {
        let status = GeneratedDecisionService::get_decision(&service, request_with_token(&token))
            .await
            .expect_err("invalid access-token claims must fail");
        assert_unauthenticated(&status, &[&token, TENANT_ID, KEY_ID]);
    }
    assert!(tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn accepts_profile_boundaries_and_overlapping_rotation_keys() {
    const FIXED_NOW: u64 = 1_000_000;

    let old_key = TestKey::generate("old-key");
    let new_key = TestKey::generate("new-key");
    let clock = FixedClock::new(FIXED_NOW);
    let config = JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        FIXED_NOW + 3_600,
        2,
        1,
    )
    .unwrap();
    let authenticator = JwtTenantAuthenticator::try_from_jwks_with_clock(
        config.clone(),
        &jwks(&[&old_key, &new_key]),
        clock.clone(),
    )
    .unwrap();
    let (service, tenants) = service_with_authenticator(authenticator);
    let mut old_claims = TestKey::claims(FIXED_NOW, "tenant-old");
    old_claims["aud"] = json!(["https://secondary-audience.test", AUDIENCE]);
    old_claims["scope"] = json!(format!("profile {REQUIRED_SCOPE}"));
    old_claims["iat"] = json!(FIXED_NOW + 30);
    old_claims["nbf"] = json!(FIXED_NOW + 30);
    old_claims["exp"] = json!(FIXED_NOW + 930);
    let mut old_header = access_token_header("old-key");
    old_header.typ = Some("Application/AT+JWT".to_owned());
    let old_token = old_key.sign(old_header, old_claims);
    let mut new_claims = TestKey::claims(FIXED_NOW, "tenant-new");
    new_claims["nbf"] = json!(FIXED_NOW);
    new_claims["exp"] = json!(FIXED_NOW + 5);
    let mut new_header = access_token_header("new-key");
    new_header.typ = Some("AT+JWT".to_owned());
    let new_token = new_key.sign(new_header, new_claims);

    GeneratedDecisionService::get_decision(
        &service,
        request_with_authorization(&format!("bEaReR {old_token}")),
    )
    .await
    .unwrap();
    GeneratedDecisionService::get_decision(&service, request_with_token(&new_token))
        .await
        .unwrap();

    assert_eq!(
        *tenants.lock().unwrap(),
        vec!["tenant-old".to_owned(), "tenant-new".to_owned()]
    );

    let new_only =
        JwtTenantAuthenticator::try_from_jwks_with_clock(config, &jwks(&[&new_key]), clock)
            .unwrap();
    let (new_only_service, new_only_tenants) = service_with_authenticator(new_only);
    let status =
        GeneratedDecisionService::get_decision(&new_only_service, request_with_token(&old_token))
            .await
            .expect_err("removed rotation key must no longer authenticate");
    assert_unauthenticated(&status, &[&old_token, "tenant-old", "old-key"]);
    assert!(new_only_tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn valid_access_token_executes_with_the_signed_tenant_only() {
    let now = now();
    let key = TestKey::generate(KEY_ID);
    let (service, tenants) = service(&key, now, 2);
    let token = key.token(now, TENANT_ID);
    let mut request = request_with_token(&token);
    request
        .metadata_mut()
        .insert("x-tenant-id", "hostile-tenant".parse().unwrap());

    let response = GeneratedDecisionService::get_decision(&service, request)
        .await
        .unwrap();

    let response = response.into_inner();
    assert_eq!(
        response.prediction_interval,
        Some(prediction_interval("0.25", "1.5"))
    );
    assert_eq!(response.prediction_positions, prediction_positions());
    assert_eq!(response, record());
    assert_eq!(*tenants.lock().unwrap(), vec![TENANT_ID.to_owned()]);
}
