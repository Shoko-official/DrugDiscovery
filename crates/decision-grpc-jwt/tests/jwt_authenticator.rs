use std::{
    future::{Future, poll_fn},
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
    DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest, OodDetectorRef, OodStatus,
    Recommendation, decision_service_server::DecisionService as GeneratedDecisionService,
};
use bioworld_decision_grpc::{
    DecisionGrpcService, DecisionGrpcServiceConfig, TenantScope, TenantScopedGetDecisionExecutor,
    TenantScopedGetDecisionFuture,
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
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn config(now: u64, max_concurrent_verifications: usize) -> JwtTenantAuthenticatorConfig {
    JwtTenantAuthenticatorConfig::try_new(
        ISSUER.to_owned(),
        AUDIENCE.to_owned(),
        REQUIRED_SCOPE.to_owned(),
        now + 3_600,
        max_concurrent_verifications,
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
    let mut request = Request::new(GetDecisionRequest {
        decision_id: DECISION_ID.to_owned(),
    });
    request
        .metadata_mut()
        .insert("authorization", value.parse().unwrap());
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
    );

    assert!(result.is_err());
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
        ),
        JwtTenantAuthenticatorConfig::try_new(
            "http://identity.bioworld.test".to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            2,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            "https://identity.bioworld.test:not-a-port".to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            2,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            String::new(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            2,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            "decision:read decision:write".to_owned(),
            now + 3_600,
            2,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            0,
            2,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            0,
        ),
        JwtTenantAuthenticatorConfig::try_new(
            ISSUER.to_owned(),
            AUDIENCE.to_owned(),
            REQUIRED_SCOPE.to_owned(),
            now + 3_600,
            65,
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

    assert_eq!(clock.calls(), 2);
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

    assert_eq!(response.into_inner(), record());
    assert_eq!(*tenants.lock().unwrap(), vec![TENANT_ID.to_owned()]);
}
