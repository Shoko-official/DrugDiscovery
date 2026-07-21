use std::{
    fs::{self, OpenOptions},
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    rand::SystemRandom,
    rsa::{KeyPair, KeySize, PublicKeyComponents},
    signature::{KeyPair as _, RSA_PKCS1_SHA256},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bioworld_contracts::v2::{
    DecisionEvent, DecisionRecord, EvidenceSnapshotRef, GetDecisionRequest, ProposeDecisionRequest,
    Recommendation, WatchDecisionRequest, decision_service_client::DecisionServiceClient,
};
use bioworld_decision_grpc_jwt::BIOWORLD_TENANT_CLAIM;
use bioworld_decision_server::{DecisionServerConfig, DecisionServerRuntime};
use bioworld_event_store_contracts::DecisionEventMetadata;
use bioworld_event_store_postgres::PostgresDecisionEventWriter;
use chrono::{DateTime, Utc};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject, pem::SectionKind},
};
use serde_json::json;
use tokio::{sync::oneshot, task::JoinHandle};
use tokio_postgres::{
    Client,
    config::{ChannelBinding, SslMode},
};
use tokio_postgres_rustls::MakeRustlsConnect;
use tonic::{
    Code, Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};
use zeroize::Zeroizing;

const POSTGRES_HOST: &str = "127.0.0.1";
const POSTGRES_PORT: u16 = 5432;
const POSTGRES_DATABASE: &str = "bioworld_migrations";
const POSTGRES_WRITER_USER: &str = "bioworld_writer";
const WRITER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_WRITER_PASSWORD";
const READER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_READER_PASSWORD";
const POSTGRES_CA_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_TLS_CA_FILE";
const INTEGRATION_REQUIRED_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_INTEGRATION_REQUIRED";
const JWT_ISSUER: &str = "https://identity.runtime-integration.test";
const JWT_AUDIENCE: &str = "bioworld-decision-runtime-integration";
const JWT_REQUIRED_SCOPE: &str = "decision:read";
const JWT_KEY_ID: &str = "runtime-integration-key";
const TENANT_A: &str = "tenant-runtime-integration-a";
const TENANT_B: &str = "tenant-runtime-integration-b";
const DECISION_ID: &str = "018f5a72-9c4b-7d31-8f6a-26f08f3fb701";
const EVENT_ID: &str = "01910d47-6f80-7a31-8c29-1d5c4f6bd701";
const TEST_TIMEOUT: Duration = Duration::from_secs(15);

struct IntegrationInputs {
    writer_password: Zeroizing<String>,
    reader_password: Zeroizing<String>,
    postgres_ca_file: PathBuf,
}

struct IntegrationJwtKey {
    key_pair: KeyPair,
    jwks: Vec<u8>,
}

impl IntegrationJwtKey {
    fn generate() -> Self {
        let key_pair =
            KeyPair::generate(KeySize::Rsa2048).expect("ephemeral RSA key generation must succeed");
        let components = PublicKeyComponents::<Vec<u8>>::from(key_pair.public_key());
        let jwks = serde_json::to_vec(&json!({
            "keys": [{
                "alg": "RS256",
                "e": URL_SAFE_NO_PAD.encode(components.e),
                "kid": JWT_KEY_ID,
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode(components.n),
                "use": "sig"
            }]
        }))
        .expect("ephemeral JWKS serialization must succeed");

        Self { key_pair, jwks }
    }

    fn token(&self, now: u64, tenant_id: &str) -> Zeroizing<String> {
        let encoded_header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "RS256",
                "kid": JWT_KEY_ID,
                "typ": "at+jwt"
            }))
            .expect("JWT header serialization must succeed"),
        );
        let encoded_claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "aud": JWT_AUDIENCE,
                "client_id": "runtime-integration-client",
                "exp": now + 300,
                "iat": now,
                "iss": JWT_ISSUER,
                "jti": format!("runtime-integration-{tenant_id}"),
                "scope": JWT_REQUIRED_SCOPE,
                "sub": "runtime-integration-subject",
                BIOWORLD_TENANT_CLAIM: tenant_id
            }))
            .expect("JWT claims serialization must succeed"),
        );
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let mut signature = vec![0; self.key_pair.public_modulus_len()];
        self.key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .expect("ephemeral JWT signing must succeed");

        Zeroizing::new(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn create() -> Self {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must follow Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bioworld-decision-runtime-{}-{nonce}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("isolated runtime integration directory must be created");
        set_directory_permissions(&path);
        Self(path)
    }

    fn write_public(&self, name: &str, contents: &[u8]) -> PathBuf {
        self.write(name, contents, 0o644)
    }

    fn write_private(&self, name: &str, contents: &[u8]) -> PathBuf {
        self.write(name, contents, 0o600)
    }

    fn write(&self, name: &str, contents: &[u8], unix_mode: u32) -> PathBuf {
        let path = self.0.join(name);
        write_new_file(&path, contents, unix_mode);
        path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct WriterConnection {
    client: Client,
    connection_task: JoinHandle<()>,
}

impl Drop for WriterConnection {
    fn drop(&mut self) {
        self.connection_task.abort();
    }
}

fn integration_inputs() -> Option<IntegrationInputs> {
    let writer_password = std::env::var(WRITER_PASSWORD_ENVIRONMENT_VARIABLE)
        .ok()
        .filter(|value| !value.is_empty());
    let reader_password = std::env::var(READER_PASSWORD_ENVIRONMENT_VARIABLE)
        .ok()
        .filter(|value| !value.is_empty());
    let postgres_ca_file = std::env::var_os(POSTGRES_CA_ENVIRONMENT_VARIABLE)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());

    match (writer_password, reader_password, postgres_ca_file) {
        (Some(writer_password), Some(reader_password), Some(postgres_ca_file)) => {
            Some(IntegrationInputs {
                writer_password: Zeroizing::new(writer_password),
                reader_password: Zeroizing::new(reader_password),
                postgres_ca_file,
            })
        }
        _ if std::env::var(INTEGRATION_REQUIRED_ENVIRONMENT_VARIABLE).as_deref() == Ok("1") => {
            panic!("required PostgreSQL TLS integration inputs are unavailable")
        }
        _ => None,
    }
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("temporary directory permissions must be restricted");
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) {}

#[cfg(unix)]
fn write_new_file(path: &Path, contents: &[u8], unix_mode: u32) {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(unix_mode)
        .open(path)
        .expect("runtime integration file must be created");
    file.write_all(contents)
        .expect("runtime integration file must be written");
}

#[cfg(not(unix))]
fn write_new_file(path: &Path, contents: &[u8], _unix_mode: u32) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("runtime integration file must be created");
    file.write_all(contents)
        .expect("runtime integration file must be written");
}

fn postgres_tls(ca_file: &Path) -> MakeRustlsConnect {
    let ca_pem = fs::read(ca_file).expect("PostgreSQL CA file must be readable");
    assert!(!ca_pem.is_empty() && ca_pem.len() <= 65_536);
    let mut roots = RootCertStore::empty();
    let mut certificate_count = 0_usize;
    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(&ca_pem) {
        let (SectionKind::Certificate, certificate) =
            item.expect("PostgreSQL CA PEM must be valid")
        else {
            panic!("PostgreSQL CA PEM must contain certificates only");
        };
        roots
            .add(CertificateDer::from(certificate))
            .expect("PostgreSQL trust anchor must be accepted");
        certificate_count += 1;
    }
    assert!((1..=32).contains(&certificate_count));

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let client = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("safe PostgreSQL TLS versions must be available")
        .with_root_certificates(roots)
        .with_no_client_auth();
    MakeRustlsConnect::new(client)
}

async fn connect_writer(password: &[u8], ca_file: &Path) -> WriterConnection {
    let mut configuration = tokio_postgres::Config::new();
    configuration
        .host(POSTGRES_HOST)
        .port(POSTGRES_PORT)
        .dbname(POSTGRES_DATABASE)
        .user(POSTGRES_WRITER_USER)
        .password(password)
        .application_name("bioworld-decision-runtime-integration")
        .ssl_mode(SslMode::Require)
        .channel_binding(ChannelBinding::Require)
        .connect_timeout(Duration::from_secs(5));
    let (client, connection) = configuration
        .connect(postgres_tls(ca_file))
        .await
        .unwrap_or_else(|_| {
            panic!("writer must connect through explicitly trusted PostgreSQL TLS")
        });
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let tls_active: bool = client
        .query_one(
            "SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid()",
            &[],
        )
        .await
        .expect("writer TLS state must be queryable")
        .get(0);
    assert!(tls_active);

    WriterConnection {
        client,
        connection_task,
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must follow Unix epoch")
        .as_secs()
}

fn occurred_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
        .expect("fixed integration timestamp must parse")
        .with_timezone(&Utc)
}

#[allow(deprecated)]
fn decision_record() -> DecisionRecord {
    DecisionRecord {
        decision_id: DECISION_ID.to_owned(),
        cou_id: "COU-RUNTIME-INTEGRATION".to_owned(),
        evidence_snapshot_id: "ES-RUNTIME-INTEGRATION".to_owned(),
        recommendation: Recommendation::Defer as i32,
        rationale: vec!["Synthetic integration fixture.".to_owned()],
        aggregate_version: 1,
        evidence: Some(EvidenceSnapshotRef {
            id: "ES-RUNTIME-INTEGRATION".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        }),
    }
}

async fn seed_decision(writer: &mut Client, expected: &DecisionRecord) {
    let event = DecisionEvent {
        decision: Some(expected.clone()),
        event_id: EVENT_ID.to_owned(),
    };
    let metadata = DecisionEventMetadata::try_new(
        TENANT_A.to_owned(),
        occurred_at(),
        json!({
            "algorithm": "synthetic",
            "key_id": "runtime-integration",
            "value": "non-production-fixture"
        }),
    )
    .expect("synthetic event metadata must be valid");
    PostgresDecisionEventWriter::new(writer)
        .append(event, metadata)
        .await
        .expect("synthetic decision fixture must be appended through the writer");
}

fn path_text(path: &Path) -> String {
    path.to_str()
        .expect("runtime integration paths must be UTF-8")
        .to_owned()
}

fn runtime_config(
    files: &TemporaryDirectory,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    signing_key: &IntegrationJwtKey,
    inputs: &IntegrationInputs,
    now: u64,
) -> DecisionServerConfig {
    let certificate_file = files.write_public("server-cert.pem", certificate_pem);
    let private_key_file = files.write_private("server-key.pem", private_key_pem);
    let jwks_file = files.write_public("jwks.json", &signing_key.jwks);
    let password_file = files.write_private("postgres-password", inputs.reader_password.as_bytes());
    let control = json!({
        "listen": {
            "address": "127.0.0.1:0",
            "exposure": "loopback"
        },
        "server_tls": {
            "certificate_chain_file": path_text(&certificate_file),
            "private_key_file": path_text(&private_key_file)
        },
        "jwt": {
            "issuer": JWT_ISSUER,
            "audience": JWT_AUDIENCE,
            "required_scope": JWT_REQUIRED_SCOPE,
            "jwks_file": path_text(&jwks_file),
            "jwks_valid_until": now + 600,
            "max_concurrent_verifications": 2
        },
        "postgres": {
            "host": POSTGRES_HOST,
            "port": POSTGRES_PORT,
            "database": POSTGRES_DATABASE,
            "password_file": path_text(&password_file),
            "ca_file": path_text(&inputs.postgres_ca_file),
            "pool_max_size": 2,
            "acquire_timeout_seconds": 2,
            "connect_timeout_seconds": 2
        },
        "service": {
            "max_in_flight": 2,
            "request_timeout_seconds": 5
        },
        "transport": {
            "max_active_connections": 2,
            "max_concurrent_streams_per_connection": 4,
            "tls_handshake_timeout_seconds": 2,
            "request_timeout_seconds": 5,
            "max_connection_age_seconds": 60,
            "connection_age_grace_seconds": 5,
            "shutdown_grace_seconds": 10
        }
    });
    DecisionServerConfig::try_from_json(
        &serde_json::to_vec(&control).expect("runtime control serialization must succeed"),
    )
    .expect("runtime integration control must be valid")
}

async fn guarded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(TEST_TIMEOUT, future)
        .await
        .expect("runtime integration operation timed out")
}

async fn trusted_channel(address: std::net::SocketAddr, certificate_pem: Vec<u8>) -> Channel {
    guarded(
        Endpoint::from_shared(format!("https://{address}"))
            .expect("runtime endpoint must be valid")
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(certificate_pem))
                    .domain_name("localhost"),
            )
            .expect("runtime client TLS must be valid")
            .connect(),
    )
    .await
    .expect("runtime client must establish trusted TLS")
}

fn authenticated_request<T>(message: T, token: &str, hostile_tenant: &str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}")
            .parse()
            .expect("authorization metadata must be valid"),
    );
    request.metadata_mut().insert(
        "x-tenant-id",
        hostile_tenant
            .parse()
            .expect("hostile tenant metadata must be valid"),
    );
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serves_tls_authenticated_tenant_isolated_reads_and_stops_cleanly() {
    let Some(inputs) = integration_inputs() else {
        return;
    };
    let mut writer =
        connect_writer(inputs.writer_password.as_bytes(), &inputs.postgres_ca_file).await;
    let expected = decision_record();
    seed_decision(&mut writer.client, &expected).await;

    let signing_key = IntegrationJwtKey::generate();
    let CertifiedKey {
        cert,
        signing_key: server_key,
    } = generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("ephemeral server TLS identity must be generated");
    let certificate_pem = cert.pem().into_bytes();
    let private_key_pem = Zeroizing::new(server_key.serialize_pem().into_bytes());
    let now = unix_timestamp();
    let files = TemporaryDirectory::create();
    let config = runtime_config(
        &files,
        &certificate_pem,
        &private_key_pem,
        &signing_key,
        &inputs,
        now,
    );
    let runtime = guarded(DecisionServerRuntime::prepare(config))
        .await
        .expect("runtime must prepare through PostgreSQL TLS preflight");
    let address = runtime.local_addr();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = tokio::spawn(runtime.serve(async move {
        let _ = shutdown_rx.await;
    }));
    let channel = trusted_channel(address, certificate_pem).await;
    let mut client = DecisionServiceClient::new(channel);
    let tenant_a_token = signing_key.token(now, TENANT_A);
    let tenant_b_token = signing_key.token(now, TENANT_B);

    let actual = guarded(client.get_decision(authenticated_request(
        GetDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        },
        tenant_a_token.as_str(),
        TENANT_B,
    )))
    .await
    .expect("signed tenant must load its decision")
    .into_inner();
    assert_eq!(actual, expected);

    let hidden = guarded(client.get_decision(authenticated_request(
        GetDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        },
        tenant_b_token.as_str(),
        TENANT_A,
    )))
    .await
    .expect_err("cross-tenant decision must remain hidden");
    assert_eq!(hidden.code(), Code::NotFound);
    assert_eq!(hidden.message(), "decision was not found");

    let propose = guarded(client.propose_decision(authenticated_request(
        ProposeDecisionRequest {
            idempotency_key: "runtime-integration-idempotency".to_owned(),
            cou_id: "COU-RUNTIME-INTEGRATION".to_owned(),
            evidence_snapshot_id: "ES-RUNTIME-INTEGRATION".to_owned(),
            recommendation: Recommendation::Defer as i32,
            rationale: vec!["Synthetic integration fixture.".to_owned()],
        },
        tenant_a_token.as_str(),
        TENANT_B,
    )))
    .await
    .expect_err("proposal endpoint must remain unavailable");
    assert_eq!(propose.code(), Code::Unimplemented);
    assert_eq!(propose.message(), "decision operation is not implemented");

    let watch = match guarded(client.watch_decision(authenticated_request(
        WatchDecisionRequest {
            decision_id: DECISION_ID.to_owned(),
        },
        tenant_a_token.as_str(),
        TENANT_B,
    )))
    .await
    {
        Ok(_) => panic!("watch endpoint must remain unavailable"),
        Err(status) => status,
    };
    assert_eq!(watch.code(), Code::Unimplemented);
    assert_eq!(watch.message(), "decision operation is not implemented");

    drop(client);
    shutdown_tx
        .send(())
        .expect("runtime shutdown receiver must remain available");
    guarded(server_task)
        .await
        .expect("runtime serving task must join")
        .expect("runtime must stop cleanly");
}
