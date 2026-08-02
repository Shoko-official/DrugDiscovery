use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    rand::SystemRandom,
    rsa::{KeyPair, KeySize, PublicKeyComponents},
    signature::{Ed25519KeyPair, KeyPair as _},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde_json::json;
use zeroize::Zeroizing;

const CONTROL_ENVIRONMENT: &str = "BIOWORLD_DECISION_SERVER_CONFIG";
const JWT_KEY_ID: &str = "process-lifecycle-jwt-key";
const EVENT_KEY_ID: &str = "process-lifecycle-event-key";
const TENANT_ID: &str = "process-lifecycle-tenant";
const POSTGRES_HOST: &str = "127.0.0.1";
const POSTGRES_PORT: u16 = 5432;
const POSTGRES_DATABASE: &str = "bioworld_migrations";
const WRITER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_WRITER_PASSWORD";
const READER_PASSWORD_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_READER_PASSWORD";
const POSTGRES_CA_ENVIRONMENT_VARIABLE: &str = "BIOWORLD_POSTGRES_TLS_CA_FILE";
const SHORT_PROCESS_TIMEOUT: Duration = Duration::from_secs(5);
const TRUST_LIFECYCLE_PROCESS_TIMEOUT: Duration = Duration::from_secs(35);

struct TemporaryDirectory(PathBuf);

struct ProcessIntegrationInputs {
    reader_password: Zeroizing<String>,
    postgres_ca_file: PathBuf,
}

#[derive(Clone, Copy)]
enum PostgresCa<'a> {
    ServerCertificate,
    Existing(&'a Path),
}

#[derive(Clone, Copy)]
struct ProcessControlOptions<'a> {
    jwks_valid_for_seconds: u64,
    event_verification_valid_for_seconds: u64,
    postgres_password: &'a [u8],
    postgres_ca: PostgresCa<'a>,
    postgres_port: u16,
}

struct WrittenProcessControl {
    path: PathBuf,
    event_verification_valid_until: u64,
}

impl TemporaryDirectory {
    fn create() -> Self {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must follow Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bioworld-decision-process-{}-{nonce}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("isolated process test directory must be created");
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

#[cfg(unix)]
fn set_directory_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("process test directory permissions must be restricted");
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
        .expect("process test file must be created");
    file.write_all(contents)
        .expect("process test file must be written");
}

#[cfg(not(unix))]
fn write_new_file(path: &Path, contents: &[u8], _unix_mode: u32) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("process test file must be created");
    file.write_all(contents)
        .expect("process test file must be written");
}

fn path_text(path: &Path) -> String {
    path.to_str()
        .expect("process test paths must be UTF-8")
        .to_owned()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must follow Unix epoch")
        .as_secs()
}

fn process_integration_inputs() -> Option<ProcessIntegrationInputs> {
    let writer_password = std::env::var(WRITER_PASSWORD_ENVIRONMENT_VARIABLE)
        .ok()
        .filter(|value| !value.is_empty())
        .map(Zeroizing::new);
    let reader_password = std::env::var(READER_PASSWORD_ENVIRONMENT_VARIABLE)
        .ok()
        .filter(|value| !value.is_empty())
        .map(Zeroizing::new);
    let postgres_ca_file = std::env::var_os(POSTGRES_CA_ENVIRONMENT_VARIABLE)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());

    match (writer_password, reader_password, postgres_ca_file) {
        (Some(_writer_password), Some(reader_password), Some(postgres_ca_file)) => {
            Some(ProcessIntegrationInputs {
                reader_password,
                postgres_ca_file,
            })
        }
        _ => None,
    }
}

fn write_process_control(
    files: &TemporaryDirectory,
    options: ProcessControlOptions<'_>,
) -> WrittenProcessControl {
    let CertifiedKey {
        cert,
        signing_key: server_key,
    } = generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("ephemeral server TLS identity must be generated");
    let certificate_pem = cert.pem();
    let private_key_pem = Zeroizing::new(server_key.serialize_pem());
    let certificate_file = files.write_public("server-cert.pem", certificate_pem.as_bytes());
    let private_key_file = files.write_private("server-key.pem", private_key_pem.as_bytes());

    let jwt_key =
        KeyPair::generate(KeySize::Rsa2048).expect("ephemeral RSA key generation must succeed");
    let jwt_components = PublicKeyComponents::<Vec<u8>>::from(jwt_key.public_key());
    let jwks = serde_json::to_vec(&json!({
        "keys": [{
            "alg": "RS256",
            "e": URL_SAFE_NO_PAD.encode(jwt_components.e),
            "kid": JWT_KEY_ID,
            "kty": "RSA",
            "n": URL_SAFE_NO_PAD.encode(jwt_components.n),
            "use": "sig"
        }]
    }))
    .expect("ephemeral JWKS serialization must succeed");
    let jwks_file = files.write_public("jwks.json", &jwks);

    let event_key_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .expect("ephemeral event key generation must succeed");
    let event_key = Ed25519KeyPair::from_pkcs8(event_key_document.as_ref())
        .expect("ephemeral event key parsing must succeed");
    let now = unix_timestamp();
    let jwks_valid_until = now
        .checked_add(options.jwks_valid_for_seconds)
        .expect("JWKS expiration must fit Unix seconds");
    let event_verification_valid_until = now
        .checked_add(options.event_verification_valid_for_seconds)
        .expect("event verification expiration must fit Unix seconds");
    let event_keys = serde_json::to_vec(&json!({
        "version": "1",
        "valid_until": event_verification_valid_until,
        "keys": [{
            "tenant_id": TENANT_ID,
            "key_id": EVENT_KEY_ID,
            "algorithm": "Ed25519",
            "public_key": URL_SAFE_NO_PAD.encode(event_key.public_key().as_ref()),
            "not_before": 1,
            "not_after": now + 3_600,
            "status": "trusted"
        }]
    }))
    .expect("event verification snapshot serialization must succeed");
    let event_keys_file = files.write_public("event-keys.json", &event_keys);
    let password_file = files.write_private("postgres-password", options.postgres_password);
    let ca_file = match options.postgres_ca {
        PostgresCa::ServerCertificate => {
            files.write_public("postgres-ca.pem", certificate_pem.as_bytes())
        }
        PostgresCa::Existing(path) => path.to_owned(),
    };
    let control = serde_json::to_vec(&json!({
        "listen": {
            "address": "127.0.0.1:0",
            "exposure": "loopback"
        },
        "server_tls": {
            "certificate_chain_file": path_text(&certificate_file),
            "private_key_file": path_text(&private_key_file)
        },
        "jwt": {
            "issuer": "https://identity.process-lifecycle.test",
            "audience": "bioworld-process-lifecycle",
            "required_scope": "decision:read",
            "jwks_file": path_text(&jwks_file),
            "jwks_valid_until": jwks_valid_until,
            "max_concurrent_verifications": 2,
            "max_concurrent_verifications_per_peer": 1
        },
        "event_verification": {
            "keys_file": path_text(&event_keys_file)
        },
        "postgres": {
            "host": POSTGRES_HOST,
            "port": options.postgres_port,
            "database": POSTGRES_DATABASE,
            "password_file": path_text(&password_file),
            "ca_file": path_text(&ca_file),
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
            "max_active_connections_per_peer": 1,
            "max_concurrent_streams_per_connection": 4,
            "tls_handshake_timeout_seconds": 2,
            "request_timeout_seconds": 5,
            "max_connection_age_seconds": 60,
            "connection_age_grace_seconds": 5,
            "shutdown_grace_seconds": 10
        }
    }))
    .expect("process control serialization must succeed");
    WrittenProcessControl {
        path: files.write_public("control.json", &control),
        event_verification_valid_until,
    }
}

fn output_with_timeout(command: &mut Command, timeout: Duration) -> Output {
    command
        .env_remove(WRITER_PASSWORD_ENVIRONMENT_VARIABLE)
        .env_remove(READER_PASSWORD_ENVIRONMENT_VARIABLE)
        .env_remove(POSTGRES_CA_ENVIRONMENT_VARIABLE);
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("decision server process must start");
    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("process timeout must fit the monotonic clock");
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                terminate_child(&mut child);
                panic!("decision server process timed out");
            }
            Err(_) => {
                terminate_child(&mut child);
                panic!("decision server process wait failed");
            }
        }
    };
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("decision server stdout must be piped")
        .read_to_end(&mut stdout)
        .expect("decision server stdout must be readable");
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("decision server stderr must be piped")
        .read_to_end(&mut stderr)
        .expect("decision server stderr must be readable");

    Output {
        status,
        stdout,
        stderr,
    }
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn missing_control_environment_fails_with_fixed_lifecycle_output() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bioworld-decision-server"));
    command.env_remove(CONTROL_ENVIRONMENT);
    let output = output_with_timeout(&mut command, SHORT_PROCESS_TIMEOUT);

    assert!(!output.status.success());
    assert_eq!(output.stdout, b"decision_server starting\n");
    assert_eq!(output.stderr, b"decision_server failed\n");
}

#[test]
fn rejected_control_location_is_not_reflected_in_lifecycle_output() {
    let sensitive_path = std::env::temp_dir().join("private-control-secret-8472.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_bioworld-decision-server"));
    command.env(CONTROL_ENVIRONMENT, &sensitive_path);
    let output = output_with_timeout(&mut command, SHORT_PROCESS_TIMEOUT);

    assert!(!output.status.success());
    assert_eq!(output.stdout, b"decision_server starting\n");
    assert_eq!(output.stderr, b"decision_server failed\n");
    assert!(!output.stdout.windows(7).any(|part| part == b"private"));
    assert!(!output.stderr.windows(7).any(|part| part == b"private"));
}

#[test]
fn relative_control_location_fails_without_reporting_readiness() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bioworld-decision-server"));
    command.env(CONTROL_ENVIRONMENT, "private-control-secret-8472.json");
    let output = output_with_timeout(&mut command, SHORT_PROCESS_TIMEOUT);

    assert!(!output.status.success());
    assert_eq!(output.stdout, b"decision_server starting\n");
    assert_eq!(output.stderr, b"decision_server failed\n");
}

#[test]
fn near_expiry_trust_fails_without_readiness_or_database_access() {
    let files = TemporaryDirectory::create();
    let database_probe =
        TcpListener::bind("127.0.0.1:0").expect("isolated database probe listener must bind");
    database_probe
        .set_nonblocking(true)
        .expect("database probe listener must become nonblocking");
    let database_probe_port = database_probe
        .local_addr()
        .expect("database probe address must be available")
        .port();
    let control = write_process_control(
        &files,
        ProcessControlOptions {
            jwks_valid_for_seconds: 1,
            event_verification_valid_for_seconds: 60,
            postgres_password: b"unused-process-password",
            postgres_ca: PostgresCa::ServerCertificate,
            postgres_port: database_probe_port,
        },
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_bioworld-decision-server"));
    command.env(CONTROL_ENVIRONMENT, control.path);
    let output = output_with_timeout(&mut command, SHORT_PROCESS_TIMEOUT);

    assert!(!output.status.success());
    assert_eq!(output.stdout, b"decision_server starting\n");
    assert_eq!(output.stderr, b"decision_server failed\n");
    let database_error = database_probe
        .accept()
        .expect_err("expired trust must prevent PostgreSQL connection attempts");
    assert_eq!(database_error.kind(), ErrorKind::WouldBlock);
}

#[test]
fn process_reports_bounded_readiness_then_fails_at_event_trust_expiry() {
    let Some(inputs) = process_integration_inputs() else {
        return;
    };
    let files = TemporaryDirectory::create();
    let control = write_process_control(
        &files,
        ProcessControlOptions {
            jwks_valid_for_seconds: 120,
            event_verification_valid_for_seconds: 15,
            postgres_password: inputs.reader_password.as_bytes(),
            postgres_ca: PostgresCa::Existing(&inputs.postgres_ca_file),
            postgres_port: POSTGRES_PORT,
        },
    );
    let readiness_valid_until = control.event_verification_valid_until - 1;
    let mut command = Command::new(env!("CARGO_BIN_EXE_bioworld-decision-server"));
    command.env(CONTROL_ENVIRONMENT, control.path);
    let output = output_with_timeout(&mut command, TRUST_LIFECYCLE_PROCESS_TIMEOUT);
    let expected_stdout =
        format!("decision_server starting\ndecision_server ready_until={readiness_valid_until}\n");

    assert!(!output.status.success());
    assert_eq!(output.stdout, expected_stdout.as_bytes());
    assert_eq!(output.stderr, b"decision_server failed\n");
}
