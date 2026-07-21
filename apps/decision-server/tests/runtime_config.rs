use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use bioworld_decision_server::{
    DecisionServerConfig, DecisionServerRuntime, DecisionServerStartupError,
    MAX_DECISION_SERVER_CONTROL_BYTES,
};
use serde_json::{Value, json};

fn sensitive_path(name: &str) -> String {
    std::env::temp_dir()
        .join("bioworld-decision-server-tests")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn valid_control_value() -> Value {
    json!({
        "listen": {
            "address": "127.0.0.1:8443",
            "exposure": "loopback"
        },
        "server_tls": {
            "certificate_chain_file": sensitive_path("server-cert.pem"),
            "private_key_file": sensitive_path("server-key.pem")
        },
        "jwt": {
            "issuer": "https://identity.example.test",
            "audience": "bioworld-decision-service",
            "required_scope": "decision.read",
            "jwks_file": sensitive_path("jwks.json"),
            "jwks_valid_until": 4_102_444_800_u64,
            "max_concurrent_verifications": 32
        },
        "postgres": {
            "host": "database.example.test",
            "port": 5432,
            "database": "bioworld",
            "password_file": sensitive_path("postgres-password"),
            "ca_file": sensitive_path("postgres-ca.pem"),
            "pool_max_size": 16,
            "acquire_timeout_seconds": 5,
            "connect_timeout_seconds": 5
        },
        "service": {
            "max_in_flight": 128,
            "request_timeout_seconds": 300
        },
        "transport": {
            "max_active_connections": 128,
            "max_concurrent_streams_per_connection": 32,
            "tls_handshake_timeout_seconds": 5,
            "request_timeout_seconds": 300,
            "max_connection_age_seconds": 3600,
            "connection_age_grace_seconds": 30,
            "shutdown_grace_seconds": 310
        }
    })
}

fn valid_control() -> Vec<u8> {
    serde_json::to_vec(&valid_control_value()).expect("valid test control")
}

struct TemporaryFile(PathBuf);

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new() -> Self {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bioworld-decision-server-inputs-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("temporary input directory");
        Self(path)
    }

    fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, contents).expect("temporary input write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("temporary input permissions");
        }
        path
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl TemporaryFile {
    fn write(contents: &[u8]) -> Self {
        static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "bioworld-sensitive-control-{}-{}.json",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, contents).expect("temporary control write");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write_relative(contents: &[u8]) -> Self {
        static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from(format!(
            "bioworld-relative-control-{}-{}.json",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, contents).expect("relative control write");
        Self(path)
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn accepts_explicit_bounded_configuration_with_redacted_debug() {
    let control = DecisionServerConfig::try_from_json(&valid_control()).expect("valid control");

    assert_eq!(format!("{control:?}"), "DecisionServerConfig");
}

#[test]
fn rejects_empty_malformed_unknown_and_duplicate_control_fields() {
    let mut unknown = valid_control_value();
    unknown["postgres"]["connection_string"] = json!("not accepted");

    let mut duplicate = valid_control();
    duplicate.pop();
    duplicate
        .extend_from_slice(br#","listen":{"address":"127.0.0.1:8443","exposure":"loopback"}}"#);

    for input in [
        Vec::new(),
        b"{".to_vec(),
        serde_json::to_vec(&unknown).expect("test control serialization"),
        duplicate,
    ] {
        assert!(DecisionServerConfig::try_from_json(&input).is_err());
    }
}

#[test]
fn rejects_duplicate_sensitive_file_locations() {
    let mut control = valid_control_value();
    control["postgres"]["ca_file"] = control["jwt"]["jwks_file"].clone();

    assert!(
        DecisionServerConfig::try_from_json(
            &serde_json::to_vec(&control).expect("test control serialization")
        )
        .is_err()
    );
}

#[test]
fn rejects_connection_syntax_in_the_database_host() {
    let mut control = valid_control_value();
    control["postgres"]["host"] = json!("database.example.test:5432");

    assert!(
        DecisionServerConfig::try_from_json(
            &serde_json::to_vec(&control).expect("test control serialization")
        )
        .is_err()
    );
}

#[test]
fn rejects_database_acquisition_beyond_the_request_budget() {
    let mut control = valid_control_value();
    control["postgres"]["acquire_timeout_seconds"] = json!(301);

    assert!(
        DecisionServerConfig::try_from_json(
            &serde_json::to_vec(&control).expect("test control serialization")
        )
        .is_err()
    );
}

#[tokio::test]
async fn rejects_oversized_control_file_without_reflecting_its_path() {
    let file = TemporaryFile::write(&vec![b' '; MAX_DECISION_SERVER_CONTROL_BYTES + 1]);

    let error = DecisionServerConfig::load(file.path())
        .await
        .expect_err("oversized control must fail");

    assert_eq!(format!("{error:?}"), "InvalidDecisionServerConfig");
    assert_eq!(
        error.to_string(),
        "decision server configuration is invalid"
    );
    assert!(
        !error
            .to_string()
            .contains(&file.path().to_string_lossy()[..])
    );
}

#[tokio::test]
async fn rejects_relative_control_file_locations() {
    let file = TemporaryFile::write_relative(&valid_control());

    let error = DecisionServerConfig::load(file.path())
        .await
        .expect_err("relative control path must fail");

    assert_eq!(error, bioworld_decision_server::InvalidDecisionServerConfig);
}

#[tokio::test]
async fn rejects_missing_server_identity_before_attempting_listener_bind() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("occupied listener");
    let mut control = valid_control_value();
    control["listen"]["address"] =
        json!(occupied.local_addr().expect("occupied address").to_string());
    let config = DecisionServerConfig::try_from_json(
        &serde_json::to_vec(&control).expect("test control serialization"),
    )
    .expect("valid control");

    let error = DecisionServerRuntime::prepare(config)
        .await
        .expect_err("missing identity must fail");

    assert_eq!(error, DecisionServerStartupError::SensitiveInputRejected);
    assert_eq!(
        error.to_string(),
        "decision server sensitive input is rejected"
    );
}

#[tokio::test]
async fn rejects_hard_linked_sensitive_inputs_before_identity_parsing() {
    let directory = TemporaryDirectory::new();
    let certificate = directory.write("server-cert.pem", b"not a certificate");
    let private_key = directory.0.join("server-key.pem");
    fs::hard_link(&certificate, &private_key).expect("sensitive hard link");
    let jwks = directory.write("jwks.json", b"{}");
    let password = directory.write("postgres-password", b"password");
    let ca = directory.write("postgres-ca.pem", b"not a CA");
    let mut control = valid_control_value();
    control["server_tls"]["certificate_chain_file"] = json!(certificate.to_string_lossy());
    control["server_tls"]["private_key_file"] = json!(private_key.to_string_lossy());
    control["jwt"]["jwks_file"] = json!(jwks.to_string_lossy());
    control["postgres"]["password_file"] = json!(password.to_string_lossy());
    control["postgres"]["ca_file"] = json!(ca.to_string_lossy());
    let config = DecisionServerConfig::try_from_json(
        &serde_json::to_vec(&control).expect("test control serialization"),
    )
    .expect("valid control");

    let error = DecisionServerRuntime::prepare(config)
        .await
        .expect_err("aliased sensitive files must fail");

    assert_eq!(error, DecisionServerStartupError::SensitiveInputRejected);
}
