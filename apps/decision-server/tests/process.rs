use std::process::Command;

const CONTROL_ENVIRONMENT: &str = "BIOWORLD_DECISION_SERVER_CONFIG";

#[test]
fn missing_control_environment_fails_with_fixed_lifecycle_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_bioworld-decision-server"))
        .env_remove(CONTROL_ENVIRONMENT)
        .output()
        .expect("decision server process");

    assert!(!output.status.success());
    assert_eq!(output.stdout, b"decision_server starting\n");
    assert_eq!(output.stderr, b"decision_server failed\n");
}

#[test]
fn rejected_control_location_is_not_reflected_in_lifecycle_output() {
    let sensitive_path = std::env::temp_dir().join("private-control-secret-8472.json");
    let output = Command::new(env!("CARGO_BIN_EXE_bioworld-decision-server"))
        .env(CONTROL_ENVIRONMENT, &sensitive_path)
        .output()
        .expect("decision server process");

    assert!(!output.status.success());
    assert_eq!(output.stdout, b"decision_server starting\n");
    assert_eq!(output.stderr, b"decision_server failed\n");
    assert!(!output.stdout.windows(7).any(|part| part == b"private"));
    assert!(!output.stderr.windows(7).any(|part| part == b"private"));
}

#[test]
fn relative_control_location_fails_without_reporting_readiness() {
    let output = Command::new(env!("CARGO_BIN_EXE_bioworld-decision-server"))
        .env(CONTROL_ENVIRONMENT, "private-control-secret-8472.json")
        .output()
        .expect("decision server process");

    assert!(!output.status.success());
    assert_eq!(output.stdout, b"decision_server starting\n");
    assert_eq!(output.stderr, b"decision_server failed\n");
}
