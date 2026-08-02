use std::{env, process::Command};

use bioworld_decision_server::install_redacted_panic_hook;

const CHILD_ENVIRONMENT: &str = "BIOWORLD_DECISION_SERVER_PANIC_HOOK_CHILD";
const PRIVATE_PANIC_SENTINEL: &str = "private-watch-panic-payload-8472";

#[test]
fn redacted_panic_child() {
    if env::var_os(CHILD_ENVIRONMENT).is_none() {
        return;
    }

    install_redacted_panic_hook();
    panic!("{PRIVATE_PANIC_SENTINEL}");
}

#[test]
fn process_panic_hook_never_emits_the_payload() {
    let output = Command::new(env::current_exe().expect("current test executable"))
        .args(["--exact", "redacted_panic_child", "--nocapture"])
        .env(CHILD_ENVIRONMENT, "1")
        .output()
        .expect("panic hook child process");

    assert!(!output.status.success());
    let mut emitted = output.stdout;
    emitted.extend_from_slice(&output.stderr);
    assert!(
        emitted
            .windows(b"decision_server panicked".len())
            .any(|window| window == b"decision_server panicked")
    );
    assert!(
        !emitted
            .windows(PRIVATE_PANIC_SENTINEL.len())
            .any(|window| { window == PRIVATE_PANIC_SENTINEL.as_bytes() })
    );
}
