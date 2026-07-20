#![deny(unsafe_code)]

mod decision_ipc;
mod decision_runtime;

use decision_ipc::read_current_decision;
use decision_runtime::DecisionRuntime;

#[tauri::command]
async fn app_health() -> Result<&'static str, String> {
    Ok("healthy")
}

fn main() {
    tauri::Builder::default()
        .manage(DecisionRuntime::bundled())
        .invoke_handler(tauri::generate_handler![app_health, read_current_decision])
        .run(tauri::generate_context!())
        .expect("BioWorld desktop runtime failed");
}
