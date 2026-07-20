#![deny(unsafe_code)]

mod decision_ipc;

use decision_ipc::read_current_decision;

#[tauri::command]
async fn app_health() -> Result<&'static str, String> {
    Ok("healthy")
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![app_health, read_current_decision])
        .run(tauri::generate_context!())
        .expect("BioWorld desktop runtime failed");
}
