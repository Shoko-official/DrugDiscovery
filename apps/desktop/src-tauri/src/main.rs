#![deny(unsafe_code)]

#[tauri::command]
async fn app_health() -> Result<&'static str, String> {
    Ok("healthy")
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![app_health])
        .run(tauri::generate_context!())
        .expect("BioWorld desktop runtime failed");
}
