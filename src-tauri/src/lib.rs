pub mod classifier;
pub mod collector;
pub mod db;
mod external;
pub mod models;
mod reports;

use std::sync::Mutex;
use tauri::{Listener, Manager, State};

use models::{ScanEntry, ScanResult, ScanSummary, ServiceInfo, Verdict};

struct AppState {
    db: Mutex<db::Db>,
}

fn db_path(app: &tauri::AppHandle) -> std::path::PathBuf {
    let dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    dir.join("deamonize.db")
}

/// Runs a full scan: enumerate services, classify locally, persist, return.
#[tauri::command]
fn scan_services(state: State<'_, AppState>) -> Result<ScanResult, String> {
    let started = chrono::Utc::now();
    let services = collector::collect_services()?;
    let rules = state.db.lock().unwrap().list_rules()?;
    let verdicts: Vec<Verdict> = services
        .iter()
        .map(|s| classifier::classify(s, &rules))
        .collect();
    let (safe, suspicious, dangerous, unknown) = classifier::summarize(&verdicts);
    let finished = chrono::Utc::now();

    let scan_id = {
        let db = state.db.lock().unwrap();
        db.save_scan(
            &started.to_rfc3339(),
            &finished.to_rfc3339(),
            &services,
            &verdicts,
        )?
    };

    let entries: Vec<ScanEntry> = services
        .into_iter()
        .zip(verdicts)
        .map(|(service, verdict)| ScanEntry { service, verdict })
        .collect();

    Ok(ScanResult {
        summary: ScanSummary {
            scan_id,
            started_at: started.to_rfc3339(),
            finished_at: finished.to_rfc3339(),
            total: entries.len() as i64,
            safe,
            suspicious,
            dangerous,
            unknown,
        },
        entries,
    })
}

/// Summary of the most recent scan (for restoring state after restart).
#[tauri::command]
fn get_last_summary(state: State<'_, AppState>) -> Result<Option<ScanSummary>, String> {
    state.db.lock().unwrap().latest_summary()
}

#[tauri::command]
fn list_rules(state: State<'_, AppState>) -> Result<Vec<models::Rule>, String> {
    state.db.lock().unwrap().list_rules()
}

#[tauri::command]
fn add_rule(
    state: State<'_, AppState>,
    kind: String,
    pattern: String,
    category: String,
    note: Option<String>,
) -> Result<i64, String> {
    state.db.lock().unwrap().add_rule(&kind, &pattern, &category, note.as_deref())
}

#[tauri::command]
fn toggle_rule(state: State<'_, AppState>, id: i64, enabled: bool) -> Result<(), String> {
    state.db.lock().unwrap().toggle_rule(id, enabled)
}

#[tauri::command]
fn delete_rule(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    state.db.lock().unwrap().delete_rule(id)
}

// ---- Fase 2: historial, diff y caché ----

#[tauri::command]
fn get_scan_history(state: State<'_, AppState>) -> Result<Vec<models::ScanSummary>, String> {
    state.db.lock().unwrap().scan_history(20)
}

#[tauri::command]
fn diff_scans(state: State<'_, AppState>, scan_a: i64, scan_b: i64) -> Result<db::ScanDiff, String> {
    state.db.lock().unwrap().diff_scans(scan_a, scan_b)
}

#[tauri::command]
fn get_cache_stats(state: State<'_, AppState>) -> Result<db::CacheStats, String> {
    state.db.lock().unwrap().cache_stats()
}

#[tauri::command]
fn clear_cache(state: State<'_, AppState>) -> Result<usize, String> {
    state.db.lock().unwrap().cache_clear()
}

// ---- Fase 3: consultas externas escalonadas ----

#[tauri::command]
async fn get_provider_statuses(state: State<'_, AppState>) -> Result<Vec<external::ProviderStatus>, String> {
    let cfg = {
        let db = state.db.lock().unwrap();
        external::ProviderConfig::load(&db)
    };
    Ok(cfg.statuses())
}

#[tauri::command]
async fn set_provider_key(
    state: State<'_, AppState>,
    provider: String,
    value: String,
) -> Result<(), String> {
    let key = match provider.as_str() {
        "virustotal" => "virustotal_key",
        "web" => "web_api_key",
        "ai" => "ai_api_key",
        "ai_base_url" => "ai_base_url",
        "ai_model" => "ai_model",
        _ => return Err(format!("proveedor desconocido: {provider}")),
    };
    let db = state.db.lock().unwrap();
    db.set_setting(key, &value)
}

#[tauri::command]
async fn lookup_external(
    state: State<'_, AppState>,
    service_name: String,
) -> Result<external::ExternalLookupResult, String> {
    // Find the service in the most recent scan.
    let (svc, cfg) = {
        let db = state.db.lock().unwrap();
        let svc = db
            .latest_service(&service_name)?
            .ok_or_else(|| format!("servicio no encontrado: {service_name}"))?;
        let cfg = external::ProviderConfig::load(&db);
        (svc, cfg)
    };
    let res = external::escalate(&state.db, &cfg, &svc).await;
    // Persist the enriched verdict + write-through cache.
    {
        let db = state.db.lock().unwrap();
        let verdict = external::to_verdict(&svc, &res);
        db.upsert_verdict(&service_name, &verdict)?;
    }
    Ok(res)
}

// ---- Fase 5: reportes exportables ----

/// Returns the latest scan's report as a self-contained HTML document.
#[tauri::command]
fn export_report_html(state: State<'_, AppState>) -> Result<String, String> {
    let db = state.db.lock().unwrap();
    let summary = db.latest_summary()?.ok_or("no hay escaneos")?;
    reports::render_html(&db, &summary)
}

/// Returns the latest scan's report as structured JSON (machine-readable).
#[tauri::command]
fn export_report_json(state: State<'_, AppState>) -> Result<String, String> {
    let db = state.db.lock().unwrap();
    let summary = db.latest_summary()?.ok_or("no hay escaneos")?;
    let rows = db.scan_report_rows(summary.scan_id)?;
    serde_json::to_string_pretty(&serde_json::json!({
        "summary": summary,
        "services": rows,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
    }))
    .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let path = db_path(app.handle());
            let database = db::Db::open(&path)?;
            app.manage(AppState {
                db: Mutex::new(database),
            });

            // Pantalla de carga: el frontend emite "app-ready" cuando la UI está
            // cargada; entonces mostramos la ventana principal y cerramos el splash.
            let handle = app.handle().clone();
            app.listen("app-ready", move |_| {
                if let Some(splash) = handle.get_webview_window("splash") {
                    let _ = splash.close();
                }
                if let Some(main) = handle.get_webview_window("main") {
                    let _ = main.show();
                    let _ = main.set_focus();
                }
            });

            // Red de seguridad: si la señal nunca llega, no dejamos al usuario
            // varado en el splash (máx. 10 s) y mostramos la ventana principal.
            let fallback = app.handle().clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(10));
                let splash_alive = fallback
                    .get_webview_window("splash")
                    .and_then(|w| w.is_visible().ok())
                    .unwrap_or(false);
                if splash_alive {
                    if let Some(splash) = fallback.get_webview_window("splash") {
                        let _ = splash.close();
                    }
                    if let Some(main) = fallback.get_webview_window("main") {
                        let _ = main.show();
                        let _ = main.set_focus();
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            scan_services,
            get_last_summary,
            list_rules,
            add_rule,
            toggle_rule,
            delete_rule,
            get_scan_history,
            diff_scans,
            get_cache_stats,
            clear_cache,
            get_provider_statuses,
            set_provider_key,
            lookup_external,
            export_report_html,
            export_report_json
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// Suppress unused warning for ServiceInfo until Fase 2 uses it directly.
#[allow(unused)]
fn _touch(_: &ServiceInfo) {}
