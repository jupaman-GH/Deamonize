//! Escalation chain: local verdict -> VirusTotal -> web search -> AI.
//! Every provider is optional; without keys the app stays fully offline.
//! Results are written back to the local DB (cache + verdict) so the internal
//! knowledge base improves over time (Idea.md point 3).

use serde::{Deserialize, Serialize};

use crate::db::Db;
use crate::models::{ServiceInfo, Verdict, VerdictCategory, VerdictReason};

/// What each provider needs to be usable.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProviderStatus {
    pub name: String,
    pub configured: bool,
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EscalationStep {
    pub provider: String,
    pub query: String,
    pub ok: bool,
    pub detail: String,
    pub elapsed_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalLookupResult {
    pub category: VerdictCategory,
    pub confidence: f64,
    pub source: String,
    pub source_url: Option<String>,
    pub summary: String,
    pub steps: Vec<EscalationStep>,
}

/// API keys / endpoints, stored in the settings table.
#[derive(Clone, Default)]
pub struct ProviderConfig {
    pub virustotal_key: Option<String>,
    pub web_api_key: Option<String>,
    pub ai_api_key: Option<String>,
    pub ai_base_url: Option<String>,
    pub ai_model: Option<String>,
}

impl ProviderConfig {
    pub fn load(db: &Db) -> Self {
        let get = |k: &str| -> Option<String> {
            db.setting(k).ok().flatten().filter(|v| !v.trim().is_empty())
        };
        ProviderConfig {
            virustotal_key: get("virustotal_key"),
            web_api_key: get("web_api_key"),
            ai_api_key: get("ai_api_key"),
            ai_base_url: get("ai_base_url"),
            ai_model: get("ai_model"),
        }
    }

    pub fn statuses(&self) -> Vec<ProviderStatus> {
        vec![
            ProviderStatus {
                name: "VirusTotal".into(),
                configured: self.virustotal_key.is_some(),
                description: "Reputación por hash SHA-256 (nivel 1)".into(),
            },
            ProviderStatus {
                name: "Búsqueda web".into(),
                configured: self.web_api_key.is_some(),
                description: "Brave Search API para el servicio (nivel 2)".into(),
            },
            ProviderStatus {
                name: "IA".into(),
                configured: self.ai_api_key.is_some(),
                description: "Resumen de evidencia (nivel 3, OpenAI-compatible)".into(),
            },
        ]
    }
}

const VT_BASE: &str = "https://www.virustotal.com/api/v3/files";
const BRAVE_BASE: &str = "https://api.search.brave.com/res/v1/web/search";
/// TTLs (seconds) per provider, per plan.
const VT_TTL: i64 = 7 * 24 * 3600; // hashes are immutable; long TTL
const WEB_TTL: i64 = 24 * 3600;
const AI_TTL: i64 = 30 * 24 * 3600;

struct StepLog {
    steps: Vec<EscalationStep>,
}

impl StepLog {
    fn push(&mut self, provider: &str, query: &str, ok: bool, detail: String, start: std::time::Instant) {
        self.steps.push(EscalationStep {
            provider: provider.into(),
            query: query.into(),
            ok,
            detail,
            elapsed_ms: start.elapsed().as_millis() as u64,
        });
    }
}

/// Level 1: VirusTotal lookup by SHA-256.
async fn virustotal(
    cfg: &ProviderConfig,
    sha256: &str,
    log: &mut StepLog,
) -> Option<(VerdictCategory, f64, String, String)> {
    let key = cfg.virustotal_key.as_deref()?;
    let url = format!("{VT_BASE}/{sha256}");
    let start = std::time::Instant::now();
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("x-apikey", key)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await;

    match resp {
        Ok(r) if r.status() == 200 => {
            let body: serde_json::Value = r.json().await.ok()?;
            let stats = body.get("data")?.get("attributes")?.get("last_analysis_stats")?;
            let malicious = stats.get("malicious")?.as_i64().unwrap_or(0);
            let suspicious = stats.get("suspicious")?.as_i64().unwrap_or(0);
            let total = stats
                .as_object()?
                .values()
                .filter_map(|v| v.as_i64())
                .sum::<i64>();
            let report_url = body
                .get("data")?
                .get("attributes")?
                .get("permalink")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| format!("https://www.virustotal.com/gui/file/{sha256}"));

            let detail = format!("{malicious} malicioso, {suspicious} sospechoso de {total} motores");
            log.push("virustotal", sha256, true, detail, start);

            let (cat, conf) = if malicious >= 3 {
                (VerdictCategory::Dangerous, 0.95)
            } else if malicious > 0 {
                (VerdictCategory::Suspicious, 0.85)
            } else if suspicious > 0 {
                (VerdictCategory::Suspicious, 0.7)
            } else {
                (VerdictCategory::Safe, 0.8)
            };
            let summary = format!(
                "VirusTotal: {malicious} detecciones maliciosas y {suspicious} sospechosas de {total} motores."
            );
            Some((cat, conf, report_url, summary))
        }
        Ok(r) if r.status() == 404 => {
            log.push("virustotal", sha256, false, "hash no encontrado en VirusTotal".into(), start);
            None
        }
        Ok(r) => {
            log.push("virustotal", sha256, false, format!("HTTP {}", r.status()), start);
            None
        }
        Err(e) => {
            log.push("virustotal", sha256, false, format!("error de red: {e}"), start);
            None
        }
    }
}

/// Level 2: web search about the service.
async fn web_search(
    cfg: &ProviderConfig,
    svc: &ServiceInfo,
    log: &mut StepLog,
) -> Option<(VerdictCategory, f64, String, String, Vec<String>)> {
    let key = cfg.web_api_key.as_deref()?;
    let query = format!(
        "\"{}\" Windows service virus OR malware OR safe",
        svc.display_name
    );
    let start = std::time::Instant::now();
    let client = reqwest::Client::new();
    let resp = client
        .get(BRAVE_BASE)
        .header("X-Subscription-Token", key)
        .header("Accept", "application/json")
        .query(&[("q", query.as_str()), ("count", "5")])
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await;

    match resp {
        Ok(r) if r.status() == 200 => {
            let body: serde_json::Value = r.json().await.ok()?;
            let items = body.get("web")?.get("results")?.as_array()?;
            let titles: Vec<String> = items
                .iter()
                .filter_map(|it| it.get("title").and_then(|t| t.as_str()).map(String::from))
                .collect();
            let first_url = items
                .first()?
                .get("url")
                .and_then(|u| u.as_str())
                .map(String::from)?;
            let detail = format!("{} resultados", titles.len());
            log.push("web", &query, true, detail, start);
            let summary = format!(
                "Búsqueda web: {} fuentes relevantes sobre \"{}\".",
                titles.len(),
                svc.display_name
            );
            // Web results alone don't flip a category; low confidence signal.
            Some((VerdictCategory::Unknown, 0.5, first_url, summary, titles))
        }
        Ok(r) => {
            log.push("web", &query, false, format!("HTTP {}", r.status()), start);
            None
        }
        Err(e) => {
            log.push("web", &query, false, format!("error de red: {e}"), start);
            None
        }
    }
}

/// Level 3: AI summary of all collected evidence.
async fn ai_summary(
    cfg: &ProviderConfig,
    svc: &ServiceInfo,
    evidence: &str,
    log: &mut StepLog,
) -> Option<(VerdictCategory, f64, String)> {
    let key = cfg.ai_api_key.as_deref()?;
    let base = cfg
        .ai_base_url
        .as_deref()
        .unwrap_or("https://api.openai.com/v1")
        .trim_end_matches('/');
    let model = cfg.ai_model.as_deref().unwrap_or("gpt-4o-mini");
    let start = std::time::Instant::now();

    let prompt = format!(
        "Eres un analista de seguridad. Clasifica el servicio de Windows '{name}' \
         (displayName: {disp}) como safe, suspicious o dangerous. Responde SOLO con JSON: \
         {{\"category\":\"safe|suspicious|dangerous\",\"confidence\":0.0-1.0,\"reasons\":[\"...\"]}}.\n\n\
         Evidencia:\n{evidence}",
        name = svc.name,
        disp = svc.display_name,
        evidence = evidence
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/chat/completions"))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "model": model,
            "messages": [{ "role": "user", "content": prompt }],
            "temperature": 0.2,
        }))
        .timeout(std::time::Duration::from_secs(45))
        .send()
        .await;

    match resp {
        Ok(r) if r.status() == 200 => {
            let body: serde_json::Value = r.json().await.ok()?;
            let content = body
                .get("choices")?
                .get(0)?
                .get("message")?
                .get("content")?
                .as_str()?;
            log.push("ai", &svc.name, true, "resumen generado".into(), start);
            // Try to parse the JSON object out of the model's reply.
            let extracted = extract_json(content);
            if let Some(v) = extracted {
                let cat = match v.get("category").and_then(|c| c.as_str()).unwrap_or("") {
                    "safe" => VerdictCategory::Safe,
                    "suspicious" => VerdictCategory::Suspicious,
                    "dangerous" => VerdictCategory::Dangerous,
                    _ => VerdictCategory::Unknown,
                };
                let conf = v.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.5);
                let summary = v
                    .get("reasons")
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_else(|| content.to_string());
                return Some((cat, conf.clamp(0.0, 1.0), summary));
            }
            Some((VerdictCategory::Unknown, 0.5, content.to_string()))
        }
        Ok(r) => {
            log.push("ai", &svc.name, false, format!("HTTP {}", r.status()), start);
            None
        }
        Err(e) => {
            log.push("ai", &svc.name, false, format!("error de red: {e}"), start);
            None
        }
    }
}

fn extract_json(text: &str) -> Option<serde_json::Value> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    serde_json::from_str(&text[start..=end]).ok()
}

/// Runs the escalation chain for one service and writes results through to
/// the cache and DB. Returns the final result with the step log.
pub async fn escalate(
    db: &std::sync::Mutex<Db>,
    cfg: &ProviderConfig,
    svc: &ServiceInfo,
) -> ExternalLookupResult {
    let mut log = StepLog { steps: Vec::new() };
    let mut best: Option<(VerdictCategory, f64, String, Option<String>, String)> = None;

    // Level 1: VirusTotal by hash (cache-aware).
    if let Some(sha) = svc.sha256.as_deref() {
        let cache_key = format!("vt:{sha}");
        let cached = db.lock().unwrap().cache_get_fresh(&cache_key).ok().flatten();
        if let Some(json) = cached {
            if let Ok(v) = serde_json::from_str::<(VerdictCategory, f64, String, String)>(&json) {
                log.push("virustotal", sha, true, "desde caché local".into(), std::time::Instant::now());
                best = Some((v.0, v.1, v.2, None, v.3));
            }
        } else if let Some((cat, conf, url, summary)) = virustotal(cfg, sha, &mut log).await {
            let payload = serde_json::to_string(&(cat, conf, url.clone(), summary.clone())).unwrap_or_default();
            db.lock().unwrap().cache_put(&cache_key, &payload, VT_TTL, "virustotal");
            best = Some((cat, conf, url, None, summary));
        }
    }

    // Level 2: web search (only if still unknown/low confidence).
    let need_web = best.as_ref().map(|b| b.1 < 0.8).unwrap_or(true);
    if need_web {
        if let Some((cat, conf, url, summary, titles)) = web_search(cfg, svc, &mut log).await {
            if best.as_ref().map(|b| conf > b.1).unwrap_or(true) {
                best = Some((cat, conf, url, None, format!("{summary} Títulos: {}", titles.join(" | "))));
            }
        }
    }

    // Level 3: AI summary (only if still low confidence).
    let need_ai = best.as_ref().map(|b| b.1 < 0.8).unwrap_or(true);
    if need_ai {
        let evidence = build_evidence(svc, best.as_ref());
        if let Some((cat, conf, summary)) = ai_summary(cfg, svc, &evidence, &mut log).await {
            if best.as_ref().map(|b| conf > b.1).unwrap_or(true) {
                best = Some((cat, conf, String::new(), None, summary));
            }
        }
    }

    let (category, confidence, source_url, _, summary) = match best {
        Some(b) => b,
        None => (
            VerdictCategory::Unknown,
            0.3,
            String::new(),
            None,
            "Sin consultas externas configuradas o sin resultados.".into(),
        ),
    };

    ExternalLookupResult {
        category,
        confidence,
        source: "external".into(),
        source_url: if source_url.is_empty() { None } else { Some(source_url) },
        summary,
        steps: log.steps,
    }
}

fn build_evidence(svc: &ServiceInfo, best: Option<&(VerdictCategory, f64, String, Option<String>, String)>) -> String {
    let mut ev = format!(
        "Ruta: {}\nHash: {}\nFirma: {:?} ({})\nEmpresa: {:?}\nProducto: {:?}\nDescripción: {:?}",
        svc.exe_path.as_deref().unwrap_or("desconocida"),
        svc.sha256.as_deref().unwrap_or("sin hash"),
        svc.signer,
        svc.signature_status.as_deref().unwrap_or("sin verificar"),
        svc.company,
        svc.product,
        svc.description,
    );
    if let Some(b) = best {
        ev.push_str(&format!("\nVeredicto previo: {:?} (confianza {:.2})", b.0, b.1));
    }
    ev
}

/// Converts an external lookup result into a DB verdict + reason.
pub fn to_verdict(svc: &ServiceInfo, res: &ExternalLookupResult) -> Verdict {
    let mut reasons = vec![VerdictReason {
        code: "external.lookup".into(),
        message: res.summary.clone(),
        detail: res.source_url.clone(),
        weight: if res.category == VerdictCategory::Dangerous {
            1.0
        } else if res.category == VerdictCategory::Safe {
            -1.0
        } else {
            0.5
        },
    }];
    for s in &res.steps {
        reasons.push(VerdictReason {
            code: format!("external.step.{}", s.provider),
            message: format!("{}: {} ({} ms)", s.provider, s.detail, s.elapsed_ms),
            detail: Some(s.query.clone()),
            weight: 0.0,
        });
    }
    Verdict {
        service: svc.name.clone(),
        category: res.category,
        confidence: res.confidence,
        reasons,
        source: res.source.clone(),
        source_url: res.source_url.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}
