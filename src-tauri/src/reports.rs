//! Generates self-contained HTML and JSON reports with evidence + sources.

use crate::db::Db;
use crate::models::{ScanSummary, VerdictCategory};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Builds a dark-themed, self-contained HTML report of the latest scan.
pub fn render_html(db: &Db, summary: &ScanSummary) -> Result<String, String> {
    let entries = db
        .scan_report_rows(summary.scan_id)
        .map_err(|e| e.to_string())?;

    let mut rows = String::new();
    for e in &entries {
        let badge_class = match e.category.as_str() {
            "safe" => "safe",
            "suspicious" => "suspicious",
            "dangerous" => "dangerous",
            _ => "unknown",
        };
        let cat_label = match e.category.as_str() {
            "safe" => "Seguro",
            "suspicious" => "Sospechoso",
            "dangerous" => "Peligroso",
            _ => "Desconocido",
        };
        let source_link = match &e.source_url {
            Some(u) if !u.is_empty() => format!(
                "<a href=\"{u}\">{}</a>",
                esc(&e.source)
            ),
            _ => esc(&e.source),
        };
        rows.push_str(&format!(
            "<tr class=\"{badge_class}\">
                <td><code>{name}</code><div class=\"sub\">{disp}</div></td>
                <td class=\"cat\"><span class=\"pill {badge_class}\">{cat_label}</span>
                    <div class=\"sub\">conf. {conf}%</div></td>
                <td><code class=\"path\">{exe}</code>
                    <div class=\"sub\">SHA-256: <code>{hash}</code></div>
                    <div class=\"reasons\">{reasons}</div></td>
                <td>{source}</td>
            </tr>",
            name = esc(&e.name),
            disp = esc(&e.display_name),
            cat_label = cat_label,
            conf = (e.confidence * 100.0).round(),
            exe = esc(e.exe_path.as_deref().unwrap_or("—")),
            hash = esc(e.sha256.as_deref().unwrap_or("sin hash")),
            reasons = e
                .reasons
                .iter()
                .map(|r| format!("<div>• {}</div>", esc(&r.message)))
                .collect::<String>(),
            source = source_link,
        ));
    }

    let generated = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");
    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>Deamonize — Reporte de servicios</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background:#0f1117; color:#e5e7eb;
         margin:0; padding:32px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .meta {{ color:#9ca3af; font-size:13px; margin-bottom:24px; }}
  .summary {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }}
  .card {{ background:#161a24; border:1px solid #232838; border-radius:10px;
           padding:14px 18px; min-width:120px; }}
  .card .n {{ font-size:26px; font-weight:700; }}
  .card.safe .n {{ color:#34d399; }} .card.suspicious .n {{ color:#fbbf24; }}
  .card.dangerous .n {{ color:#f87171; }} .card.unknown .n {{ color:#94a3b8; }}
  .card .l {{ font-size:12px; color:#9ca3af; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #232838;
            vertical-align:top; }}
  th {{ color:#9ca3af; font-weight:600; font-size:12px; }}
  code {{ font-family:'Cascadia Mono',Consolas,monospace; font-size:12px; }}
  .sub {{ color:#6b7280; font-size:11px; margin-top:2px; }}
  .path {{ word-break:break-all; }}
  .pill {{ padding:2px 10px; border-radius:999px; font-size:11px; font-weight:600; }}
  .pill.safe {{ background:rgba(52,211,153,.15); color:#34d399; border:1px solid rgba(52,211,153,.3); }}
  .pill.suspicious {{ background:rgba(251,191,36,.15); color:#fbbf24; border:1px solid rgba(251,191,36,.3); }}
  .pill.dangerous {{ background:rgba(248,113,113,.15); color:#f87171; border:1px solid rgba(248,113,113,.3); }}
  .pill.unknown {{ background:rgba(148,163,184,.15); color:#94a3b8; border:1px solid rgba(148,163,184,.3); }}
  .reasons {{ color:#9ca3af; font-size:11px; margin-top:6px; }}
  a {{ color:#34d399; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  footer {{ margin-top:24px; color:#6b7280; font-size:11px; }}
</style></head><body>
  <h1>Deamonize — Reporte de análisis de servicios</h1>
  <div class="meta">Generado {generated} · Escaneo #{scan_id} · {total} servicios</div>
  <div class="summary">
    <div class="card safe"><div class="n">{safe}</div><div class="l">Seguros</div></div>
    <div class="card suspicious"><div class="n">{suspicious}</div><div class="l">Sospechosos</div></div>
    <div class="card dangerous"><div class="n">{dangerous}</div><div class="l">Peligrosos</div></div>
    <div class="card unknown"><div class="n">{unknown}</div><div class="l">Desconocidos</div></div>
  </div>
  <table>
    <thead><tr><th>Servicio</th><th>Categoría</th><th>Evidencia</th><th>Fuente</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <footer>Reporte generado localmente por Deamonize. Las fuentes citadas enlazan al
  origen de cada veredicto.</footer>
</body></html>"#,
        generated = generated,
        scan_id = summary.scan_id,
        total = summary.total,
        safe = summary.safe,
        suspicious = summary.suspicious,
        dangerous = summary.dangerous,
        unknown = summary.unknown,
        rows = rows,
    ))
}
