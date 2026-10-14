//! SQLite persistence: scans, snapshots, verdicts, rules, cache and settings.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::models::{Rule, ScanSummary, Verdict, VerdictCategory};

pub struct Db {
    pub conn: Connection,
}

/// Seed entry: a curated service classification bundled with the app.
#[derive(Deserialize)]
struct SeedEntry {
    name: String,
    #[serde(default)]
    display: Option<String>,
    category: String,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    services_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS service_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    display_name TEXT,
    description TEXT,
    pid INTEGER,
    status TEXT,
    start_type TEXT,
    kind TEXT,
    account TEXT,
    bin_path TEXT,
    exe_path TEXT,
    dll_path TEXT,
    dependencies TEXT,
    sha256 TEXT,
    signed INTEGER,
    signer TEXT,
    signature_status TEXT,
    company TEXT,
    product TEXT,
    file_description TEXT,
    original_filename TEXT,
    file_version TEXT,
    first_seen TEXT,
    last_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_snapshots_scan ON service_snapshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_name ON service_snapshots(name);
CREATE TABLE IF NOT EXISTS verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL REFERENCES service_snapshots(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    confidence REAL NOT NULL,
    reasons_json TEXT NOT NULL,
    source TEXT NOT NULL,
    source_url TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_snapshot ON verdicts(snapshot_id);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    pattern TEXT NOT NULL,
    category TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    note TEXT,
    source_url TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_unique ON rules(kind, pattern, category);
CREATE TABLE IF NOT EXISTS cache_entries (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    provider TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

impl Db {
    /// In-memory DB for tests (schema + seed, no disk).
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        let db = Db { conn };
        db.seed_rules()?;
        Ok(db)
    }

    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        let db = Db { conn };
        db.seed_rules()?;
        Ok(db)
    }

    /// Inserts the curated baseline (idempotent: skips existing patterns).
    fn seed_rules(&self) -> Result<(), String> {
        let seed_json = include_str!("../seed/services_seed.json");
        let entries: Vec<SeedEntry> =
            serde_json::from_str(seed_json).map_err(|e| format!("seed parse: {e}"))?;
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM rules", [], |r| r.get(0))
            .unwrap_or(0);
        if count > 0 {
            return Ok(());
        }
        for e in &entries {
            let category = match e.category.as_str() {
                "safe" => "safe",
                "suspicious" => "suspicious",
                _ => "dangerous",
            };
            let note = match (&e.note, &e.display) {
                (Some(n), _) => Some(n.clone()),
                (None, Some(d)) => Some(d.clone()),
                _ => None,
            };
            let _ = self.conn.execute(
                "INSERT OR IGNORE INTO rules(kind, pattern, category, priority, enabled, note, source_url)
                 VALUES('name', ?1, ?2, 100, 1, ?3, ?4)",
                params![e.name, category, note, e.url],
            );
        }
        Ok(())
    }

    // ---- Rules ----

    pub fn list_rules(&self) -> Result<Vec<Rule>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, kind, pattern, category, priority, enabled, note
                 FROM rules ORDER BY priority DESC, id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Rule {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    pattern: r.get(2)?,
                    category: VerdictCategory::from_str(&r.get::<_, String>(3)?),
                    priority: r.get(4)?,
                    enabled: r.get::<_, i64>(5)? != 0,
                    note: r.get(6)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn add_rule(&self, kind: &str, pattern: &str, category: &str, note: Option<&str>) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO rules(kind, pattern, category, priority, enabled, note)
                 VALUES(?1, ?2, ?3, 100, 1, ?4)",
                params![kind, pattern, category, note],
            )
            .map_err(|e| e.to_string())?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn toggle_rule(&self, id: i64, enabled: bool) -> Result<(), String> {
        self.conn
            .execute("UPDATE rules SET enabled = ?1 WHERE id = ?2", params![enabled as i64, id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn delete_rule(&self, id: i64) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM rules WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---- Scans ----

    pub fn save_scan(
        &self,
        started_at: &str,
        finished_at: &str,
        services: &[crate::models::ServiceInfo],
        verdicts: &[Verdict],
    ) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT INTO scan_history(started_at, finished_at, services_count)
                 VALUES(?1, ?2, ?3)",
                params![started_at, finished_at, services.len() as i64],
            )
            .map_err(|e| e.to_string())?;
        let scan_id = self.conn.last_insert_rowid();

        for (svc, verdict) in services.iter().zip(verdicts.iter()) {
            let deps = serde_json::to_string(&svc.dependencies).unwrap_or_else(|_| "[]".into());
            self.conn
                .execute(
                    "INSERT INTO service_snapshots(
                        scan_id, name, display_name, description, pid, status, start_type, kind,
                        account, bin_path, exe_path, dll_path, dependencies, sha256, signed,
                        signer, signature_status, company, product, file_description,
                        original_filename, file_version, first_seen, last_seen
                    ) VALUES(
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                        ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24
                    )",
                    params![
                        scan_id,
                        svc.name,
                        svc.display_name,
                        svc.description,
                        svc.pid,
                        format!("{:?}", svc.status).to_lowercase(),
                        format!("{:?}", svc.start_type).to_lowercase(),
                        format!("{:?}", svc.kind).to_lowercase(),
                        svc.account,
                        svc.bin_path,
                        svc.exe_path,
                        svc.dll_path,
                        deps,
                        svc.sha256,
                        svc.signed.map(|b| b as i64),
                        svc.signer,
                        svc.signature_status,
                        svc.company,
                        svc.product,
                        svc.file_description,
                        svc.original_filename,
                        svc.file_version,
                        started_at,
                        finished_at
                    ],
                )
                .map_err(|e| e.to_string())?;
            let snapshot_id = self.conn.last_insert_rowid();
            let reasons = serde_json::to_string(&verdict.reasons).unwrap_or_else(|_| "[]".into());
            self.conn
                .execute(
                    "INSERT INTO verdicts(snapshot_id, category, confidence, reasons_json, source, source_url, created_at)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        snapshot_id,
                        verdict.category.as_str(),
                        verdict.confidence,
                        reasons,
                        verdict.source,
                        verdict.source_url,
                        verdict.created_at
                    ],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(scan_id)
    }

    pub fn latest_summary(&self) -> Result<Option<ScanSummary>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT s.id, s.started_at, s.finished_at, s.services_count,
                        SUM(CASE WHEN v.category='safe' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN v.category='suspicious' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN v.category='dangerous' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN v.category='unknown' THEN 1 ELSE 0 END)
                 FROM scan_history s
                 LEFT JOIN service_snapshots sn ON sn.scan_id = s.id
                 LEFT JOIN verdicts v ON v.snapshot_id = sn.id
                 WHERE s.id = (SELECT MAX(id) FROM scan_history)
                 GROUP BY s.id",
            )
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query_map([], |r| {
            Ok(ScanSummary {
                scan_id: r.get(0)?,
                started_at: r.get(1)?,
                finished_at: r.get(2)?,
                total: r.get(3)?,
                safe: r.get(4)?,
                suspicious: r.get(5)?,
                dangerous: r.get(6)?,
                unknown: r.get(7)?,
            })
        }).map_err(|e| e.to_string())?;
        rows.next()
            .transpose()
            .map_err(|e| e.to_string())
    }

    pub fn scan_history(&self, limit: i64) -> Result<Vec<ScanSummary>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, started_at, finished_at, services_count FROM scan_history
                 ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(ScanSummary {
                    scan_id: r.get(0)?,
                    started_at: r.get(1)?,
                    finished_at: r.get(2)?,
                    total: r.get(3)?,
                    safe: 0,
                    suspicious: 0,
                    dangerous: 0,
                    unknown: 0,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    /// Returns (service_name, sha256, category) for every snapshot in a scan.
    fn scan_pairs(&self, scan_id: i64) -> Result<Vec<(String, Option<String>, String)>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sn.name, sn.sha256, v.category
                 FROM service_snapshots sn
                 JOIN verdicts v ON v.snapshot_id = sn.id
                 WHERE sn.scan_id = ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![scan_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get(1)?, r.get::<_, String>(2)?))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    pub fn diff_scans(&self, a: i64, b: i64) -> Result<ScanDiff, String> {
        use std::collections::BTreeMap;
        let pa = self.scan_pairs(a)?;
        let pb = self.scan_pairs(b)?;
        let ma: BTreeMap<String, (Option<String>, String)> = pa
            .into_iter()
            .map(|(n, h, c)| (n.to_lowercase(), (h, c)))
            .collect();
        let mb: BTreeMap<String, (Option<String>, String)> = pb
            .into_iter()
            .map(|(n, h, c)| (n.to_lowercase(), (h, c)))
            .collect();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();

        for (name, (hash_b, cat_b)) in &mb {
            match ma.get(name) {
                None => added.push(name.clone()),
                Some((hash_a, cat_a)) => {
                    if hash_a != hash_b || cat_a != cat_b {
                        changed.push(ScanChange {
                            service: name.clone(),
                            from_category: cat_a.clone(),
                            to_category: cat_b.clone(),
                            hash_changed: hash_a != hash_b,
                        });
                    }
                }
            }
        }
        for name in ma.keys() {
            if !mb.contains_key(name) {
                removed.push(name.clone());
            }
        }
        Ok(ScanDiff { scan_a: a, scan_b: b, added, removed, changed })
    }

    // ---- Settings ----

    pub fn setting(&self, key: &str) -> Result<Option<String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(|e| e.to_string())?;
        let mut rows = stmt
            .query_map(params![key], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        rows.next().transpose().map_err(|e| e.to_string())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO settings(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Rebuilds a ServiceInfo from the most recent snapshot of a service.
    pub fn latest_service(&self, name: &str) -> Result<Option<crate::models::ServiceInfo>, String> {
        use crate::models::{ServiceInfo, ServiceKind, ServiceStatus, StartType};
        let mut stmt = self
            .conn
            .prepare(
                "SELECT name, display_name, description, pid, status, start_type, kind,
                        account, bin_path, exe_path, dll_path, dependencies, sha256, signed,
                        signer, signature_status, company, product, file_description,
                        original_filename, file_version
                 FROM service_snapshots
                 WHERE name = ?1
                 ORDER BY id DESC LIMIT 1",
            )
            .map_err(|e| e.to_string())?;
        let mut rows = stmt
            .query_map(params![name], |r| {
                let deps_json: String = r.get(11)?;
                let dependencies: Vec<String> =
                    serde_json::from_str(&deps_json).unwrap_or_default();
                Ok(ServiceInfo {
                    name: r.get(0)?,
                    display_name: r.get(1)?,
                    description: r.get(2)?,
                    pid: r.get(3)?,
                    status: parse_status(&r.get::<_, String>(4)?),
                    start_type: parse_start_type(&r.get::<_, String>(5)?),
                    kind: parse_kind(&r.get::<_, String>(6)?),
                    account: r.get(7)?,
                    bin_path: r.get(8)?,
                    exe_path: r.get(9)?,
                    dll_path: r.get(10)?,
                    dependencies,
                    sha256: r.get(12)?,
                    signed: r.get::<_, Option<i64>>(13)?.map(|v| v != 0),
                    signer: r.get(14)?,
                    signature_status: r.get(15)?,
                    company: r.get(16)?,
                    product: r.get(17)?,
                    file_description: r.get(18)?,
                    original_filename: r.get(19)?,
                    file_version: r.get(20)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.next().transpose().map_err(|e| e.to_string())
    }

    /// Stores or replaces the verdict for the latest snapshot of a service.
    pub fn upsert_verdict(&self, name: &str, verdict: &crate::models::Verdict) -> Result<(), String> {
        let snapshot_id: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM service_snapshots WHERE name = ?1 ORDER BY id DESC LIMIT 1",
                params![name],
                |r| r.get(0),
            )
            .ok();
        let Some(snapshot_id) = snapshot_id else {
            return Ok(());
        };
        let reasons = serde_json::to_string(&verdict.reasons).unwrap_or_else(|_| "[]".into());
        self.conn
            .execute(
                "DELETE FROM verdicts WHERE snapshot_id = ?1",
                params![snapshot_id],
            )
            .map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "INSERT INTO verdicts(snapshot_id, category, confidence, reasons_json, source, source_url, created_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    snapshot_id,
                    verdict.category.as_str(),
                    verdict.confidence,
                    reasons,
                    verdict.source,
                    verdict.source_url,
                    verdict.created_at
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---- Cache ----

    #[allow(dead_code)]
    pub fn cache_get(&self, key: &str) -> Result<Option<CacheEntry>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT key, value_json, fetched_at, ttl_seconds, provider
                 FROM cache_entries WHERE key = ?1",
            )
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query_map(params![key], |r| {
            Ok(CacheEntry {
                key: r.get(0)?,
                value_json: r.get(1)?,
                fetched_at: r.get(2)?,
                ttl_seconds: r.get(3)?,
                provider: r.get(4)?,
            })
        }).map_err(|e| e.to_string())?;
        rows.next().transpose().map_err(|e| e.to_string())
    }

    pub fn cache_put(
        &self,
        key: &str,
        value_json: &str,
        ttl_seconds: i64,
        provider: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO cache_entries(key, value_json, fetched_at, ttl_seconds, provider)
                 VALUES(?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    fetched_at = excluded.fetched_at,
                    ttl_seconds = excluded.ttl_seconds,
                    provider = excluded.provider",
                params![key, value_json, chrono::Utc::now().to_rfc3339(), ttl_seconds, provider],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Flattened report row (service + verdict joined) for HTML/JSON reports.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRow {
    pub name: String,
    pub display_name: String,
    pub exe_path: Option<String>,
    pub sha256: Option<String>,
    pub category: String,
    pub confidence: f64,
    pub reasons: Vec<crate::models::VerdictReason>,
    pub source: String,
    pub source_url: Option<String>,
}

impl Db {
    /// Returns flattened report rows for one scan.
    pub fn scan_report_rows(&self, scan_id: i64) -> Result<Vec<ReportRow>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sn.name, sn.display_name, sn.exe_path, sn.sha256,
                        v.category, v.confidence, v.reasons_json, v.source, v.source_url
                 FROM service_snapshots sn
                 JOIN verdicts v ON v.snapshot_id = sn.id
                 WHERE sn.scan_id = ?1
                 ORDER BY CASE v.category
                            WHEN 'dangerous' THEN 0
                            WHEN 'suspicious' THEN 1
                            WHEN 'unknown' THEN 2
                            ELSE 3 END, sn.name",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![scan_id], |r| {
                let reasons_json: String = r.get(6)?;
                let reasons: Vec<crate::models::VerdictReason> =
                    serde_json::from_str(&reasons_json).unwrap_or_default();
                Ok(ReportRow {
                    name: r.get(0)?,
                    display_name: r.get(1)?,
                    exe_path: r.get(2)?,
                    sha256: r.get(3)?,
                    category: r.get(4)?,
                    confidence: r.get(5)?,
                    reasons,
                    source: r.get(7)?,
                    source_url: r.get(8)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }
}

fn parse_status(s: &str) -> crate::models::ServiceStatus {
    use crate::models::ServiceStatus;
    match s {
        "stopped" => ServiceStatus::Stopped,
        "startpending" | "start_pending" => ServiceStatus::StartPending,
        "stoppending" | "stop_pending" => ServiceStatus::StopPending,
        "running" => ServiceStatus::Running,
        "continuepending" | "continue_pending" => ServiceStatus::ContinuePending,
        "pausepending" | "pause_pending" => ServiceStatus::PausePending,
        "paused" => ServiceStatus::Paused,
        _ => ServiceStatus::Unknown,
    }
}

fn parse_start_type(s: &str) -> crate::models::StartType {
    use crate::models::StartType;
    match s {
        "boot" => StartType::Boot,
        "system" => StartType::System,
        "auto" => StartType::Auto,
        "delayedauto" | "delayed_auto" => StartType::DelayedAuto,
        "demand" => StartType::Demand,
        "disabled" => StartType::Disabled,
        _ => StartType::Unknown,
    }
}

fn parse_kind(s: &str) -> crate::models::ServiceKind {
    use crate::models::ServiceKind;
    match s {
        "own" => ServiceKind::Own,
        "share" => ServiceKind::Share,
        "kernel" => ServiceKind::Kernel,
        "filesystem" => ServiceKind::Filesystem,
        "recognition" => ServiceKind::Recognition,
        "driver" => ServiceKind::Driver,
        _ => ServiceKind::Unknown,
    }
}

#[derive(Serialize, Deserialize)]
pub struct CacheEntry {
    pub key: String,
    pub value_json: String,
    pub fetched_at: String,
    pub ttl_seconds: i64,
    pub provider: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanChange {
    pub service: String,
    pub from_category: String,
    pub to_category: String,
    pub hash_changed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanDiff {
    pub scan_a: i64,
    pub scan_b: i64,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<ScanChange>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheStats {
    pub entries: i64,
    pub oldest_fetched_at: Option<String>,
    pub newest_fetched_at: Option<String>,
    pub expired: i64,
}

impl Db {
    pub fn cache_stats(&self) -> Result<CacheStats, String> {
        let (entries, oldest, newest): (i64, Option<String>, Option<String>) = self
            .conn
            .query_row(
                "SELECT COUNT(*), MIN(fetched_at), MAX(fetched_at) FROM cache_entries",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| e.to_string())?;
        let now = chrono::Utc::now().timestamp();
        let expired: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM cache_entries
                 WHERE CAST(strftime('%s', fetched_at) AS INTEGER) + ttl_seconds < ?1",
                params![now],
                |r| r.get(0),
            )
            .unwrap_or(0);
        Ok(CacheStats { entries, oldest_fetched_at: oldest, newest_fetched_at: newest, expired })
    }

    pub fn cache_clear(&self) -> Result<usize, String> {
        self.conn
            .execute("DELETE FROM cache_entries", [])
            .map_err(|e| e.to_string())
    }

    /// Returns a cached value only if it has not expired (TTL respected).
    pub fn cache_get_fresh(&self, key: &str) -> Result<Option<String>, String> {
        let now = chrono::Utc::now().timestamp();
        let mut stmt = self
            .conn
            .prepare(
                "SELECT value_json FROM cache_entries
                 WHERE key = ?1
                   AND CAST(strftime('%s', fetched_at) AS INTEGER) + ttl_seconds >= ?2",
            )
            .map_err(|e| e.to_string())?;
        let mut rows = stmt
            .query_map(params![key, now], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        rows.next().transpose().map_err(|e| e.to_string())
    }
}
