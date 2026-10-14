//! DTOs shared with the frontend (`src/types.ts`). Keep both in sync.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictCategory {
    Safe,
    Suspicious,
    Dangerous,
    Unknown,
}

impl VerdictCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerdictCategory::Safe => "safe",
            VerdictCategory::Suspicious => "suspicious",
            VerdictCategory::Dangerous => "dangerous",
            VerdictCategory::Unknown => "unknown",
        }
    }
    pub fn from_str(s: &str) -> Self {
        match s {
            "safe" => VerdictCategory::Safe,
            "suspicious" => VerdictCategory::Suspicious,
            "dangerous" => VerdictCategory::Dangerous,
            _ => VerdictCategory::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartType {
    Boot,
    System,
    Auto,
    DelayedAuto,
    Demand,
    Disabled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    Own,
    Share,
    Kernel,
    Filesystem,
    Recognition,
    Driver,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub pid: Option<i64>,
    pub status: ServiceStatus,
    pub start_type: StartType,
    pub kind: ServiceKind,
    pub account: Option<String>,
    pub bin_path: Option<String>,
    pub exe_path: Option<String>,
    pub dll_path: Option<String>,
    pub dependencies: Vec<String>,
    pub sha256: Option<String>,
    pub signed: Option<bool>,
    pub signer: Option<String>,
    pub signature_status: Option<String>,
    pub company: Option<String>,
    pub product: Option<String>,
    pub file_description: Option<String>,
    pub original_filename: Option<String>,
    pub file_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerdictReason {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub service: String,
    pub category: VerdictCategory,
    pub confidence: f64,
    pub reasons: Vec<VerdictReason>,
    pub source: String,
    pub source_url: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: i64,
    pub kind: String,
    pub pattern: String,
    pub category: VerdictCategory,
    pub priority: i64,
    pub enabled: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub scan_id: i64,
    pub started_at: String,
    pub finished_at: String,
    pub total: i64,
    pub safe: i64,
    pub suspicious: i64,
    pub dangerous: i64,
    pub unknown: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanEntry {
    pub service: ServiceInfo,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub summary: ScanSummary,
    pub entries: Vec<ScanEntry>,
}
