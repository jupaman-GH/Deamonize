/**
 * Shared DTOs between the Rust backend and the React frontend.
 * Keep in sync with src-tauri/src/models.rs
 */

export type VerdictCategory = "safe" | "suspicious" | "dangerous" | "unknown";

export type ServiceStatus =
  | "stopped"
  | "start_pending"
  | "stop_pending"
  | "running"
  | "continue_pending"
  | "pause_pending"
  | "paused"
  | "unknown";

export type StartType =
  | "boot"
  | "system"
  | "auto"
  | "delayed_auto"
  | "demand"
  | "disabled"
  | "unknown";

export type ServiceKind = "own" | "share" | "kernel" | "filesystem" | "recognition" | "driver" | "unknown";

/** Full metadata collected for one Windows service at scan time. */
export interface ServiceInfo {
  /** Internal service name (registry key). */
  name: string;
  displayName: string;
  description: string | null;
  pid: number | null;
  status: ServiceStatus;
  startType: StartType;
  kind: ServiceKind;
  /** Account the service runs under (e.g. LocalSystem, NT AUTHORITY\NetworkService, domain user). */
  account: string | null;
  /** Path of the service binary, as configured (may include args and quotes). */
  binPath: string | null;
  /** Extracted executable path (args stripped). */
  exePath: string | null;
  dllPath: string | null;
  dependencies: string[];
  /** SHA-256 of the binary, lowercase hex. Null for drivers or unreadable files. */
  sha256: string | null;
  /** Whether the binary has a valid Authenticode signature. */
  signed: boolean | null;
  /** Signer subject (e.g. "Microsoft Windows"). */
  signer: string | null;
  /** Signature verification status detail, e.g. "trusted", "expired", "unsigned", "error: ..." */
  signatureStatus: string | null;
  /** Version info from the PE resources. */
  company: string | null;
  product: string | null;
  fileDescription: string | null;
  originalFilename: string | null;
  fileVersion: string | null;
}

/** One reason that contributed to a verdict. */
export interface VerdictReason {
  /** Machine code, e.g. "hash.whitelist", "path.temp", "spoof.display_name_mismatch" */
  code: string;
  /** Human-readable message (Spanish). */
  message: string;
  /** Optional extra detail (the matched rule, the offending path, ...). */
  detail?: string;
  /** Weight this reason added to the score (positive = risk, negative = safety). */
  weight: number;
}

export interface Verdict {
  service: string;
  category: VerdictCategory;
  /** 0.0 – 1.0 confidence in the verdict. */
  confidence: number;
  reasons: VerdictReason[];
  /** Where the verdict came from: "local", "cache", "virustotal", "web", "ai" */
  source: string;
  /** Citable reference URL (Learn doc, VirusTotal report, web result...). */
  sourceUrl: string | null;
  createdAt: string;
}

export interface Rule {
  id: number;
  /** "name" | "path" | "signer" | "hash" */
  kind: string;
  pattern: string;
  category: VerdictCategory;
  priority: number;
  enabled: boolean;
  note: string | null;
}

export interface ScanSummary {
  scanId: number;
  startedAt: string;
  finishedAt: string;
  total: number;
  safe: number;
  suspicious: number;
  dangerous: number;
  unknown: number;
}

export interface ScanResult {
  summary: ScanSummary;
  /** One row per service: metadata + verdict. */
  entries: ScanEntry[];
}

export interface ScanEntry {
  service: ServiceInfo;
  verdict: Verdict;
}

export interface CacheStats {
  entries: number;
  oldestFetchedAt: string | null;
  newestFetchedAt: string | null;
  expired: number;
}

export interface ProviderStatus {
  name: string;
  configured: boolean;
  description: string;
}

export interface EscalationStep {
  provider: string;
  query: string;
  ok: boolean;
  detail: string;
  elapsedMs: number;
}

export interface ScanChange {
  service: string;
  fromCategory: string;
  toCategory: string;
  hashChanged: boolean;
}

export interface ScanDiff {
  scanA: number;
  scanB: number;
  added: string[];
  removed: string[];
  changed: ScanChange[];
}

export interface ExternalLookupResult {
  category: VerdictCategory;
  confidence: number;
  source: string;
  sourceUrl: string | null;
  summary: string;
  steps: EscalationStep[];
}
