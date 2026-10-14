// Typed wrappers around the Tauri invoke bridge.
import { invoke } from "@tauri-apps/api/core";
import type {
  CacheStats,
  ExternalLookupResult,
  ProviderStatus,
  Rule,
  ScanDiff,
  ScanResult,
  ScanSummary,
} from "@/types";

export function scanServices(): Promise<ScanResult> {
  return invoke<ScanResult>("scan_services");
}

export function getLastSummary(): Promise<ScanSummary | null> {
  return invoke<ScanSummary | null>("get_last_summary");
}

export function listRules(): Promise<Rule[]> {
  return invoke<Rule[]>("list_rules");
}

export function addRule(
  kind: string,
  pattern: string,
  category: string,
  note?: string,
): Promise<number> {
  return invoke<number>("add_rule", { kind, pattern, category, note: note ?? null });
}

export function toggleRule(id: number, enabled: boolean): Promise<void> {
  return invoke<void>("toggle_rule", { id, enabled });
}

export function deleteRule(id: number): Promise<void> {
  return invoke<void>("delete_rule", { id });
}

export function getScanHistory(): Promise<ScanSummary[]> {
  return invoke<ScanSummary[]>("get_scan_history");
}

export function diffScans(scanA: number, scanB: number): Promise<ScanDiff> {
  return invoke<ScanDiff>("diff_scans", { scanA, scanB });
}

export function getCacheStats(): Promise<CacheStats> {
  return invoke<CacheStats>("get_cache_stats");
}

export function clearCache(): Promise<number> {
  return invoke<number>("clear_cache");
}

export function getProviderStatuses(): Promise<ProviderStatus[]> {
  return invoke<ProviderStatus[]>("get_provider_statuses");
}

export function setProviderKey(provider: string, value: string): Promise<void> {
  return invoke<void>("set_provider_key", { provider, value });
}

export function lookupExternal(serviceName: string): Promise<ExternalLookupResult> {
  return invoke<ExternalLookupResult>("lookup_external", { serviceName });
}

export function exportReportHtml(): Promise<string> {
  return invoke<string>("export_report_html");
}

export function exportReportJson(): Promise<string> {
  return invoke<string>("export_report_json");
}
