// Thin wrapper around the Tauri updater plugin (GitHub Releases endpoint).
// Every call is a no-op when running outside Tauri (plain-browser dev) or when
// the updater has not been configured, so the UI never crashes on unsupported
// environments.
import { check } from "@tauri-apps/plugin-updater";
import { getVersion } from "@tauri-apps/api/app";

const STORAGE_KEY = "deamonize.autoUpdate";

export function isAutoUpdateEnabled(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

export function setAutoUpdateEnabled(enabled: boolean): void {
  try {
    localStorage.setItem(STORAGE_KEY, String(enabled));
  } catch {
    /* storage unavailable */
  }
}

export interface UpdateInfo {
  version: string;
  currentVersion: string;
}

/**
 * Checks the configured endpoint for a newer release. Returns `null` when there
 * is no update, and `undefined` when the updater is unavailable (not running in
 * Tauri, no endpoint configured, or the network/release metadata is missing).
 */
export async function checkForUpdate(): Promise<UpdateInfo | null | undefined> {
  try {
    const current = await getVersion();
    const update = await check();
    if (!update || update.version === current) return null;
    return { version: update.version, currentVersion: current };
  } catch {
    // Endpoint unreachable, not configured, or not inside Tauri.
    return undefined;
  }
}

/**
 * Downloads and installs the update in the background. On Windows the updater
 * stages the new binaries and the installer runs on exit, so the caller just
 * asks the user to restart the app.
 */
export async function installUpdate(): Promise<boolean> {
  try {
    const update = await check();
    if (!update) return false;
    await update.downloadAndInstall();
    return true;
  } catch {
    return false;
  }
}
