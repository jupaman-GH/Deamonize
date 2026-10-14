import { getVersion } from "@tauri-apps/api/app";
import { useEffect, useState } from "react";

/** Fallback used when not running inside Tauri (plain-browser dev). */
const FALLBACK_VERSION = "1.0.0";

let cached: string | null = null;

async function loadVersion(): Promise<string> {
  if (cached) return cached;
  try {
    cached = await getVersion();
  } catch {
    cached = FALLBACK_VERSION;
  }
  return cached;
}

/**
 * App version as reported by Tauri (tauri.conf.json), so the UI always shows
 * the real software version. Returns `null` until it resolves.
 */
export function useAppVersion(): string | null {
  const [version, setVersion] = useState<string | null>(cached);
  useEffect(() => {
    let disposed = false;
    void loadVersion().then((v) => {
      if (!disposed) setVersion(v);
    });
    return () => {
      disposed = true;
    };
  }, []);
  return version;
}
