import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { toast } from "sonner";
import { emit } from "@tauri-apps/api/event";
import { getLastSummary, scanServices } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import type { ScanEntry, ScanResult, ScanSummary } from "@/types";

interface ScanContextValue {
  summary: ScanSummary | null;
  entries: ScanEntry[];
  scanning: boolean;
  runScan: () => Promise<void>;
  loadLastSummary: () => Promise<void>;
}

const ScanContext = createContext<ScanContextValue | null>(null);

export function ScanProvider({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [entries, setEntries] = useState<ScanEntry[]>([]);
  const [scanning, setScanning] = useState(false);

  const loadLastSummary = useCallback(async () => {
    try {
      const s = await getLastSummary();
      if (s) setSummary(s);
    } catch {
      /* no previous scan */
    }
  }, []);

  /**
   * Initial load: fetch the last summary, then tell Rust the app is ready so it
   * can close the splash window and show the main one. The splash stays visible
   * at least 1.2 s so its animation is perceptible.
   */
  useEffect(() => {
    let disposed = false;
    const startedAt = Date.now();
    void loadLastSummary().finally(() => {
      const remaining = Math.max(0, 1200 - (Date.now() - startedAt));
      window.setTimeout(() => {
        if (disposed) return;
        void emit("app-ready").catch(() => {
          /* not running inside Tauri */
        });
      }, remaining);
    });
    return () => {
      disposed = true;
    };
  }, [loadLastSummary]);

  const runScan = useCallback(async () => {
    setScanning(true);
    const started = Date.now();
    try {
      const result: ScanResult = await scanServices();
      setSummary(result.summary);
      setEntries(result.entries);
      const secs = ((Date.now() - started) / 1000).toFixed(1);
      toast.success(t("toast.scanCompleted"), {
        description: t("toast.scanCompletedDesc", {
          total: result.summary.total,
          secs,
        }),
      });
    } catch (e) {
      toast.error(t("toast.scanFailed"), { description: String(e) });
    } finally {
      setScanning(false);
    }
  }, [t]);

  const value = useMemo(
    () => ({ summary, entries, scanning, runScan, loadLastSummary }),
    [summary, entries, scanning, runScan, loadLastSummary],
  );

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan(): ScanContextValue {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScan must be used within ScanProvider");
  return ctx;
}
