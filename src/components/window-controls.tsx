import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Copy, Minus, Square, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { useI18n } from "@/lib/i18n";

type AppWindow = ReturnType<typeof getCurrentWindow>;

/** Runs a window action, no-op'ing outside Tauri (e.g. plain-browser dev). */
function call(fn: (win: AppWindow) => Promise<unknown>) {
  try {
    void fn(getCurrentWindow()).catch(() => {});
  } catch {
    /* not running inside Tauri */
  }
}

/**
 * Custom minimize / maximize / close buttons for the frameless window.
 * Sits at the top-right of the app header, which acts as the titlebar.
 */
export function WindowControls() {
  const { t } = useI18n();
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        const win = getCurrentWindow();
        setMaximized(await win.isMaximized());
        unlisten = await win.onResized(async () => {
          if (disposed) return;
          try {
            setMaximized(await win.isMaximized());
          } catch {
            /* ignore */
          }
        });
      } catch {
        /* not running inside Tauri */
      }
    })();
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  const base =
    "flex h-full w-12 shrink-0 items-center justify-center text-muted-foreground transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring";

  return (
    <div className="ml-auto flex h-full shrink-0">
      <button
        type="button"
        aria-label={t("win.minimize")}
        title={t("win.minimize")}
        className={cn(base, "hover:bg-accent hover:text-foreground")}
        onClick={() => call((w) => w.minimize())}
      >
        <Minus className="size-4" />
      </button>
      <button
        type="button"
        aria-label={maximized ? t("win.restore") : t("win.maximize")}
        title={maximized ? t("win.restore") : t("win.maximize")}
        className={cn(base, "hover:bg-accent hover:text-foreground")}
        onClick={() => call((w) => w.toggleMaximize())}
      >
        {maximized ? (
          <Copy className="size-3.5" />
        ) : (
          <Square className="size-3" strokeWidth={2.5} />
        )}
      </button>
      <button
        type="button"
        aria-label={t("win.close")}
        title={t("win.close")}
        className={cn(base, "hover:bg-destructive hover:text-white")}
        onClick={() => call((w) => w.close())}
      >
        <X className="size-4" />
      </button>
    </div>
  );
}
