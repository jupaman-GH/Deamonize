import { useEffect, useState } from "react";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { Toaster } from "@/components/ui/sonner";
import { toast } from "sonner";
import { AppSidebar, type PageId } from "@/components/app-sidebar";
import { WindowControls } from "@/components/window-controls";
import { ScanProvider } from "@/lib/scan-context";
import { DashboardPage } from "@/pages/dashboard";
import { ServicesPage } from "@/pages/services";
import { RulesPage } from "@/pages/rules";
import { CachePage } from "@/pages/cache";
import { ReportsPage } from "@/pages/reports";
import { SettingsPage } from "@/pages/settings";
import { useI18n, type TKey } from "@/lib/i18n";
import { useTheme } from "@/lib/theme";
import { checkForUpdate, isAutoUpdateEnabled } from "@/lib/updater";
import { useAppVersion } from "@/lib/version";
import type { VerdictCategory } from "@/types";

const pageMeta: Record<PageId, { title: TKey; subtitle: TKey }> = {
  dashboard: { title: "page.dashboard.title", subtitle: "page.dashboard.subtitle" },
  services: { title: "page.services.title", subtitle: "page.services.subtitle" },
  rules: { title: "page.rules.title", subtitle: "page.rules.subtitle" },
  cache: { title: "page.cache.title", subtitle: "page.cache.subtitle" },
  reports: { title: "page.reports.title", subtitle: "page.reports.subtitle" },
  settings: { title: "page.settings.title", subtitle: "page.settings.subtitle" },
};

export default function App() {
  const [page, setPage] = useState<PageId>("dashboard");
  const [categoryFilter, setCategoryFilter] = useState<VerdictCategory | "all">("all");
  const { t } = useI18n();
  const { theme } = useTheme();
  const version = useAppVersion();
  const meta = pageMeta[page];

  /** Background auto-update check at startup (opt-in from Ajustes). */
  useEffect(() => {
    if (!isAutoUpdateEnabled()) return;
    let disposed = false;
    const timer = window.setTimeout(() => {
      void checkForUpdate().then((result) => {
        if (disposed || result == null) return;
        toast.info(t("toast.updateFound", { version: result.version }), {
          description: t("settings.updateDesc"),
        });
      });
    }, 4000);
    return () => {
      disposed = true;
      window.clearTimeout(timer);
    };
  }, [t]);

  /** Dashboard summary card click: open Services pre-filtered by that category. */
  const openCategory = (cat: VerdictCategory) => {
    setCategoryFilter(cat);
    setPage("services");
  };

  return (
    <ScanProvider>
      <SidebarProvider>
        <AppSidebar active={page} onNavigate={setPage} />
        <SidebarInset>
          <header
            className="flex h-16 shrink-0 items-center gap-2 border-b"
            data-tauri-drag-region
          >
            <div className="flex items-center gap-2 px-4">
              <SidebarTrigger className="-ml-1" />
              <Separator orientation="vertical" className="mr-2 data-[orientation=vertical]:h-4" />
              <div data-tauri-drag-region>
                <h1 className="text-sm font-semibold leading-tight" data-tauri-drag-region>
                  {t(meta.title)}
                </h1>
                <p className="text-xs leading-tight text-muted-foreground" data-tauri-drag-region>
                  {t(meta.subtitle)}
                </p>
              </div>
            </div>
            <WindowControls />
          </header>
          <div className="flex-1 overflow-y-auto p-4 md:p-6">
            {page === "dashboard" && <DashboardPage onOpenCategory={openCategory} />}
            {page === "services" && <ServicesPage categoryFilter={categoryFilter} />}
            {page === "rules" && <RulesPage />}
            {page === "cache" && <CachePage />}
            {page === "reports" && <ReportsPage />}
            {page === "settings" && <SettingsPage />}
          </div>
          <footer
            className="flex h-6 shrink-0 items-center justify-end border-t px-4"
            data-tauri-drag-region
          >
            {version && (
              <span className="text-[10px] tabular-nums text-muted-foreground">
                {t("app.version", { version })}
              </span>
            )}
          </footer>
        </SidebarInset>
      </SidebarProvider>
      <Toaster theme={theme} position="bottom-right" />
    </ScanProvider>
  );
}
