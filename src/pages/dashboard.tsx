import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { SummaryCards } from "@/components/summary-cards";
import { useScan } from "@/lib/scan-context";
import { useI18n } from "@/lib/i18n";
import type { VerdictCategory } from "@/types";
import { ScanSearch } from "lucide-react";
import { toast } from "sonner";

export function DashboardPage({
  onOpenCategory,
}: {
  onOpenCategory: (category: VerdictCategory) => void;
}) {
  const { summary, entries, scanning, runScan } = useScan();
  const { t } = useI18n();
  const hasEntries = entries.length > 0;

  /** Only open Services when this session actually has scan results loaded. */
  const handleOpenCategory = (cat: VerdictCategory) => {
    if (!hasEntries) {
      toast.warning(t("dashboard.scanFirstTitle"), {
        description: t("dashboard.scanFirstDesc"),
      });
      return;
    }
    onOpenCategory(cat);
  };

  const pct = summary && summary.total > 0
    ? Math.round(
        ((summary.safe + summary.unknown) / summary.total) * 100,
      )
    : 0;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">{t("dashboard.heading")}</h2>
          <p className="text-sm text-muted-foreground">
            {summary
              ? t("dashboard.lastScan", {
                  date: new Date(summary.finishedAt).toLocaleString(),
                })
              : t("dashboard.noScan")}
          </p>
        </div>
        <Button onClick={() => void runScan()} disabled={scanning} className="glow-primary">
          {scanning ? (
            <>
              <ScanSearch className="animate-pulse" />
              {t("dashboard.scanning")}
            </>
          ) : (
            <>
              <ScanSearch />
              {t("dashboard.scanNow")}
            </>
          )}
        </Button>
      </div>

      {scanning && (
        <Card>
          <CardContent className="flex flex-col gap-2 p-4">
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>{t("dashboard.analyzing")}</span>
              <span>{pct}%</span>
            </div>
            <Progress value={pct} />
          </CardContent>
        </Card>
      )}

      {scanning ? (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-[76px]" />
          ))}
        </div>
      ) : (
        <SummaryCards
          summary={summary}
          onSelect={handleOpenCategory}
          hint={hasEntries ? undefined : t("dashboard.scanFirstHint")}
        />
      )}
    </div>
  );
}
