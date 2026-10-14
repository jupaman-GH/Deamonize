import { Card, CardContent } from "@/components/ui/card";
import { categoryMeta } from "@/lib/labels";
import type { ScanSummary, VerdictCategory } from "@/types";
import { cn } from "@/lib/utils";
import { useI18n } from "@/lib/i18n";
import { ChevronRight } from "lucide-react";

const order: VerdictCategory[] = ["safe", "suspicious", "dangerous", "unknown"];

const glowByCategory: Record<VerdictCategory, string> = {
  safe: "glow-safe",
  suspicious: "glow-suspicious",
  dangerous: "glow-dangerous",
  unknown: "glow-unknown",
};

export function SummaryCards({
  summary,
  onSelect,
  hint,
}: {
  summary: ScanSummary | null;
  onSelect?: (category: VerdictCategory) => void;
  /** Tooltip shown instead of the default one (e.g. "scan first"). */
  hint?: string;
}) {
  const { t } = useI18n();
  const values: Record<VerdictCategory, number> = {
    safe: summary?.safe ?? 0,
    suspicious: summary?.suspicious ?? 0,
    dangerous: summary?.dangerous ?? 0,
    unknown: summary?.unknown ?? 0,
  };
  const clickable = summary != null && onSelect != null;

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {order.map((cat) => {
        const meta = categoryMeta[cat];
        const label = t(`category.${cat}`);
        return (
          <Card
            key={cat}
            role={clickable ? "button" : undefined}
            tabIndex={clickable ? 0 : undefined}
            aria-disabled={!clickable}
            title={
              clickable ? (hint ?? t("dashboard.viewCategory", { category: label })) : undefined
            }
            onClick={clickable ? () => onSelect?.(cat) : undefined}
            onKeyDown={
              clickable
                ? (e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onSelect?.(cat);
                    }
                  }
                : undefined
            }
            className={cn(
              "group relative overflow-hidden border bg-card/60 backdrop-blur transition-all",
              summary && glowByCategory[cat],
              clickable &&
                "cursor-pointer hover:-translate-y-0.5 hover:border-primary/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70",
              !clickable && "cursor-default",
            )}
          >
            <CardContent className="flex items-center gap-4 p-4">
              <div
                className={cn(
                  "flex size-11 shrink-0 items-center justify-center rounded-lg border",
                  meta.badge,
                )}
              >
                <meta.icon className="size-5" />
              </div>
              <div className="min-w-0">
                <div className="text-2xl font-bold tabular-nums leading-none">
                  {summary ? values[cat] : "—"}
                </div>
                <div className="mt-1 truncate text-xs text-muted-foreground">{label}</div>
              </div>
              {clickable && (
                <ChevronRight className="ml-auto size-4 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100" />
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
