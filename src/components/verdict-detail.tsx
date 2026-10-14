import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { categoryMeta } from "@/lib/labels";
import type { Verdict, VerdictReason } from "@/types";
import { cn } from "@/lib/utils";
import { useI18n } from "@/lib/i18n";
import { ExternalLink, Hash, Info, ShieldCheck } from "lucide-react";

function ReasonRow({ reason }: { reason: VerdictReason }) {
  const { tReason } = useI18n();
  const positive = reason.weight < 0;
  const neutral = reason.weight === 0;
  return (
    <li
      className={cn(
        "flex items-start gap-2 rounded-md border p-2 text-xs",
        neutral
          ? "border-border bg-muted/30"
          : positive
            ? "border-safe/30 bg-safe/5"
            : "border-suspicious/30 bg-suspicious/5",
      )}
    >
      <Info
        className={cn(
          "mt-0.5 size-3.5 shrink-0",
          neutral ? "text-unknown" : positive ? "text-safe" : "text-suspicious",
        )}
      />
      <div className="min-w-0">
        <p>{tReason(reason.code, reason.message)}</p>
        {reason.detail && (
          <p className="mt-0.5 break-all font-mono text-[11px] text-muted-foreground">
            {reason.detail}
          </p>
        )}
      </div>
    </li>
  );
}

export function VerdictDetail({ verdict }: { verdict: Verdict }) {
  const { t } = useI18n();
  const meta = categoryMeta[verdict.category];
  return (
    <Card className={cn("border", meta.badge.split(" ")[2])}>
      <CardContent className="flex flex-col gap-3 p-4">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <meta.icon className={cn("size-5", meta.color)} />
            <span className={cn("font-semibold", meta.color)}>
              {t(`category.${verdict.category}`)}
            </span>
          </div>
          <Badge variant="secondary" className="font-mono text-[10px]">
            {t("verdict.confidence", { pct: (verdict.confidence * 100).toFixed(0) })}
          </Badge>
        </div>

        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <ShieldCheck className="size-3.5" />
          <span>
            {t("verdict.source")} <span className="font-medium">{verdict.source}</span>
          </span>
          {verdict.sourceUrl && (
            <a
              href={verdict.sourceUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              {t("verdict.reference")} <ExternalLink className="size-3" />
            </a>
          )}
        </div>

        {verdict.reasons.length > 0 && (
          <div>
            <p className="mb-1.5 text-xs font-medium text-muted-foreground">
              {t("verdict.reasons")}
            </p>
            <ul className="flex flex-col gap-1.5">
              {verdict.reasons.map((r, i) => (
                <ReasonRow key={i} reason={r} />
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function HashRow({ hash }: { hash: string | null }) {
  if (!hash) return null;
  return (
    <div className="flex items-start gap-2 text-xs">
      <Hash className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
      <div className="min-w-0">
        <p className="text-muted-foreground">SHA-256</p>
        <p className="break-all font-mono text-[11px]">{hash}</p>
      </div>
    </div>
  );
}
