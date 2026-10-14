import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { HashRow, VerdictDetail } from "@/components/verdict-detail";
import { VerdictBadge } from "@/components/verdict-badge";
import { useScan } from "@/lib/scan-context";
import { useI18n, type TKey } from "@/lib/i18n";
import type { ExternalLookupResult, ScanEntry, VerdictCategory } from "@/types";
import { lookupExternal } from "@/lib/api";
import { Search, Globe } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

const filters: { value: VerdictCategory | "all"; labelKey: TKey }[] = [
  { value: "all", labelKey: "filter.all" },
  { value: "safe", labelKey: "filter.safe" },
  { value: "suspicious", labelKey: "filter.suspicious" },
  { value: "dangerous", labelKey: "filter.dangerous" },
  { value: "unknown", labelKey: "filter.unknown" },
];

function DetailSheet({
  entry,
  open,
  onOpenChange,
}: {
  entry: ScanEntry | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const [external, setExternal] = useState<ExternalLookupResult | null>(null);
  const [lookupBusy, setLookupBusy] = useState(false);
  const { t } = useI18n();

  const onLookup = async () => {
    if (!entry) return;
    setLookupBusy(true);
    try {
      const res = await lookupExternal(entry.service.name);
      setExternal(res);
      toast.success(t("toast.lookupDone"), { description: res.summary });
    } catch (e) {
      toast.error(t("toast.lookupFailed"), { description: String(e) });
    } finally {
      setLookupBusy(false);
    }
  };

  if (!entry) return null;
  const { service, verdict } = entry;
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="flex w-full flex-col gap-4 overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle className="font-mono">{service.name}</SheetTitle>
          <SheetDescription>{service.displayName}</SheetDescription>
        </SheetHeader>

        <VerdictDetail verdict={external
          ? {
              service: service.name,
              category: external.category,
              confidence: external.confidence,
              reasons: [
                { code: "external", message: external.summary, detail: external.sourceUrl ?? undefined, weight: 0 },
                ...external.steps.map((s) => ({
                  code: `step.${s.provider}`,
                  message: `${s.provider}: ${s.detail} (${s.elapsedMs} ms)`,
                  weight: 0,
                })),
              ],
              source: external.source,
              sourceUrl: external.sourceUrl,
              createdAt: new Date().toISOString(),
            }
          : verdict}
        />

        <Button variant="outline" size="sm" onClick={() => void onLookup()} disabled={lookupBusy}>
          <Globe />
          {lookupBusy ? t("services.lookupBusy") : t("services.lookup")}
        </Button>

        <div className="flex flex-col gap-3 text-xs">
          {service.description && (
            <p className="text-muted-foreground">{service.description}</p>
          )}
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
            <dt className="text-muted-foreground">{t("th.status")}</dt>
            <dd>{t(`status.${service.status}`)}</dd>
            <dt className="text-muted-foreground">{t("th.startup")}</dt>
            <dd>{t(`start.${service.startType}`)}</dd>
            <dt className="text-muted-foreground">{t("detail.account")}</dt>
            <dd className="font-mono">{service.account ?? "—"}</dd>
            <dt className="text-muted-foreground">{t("detail.signature")}</dt>
            <dd>
              {service.signed === null
                ? "—"
                : service.signed
                  ? t("detail.signedYes", {
                      signer: service.signer ?? t("detail.noIssuer"),
                    })
                  : t("detail.signedNo")}
            </dd>
            <dt className="text-muted-foreground">{t("th.company")}</dt>
            <dd>{service.company ?? "—"}</dd>
            <dt className="text-muted-foreground">{t("detail.product")}</dt>
            <dd>{service.product ?? "—"}</dd>
            <dt className="text-muted-foreground">{t("detail.binary")}</dt>
            <dd className="break-all font-mono text-[11px]">
              {service.exePath ?? service.binPath ?? "—"}
            </dd>
          </dl>
          <HashRow hash={service.sha256} />
          {service.dependencies.length > 0 && (
            <div>
              <p className="mb-1 text-muted-foreground">{t("detail.dependencies")}</p>
              <div className="flex flex-wrap gap-1">
                {service.dependencies.map((d) => (
                  <Badge key={d} variant="secondary" className="font-mono text-[10px]">
                    {d}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

export function ServicesPage({
  categoryFilter,
}: {
  categoryFilter?: VerdictCategory | "all";
}) {
  const { entries, scanning } = useScan();
  const { t } = useI18n();
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<VerdictCategory | "all">(
    categoryFilter ?? "all",
  );
  const [selected, setSelected] = useState<ScanEntry | null>(null);
  const [sheetOpen, setSheetOpen] = useState(false);

  // Mirror the category clicked on the Dashboard.
  useEffect(() => {
    setCategory(categoryFilter ?? "all");
  }, [categoryFilter]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries.filter((e) => {
      if (category !== "all" && e.verdict.category !== category) return false;
      if (!q) return true;
      return (
        e.service.name.toLowerCase().includes(q) ||
        e.service.displayName.toLowerCase().includes(q) ||
        (e.service.company ?? "").toLowerCase().includes(q)
      );
    });
  }, [entries, query, category]);

  if (!entries.length && !scanning) {
    return (
      <Card>
        <CardContent>
          <Empty>
            <EmptyHeader>
              <EmptyTitle>{t("services.emptyTitle")}</EmptyTitle>
              <EmptyDescription>{t("services.emptyDesc")}</EmptyDescription>
            </EmptyHeader>
          </Empty>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
          <Input
            placeholder={t("services.search")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8"
          />
        </div>
        <Select
          value={category}
          onValueChange={(v) => setCategory(v as VerdictCategory | "all")}
        >
          <SelectTrigger className="w-[190px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {filters.map((f) => (
              <SelectItem key={f.value} value={f.value}>
                {t(f.labelKey)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardContent className="p-0">
          {scanning ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 8 }).map((_, i) => (
                <Skeleton key={i} className="h-9" />
              ))}
            </div>
          ) : (
            <ScrollArea className="h-[calc(100vh-320px)]">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("th.service")}</TableHead>
                    <TableHead className="hidden md:table-cell">{t("th.startup")}</TableHead>
                    <TableHead className="hidden md:table-cell">{t("th.status")}</TableHead>
                    <TableHead className="hidden lg:table-cell">{t("th.company")}</TableHead>
                    <TableHead className="text-right">{t("th.category")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((e) => (
                    <TableRow
                      key={e.service.name}
                      className="cursor-pointer"
                      onClick={() => {
                        setSelected(e);
                        setSheetOpen(true);
                      }}
                    >
                      <TableCell>
                        <div className="font-mono text-xs">{e.service.name}</div>
                        <div className="text-[11px] text-muted-foreground">
                          {e.service.displayName}
                        </div>
                      </TableCell>
                      <TableCell className="hidden text-xs md:table-cell">
                        {t(`start.${e.service.startType}`)}
                      </TableCell>
                      <TableCell className="hidden text-xs md:table-cell">
                        {t(`status.${e.service.status}`)}
                      </TableCell>
                      <TableCell className="hidden max-w-[160px] truncate text-xs lg:table-cell">
                        {e.service.company ?? e.service.signer ?? "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        <VerdictBadge category={e.verdict.category} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {filtered.length === 0 && (
                <div className="p-6 text-center text-sm text-muted-foreground">
                  {t("services.noMatch")}
                </div>
              )}
            </ScrollArea>
          )}
        </CardContent>
      </Card>

      <DetailSheet entry={selected} open={sheetOpen} onOpenChange={setSheetOpen} />
    </div>
  );
}
