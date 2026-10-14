import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { clearCache, diffScans, getCacheStats, getScanHistory } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import type { CacheStats, ScanDiff, ScanSummary } from "@/types";
import { Database, Trash2 } from "lucide-react";

export function CachePage() {
  const { t } = useI18n();
  const [stats, setStats] = useState<CacheStats | null>(null);
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [scanA, setScanA] = useState<number | null>(null);
  const [scanB, setScanB] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [s, h] = await Promise.all([getCacheStats(), getScanHistory()]);
      setStats(s);
      setHistory(h);
    } catch (e) {
      toast.error(t("toast.cacheLoadFailed"), { description: String(e) });
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const onDiff = async () => {
    if (scanA == null || scanB == null) {
      toast.warning(t("toast.cacheSelectTwo"));
      return;
    }
    try {
      setDiff(await diffScans(scanA, scanB));
    } catch (e) {
      toast.error(t("toast.cacheDiffFailed"), { description: String(e) });
    }
  };

  const onClear = async () => {
    try {
      const n = await clearCache();
      toast.success(t("toast.cacheCleared", { n }));
      await refresh();
    } catch (e) {
      toast.error(t("toast.cacheClearFailed"), { description: String(e) });
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col gap-4">
        <Skeleton className="h-20" />
        <Skeleton className="h-60" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Database className="size-5 text-primary" />
            <div>
              <div className="text-2xl font-bold tabular-nums">{stats?.entries ?? 0}</div>
              <div className="text-xs text-muted-foreground">{t("cache.entries")}</div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold tabular-nums text-suspicious">
              {stats?.expired ?? 0}
            </div>
            <div className="text-xs text-muted-foreground">{t("cache.expired")}</div>
          </CardContent>
        </Card>
        <Card className="flex items-center justify-between p-4">
          <CardContent className="p-0">
            <div className="text-xs text-muted-foreground">
              {t("cache.oldest")}{" "}
              {stats?.oldestFetchedAt
                ? new Date(stats.oldestFetchedAt).toLocaleDateString()
                : "—"}
            </div>
            <div className="text-xs text-muted-foreground">
              {t("cache.newest")}{" "}
              {stats?.newestFetchedAt
                ? new Date(stats.newestFetchedAt).toLocaleDateString()
                : "—"}
            </div>
          </CardContent>
          <Button variant="outline" size="sm" onClick={() => void onClear()}>
            <Trash2 />
            {t("cache.clear")}
          </Button>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("cache.history")}</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>{t("th.date")}</TableHead>
                <TableHead>{t("th.services")}</TableHead>
                <TableHead>{t("th.compare")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {history.map((h) => (
                <TableRow key={h.scanId}>
                  <TableCell className="font-mono text-xs">#{h.scanId}</TableCell>
                  <TableCell className="text-xs">
                    {new Date(h.finishedAt).toLocaleString()}
                  </TableCell>
                  <TableCell className="tabular-nums">{h.total}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Badge
                        variant={scanA === h.scanId ? "default" : "outline"}
                        className="cursor-pointer"
                        onClick={() => setScanA(h.scanId)}
                      >
                        A
                      </Badge>
                      <Badge
                        variant={scanB === h.scanId ? "default" : "outline"}
                        className="cursor-pointer"
                        onClick={() => setScanB(h.scanId)}
                      >
                        B
                      </Badge>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {history.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-sm text-muted-foreground">
                    {t("cache.noScans")}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <div className="flex items-center gap-2 p-4">
            <Button onClick={() => void onDiff()} disabled={scanA == null || scanB == null}>
              {t("cache.compare")}
            </Button>
          </div>
        </CardContent>
      </Card>

      {diff && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t("cache.diffTitle", { a: diff.scanA, b: diff.scanB })}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 text-sm">
            <div className="flex flex-wrap gap-4">
              <span className="text-safe">{t("cache.added", { n: diff.added.length })}</span>
              <span className="text-dangerous">{t("cache.removed", { n: diff.removed.length })}</span>
              <span className="text-suspicious">{t("cache.changed", { n: diff.changed.length })}</span>
            </div>
            {diff.changed.length > 0 && (
              <ul className="flex flex-col gap-1 text-xs">
                {diff.changed.map((c) => (
                  <li key={c.service} className="font-mono">
                    {c.service}: {c.fromCategory} → {c.toCategory}
                    {c.hashChanged && ` ${t("cache.hashChanged")}`}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
