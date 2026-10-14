import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { VerdictBadge } from "@/components/verdict-badge";
import { addRule, deleteRule, listRules, toggleRule } from "@/lib/api";
import { useI18n, type TKey } from "@/lib/i18n";
import type { Rule, VerdictCategory } from "@/types";
import { Plus, Trash2 } from "lucide-react";

const kindOptions: { value: string; labelKey: TKey }[] = [
  { value: "name", labelKey: "rule.kind.name" },
  { value: "path", labelKey: "rule.kind.path" },
  { value: "signer", labelKey: "rule.kind.signer" },
  { value: "hash", labelKey: "rule.kind.hash" },
];

const categoryOptions: { value: VerdictCategory; labelKey: TKey }[] = [
  { value: "safe", labelKey: "category.safe" },
  { value: "suspicious", labelKey: "category.suspicious" },
  { value: "dangerous", labelKey: "category.dangerous" },
];

export function RulesPage() {
  const { t } = useI18n();
  const [rules, setRules] = useState<Rule[]>([]);
  const [kind, setKind] = useState("name");
  const [pattern, setPattern] = useState("");
  const [category, setCategory] = useState<VerdictCategory>("safe");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setRules(await listRules());
    } catch (e) {
      toast.error(t("toast.ruleLoadFailed"), { description: String(e) });
    }
  }, [t]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const onAdd = async () => {
    if (!pattern.trim()) {
      toast.warning(t("toast.rulePatternRequired"));
      return;
    }
    setBusy(true);
    try {
      await addRule(kind, pattern.trim(), category, note.trim() || undefined);
      setPattern("");
      setNote("");
      toast.success(t("toast.ruleAdded"));
      await refresh();
    } catch (e) {
      toast.error(t("toast.ruleAddFailed"), { description: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const onToggle = async (rule: Rule) => {
    try {
      await toggleRule(rule.id, !rule.enabled);
      await refresh();
    } catch (e) {
      toast.error(t("toast.ruleToggleFailed"), { description: String(e) });
    }
  };

  const onDelete = async (rule: Rule) => {
    try {
      await deleteRule(rule.id);
      toast.success(t("toast.ruleDeleted"));
      await refresh();
    } catch (e) {
      toast.error(t("toast.ruleDeleteFailed"), { description: String(e) });
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardContent className="grid gap-3 p-4 md:grid-cols-[140px_1fr_150px_1fr_auto] md:items-end">
          <div className="flex flex-col gap-1.5">
            <Label>{t("rule.field.kind")}</Label>
            <Select value={kind} onValueChange={setKind}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {kindOptions.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {t(o.labelKey)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>{t("rule.field.pattern")}</Label>
            <Input
              placeholder={kind === "hash" ? t("rule.placeholder.hash") : t("rule.placeholder.name")}
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              className="font-mono"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>{t("th.category")}</Label>
            <Select
              value={category}
              onValueChange={(v) => setCategory(v as VerdictCategory)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {categoryOptions.map((o) => (
                  <SelectItem key={o.value} value={o.value}>
                    {t(o.labelKey)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>{t("rule.field.note")}</Label>
            <Input
              placeholder={t("rule.placeholder.note")}
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </div>
          <Button onClick={() => void onAdd()} disabled={busy}>
            <Plus />
            {t("rule.add")}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100vh-360px)]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("rule.field.kind")}</TableHead>
                  <TableHead>{t("rule.field.pattern")}</TableHead>
                  <TableHead>{t("th.category")}</TableHead>
                  <TableHead>{t("th.note")}</TableHead>
                  <TableHead>{t("th.enabled")}</TableHead>
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id} className={rule.enabled ? "" : "opacity-50"}>
                    <TableCell>
                      <Badge variant="secondary" className="font-mono text-[10px]">
                        {rule.kind}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-[220px] truncate font-mono text-xs">
                      {rule.pattern}
                    </TableCell>
                    <TableCell>
                      <VerdictBadge category={rule.category} />
                    </TableCell>
                    <TableCell className="max-w-[200px] truncate text-xs text-muted-foreground">
                      {rule.note ?? "—"}
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={rule.enabled}
                        onCheckedChange={() => void onToggle(rule)}
                      />
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-7 text-muted-foreground hover:text-destructive"
                        onClick={() => void onDelete(rule)}
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {rules.length === 0 && (
              <div className="p-6 text-center text-sm text-muted-foreground">
                {t("rule.empty")}
              </div>
            )}
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
