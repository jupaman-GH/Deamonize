import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { getProviderStatuses, setProviderKey } from "@/lib/api";
import { LANGUAGES, useI18n, type Lang, type TKey } from "@/lib/i18n";
import { useTheme } from "@/lib/theme";
import {
  checkForUpdate,
  installUpdate,
  isAutoUpdateEnabled,
  setAutoUpdateEnabled,
} from "@/lib/updater";
import { useAppVersion } from "@/lib/version";
import type { ProviderStatus } from "@/types";
import {
  CheckCircle2,
  CircleDashed,
  Download,
  Loader2,
  Moon,
  RefreshCw,
  Sun,
} from "lucide-react";

const fields: { provider: string; labelKey: TKey; placeholder: string; secret: boolean }[] = [
  {
    provider: "virustotal",
    labelKey: "settings.key.virustotal",
    placeholder: "vt-...",
    secret: true,
  },
  { provider: "web", labelKey: "settings.key.web", placeholder: "BSA...", secret: true },
  { provider: "ai", labelKey: "settings.key.ai", placeholder: "sk-...", secret: true },
  {
    provider: "ai_base_url",
    labelKey: "settings.key.aiBaseUrl",
    placeholder: "https://api.openai.com/v1",
    secret: false,
  },
  {
    provider: "ai_model",
    labelKey: "settings.key.aiModel",
    placeholder: "gpt-4o-mini",
    secret: false,
  },
];

export function SettingsPage() {
  const { t, lang, setLang } = useI18n();
  const { theme, setTheme } = useTheme();
  const [statuses, setStatuses] = useState<ProviderStatus[]>([]);
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const version = useAppVersion();
  const [autoUpdate, setAutoUpdate] = useState(isAutoUpdateEnabled());
  const [updateBusy, setUpdateBusy] = useState<"check" | "install" | null>(null);
  const [availableUpdate, setAvailableUpdate] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatuses(await getProviderStatuses());
    } catch (e) {
      toast.error(t("toast.statusLoadFailed"), { description: String(e) });
    }
  }, [t]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const onSave = async (provider: string) => {
    setBusy(provider);
    try {
      await setProviderKey(provider, values[provider] ?? "");
      toast.success(t("toast.saved"));
      setValues((v) => ({ ...v, [provider]: "" }));
      await refresh();
    } catch (e) {
      toast.error(t("toast.saveFailed"), { description: String(e) });
    } finally {
      setBusy(null);
    }
  };

  const onToggleAutoUpdate = (enabled: boolean) => {
    setAutoUpdate(enabled);
    setAutoUpdateEnabled(enabled);
  };

  const onCheckUpdate = async () => {
    setUpdateBusy("check");
    try {
      const result = await checkForUpdate();
      if (result === undefined) {
        toast.info(t("toast.updateUnavailable"));
      } else if (result === null) {
        setAvailableUpdate(null);
        toast.success(t("toast.updateNone"));
      } else {
        setAvailableUpdate(result.version);
        toast.info(t("toast.updateFound", { version: result.version }));
      }
    } finally {
      setUpdateBusy(null);
    }
  };

  const onInstallUpdate = async () => {
    setUpdateBusy("install");
    try {
      const ok = await installUpdate();
      if (ok) {
        toast.success(t("toast.updateInstalled"));
      } else {
        toast.error(t("toast.updateInstallFailed"));
      }
    } finally {
      setUpdateBusy(null);
    }
  };

  return (
    <div className="flex max-w-2xl flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>{t("settings.updateTitle")}</CardTitle>
          <CardDescription>{t("settings.updateDesc")}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="grid gap-0.5">
              <Label htmlFor="auto-update" className="cursor-pointer">
                {t("settings.autoUpdateLabel")}
              </Label>
              <span className="text-xs text-muted-foreground">
                {t("settings.autoUpdateHint")}
              </span>
            </div>
            <Switch
              id="auto-update"
              checked={autoUpdate}
              onCheckedChange={onToggleAutoUpdate}
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              onClick={() => void onCheckUpdate()}
              disabled={updateBusy !== null}
            >
              {updateBusy === "check" ? (
                <Loader2 className="animate-spin" />
              ) : (
                <RefreshCw />
              )}
              {t("settings.checkUpdate")}
            </Button>
            {availableUpdate && (
              <Button
                onClick={() => void onInstallUpdate()}
                disabled={updateBusy !== null}
                className="glow-primary"
              >
                {updateBusy === "install" ? (
                  <Loader2 className="animate-spin" />
                ) : (
                  <Download />
                )}
                {t("settings.installUpdate", { version: availableUpdate })}
              </Button>
            )}
            {version && (
              <Badge variant="secondary" className="ml-auto tabular-nums">
                {t("app.version", { version })}
              </Badge>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("settings.appearanceTitle")}</CardTitle>
          <CardDescription>{t("settings.appearanceDesc")}</CardDescription>
        </CardHeader>
        <CardContent className="flex gap-2">
          <Button
            variant={theme === "light" ? "default" : "outline"}
            onClick={() => setTheme("light")}
            aria-pressed={theme === "light"}
          >
            <Sun />
            {t("theme.light")}
          </Button>
          <Button
            variant={theme === "dark" ? "default" : "outline"}
            onClick={() => setTheme("dark")}
            aria-pressed={theme === "dark"}
          >
            <Moon />
            {t("theme.dark")}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("settings.languageTitle")}</CardTitle>
          <CardDescription>{t("settings.languageDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Select value={lang} onValueChange={(v) => setLang(v as Lang)}>
            <SelectTrigger className="w-[220px]" aria-label={t("settings.languageTitle")}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {LANGUAGES.map((l) => (
                <SelectItem key={l.code} value={l.code}>
                  <span aria-hidden className="text-base leading-none">
                    {l.flag}
                  </span>
                  {l.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("settings.externalTitle")}</CardTitle>
          <CardDescription>{t("settings.externalDesc")}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-wrap gap-2">
            {statuses.map((s) => (
              <Badge
                key={s.name}
                variant={s.configured ? "default" : "outline"}
                className="gap-1"
                title={s.description}
              >
                {s.configured ? (
                  <CheckCircle2 className="size-3" />
                ) : (
                  <CircleDashed className="size-3" />
                )}
                {s.name}
              </Badge>
            ))}
          </div>

          {fields.map((f) => (
            <div key={f.provider} className="flex flex-col gap-1.5">
              <Label htmlFor={f.provider}>{t(f.labelKey)}</Label>
              <div className="flex gap-2">
                <Input
                  id={f.provider}
                  type={f.secret ? "password" : "text"}
                  placeholder={f.placeholder}
                  value={values[f.provider] ?? ""}
                  onChange={(e) =>
                    setValues((v) => ({ ...v, [f.provider]: e.target.value }))
                  }
                  className="font-mono"
                />
                <Button
                  variant="outline"
                  onClick={() => void onSave(f.provider)}
                  disabled={busy === f.provider}
                >
                  {t("button.save")}
                </Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
