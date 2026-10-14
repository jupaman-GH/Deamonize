import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { exportReportHtml, exportReportJson } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import { FileText, FileJson, Download } from "lucide-react";

/** Saves text to a file via a browser download. */
function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function ReportsPage() {
  const { t } = useI18n();
  const [preview, setPreview] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onPreview = async () => {
    setBusy(true);
    try {
      setPreview(await exportReportHtml());
    } catch (e) {
      toast.error(t("toast.reportGenerateFailed"), { description: String(e) });
    } finally {
      setBusy(false);
    }
  };

  const onExportHtml = async () => {
    try {
      const html = await exportReportHtml();
      download(`deamonize-reporte-${Date.now()}.html`, html, "text/html");
      toast.success(t("toast.reportHtmlExported"));
    } catch (e) {
      toast.error(t("toast.reportExportFailed"), { description: String(e) });
    }
  };

  const onExportJson = async () => {
    try {
      const json = await exportReportJson();
      download(`deamonize-reporte-${Date.now()}.json`, json, "application/json");
      toast.success(t("toast.reportJsonExported"));
    } catch (e) {
      toast.error(t("toast.reportExportFailed"), { description: String(e) });
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{t("reports.exportTitle")}</CardTitle>
          <CardDescription>{t("reports.exportDesc")}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button onClick={() => void onPreview()} disabled={busy}>
            <FileText />
            {t("reports.preview")}
          </Button>
          <Button variant="outline" onClick={() => void onExportHtml()}>
            <Download />
            {t("reports.exportHtml")}
          </Button>
          <Button variant="outline" onClick={() => void onExportJson()}>
            <FileJson />
            {t("reports.exportJson")}
          </Button>
        </CardContent>
      </Card>

      {preview ? (
        <Card>
          <CardContent className="p-0">
            <iframe
              title={t("reports.previewTitle")}
              srcDoc={preview}
              className="h-[calc(100vh-360px)] w-full rounded-lg border"
            />
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent>
            <Empty>
              <EmptyHeader>
                <EmptyTitle>{t("reports.emptyTitle")}</EmptyTitle>
                <EmptyDescription>{t("reports.emptyDesc")}</EmptyDescription>
              </EmptyHeader>
            </Empty>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
