import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type Lang = "es" | "en";

/** Available languages. The flag is rendered next to the option in Ajustes. */
export const LANGUAGES: { code: Lang; label: string; flag: string }[] = [
  { code: "es", label: "Español", flag: "🇪🇸" },
  { code: "en", label: "English", flag: "🇬🇧" },
];

const es = {
  // ---- App chrome ----
  "page.dashboard.title": "Dashboard",
  "page.dashboard.subtitle": "Resumen del estado de los servicios",
  "page.services.title": "Servicios",
  "page.services.subtitle": "Detalle completo de los servicios del sistema",
  "page.rules.title": "Reglas",
  "page.rules.subtitle": "Listas blancas, negras y grises del motor de clasificación",
  "page.cache.title": "Caché",
  "page.cache.subtitle": "Resultados en caché y su vigencia",
  "page.reports.title": "Reportes",
  "page.reports.subtitle": "Exportación de resultados con evidencia y fuentes",
  "page.settings.title": "Ajustes",
  "page.settings.subtitle": "Consultas externas, claves API y preferencias",

  // ---- Sidebar ----
  "app.tagline": "Analizador de servicios",
  "app.version": "Versión {version}",
  "nav.analysis": "Análisis",
  "nav.dashboard": "Dashboard",
  "nav.services": "Servicios",
  "nav.rules": "Reglas",
  "nav.cache": "Caché",
  "nav.reports": "Reportes",
  "nav.settings": "Ajustes",

  // ---- Verdict categories & filters ----
  "category.safe": "Seguro",
  "category.suspicious": "Sospechoso",
  "category.dangerous": "Peligroso",
  "category.unknown": "Desconocido",
  "filter.all": "Todas las categorías",
  "filter.safe": "Seguros",
  "filter.suspicious": "Sospechosos",
  "filter.dangerous": "Peligrosos",
  "filter.unknown": "Desconocidos",

  // ---- Service status / start type ----
  "status.running": "En ejecución",
  "status.stopped": "Detenido",
  "status.start_pending": "Iniciando",
  "status.stop_pending": "Deteniendo",
  "status.continue_pending": "Reanudando",
  "status.pause_pending": "Pausando",
  "status.paused": "Pausado",
  "status.unknown": "Desconocido",
  "start.boot": "Arranque",
  "start.system": "Sistema",
  "start.auto": "Automático",
  "start.delayed_auto": "Automático (retrasado)",
  "start.demand": "Manual",
  "start.disabled": "Deshabilitado",
  "start.unknown": "Desconocido",

  // ---- Dashboard ----
  "dashboard.heading": "Estado del sistema",
  "dashboard.lastScan": "Último escaneo: {date}",
  "dashboard.noScan": "Aún no se ha ejecutado ningún escaneo",
  "dashboard.scanNow": "Escanear ahora",
  "dashboard.scanning": "Escaneando...",
  "dashboard.analyzing": "Analizando servicios, hashes y firmas...",
  "dashboard.viewCategory": "Ver los servicios {category} en Servicios",
  "dashboard.scanFirstTitle": "Escanea antes de filtrar",
  "dashboard.scanFirstDesc":
    "Aún no se han cargado servicios en esta sesión. Pulsa «Escanear ahora» para analizar el sistema y poder filtrar por categoría.",
  "dashboard.scanFirstHint": "Escanea el sistema para poder filtrar los servicios",
  "toast.scanCompleted": "Escaneo completado",
  "toast.scanCompletedDesc": "{total} servicios analizados en {secs}s",
  "toast.scanFailed": "Error al escanear",

  // ---- Services ----
  "services.search": "Buscar por nombre, empresa...",
  "services.emptyTitle": "Sin resultados todavía",
  "services.emptyDesc": "Ejecuta un escaneo desde el Dashboard para ver y clasificar los servicios.",
  "services.noMatch": "Ningún servicio coincide con el filtro.",
  "th.service": "Servicio",
  "th.startup": "Inicio",
  "th.status": "Estado",
  "th.company": "Empresa",
  "th.category": "Categoría",
  "detail.account": "Cuenta",
  "detail.signature": "Firma",
  "detail.signedYes": "Sí ({signer})",
  "detail.noIssuer": "sin emisor",
  "detail.signedNo": "No firmado",
  "detail.product": "Producto",
  "detail.binary": "Binario",
  "detail.dependencies": "Dependencias",
  "services.lookup": "Consultar fuentes externas",
  "services.lookupBusy": "Consultando fuentes...",
  "toast.lookupDone": "Consulta externa completada",
  "toast.lookupFailed": "Fallo en la consulta externa",

  // ---- Rules ----
  "rule.kind.name": "Nombre de servicio",
  "rule.kind.path": "Ruta del binario",
  "rule.kind.signer": "Firmante",
  "rule.kind.hash": "SHA-256",
  "rule.field.kind": "Tipo",
  "rule.field.pattern": "Patrón",
  "rule.field.note": "Nota (opcional)",
  "th.note": "Nota",
  "th.enabled": "Activa",
  "rule.placeholder.hash": "hash sha256...",
  "rule.placeholder.name": "ej. MiServicio",
  "rule.placeholder.note": "contexto o referencia",
  "rule.add": "Añadir",
  "rule.empty": "No hay reglas cargadas.",
  "toast.rulePatternRequired": "Indica el patrón de la regla",
  "toast.ruleAdded": "Regla añadida",
  "toast.ruleAddFailed": "No se pudo añadir la regla",
  "toast.ruleLoadFailed": "No se pudieron cargar las reglas",
  "toast.ruleToggleFailed": "No se pudo cambiar la regla",
  "toast.ruleDeleted": "Regla eliminada",
  "toast.ruleDeleteFailed": "No se pudo eliminar la regla",

  // ---- Cache ----
  "cache.entries": "Entradas en caché",
  "cache.expired": "Caducadas (TTL vencido)",
  "cache.oldest": "Más antigua:",
  "cache.newest": "Más reciente:",
  "cache.clear": "Limpiar",
  "cache.history": "Historial de escaneos",
  "th.date": "Fecha",
  "th.services": "Servicios",
  "th.compare": "Comparar",
  "cache.noScans": "Sin escaneos registrados.",
  "cache.compare": "Comparar A y B",
  "cache.diffTitle": "Diferencia #{a} → #{b}",
  "cache.added": "+ {n} añadidos",
  "cache.removed": "- {n} eliminados",
  "cache.changed": "~ {n} cambiados",
  "cache.hashChanged": "(hash modificado)",
  "toast.cacheLoadFailed": "No se pudo cargar la caché",
  "toast.cacheCleared": "{n} entradas de caché eliminadas",
  "toast.cacheClearFailed": "No se pudo limpiar la caché",
  "toast.cacheSelectTwo": "Selecciona dos escaneos para comparar",
  "toast.cacheDiffFailed": "No se pudo comparar",

  // ---- Reports ----
  "reports.exportTitle": "Exportar resultados",
  "reports.exportDesc":
    "Genera un reporte con la evidencia y las fuentes de cada veredicto del último escaneo. El HTML es autocontenido (se puede compartir); el JSON es legible por máquina.",
  "reports.preview": "Vista previa",
  "reports.exportHtml": "Exportar HTML",
  "reports.exportJson": "Exportar JSON",
  "reports.previewTitle": "Vista previa del reporte",
  "reports.emptyTitle": "Sin vista previa",
  "reports.emptyDesc": "Pulsa «Vista previa» para visualizar el reporte antes de exportarlo.",
  "toast.reportGenerateFailed": "No se pudo generar el reporte",
  "toast.reportHtmlExported": "Reporte HTML exportado",
  "toast.reportJsonExported": "Reporte JSON exportado",
  "toast.reportExportFailed": "Error al exportar",

  // ---- Settings ----
  "settings.appearanceTitle": "Apariencia",
  "settings.appearanceDesc":
    "Cambia entre el tema claro y el oscuro. La preferencia se guarda en este equipo.",
  "theme.light": "Claro",
  "theme.dark": "Oscuro",
  "settings.languageTitle": "Idioma",
  "settings.languageDesc":
    "Idioma de la interfaz. Cada opción muestra la bandera de su país.",
  "settings.externalTitle": "Consultas externas",
  "settings.externalDesc":
    "Deamonize funciona 100% sin conexión. Configura estas claves para habilitar la escalación VirusTotal → Búsqueda web → IA, que solo se usa cuando la confianza local es baja. Las claves se guardan localmente en tu equipo.",
  "settings.key.virustotal": "Clave API de VirusTotal",
  "settings.key.web": "Clave API de Brave Search",
  "settings.key.ai": "Clave API de IA",
  "settings.key.aiBaseUrl": "Base URL de IA (opcional)",
  "settings.key.aiModel": "Modelo de IA (opcional)",
  "button.save": "Guardar",
  "toast.saved": "Guardado",
  "toast.saveFailed": "No se pudo guardar",
  "toast.statusLoadFailed": "No se pudo cargar el estado",

  // ---- Updates ----
  "settings.updateTitle": "Actualizaciones",
  "settings.updateDesc":
    "Deamonize se actualiza desde su repositorio oficial de GitHub. Activa la actualización automática para comprobar si hay una versión nueva cada vez que abres la app.",
  "settings.autoUpdateLabel": "Actualización automática",
  "settings.autoUpdateHint": "Busca nuevas versiones en GitHub al iniciar la aplicación.",
  "settings.checkUpdate": "Buscar actualizaciones",
  "settings.installUpdate": "Instalar v{version}",
  "toast.updateNone": "Tienes la última versión",
  "toast.updateFound": "Nueva versión disponible: v{version}",
  "toast.updateInstalled": "Actualización instalada. Reinicia la aplicación para aplicarla.",
  "toast.updateInstallFailed": "No se pudo instalar la actualización",
  "toast.updateUnavailable": "No se pudo consultar el repositorio de actualizaciones",

  // ---- Verdict detail ----
  "verdict.confidence": "confianza {pct}%",
  "verdict.source": "Fuente:",
  "verdict.reference": "referencia",
  "verdict.reasons": "Razones del veredicto",

  // ---- Window controls ----
  "win.minimize": "Minimizar",
  "win.maximize": "Maximizar",
  "win.restore": "Restaurar",
  "win.close": "Cerrar",
} as const;

export type TKey = keyof typeof es;

const en: Record<TKey, string> = {
  // ---- App chrome ----
  "page.dashboard.title": "Dashboard",
  "page.dashboard.subtitle": "Overview of service health",
  "page.services.title": "Services",
  "page.services.subtitle": "Complete detail of the system's services",
  "page.rules.title": "Rules",
  "page.rules.subtitle": "Whitelist, blacklist and greylist of the classification engine",
  "page.cache.title": "Cache",
  "page.cache.subtitle": "Cached results and their freshness",
  "page.reports.title": "Reports",
  "page.reports.subtitle": "Export results with evidence and sources",
  "page.settings.title": "Settings",
  "page.settings.subtitle": "External lookups, API keys and preferences",

  // ---- Sidebar ----
  "app.tagline": "Service analyzer",
  "app.version": "Version {version}",
  "nav.analysis": "Analysis",
  "nav.dashboard": "Dashboard",
  "nav.services": "Services",
  "nav.rules": "Rules",
  "nav.cache": "Cache",
  "nav.reports": "Reports",
  "nav.settings": "Settings",

  // ---- Verdict categories & filters ----
  "category.safe": "Safe",
  "category.suspicious": "Suspicious",
  "category.dangerous": "Dangerous",
  "category.unknown": "Unknown",
  "filter.all": "All categories",
  "filter.safe": "Safe",
  "filter.suspicious": "Suspicious",
  "filter.dangerous": "Dangerous",
  "filter.unknown": "Unknown",

  // ---- Service status / start type ----
  "status.running": "Running",
  "status.stopped": "Stopped",
  "status.start_pending": "Starting",
  "status.stop_pending": "Stopping",
  "status.continue_pending": "Resuming",
  "status.pause_pending": "Pausing",
  "status.paused": "Paused",
  "status.unknown": "Unknown",
  "start.boot": "Boot",
  "start.system": "System",
  "start.auto": "Automatic",
  "start.delayed_auto": "Automatic (delayed)",
  "start.demand": "Manual",
  "start.disabled": "Disabled",
  "start.unknown": "Unknown",

  // ---- Dashboard ----
  "dashboard.heading": "System status",
  "dashboard.lastScan": "Last scan: {date}",
  "dashboard.noScan": "No scan has been run yet",
  "dashboard.scanNow": "Scan now",
  "dashboard.scanning": "Scanning...",
  "dashboard.analyzing": "Analyzing services, hashes and signatures...",
  "dashboard.viewCategory": "View the {category} services in Services",
  "dashboard.scanFirstTitle": "Scan before filtering",
  "dashboard.scanFirstDesc":
    "No services have been loaded in this session. Press “Scan now” to analyze the system so you can filter by category.",
  "dashboard.scanFirstHint": "Scan the system to filter services",
  "toast.scanCompleted": "Scan completed",
  "toast.scanCompletedDesc": "{total} services analyzed in {secs}s",
  "toast.scanFailed": "Scan failed",

  // ---- Services ----
  "services.search": "Search by name, company...",
  "services.emptyTitle": "No results yet",
  "services.emptyDesc": "Run a scan from the Dashboard to view and classify services.",
  "services.noMatch": "No service matches the filter.",
  "th.service": "Service",
  "th.startup": "Startup",
  "th.status": "Status",
  "th.company": "Company",
  "th.category": "Category",
  "detail.account": "Account",
  "detail.signature": "Signature",
  "detail.signedYes": "Yes ({signer})",
  "detail.noIssuer": "no issuer",
  "detail.signedNo": "Unsigned",
  "detail.product": "Product",
  "detail.binary": "Binary",
  "detail.dependencies": "Dependencies",
  "services.lookup": "Check external sources",
  "services.lookupBusy": "Querying sources...",
  "toast.lookupDone": "External lookup completed",
  "toast.lookupFailed": "External lookup failed",

  // ---- Rules ----
  "rule.kind.name": "Service name",
  "rule.kind.path": "Binary path",
  "rule.kind.signer": "Signer",
  "rule.kind.hash": "SHA-256",
  "rule.field.kind": "Type",
  "rule.field.pattern": "Pattern",
  "rule.field.note": "Note (optional)",
  "th.note": "Note",
  "th.enabled": "Enabled",
  "rule.placeholder.hash": "sha256 hash...",
  "rule.placeholder.name": "e.g. MyService",
  "rule.placeholder.note": "context or reference",
  "rule.add": "Add",
  "rule.empty": "No rules loaded.",
  "toast.rulePatternRequired": "Enter the rule pattern",
  "toast.ruleAdded": "Rule added",
  "toast.ruleAddFailed": "Could not add the rule",
  "toast.ruleLoadFailed": "Could not load rules",
  "toast.ruleToggleFailed": "Could not toggle the rule",
  "toast.ruleDeleted": "Rule deleted",
  "toast.ruleDeleteFailed": "Could not delete the rule",

  // ---- Cache ----
  "cache.entries": "Cache entries",
  "cache.expired": "Expired (TTL elapsed)",
  "cache.oldest": "Oldest:",
  "cache.newest": "Newest:",
  "cache.clear": "Clear",
  "cache.history": "Scan history",
  "th.date": "Date",
  "th.services": "Services",
  "th.compare": "Compare",
  "cache.noScans": "No scans recorded.",
  "cache.compare": "Compare A and B",
  "cache.diffTitle": "Difference #{a} → #{b}",
  "cache.added": "+ {n} added",
  "cache.removed": "- {n} removed",
  "cache.changed": "~ {n} changed",
  "cache.hashChanged": "(hash changed)",
  "toast.cacheLoadFailed": "Could not load the cache",
  "toast.cacheCleared": "{n} cache entries cleared",
  "toast.cacheClearFailed": "Could not clear the cache",
  "toast.cacheSelectTwo": "Select two scans to compare",
  "toast.cacheDiffFailed": "Comparison failed",

  // ---- Reports ----
  "reports.exportTitle": "Export results",
  "reports.exportDesc":
    "Generate a report with the evidence and sources of every verdict from the last scan. The HTML is self-contained (shareable); the JSON is machine-readable.",
  "reports.preview": "Preview",
  "reports.exportHtml": "Export HTML",
  "reports.exportJson": "Export JSON",
  "reports.previewTitle": "Report preview",
  "reports.emptyTitle": "No preview",
  "reports.emptyDesc": "Press «Preview» to view the report before exporting it.",
  "toast.reportGenerateFailed": "Could not generate the report",
  "toast.reportHtmlExported": "HTML report exported",
  "toast.reportJsonExported": "JSON report exported",
  "toast.reportExportFailed": "Export failed",

  // ---- Settings ----
  "settings.appearanceTitle": "Appearance",
  "settings.appearanceDesc":
    "Switch between the light and dark theme. The preference is saved on this device.",
  "theme.light": "Light",
  "theme.dark": "Dark",
  "settings.languageTitle": "Language",
  "settings.languageDesc":
    "Interface language. Each option shows its country's flag.",
  "settings.externalTitle": "External lookups",
  "settings.externalDesc":
    "Deamonize works 100% offline. Configure these keys to enable the VirusTotal → Web search → AI escalation, which is only used when local confidence is low. Keys are stored locally on your device.",
  "settings.key.virustotal": "VirusTotal API key",
  "settings.key.web": "Brave Search API key",
  "settings.key.ai": "AI API key",
  "settings.key.aiBaseUrl": "AI base URL (optional)",
  "settings.key.aiModel": "AI model (optional)",
  "button.save": "Save",
  "toast.saved": "Saved",
  "toast.saveFailed": "Could not save",
  "toast.statusLoadFailed": "Could not load statuses",

  // ---- Updates ----
  "settings.updateTitle": "Updates",
  "settings.updateDesc":
    "Deamonize updates itself from its official GitHub repository. Enable auto-update to check for a new version every time you open the app.",
  "settings.autoUpdateLabel": "Automatic updates",
  "settings.autoUpdateHint": "Check for new releases on GitHub at startup.",
  "settings.checkUpdate": "Check for updates",
  "settings.installUpdate": "Install v{version}",
  "toast.updateNone": "You are on the latest version",
  "toast.updateFound": "New version available: v{version}",
  "toast.updateInstalled": "Update installed. Restart the app to apply it.",
  "toast.updateInstallFailed": "Could not install the update",
  "toast.updateUnavailable": "Could not reach the update repository",

  // ---- Verdict detail ----
  "verdict.confidence": "confidence {pct}%",
  "verdict.source": "Source:",
  "verdict.reference": "reference",
  "verdict.reasons": "Verdict reasons",

  // ---- Window controls ----
  "win.minimize": "Minimize",
  "win.maximize": "Maximize",
  "win.restore": "Restore",
  "win.close": "Close",
};

/**
 * Verdict reason messages, keyed by the `code` produced by the Rust engine.
 * Missing codes fall back to the message returned by the backend.
 */
const REASON_MESSAGES: Record<Lang, Record<string, string>> = {
  es: {
    "rule.hash.blacklist": "El hash del binario coincide con una entrada de la lista negra.",
    "rule.path.blacklist": "La ruta del binario coincide con una entrada de la lista negra.",
    "rule.signer.blacklist": "El firmante del binario coincide con una entrada de la lista negra.",
    "rule.name.blacklist": "El nombre del servicio coincide con una entrada de la lista negra.",
    "rule.hash.whitelist": "El hash del binario coincide con una entrada conocida segura.",
    "rule.path.whitelist": "La ruta del binario coincide con una entrada conocida segura.",
    "rule.signer.whitelist": "El firmante del binario es un editor de confianza.",
    "rule.name.whitelist": "El nombre del servicio es una entrada conocida segura.",
    "heuristic.location": "El binario se ejecuta desde una carpeta de usuario o temporal.",
    "heuristic.unsigned": "El binario no tiene firma digital.",
    "heuristic.lookalike": "El nombre imita a un proceso o servicio del sistema y no está firmado.",
    "spoof.original_filename_mismatch":
      "El nombre original del binario (PE) no coincide con el archivo en disco.",
    "spoof.claims_microsoft_unsigned": "Dice ser de Microsoft pero el binario no está firmado.",
    "spoof.claims_microsoft_other_signer": "Dice ser de Microsoft pero el firmante es otro.",
    "heuristic.unquoted_path": "Ruta del servicio sin comillas y con espacios (vulnerable a secuestro).",
    "rule.none": "Sin coincidencias en las listas locales; veredicto pendiente de consulta.",
  },
  en: {
    "rule.hash.blacklist": "The binary hash matches a blacklisted entry.",
    "rule.path.blacklist": "The binary path matches a blacklisted entry.",
    "rule.signer.blacklist": "The binary's signer matches a blacklisted entry.",
    "rule.name.blacklist": "The service name matches a blacklisted entry.",
    "rule.hash.whitelist": "The binary hash matches a known-safe entry.",
    "rule.path.whitelist": "The binary path matches a known-safe entry.",
    "rule.signer.whitelist": "The binary's signer is a trusted publisher.",
    "rule.name.whitelist": "The service name is a known-safe entry.",
    "heuristic.location": "The binary runs from a user or temporary folder.",
    "heuristic.unsigned": "The binary has no digital signature.",
    "heuristic.lookalike": "The name imitates a system process or service and is unsigned.",
    "spoof.original_filename_mismatch":
      "The binary's original name (PE) does not match the file on disk.",
    "spoof.claims_microsoft_unsigned": "Claims to be Microsoft but the binary is unsigned.",
    "spoof.claims_microsoft_other_signer": "Claims to be Microsoft but is signed by someone else.",
    "heuristic.unquoted_path": "Service path is unquoted and contains spaces (hijackable).",
    "rule.none": "No matches in the local lists; verdict pending external lookup.",
  },
};

const DICTS: Record<Lang, Record<TKey, string>> = { es, en };

function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in params ? String(params[name]) : whole,
  );
}

interface I18nValue {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: (key: TKey, params?: Record<string, string | number>) => string;
  tReason: (code: string, fallback: string) => string;
}

const I18nContext = createContext<I18nValue | null>(null);
const STORAGE_KEY = "deamonize.lang";

function readLang(): Lang {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "es" || stored === "en") return stored;
  } catch {
    /* storage unavailable */
  }
  return "es";
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(readLang);

  useEffect(() => {
    document.documentElement.lang = lang;
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch {
      /* storage unavailable */
    }
  }, [lang]);

  const t = useCallback(
    (key: TKey, params?: Record<string, string | number>) =>
      interpolate(DICTS[lang][key] ?? key, params),
    [lang],
  );

  const tReason = useCallback(
    (code: string, fallback: string) => REASON_MESSAGES[lang][code] ?? fallback,
    [lang],
  );

  const setLang = useCallback((next: Lang) => setLangState(next), []);

  const value = useMemo(
    () => ({ lang, setLang, t, tReason }),
    [lang, setLang, t, tReason],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}
