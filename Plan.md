# Deamonize — Plan de implementación por fases

**Objetivo:** aplicación de escritorio para Windows que analiza los servicios del sistema y los clasifica como **Seguros**, **Sospechosos** o **Peligrosos**, con evidencia trazable, fuentes citadas y una interfaz atractiva (prioridad).

---

## 1. Decisiones de stack y diseño

| Área | Decisión |
|---|---|
| Shell de escritorio | **Tauri 2** (binario ligero, backend Rust) |
| Frontend | **React + TypeScript + Vite** |
| UI | **Tailwind CSS + shadcn/ui** (componentes listados en `UIComponentes.md`) |
| Backend nativo | **Rust**: crates `windows` (Service Control Manager, WinVerifyTrust), `sha2`, `serde` |
| Persistencia | **SQLite** local (`rusqlite`) |
| Consultas externas | Adaptadores con **claves opcionales** (la app funciona 100% offline sin ellas) |
| Tema visual | **Dark cyber-security dashboard**: semáforo verde/ámbar/rojo, glow sutil, Inter + JetBrains Mono |

**Prerequisitos de toolchain:** Node ≥ 20 (✅ v24.16.0), npm (✅ 11.13.0), **Rust + MSVC Build Tools (pendiente de instalar)**.

---

## 2. Relevamiento de competencia (Idea.md punto 7)

| Herramienta | Qué hace | Qué le falta (oportunidad para Deamonize) |
|---|---|---|
| Sysinternals Autoruns | Inventario amplio de persistencia, lookup VT opcional | Sin veredicto safe/suspicious/dangerous; UI densa |
| NirSoft ServiWin | Inventario de servicios/drivers con metadatos | Sin motor de reputación |
| Advanced Windows Service Manager | Categorías coloreadas + lookup VT/Google | Fuentes/frescura poco claras, UI antigua |
| Security Task Manager ($29) | Risk scores + IA asistida | IA no transparente, sin evidencia citada |
| GlassWire | Monitoreo de red + escaneo VT de apps | No audita servicios de forma integral |
| Malwarebytes / HitmanPro | Detección y limpieza de malware | No ofrecen auditoría servicio por servicio |

**Diferenciadores de Deamonize:**
1. Veredictos **explicables** con lista de razones y **fuentes/referencias clicable** (punto 6).
2. **Cadena de escalación transparente**: local → VirusTotal → búsqueda web → IA, marcando hechos vs. inferencia.
3. Caché local con **historial de cambios** entre escaneos.
4. Detección de **suplantación** (display name vs. nombre interno vs. firma) y heurísticas de ubicación.
5. Separar **"legítimo pero opcional"** de **"malicioso"** (guidance de Microsoft).
6. **Acciones reversibles** con respaldo de la configuración.

---

## Fase 0 — Andamiaje y sistema de diseño

**Objetivo:** proyecto base compilable con la identidad visual definida.

- [ ] Instalar prerequisitos faltantes (rustup + MSVC Build Tools + Visual Studio C++ workload si no existen).
- [ ] Scaffold del proyecto Tauri 2 + React + TS + Vite (`npm create tauri-app` o manual).
- [ ] Tailwind CSS + shadcn/ui inicializados; importar componentes de `UIComponentes.md` usados en la app: `sidebar`, `card`, `badge`, `data-table`, `tabs`, `dialog`, `toast`, `skeleton`, `tooltip`, `progress`, `empty`, `button`, `input`, `switch`, `select`, `separator`, `scroll-area`, `sheet`, `label`, `typography`.
- [ ] Design system dark: tokens de color (fondo, superficies, bordes, texto), colores de veredicto (seguro `emerald`, sospechoso `amber`, peligroso `red`, desconocido `slate`), glow/borde sutil en tarjetas de estado, tipografía Inter (UI) + JetBrains Mono (rutas, hashes, IDs).
- [ ] Layout shell: `Sidebar` (Dashboard, Servicios, Reglas, Caché, Reportes, Ajustes) + área de contenido con header y `Toaster`.
- [ ] Rutas/estado de navegación (React Router o estado interno simple).
- [ ] Contrato de tipos compartido Rust↔TS (`src/types.ts`) con DTOs: `ServiceInfo`, `Verdict`, `Rule`, `ScanResult`, `CacheEntry`, `ProviderResult`, `Settings`.

**Entregables:** app arranca (`npm run tauri dev`), muestra el shell navegable con el tema dark aplicado.

**Verificación:** `npm run build` sin errores; la ventana Tauri abre en Windows.

---

## Fase 1 — MVP: recolección + BD local + motor de reglas + UI de escaneo

**Objetivo:** escaneo real de los servicios del equipo y clasificación local con evidencia.

### 1a. Backend Rust — recolección precisa de datos
- [ ] Módulo `collector` con crate `windows`:
  - `OpenSCManager` / `EnumServicesStatusExW` → lista de servicios.
  - Por servicio: nombre interno, display name, descripción (via `QueryServiceConfig2`), PID, estado, tipo de inicio, tipo de servicio, cuenta, dependencias.
  - Ruta del binario (`QueryServiceConfig`) → extraer ruta del ejecutable.
- [ ] Análisis del binario: hash **SHA-256**, firma digital (`WinVerifyTrust`), info de versión (empresa, producto, descripción, original filename) vía `GetFileVersionInfo`.
- [ ] Comandos Tauri expuestos al frontend: `scan_services()`, `get_service_detail(name)`, `get_last_scan()`.
- [ ] Manejo de errores: servicios sin binario (drivers), acceso denegado, servicio que desaparece durante el escaneo.

### 1b. Persistencia (SQLite) y semilla
- [ ] Esquema SQLite (archivado en el directorio de datos de la app):
  - `scan_history(id, started_at, finished_at, services_count)`
  - `service_snapshots(id, scan_id, name, display_name, description, pid, status, start_type, account, bin_path, dll, dependencies, sha256, signed, signer, company, product, version_info, first_seen, last_seen)`
  - `verdicts(id, snapshot_id, category, confidence, reasons_json, source, source_url, created_at)` — category ∈ `safe | suspicious | dangerous | unknown`
  - `rules(id, kind, pattern, category, priority, enabled, note)` — kind ∈ `name | path | signer | hash`
  - `cache_entries(key, value_json, fetched_at, ttl_seconds, provider)`
  - `settings(key, value)`
- [ ] **Semilla de BD** incluida como asset: ~300+ entradas curadas
  - Servicios Microsoft (baseline del sistema) → `safe`
  - Servicios legítimos de terceros conocidos (Google Update, Adobe, NVIDIA, etc.) → `safe`
  - Servicios asociados a amenazas/títulos típicos de malware → `dangerous`
  - Lista de indicadores sospechosos conocidos → `suspicious`
- [ ] Insertado idempotente al primer arranque (migración + seed).

### 1c. Motor de reglas local
- [ ] Evaluación por **prioridad: hash > ruta > firma > nombre**; primera coincidencia de lista negra gana; resultado = `category + confidence + reasons[]`.
- [ ] Confianza base: coincidencia exacta de hash = 0.95; firma Microsoft verificada = 0.9; nombre en whitelist = 0.8; solo heurística = ≤0.6; sin coincidencia = `unknown`.
- [ ] Razones estructuradas (`code`, `message`, `detail`) para mostrarlas en la UI.
- [ ] API: `classify(snapshot) -> Verdict`; re-evaluación masiva tras cambiar reglas.

### 1d. UI de escaneo (prioridad visual)
- [ ] **Dashboard**: 4 tarjetas de resumen (Seguros/Sospechosos/Peligrosos/Desconocidos) con conteo, ícono y color; sparkline o barra de proporción; botón **Escanear ahora** con progreso (`progress` + spinner).
- [ ] **Vista Servicios**: `data-table` con columnas (nombre, display name, inicio, estado, categoría, firma), filtros por categoría, búsqueda, orden por columna; badges de categoría.
- [ ] **Panel de detalle** (sheet/dialog): metadatos completos, ruta y hash en JetBrains Mono, razones del veredicto, firma, dependencias, acciones (abrir carpeta del binario, copiar hash).
- [ ] Estados vacíos (`empty`), skeleton al escanear, toasts de resultado.

**Entregables:** escaneo real + clasificación local + UI completa de lectura.

**Verificación:** `cargo check`, `npm run build`, ejecución real en Windows escaneando los servicios del equipo; los conteos del dashboard coinciden con la tabla.

---

## Fase 2 — Caché local + fuentes (puntos 4 y 6)

**Objetivo:** evitar recomputar/reconsultar y citar el origen de cada veredicto.

- [ ] Caché con **TTL** por clave (hash → resultado de reputación) e **invalidación por hash cambiado**; re-scan incremental (solo servicios con hash/modificación nuevos se re-analizan).
- [ ] Cada veredicto muestra **Fuente/referencia clicable** (`badge` + link): entrada de la semilla, doc de Microsoft Learn (`learn.microsoft.com/...`), URL de VirusTotal o resultado web cuando aplique.
- [ ] **Historial de escaneos**: selector de fecha, diff entre dos escaneos (servicios nuevos/eliminados/cambiados) con resaltado de cambios.
- [ ] Comandos: `get_cache_stats()`, `get_scan_history()`, `diff_scans(a, b)`.

**Verificación:** segundo escaneo más rápido (caché), diff correcto tras modificar/registrar un servicio de prueba.

---

## Fase 3 — Consulta externa escalonada (punto 3)

**Objetivo:** cadena VirusTotal → búsqueda web → IA solo cuando hace falta, actualizando la BD interna.

- [ ] Interfaz `ReputationProvider { name, is_configured(), lookup(query) -> ProviderResult }`.
- [ ] Nivel 1 **VirusTotal**: consulta por SHA-256, parsea positivos/total, URL del reporte (fuente citable).
- [ ] Nivel 2 **Búsqueda web**: proveedor con API (Brave/DuckDuckGo) o fallback; extrae títulos/URLs relevantes al servicio.
- [ ] Nivel 3 **IA**: proveedor configurable (endpoint OpenAI-compatible o Anthropic-compatible); recibe evidencia estructurada y devuelve resumen + categoría sugerida + confianza, **marcando hechos vs. inferencia**.
- [ ] **Orquestador de escalación**: solo consulta el siguiente nivel si la confianza local es baja (`unknown` o `suspicious` con confianza < umbral); respeta orden y coste; resultados con timeout y reintentos/backoff.
- [ ] **Write-through**: cada resultado se guarda en `cache_entries` y actualiza/crea `verdicts` con `source` y `source_url` (alimenta la BD interna, punto 3).
- [ ] **UI de Ajustes**: campos para claves API (opcionales), indicador de nivel habilitado/deshabilitado (`switch`), botón "Probar conexión", advertencia de rate limit (VT free: 4 req/min).
- [ ] Acción contextual en el panel de detalle: **"Consultar fuentes externas"** con log visible de la escalación (qué nivel se usó y por qué).

**Verificación:** con claves vacías la app sigue funcionando offline; con clave VT configurada, un servicio `unknown` obtiene veredicto con URL de fuente y queda persistido tras reiniciar.

---

## Fase 4 — Heurísticas y detección de suplantación (punto 5)

**Objetivo:** señales de riesgo locales explicables antes de cualquier consulta.

- [ ] **Heurísticas de ubicación** (indicador, no prueba): binario en temp/AppData/ProgramData escribible por usuario, rutas con doble extensión, nombres sospechosos, carpeta oculta, ejecutable sin firma en ruta inesperada.
- [ ] **Detección de suplantación**:
  - Display name vs. nombre interno vs. `OriginalFileName` del binario.
  - Lookalikes de procesos/servicios del sistema (`svchost`, `csrss`, `lsass`, `services` con variantes).
  - Firma ausente o firma de "Unsigned" / empresa desconocida en servicio que dice ser Microsoft.
  - Publisher esperado vs. publisher real.
- [ ] Cada señal genera una **razón** con peso en el score total (score explicable, sin caja negra).
- [ ] UI: en el panel de detalle, sección "Señales de riesgo" con chips de cada heurística disparada y su peso.
- [ ] Tests unitarios del motor de scoring con casos fixture (servicio legítimo, lookalike, binario en temp, etc.).

**Verificación:** tests de scoring pasan; un servicio de prueba renombrado/ubicado mal se clasifica como sospechoso con razones visibles.

---

## Fase 5 — Reportes, acciones y extras (puntos 6 y 7)

**Objetivo:** salidas accionables y diferenciación final.

- [ ] **Reportes exportables**: HTML (autocontenido, con evidencia y fuentes), JSON (máquina) y vía "Imprimir → PDF" del navegador para PDF.
- [ ] Vista previa del reporte dentro de la app y acción "Exportar" con selector de categoría.
- [ ] **Acciones seguras**: deshabilitar/habilitar servicio (`ChangeServiceConfig` start type) con **respaldo reversible** (se guarda la configuración original en `scan_history`/tabla de respaldos; botón "Restaurar").
- [ ] **Vista unificada**: servicios + drivers + puntos de persistencia clave (Run keys, tareas) en una sola tabla con filtros por origen.
- [ ] Filtros avanzados: Microsoft-firmado / desconocidos / recién cambiados / de red / alta privilegiada; guardados como vistas.
- [ ] **Modo monitoreo** (opcional): sondeo periódico con diff visual y toast cuando aparece un servicio nuevo.

**Verificación:** reporte HTML abierto en navegador con fuentes clicables; deshabilitar y restaurar un servicio de prueba deja la configuración original intacta.

---

## Orden de ejecución y criterios globales

| Fase | Cuándo |
|---|---|
| 0 | Inmediato — scaffold + design system |
| 1 | Tras Fase 0 — MVP funcional |
| 2–5 | En orden, verificando cada fase antes de pasar a la siguiente |

**Criterios de éxito global:**
1. Clasificación correcta y justificada en el equipo real (Windows).
2. UI atractiva y fluida (prioridad del usuario).
3. App funcional **100% offline desde la Fase 1**; claves externas opcionales desde la Fase 3.
4. Toda decisión muestra sus razones y su fuente.
5. Verificación continua: `cargo check`, `npm run build` y prueba de ejecución tras cada fase.
