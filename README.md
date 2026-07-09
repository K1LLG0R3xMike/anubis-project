# Anubis Project

Plataforma de orquestación de escaneos de seguridad web con análisis IA. Gestiona targets, lanza herramientas de seguridad de forma asíncrona, visualiza hallazgos, programa escaneos recurrentes, genera reportes en PDF y DOCX con análisis generado por Gemini, y cuenta con un modo de ataque para automatizar pruebas de penetración.

---

## Tabla de Contenidos

1. [Stack Tecnológico](#stack-tecnológico)
2. [Estructura de Directorios](#estructura-de-directorios)
3. [Backend](#backend)
4. [Frontend](#frontend)
5. [Scripts de Escaneo](#scripts-de-escaneo)
6. [Configuración y Variables de Entorno](#configuración-y-variables-de-entorno)
7. [Base de Datos](#base-de-datos)
8. [Servicios Requeridos y Arranque](#servicios-requeridos-y-arranque)
9. [Autenticación](#autenticación)
10. [Agente IA](#agente-ia)
11. [Generación de Reportes](#generación-de-reportes)
12. [Modo Ataque — UI](#modo-ataque--ui)
13. [Anubis Attack — Arquitectura del Módulo de Explotación](#anubis-attack--arquitectura-del-módulo-de-explotación)
    - [Agente de Vectores IA](#7-agente-de-vectores-ia-vector_agentpy)
14. [Limitaciones Conocidas](#limitaciones-conocidas)

---

## Stack Tecnológico

| Capa | Tecnología |
|------|-----------|
| Frontend | React 19, Vite 7, Tailwind CSS 3.4, MUI 7, Axios |
| Backend | FastAPI, SQLAlchemy, Pydantic |
| Base de datos | PostgreSQL 12+ (`ciber_db`) |
| Cola de tareas | Celery + Redis |
| Scheduler | Celery Beat (intervalo: 60 s) |
| Agente IA | Google Gemini (`gemini-2.5-flash`) via `google-genai` SDK |
| Generación DOCX | `python-docx` con plantilla Word |
| Generación PDF | LibreOffice headless (conversión desde DOCX) |
| Fuentes/iconos | Space Grotesk, Inter, JetBrains Mono, Material Symbols |

---

## Estructura de Directorios

```
AnubisProject/
├── backend/
│   ├── main.py                         # App FastAPI: rutas, lógica, generadores DOCX/PDF
│   ├── ai_agent.py                     # Agente IA: prompt builder + llamadas a Gemini/Claude/OpenAI
│   ├── models.py                       # Modelos SQLAlchemy (Target, Finding, Schedule, Report)
│   ├── database.py                     # Engine + SessionLocal + Base (SQLAlchemy)
│   ├── tasks.py                        # Tareas Celery: escaneos + análisis IA
│   ├── celery_app.py                   # Config Celery + Beat scheduler
│   ├── scan_modules.py                 # Auto-descubrimiento de módulos (ver "Scan Engine")
│   ├── attack_models.py                # Modelos SQLAlchemy de Anubis Attack (AuthorizedTarget, AttackRun, AttackResult)
│   ├── attack_schemas.py               # Schemas Pydantic del DAG de ataque (AttackNode, AttackPlan)
│   ├── attack_planner.py               # Motor de reglas N:M + constructor del DAG
│   ├── attack_orchestrator.py          # Tarea Celery de ejecución + compuerta de autorización
│   ├── vector_agent.py                 # Agente de Vectores IA (ver sección dedicada)
│   ├── templates/
│   │   └── index.html
│   ├── requirements.txt
│   ├── .env                            # Variables de entorno (ver sección dedicada)
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── main.jsx
│   │   ├── App.jsx                     # Router + guard de auth JWT + ModeProvider
│   │   ├── index.css                   # Tailwind + animaciones (logoSwitch, pulse-red, etc.)
│   │   ├── context/
│   │   │   └── ModeContext.jsx         # Contexto global: modo scan/attack
│   │   ├── components/
│   │   │   ├── Layout.jsx              # Sidebar + header + bottom nav con switch de modo
│   │   │   ├── AttackPlanViewer.jsx    # Nodos DAG con estado en tiempo real
│   │   │   ├── LiveTerminal.jsx        # Terminal WebSocket streaming logs Celery
│   │   │   ├── EvidenceGallery.jsx     # Grid de evidencias capturadas
│   │   │   └── CeleryMonitorPanel.jsx  # Panel de estado de workers (ver sección "Sistema")
│   │   └── pages/
│   │       ├── Login.jsx
│   │       ├── Dashboard.jsx           # Modo scan: KPIs, targets, hallazgos
│   │       ├── AttackDashboard.jsx     # Modo attack: mapa + Attack Control Panel
│   │       ├── Targets.jsx / AttackTargets.jsx
│   │       ├── Findings.jsx / AttackFindings.jsx
│   │       ├── Historical.jsx / AttackHistorical.jsx
│   │       ├── Schedule.jsx / AttackSchedule.jsx
│   │       └── Reports.jsx / AttackReports.jsx   # Generación, listado, descarga PDF/DOCX, análisis IA
│   ├── public/
│   │   └── anubis-logo.png
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── postcss.config.js
│
├── deploy/                             # Instalación en máquina nueva (ver "Servicios Requeridos")
│   ├── install.sh                      # Crea venvs, corre npm install, genera servicios systemd
│   └── systemd/                        # Templates de los 6 servicios systemd --user
│
├── attack_scripts/                     # ⚠️ No existe todavía en disco — módulos de explotación
│                                        # con contrato fijo (ver "Scripts de Ataque"). Sin scripts
│                                        # implementados: header_exploits.py (único que llegó a
│                                        # escribirse) se eliminó 2026-07-06 — el foco pasó al
│                                        # Vector Agent IA (backend/vector_agent.py), que ejecuta
│                                        # comandos directo en vez de depender de un script fijo.
│
├── scripts/                            # Módulos de escaneo completo (todos los targets)
│   ├── waf.py
│   ├── whatweb.py
│   ├── headers.py
│   ├── certs.py
│   ├── nikto.py
│   ├── owasp.py
│   ├── Kiterunner.py
│   ├── fuzz_dirb.py
│   ├── fuzz_gobuster.py
│   ├── cleanup_tmp.sh                  # cron: limpieza /tmp + reinicio worker heavy
│   ├── cleanup_zap_sessions.sh         # cron: purga sesiones viejas de ZAP
│   └── db_findings.py
│
├── script_induvidual/                  # Mismos módulos para 1 target
│   └── [mismos archivos]
│
├── reports/                            # JSON de resultados (static files en FastAPI)
│   ├── waf/
│   ├── whatweb/
│   ├── headers/
│   ├── certs/
│   ├── nikto/
│   ├── zap/
│   ├── kiterunner/
│   ├── fuzz_dirb/
│   ├── fuzz_gobuster/
│   ├── attack/                         # Evidencias de Anubis Attack (screenshots, JSON dumps)
│   ├── api/ · fuzzing/ · nmap/         # Placeholders sin uso todavía (solo .gitkeep)
│   └── sitios.txt                      # Leído por owasp.py (TARGETS_FILE) — copia independiente
│                                        # del sitios.txt de la raíz, puede desincronizarse de ella
│
├── Pruebas Hardening OpenClaw.docx     # Plantilla Word para generación de reportes DOCX
├── logs/
└── sitios.txt
```

---

## Backend

### Arranque

```bash
cd backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000
```

O vía systemd (recomendado):

```bash
systemctl --user start anubis-backend
systemctl --user start anubis-celery          # light + beat
systemctl --user start anubis-celery-heavy    # heavy
systemctl --user start anubis-celery-attack   # attack
```

### Endpoints Completos

#### Autenticación

| Método | Ruta | Body | Descripción |
|--------|------|------|-------------|
| `POST` | `/login` | `{username, password}` | Devuelve `token-anubis-2026` |
| `GET` | `/verify-token` | Header: `Authorization: Bearer <token>` | Valida el token |

#### Targets

| Método | Ruta | Body | Descripción |
|--------|------|------|-------------|
| `GET` | `/targets/` | — | Lista todos los targets |
| `POST` | `/targets/` | `{name, url}` | Crea un target |
| `DELETE` | `/targets/{id}` | — | Elimina un target (cascade delete, ver nota) |

> **Cascade delete**: al borrar un target se limpian en cascada sus `Finding`, `VectorRun`, `AiAttackPlan` y `AttackRun`/`AttackResult` asociados. Los `Schedule` que incluyen ese target junto con otros solo pierden la referencia (no se borran); si el target era el único del schedule, el schedule se elimina. Antes de este fix (2026-07-02) quedaban registros huérfanos apuntando a un `target_id` inexistente.

#### Escaneos (lanzan tarea Celery)

| Método | Ruta | Body | Descripción |
|--------|------|------|-------------|
| `POST` | `/run-{module}` | — | Módulo en todos los targets (genérico, reemplaza los 6 endpoints hardcodeados `/run-waf`, `/run-zap`, etc. desde 2026-07-06) |
| `POST` | `/run-individual/{module}` | `{url, target_id?}` | Módulo en 1 target |

`{module}` no es una lista fija: `discover_modules()` (`backend/scan_modules.py`) escanea `scripts/` y `script_induvidual/` en cada llamada y expone cualquier `.py` nuevo automáticamente (subido a mano o vía `/upload-script`), sin tocar código ni reiniciar nada. Módulos actuales: `waf`, `whatweb`, `headers`, `certs`, `nikto`, `zap`, `kiterunner`, `fuzz_dirb`, `fuzz_gobuster`.

#### Scan Engine — auto-detección y colas por módulo

| Método | Ruta | Body | Descripción |
|--------|------|------|-------------|
| `GET` | `/system/scan-modules` | — | Lista módulos detectados, su cola actual y si le falta la réplica en `scripts/` o `script_induvidual/` |
| `PUT` | `/system/scan-modules/{id}/queue` | `{queue}` | Fija la cola (`light`/`heavy`) de un módulo, persistida en `scan_module_configs` |

Antes de 2026-07-06 existían cinco listas hardcodeadas independientes (`SCRIPT_MAP`, `_HEAVY_MODULES`, dos `valid_modules`, `_MODULE_TOOL_LABELS`) que había que editar a mano por cada script nuevo — así fue como `Kiterunner.py` estuvo commiteado desde el 9 de junio sin quedar nunca conectado. `get_module_queue()` resuelve la cola de un módulo: usa el override en `scan_module_configs` si existe, si no cae a `heavy` para `zap`/`nikto` o `light` para el resto. `fuzz_dirb`, `fuzz_gobuster` y `kiterunner` tienen override explícito a `heavy` (herramientas de bruteforce/fuzzing, no aptas para la cola general).

#### Reportes

| Método | Ruta | Body / Params | Descripción |
|--------|------|--------------|-------------|
| `POST` | `/reports/generate` | `{target_ids, report_type, scope}` | Genera reporte con snapshot de findings |
| `GET` | `/reports/` | — | Lista todos los reportes |
| `GET` | `/reports/{id}` | — | Reporte completo con snapshot y ai_content |
| `DELETE` | `/reports/{id}` | — | Elimina un reporte |
| `GET` | `/reports/{id}/download` | — | Descarga PDF (generado vía DOCX → LibreOffice) |
| `GET` | `/reports/{id}/download/docx` | — | Descarga DOCX |
| `POST` | `/reports/{id}/ai-analyze` | — | Dispara análisis IA asíncrono (Celery) |

**Valores de `report_type`**: `"executive"`, `"technical"`, `"compliance"`, `"full"`
**Valores de `scope`**: `"single"` (usa `target_ids`), `"all"` (todos los targets)

#### Findings

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/findings/historical` | Todos los findings agrupados por target/módulo/fecha |
| `GET` | `/findings/compare` | Comparación entre dos escaneos (`target_id`, `module`, `date_old`, `date_new`) |
| `GET` | `/findings/target/{id}` | Findings de un target agrupados por módulo, directo de la tabla `findings` — usado para generar secciones automáticas de módulos sin tabla a medida (ver `Findings.jsx` abajo) |

#### Schedules

| Método | Ruta | Body | Descripción |
|--------|------|------|-------------|
| `GET` | `/schedules/` | — | Lista schedules |
| `POST` | `/schedules/` | `{target_ids, modules, scheduled_at, repeat}` | Crea schedule |
| `DELETE` | `/schedules/{id}` | — | Cancela schedule |

Valores de `repeat`: `"once"`, `"daily"`, `"weekly"`, `"monthly"`

#### Sistema

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/system/celery-status` | Estado en vivo de los workers Celery: por cada hostname (`light@`, `heavy@`, `attack@`) devuelve si está online, sus tareas activas (con `elapsed_seconds`) y las reservadas/en espera. Usa `celery_app.control.inspect()` con timeout de 2s. |
| `POST` | `/system/celery/kill-all` | Revoca (SIGKILL) todas las tareas activas/en cola de todas las colas y las purga del broker. Además mata por patrón los procesos huérfanos de `dirb`/`gobuster`/`nikto`/`kiterunner` y los wrappers `script_induvidual/*.py`, que un `revoke` normal no alcanza porque corren como nietos del worker (ver nota de `fuzz_dirb` más abajo). No toca el daemon de ZAP. |
| `POST` | `/system/celery/restart-workers` | Reinicia los servicios systemd `anubis-celery` (light), `anubis-celery-heavy` y `anubis-celery-attack`. No toca `beat` ni el daemon de ZAP. |

Consumido por el panel **Estado de Workers** (`frontend/src/components/CeleryMonitorPanel.jsx`) en `Targets`, junto a la lista de targets — **siempre visible** (antes solo aparecía tras lanzar un escaneo). Hace polling cada 3s. Debajo del header incluye los botones **Matar tareas** y **Reiniciar workers**, cada uno con confirmación antes de ejecutar.

### Tareas Celery (`tasks.py`)

```python
run_full_scan(module_type: str)
# Ejecuta scripts/{module_type}.py en todos los targets

run_individual_scan(module_type: str, target_url: str)
# Ejecuta script_induvidual/{module_type}.py en 1 target

run_sequential_scan(module_type: str, target_urls: list)
# Ejecuta el módulo secuencialmente en varios targets

analyze_report_with_ai(report_id: int)
# Llama al agente IA (Gemini), genera markdown_report y actualiza ai_content en DB

check_and_run_schedules()
# Tarea beat cada 60s: evalúa schedules pendientes y lanza escaneos
```

### Control de concurrencia y deduplicación de escaneos

#### Problema

Sin control, lanzar múltiples escaneos desde el frontend (o vía API) encolaba todas las solicitudes y las ejecutaba en paralelo, acumulando procesos Firefox/GeckoDriver en `/tmp` hasta llenar la partición.

#### Solución implementada (3 capas)

**Capa 1 — Cuatro colas Celery (`celery_app.py`)**

| Cola | Módulos | Concurrencia recomendada | Servicio systemd |
|------|---------|--------------------------|-------------------|
| `heavy` | `zap`, `nikto`, `vector_agent` | 2 (slot 1 para ZAP/Nikto, slot 2 libre para vector agent tasks) | `anubis-celery-heavy.service` |
| `light` | `waf`, `whatweb`, `headers`, `certs` | 2 (worker general) | `anubis-celery.service` (`--queues=light,beat`) |
| `attack` | `execute_attack_run` (orquestación DAG de Anubis Attack) | 2 | `anubis-celery-attack.service` |
| `beat` | `check_and_run_schedules` | — | `anubis-celery.service` |

> **Nota**: la cola `attack` existió en el código (`queue="attack"` en `main.py`) antes de tener un worker dedicado — hasta 2026-06-30 ningún proceso la consumía y los attack runs se quedaban en `planned` indefinidamente. El servicio `anubis-celery-attack.service` resuelve esto.

El worker general corre con `worker_concurrency=2`. Para ejecución estrictamente serial de escaneos pesados, arrancar un segundo worker dedicado:

```bash
celery -A celery_app worker --queues=heavy --concurrency=1 --hostname=heavy@%h
```

**Capa 2 — Lock de deduplicación por módulo (`main.py` + `tasks.py`)**

Antes de encolar cualquier tarea, `main.py` intenta adquirir un lock en Redis (`db=1`, separado del broker):

```
anubis:scan_lock:zap          ← full scan
anubis:scan_lock:individual:nikto:a3f2b1c4   ← scan individual (hash de URL)
```

- Si el lock **no existe**: se adquiere (TTL=90 min) y la tarea se encola.
- Si el lock **ya existe**: respuesta `409 Conflict` — el mismo módulo ya está en cola o corriendo.
- Cuando la tarea **termina** (éxito o error): el `finally` en `tasks.py` borra el lock.
- El TTL de 90 min actúa de safety net si el worker muere sin liberar el lock.

**Capa 3 — Lanzamiento secuencial en Dashboard (`Dashboard.jsx`)**

El modal "Nuevo Objetivo + Escaneo" enviaba todos los módulos seleccionados en paralelo con `Promise.allSettled()`. Cambiado a `for...of` con `await` — cada módulo espera la respuesta del anterior antes de encolarse.

#### Comportamiento resultante

| Escenario | Antes | Ahora |
|-----------|-------|-------|
| Lanzar ZAP dos veces seguidas | 2 instancias paralelas | `409` en la segunda — espera a que termine la primera |
| Dashboard con ZAP + Nikto + Headers seleccionados | 3 peticiones simultáneas | 3 peticiones secuenciales; ZAP y Nikto van a cola `heavy`, Headers a `light` |
| Worker general (concurrency=2) | Hasta 4 tareas paralelas | Hasta 2 tareas paralelas |
| Worker dedicado `heavy` (concurrency=1) | N/A | ZAP y Nikto ejecutan uno tras otro, nunca en paralelo |

---

## Frontend

### Arranque

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173
npm run build
```

### Sistema de Modos (Scan / Attack)

El logo de la cabecera es un **switch de modo**. Al hacer clic cambia entre:

- **Anubis Scan** (tema azul `#9aa8ff`): interfaz estándar de análisis defensivo
- **Anubis Attack** (tema rojo `#FF3131`): dashboard de pentesting con mapa de vulnerabilidades

El estado de modo vive en `ModeContext.jsx` y es accesible en cualquier componente con `useMode()`. `Layout.jsx` aplica los temas dinámicamente usando dos objetos de tema (`SCAN_THEME` / `ATTACK_THEME`).

### Páginas y Rutas

| Ruta | Archivo | Funcionalidad |
|------|---------|---------------|
| `/login` | `Login.jsx` | Login. Credenciales: `admin` / `anubis2026` |
| `/dashboard` | `Dashboard.jsx` / `AttackDashboard.jsx` | KPIs, targets, hallazgos (varía según modo) |
| `/targets` | `Targets.jsx` | CRUD targets, escaneo por módulo (lista de módulos auto-detectada vía `/system/scan-modules`), subida de scripts, monitor de workers Celery siempre visible junto a la lista (sin vista de cuadrícula, solo lista, desde 2026-07-07) |
| `/findings` | `Findings.jsx` | Findings por target y módulo con severidad. ZAP, Nikto y los módulos genéricos colapsan los hallazgos Low/Informational detrás de un botón "Ver N hallazgos de severidad baja / informativa" (2026-07-06), mostrando por defecto solo Medium/High/Critical. Módulos sin tabla a medida (`fuzz_dirb`, `fuzz_gobuster`, y cualquier script futuro conectado a `save_findings()`) generan su sección automáticamente vía `GET /findings/target/{id}` — no requieren tocar el frontend |
| `/historical` | `Historical.jsx` | Timeline histórico, comparación antes/después |
| `/schedule` | `Schedule.jsx` | Calendario, schedules recurrentes multi-módulo |
| `/reports` | `Reports.jsx` | Generación, listado, descarga PDF/DOCX, análisis IA |

### Animaciones CSS (`index.css`)

| Nombre | Uso |
|--------|-----|
| `logoSwitch` | Animación del logo al cambiar de modo |
| `modeFlash` | Flash del contenido principal al cambiar modo |
| `pulse-red` | Indicador pulsante modo Attack |
| `pulse-blue` | Indicador pulsante modo Scan |
| `neon-pulse` | Borde neón en tarjetas del dashboard Attack |

---

## Scripts de Escaneo

Cada script sigue el mismo patrón:

1. Lee targets de `sitios.txt` o recibe URL por argumento
2. Ejecuta herramienta externa vía `subprocess`
3. Guarda JSON en `/reports/{módulo}/{target_name}.json`
4. Llama a `db_findings.save_findings(target_id, module, findings_list)`

### Módulos Disponibles

| Módulo | Herramienta | Qué detecta |
|--------|-------------|-------------|
| `waf` | `wafw00f` | WAF/CDN (Cloudflare, Akamai, etc.) |
| `whatweb` | `whatweb` | Stack tecnológico (CMS, frameworks, versiones) |
| `headers` | requests | Cabeceras de seguridad HTTP (CSP, HSTS, X-Frame, etc.) |
| `certs` | `testssl.sh` | Protocolos SSL/TLS, cifrados débiles, caducidad |
| `nikto` | `nikto` | Vulnerabilidades del servidor web |
| `zap` | OWASP ZAP API | Vulnerabilidades OWASP Top 10 |
| `kiterunner` | `kiterunner` | Descubrimiento de endpoints de API |
| `fuzz_dirb` | `dirb` | Fuerza bruta de rutas/directorios (wordlist `dirb/common.txt`) |
| `fuzz_gobuster` | `gobuster` | Fuerza bruta de rutas/directorios (wordlist SecLists `raft-large-directories.txt`, ~62.300 palabras — subida desde `common.txt` el 2026-07-07 por baja cobertura) |

> **Cableado de `fuzz_dirb`/`fuzz_gobuster`/`kiterunner` (2026-07-06)**: ninguno de los tres llamaba a `save_findings()` — corrían la herramienta y el resultado se perdía sin tocar la tabla `findings`. Las copias en `scripts/` de fuzz_dirb/gobuster además tenían una contraseña de DB equivocada y escribían el JSON fuera del proyecto. Kiterunner leía targets desde `reports/sitios.txt` (podía desincronizarse de la tabla `targets`) y guardaba bajo `module='api'`, un id no reconocido por `discover_modules()` — los resultados quedaban invisibles en el frontend aunque el escaneo corriera bien. Los tres quedaron corregidos: consultan `targets` en vivo, usan su module id real, y escriben en `reports/{módulo}/`.

### Extracción de evidencia en alertas de ZAP (2026-07-06 / 2026-07-07)

`run_zap_engine()` deduplica alertas por `alert-risk-param` (antes era solo `alert-risk`, lo que descartaba alertas distintas del mismo tipo con distinto parámetro afectado). Para el campo `evidencia`, `_extract_evidencia()` en `owasp.py` resuelve un fallback cuando ZAP no llena `evidence` (pasa en reglas activas basadas en timing/errores, como Path Traversal o SQLi): prioriza el payload real enviado (`attack` + `param`), luego el campo `other` (explicación técnica de ZAP, ej. condiciones booleanas probadas), y por último la URL. Antes esos casos quedaban como `"N/A"`; desde 2026-07-07 la URL **siempre** se agrega al final de la evidencia (no solo como fallback), para poder reproducir el hallazgo sin volver a consultar ZAP.

### Active Scan por etapas (2026-07-06)

El active scan corría con las ~53 reglas de la política activa a la vez, enviando ráfagas grandes de payloads "sospechosos" en simultáneo — con un WAF de por medio, eso da pie a que bloquee o limite por volumen antes de que ZAP complete comparaciones diferenciales (ej. SQLi boolean-based, que necesita varias respuestas comparables). `run_zap_engine()` ahora agrupa los scanners por palabra clave en su nombre y corre cada grupo como pasada separada, con una pausa de 15s entre etapas:

```
sqli        → "sql injection"
xss         → "cross site scripting", "xss"
cmd_rce     → "command injection", "code injection", "shell", "remote code execution", ...
traversal   → "path traversal", "file inclusion", "external entity", "xxe", ...
misc_inject → "injection", "padding oracle", "soap"
resto       → todo lo que no matcheó ninguna keyword (headers, info leaks, fuzzing, etc.)
```

La regla "Cross Site Scripting (DOM Based)" se excluye del ciclo automático: es la única que abre Firefox real vía Selenium, y se cuelga de forma reproducible tras 15-20 min incluso con concurrencia limitada (17.000+ requests sin avanzar, ~60 procesos Firefox/GeckoDriver acumulados). Sigue disponible manual vía la API de ZAP si hace falta.

Dos escaneos de ZAP corriendo a la vez (la cola `heavy` permite concurrencia 2) pisarían la política de reglas compartida si ambos la tocan al mismo tiempo — por eso la fase de active scan por etapas se serializa con un lock de Redis (`anubis:zap_policy_lock`, db=1, timeout 90 min desde 2026-07-07, antes 30 min). Si el ciclo completo tarda más que el timeout, Redis expira el lock solo; el `finally` que lo libera ahora ignora `LockNotOwnedError` en vez de dejar que reviente la extracción de alertas y el guardado de resultados que viene después (bug real: un escaneo completo en producción terminó el active scan al 100% pero perdió todo el resultado por esto).

### Rotación de sesión de ZAP (2026-07-07)

`start_zap()` reusaba la sesión default de ZAP (`untitled1`) indefinidamente entre reinicios del daemon. En producción llegó a pesar **14.6 GB** al no reiniciarse nunca desde el 30 de abril, hasta que el propio ZAP se autoapagó por uso de memoria (monitor interno "Insights", umbral 96%) y descartó la sesión a mitad de un escaneo — sin excepción visible más allá de un error de conexión genérico. Ahora cada arranque del daemon crea una sesión nueva con timestamp (`-newsession /home/anubis/.ZAP/session/anubis_<timestamp>`), y `scripts/cleanup_zap_sessions.sh` (cron diario, `0 4 * * *`) purga las que quedan con más de 3 días, saltando la que esté en uso (detecta el `.lck`).

### Persistencia de resultados aunque el escaneo falle a mitad de camino (2026-07-08)

`run_zap_engine()` (`scripts/owasp.py` y `script_induvidual/owasp.py`) solo extraía las alertas de ZAP y llamaba a `save_findings()` al final del flujo feliz, después del spider y las 6 etapas del active scan. Si algo fallaba antes de llegar ahí (excepción durante el spider, un timeout de etapa, el lock de política de ZAP, etc.), el bloque `try/except` del `__main__` atrapaba el error, actualizaba el status a "ZAP: Error en escaneo" y listo — pero como nunca hacía `sys.exit(1)`, el proceso salía con `exit_code=0` y Celery lo registraba como éxito. Las alertas ya detectadas por ZAP quedaban atrapadas solo en la sesión, sin JSON ni fila en `findings`.

Esto pasó en producción con `fundacionserenadelmar.org`: el escaneo corrió ~1h52m y terminó con `exit_code=0`, pero no generó `reports/zap/fundacion.json` ni guardó nada en la DB. Cargando la sesión de ZAP de ese día se recuperaron 73 hallazgos únicos, incluidas **22 alertas de SQL Injection (High)** sobre distintos parámetros de un WordPress — datos reales que habían quedado invisibles en el frontend.

Dos cambios:
- El bloque de extracción + guardado se movió a `_extract_and_save_alerts()` y ahora se llama siempre desde un `finally` que envuelve todo `run_zap_engine()` (spider + active scan), así se persiste lo que ZAP ya tenga acumulado sin importar en qué punto falló el escaneo. Si el guardado mismo falla, se loguea sin tapar la excepción original.
- Los bloques `__main__` de ambos scripts ahora hacen `sys.exit(1)` cuando `run_zap_engine()` lanza una excepción (en `scripts/owasp.py`, que escanea todos los targets en un loop, se acumula en una bandera `had_errors` y se sale con 1 al final si algún target falló), para que un fallo real ya no se reporte como éxito.

### Control de concurrencia en OWASP ZAP

ZAP lanza instancias de Firefox headless (vía GeckoDriver) durante el active scan. Sin límite, un escaneo multi-target puede acumular decenas de procesos Firefox en `/tmp` y llenar la partición.

Al inicio de cada `run_zap_engine()` (tanto en `scripts/owasp.py` como en `script_induvidual/owasp.py`) se fijan los siguientes parámetros vía la API de ZAP:

| Parámetro ZAP | Valor | Descripción |
|---------------|-------|-------------|
| `ThreadPerHost` | **6** | Hilos por host en el active scan (era 8, bajado a 4, subido a 6 para reducir tiempo de scan) |
| `HostPerScan` | **1** | Hosts escaneados en paralelo (evita scans simultáneos) |

Esto limita a un máximo de ~4 instancias de Firefox activas simultáneamente, reduciendo el uso de `/tmp` de forma proporcional.

### Progreso en vivo de `fuzz_dirb` (2026-07-07)

`run_dirb()` usaba `subprocess.run(['dirb', ..., '-S'], capture_output=True)`: bloqueante, sin imprimir nada hasta que el proceso completo terminaba. Un escaneo real contra un target con WAF tardó 116 minutos en silencio total — indistinguible de un proceso colgado, y de hecho el timeout de 75 min de `_stream_subprocess` (`tasks.py`) nunca se disparó porque solo se evalúa *después* de que el bucle de lectura de líneas termine, y ese bucle no arrancaba con nada que leer. Ahora corre sin `-S` (dirb reporta cada palabra probada) leyendo la salida en vivo con `Popen`, separando por `\r` en vez de `\n` — dirb emite su progreso como barra de terminal (`\r`), no como líneas (`\n`), así que un `readline()` normal nunca las vería. Cada 25 palabras probadas se publica `[.] DIRB: N rutas probadas (X%)...` por stdout (llega al frontend vía el pubsub de `_stream_subprocess`) y se actualiza `targets.status`.

> Nota: el contador puede superar 100% — cuenta también las palabras reintentadas por recursión en subdirectorios encontrados, no solo las de la wordlist base.

---

### Script de limpieza de `/tmp` y reinicio seguro del worker heavy

**Archivo**: `scripts/cleanup_tmp.sh`
**Ejecución**: cron job cada 5 minutos (`*/5 * * * *`) — solo actúa si `/tmp` supera el umbral; en el resto de corridas sale sin loguear nada.

Segunda línea de defensa para el caso en que `/tmp` supere el 90% de uso a pesar del límite de concurrencia de ZAP.

#### Por qué existe

ZAP mantiene un daemon Java persistente entre escaneos (`anubis-celery-heavy` lo lanza como subproceso la primera vez y lo reutiliza, para no pagar el arranque de la JVM en cada scan). Cuando ese daemon queda en un estado colgado — se observó tras el incidente del 2026-07-02 en que `/tmp` se llenó a mitad de un active scan — sigue abriendo y matando sesiones de Firefox/GeckoDriver por su cuenta cada pocos minutos, **sin que haya ningún escaneo real en curso** (confirmado vía `/system/celery-status` y la API de ZAP: spider/ajaxSpider/ascan en `FINISHED`/`stopped`). Matar solo los procesos `firefox-esr`/`geckodriver` no alcanza: el daemon Java sigue vivo y regenera más en minutos, por eso el script fue corregido el 2026-07-06 para atacar también al proceso ZAP.

#### Flujo de intervención

```
/tmp > 90%
    │
    ├─ ¿Cola heavy (zap/nikto) tiene tareas activas?
    │       └─ Sí → vaciar solo la cola heavy (purge -Q heavy)
    │               esperar 15s para drenaje de tareas en curso
    │
    ├─ Matar el daemon Java de ZAP (causa raíz) y los procesos
    │   firefox-esr / geckodriver huérfanos que dependían de él
    │
    ├─ Limpiar artefactos de /tmp:
    │       rust_mozprofile* / userprofile*copy /
    │       anonymous*webdriver-profile / selenium-manager* / pymp-*
    │
    └─ Reiniciar anubis-celery-heavy vía systemd
```

#### Consideraciones

- Las tareas activas de ZAP/Nikto **se interrumpen** cuando se mata el daemon. La intervención es equivalente a un abort manual — el scan queda incompleto pero el worker se recupera limpio y arranca un daemon ZAP nuevo en el siguiente escaneo.
- El chequeo de tareas activas y el `purge` están acotados a la cola `heavy` — no toca tareas pendientes en `light`/`attack`/`beat`.
- El script exporta `XDG_RUNTIME_DIR`/`DBUS_SESSION_BUS_ADDRESS` antes de invocar `systemctl --user`: cron no hereda el bus de sesión del usuario, y sin esas variables el comando fallaba silenciosamente (el reinicio nunca se ejecutaba, aunque el log lo reportara como intentado).
- El script registra cada acción en `logs/cleanup_tmp.log` con timestamp.
- Si el servicio `anubis-celery-heavy` no estaba activo, se omite el reinicio y se loguea una advertencia.

#### Activación manual

```bash
bash /home/anubis/AnubisProject/scripts/cleanup_tmp.sh
```

#### Ver log de intervenciones

```bash
tail -f /home/anubis/AnubisProject/logs/cleanup_tmp.log
```

---

## Configuración y Variables de Entorno

### `backend/.env`

```env
DATABASE_URL=postgresql://admin:<password>@localhost:5432/ciber_db

# Gemini (proveedor por defecto)
GEMINI_API_KEY=<clave_primaria>
GEMINI_API_KEY_2=<clave_fallback>        # opcional, se añaden _3, _4... según necesidad
GEMINI_MODEL=gemini-2.5-flash

AI_PROVIDER=gemini                        # opciones: gemini | claude | openai

# Opcional — otros proveedores
# ANTHROPIC_API_KEY=...
# CLAUDE_MODEL=claude-sonnet-4-6
# OPENAI_API_KEY=...
# OPENAI_MODEL=gpt-4o
```

El agente itera sobre todas las claves `GEMINI_API_KEY*` en orden. Si una falla por quota o error, pasa automáticamente a la siguiente.

### Celery (`celery_app.py`)

```python
broker_url     = "redis://localhost:6379/0"
result_backend = "redis://localhost:6379/0"
timezone       = "Europe/Madrid"
beat_schedule  = {"check-schedules-every-60s": {"task": "tasks.check_and_run_schedules", "schedule": 60.0}}
```

---

## Base de Datos

**Motor**: PostgreSQL 12+ | **DB**: `ciber_db` | **Usuario**: `admin`

### Tabla `targets`

| Columna | Tipo | Notas |
|---------|------|-------|
| `id` | Integer PK | |
| `name` | String | nombre legible |
| `url` | String UNIQUE | |
| `status` | String | `Pendiente`, `Escaneando`, `Completado`, `Error` |
| `last_scan` | DateTime | |
| `waf_detected` | String | nombre del WAF detectado |

### Tabla `findings`

| Columna | Tipo | Notas |
|---------|------|-------|
| `id` | Integer PK | |
| `target_id` | FK → targets | |
| `module` | String | `waf`, `whatweb`, `headers`, `certs`, `nikto`, `zap`, `kiterunner` |
| `severity` | String | `critical`, `high`, `medium`, `low`, `info` |
| `title` | String | |
| `description` | Text | |
| `extra` | Text (JSON) | datos adicionales |
| `scan_date` | DateTime | |

### Tabla `schedules`

| Columna | Tipo | Notas |
|---------|------|-------|
| `id` | Integer PK | |
| `target_ids` | Text | JSON array: `"[1, 2, 3]"` |
| `module` | Text | JSON array: `'["waf", "nikto"]'` |
| `scheduled_at` | String | ISO datetime |
| `repeat` | String | `once`, `daily`, `weekly`, `monthly` |
| `last_run` | Text | ISO del último run |

### Tabla `reports`

| Columna | Tipo | Notas |
|---------|------|-------|
| `id` | Integer PK | |
| `scope` | String | `single` o `all` |
| `target_ids` | Text | JSON array |
| `report_type` | String | `executive`, `technical`, `compliance`, `full` |
| `title` | String | generado automáticamente |
| `status` | String | `ready`, `analyzing` |
| `findings_snapshot` | Text (JSON) | snapshot de findings al momento de generar |
| `ai_content` | Text (JSON) | resultado del análisis IA (ver sección Agente IA) |
| `generated_at` | DateTime | |

---

## Servicios Requeridos y Arranque

### Instalación en un equipo nuevo

Clonar el repo NO configura Celery/Redis/systemd automáticamente — eso vive fuera de git (unit files en `~/.config/systemd/user/`, Redis del sistema, `.env` con credenciales). Para levantar todo de una en una máquina nueva (con Redis, Python 3.11+ y Node ya instalados):

```bash
./deploy/install.sh
```

El script crea el venv del backend, instala `backend/requirements.txt`, corre `npm install` en el frontend, copia `backend/.env.example` a `backend/.env` (hay que completar las credenciales a mano) y genera + habilita los 6 servicios `systemd --user` (`anubis-backend`, `anubis-frontend`, `anubis-celery`, `anubis-celery-heavy`, `anubis-celery-attack`, `anubis-celery-beat`) a partir de los templates en `deploy/systemd/`.

### Con systemd (recomendado)

```bash
systemctl --user start anubis-backend          # FastAPI en puerto 8000
systemctl --user start anubis-celery           # Worker cola light + Beat
systemctl --user start anubis-celery-heavy     # Worker cola heavy (zap, nikto, vector_agent)
systemctl --user start anubis-celery-attack    # Worker cola attack (execute_attack_run)
systemctl --user start anubis-frontend         # Vite dev server en puerto 5173
```

### Manual

```bash
# PostgreSQL y Redis (servicios del sistema)
sudo systemctl start postgresql redis

# Backend
cd backend && source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000

# Celery Worker
celery -A celery_app worker --loglevel=info

# Celery Beat
celery -A celery_app beat --loglevel=info

# Frontend
cd frontend && npm run dev
```

### Herramientas externas requeridas

```bash
pip install wafw00f
apt install whatweb nikto dirb gobuster
apt install libreoffice-writer          # para conversión DOCX → PDF
# OWASP ZAP: instalar con API activa en localhost:9090
# testssl.sh: en PATH del sistema
# kiterunner: binario en PATH
```

---

## Autenticación

| Campo | Valor |
|-------|-------|
| Usuario | `admin` |
| Contraseña | `anubis2026` |
| Token | `token-anubis-2026` (estático) |
| Header | `Authorization: Bearer token-anubis-2026` |

---

## Agente IA

El agente vive en `ai_agent.py` y se invoca vía `POST /reports/{id}/ai-analyze`.

### Flujo

1. El endpoint encola una tarea Celery `analyze_report_with_ai`
2. El worker carga el `findings_snapshot` del reporte (datos de WAF, SSL, cabeceras, WhatWeb, ZAP, Nikto, Kiterunner)
3. `_build_prompt()` construye un prompt detallado con todos los datos por target
4. Se llama al proveedor IA configurado (Gemini por defecto)
5. La respuesta Markdown se guarda en `ai_content.markdown_report`
6. El frontend detecta el cambio (`ai_generated: true`) y habilita las descargas

### Estructura del informe generado

El agente genera un Markdown con 6 secciones:

```
# 1. TÍTULO
# 2. INTRODUCCIÓN
# 3. ALCANCE
# 4. HALLAZGOS
    ## 4.1 WAF
    ## 4.2 SSL/TLS
    ## 4.3 Cabeceras HTTP
    ## 4.4 Stack Tecnológico (WhatWeb)
    ## 4.5 OWASP ZAP
    ## 4.6 Nikto
    ## 4.7 Endpoints API (Kiterunner)
# 5. RESUMEN DE HALLAZGOS  ← tabla Markdown
# 6. CONCLUSIONES
```

### Distinción "módulo no ejecutado" vs "sin hallazgos" (2026-07-06)

Antes de este fix, una lista de findings vacía era ambigua: podía significar "el módulo corrió y no encontró nada" o "el módulo nunca se ejecutó sobre este target", y la IA a veces inventaba un resultado positivo para el segundo caso. La solución:

- `scripts/waf.py` / `script_induvidual/waf.py` ahora persisten `waf_detected` en la tabla `targets` cuando corre wafw00f (antes solo actualizaban `status`).
- `scripts/certs.py` / `script_induvidual/certs.py` ahora guardan un finding informativo ("sin protocolos inseguros detectados") cuando testssl.sh corre limpio, en vez de dejar la lista vacía.
- `_build_prompt()` en `ai_agent.py` inserta un marcador explícito `NOT_RUN_MARKER` en el bloque de datos de WAF/certs cuando de verdad no hay dato. El prompt instruye a la IA: si ve ese marcador debe reportar **"NO EVALUADO"** / estado `➖` en la tabla resumen — nunca inventar un resultado positivo o negativo.
- El resto de módulos (headers, ZAP, Nikto, WhatWeb, Kiterunner) no usan este marcador: para ellos una lista vacía sigue significando legítimamente "corrió y no encontró nada".

### Fallback de API keys Gemini

Se pueden configurar múltiples claves en `.env`: `GEMINI_API_KEY`, `GEMINI_API_KEY_2`, `GEMINI_API_KEY_3`... El agente las intenta en orden y pasa a la siguiente si hay error de quota.

### Cambio de proveedor

```env
AI_PROVIDER=claude    # requiere ANTHROPIC_API_KEY
AI_PROVIDER=openai    # requiere OPENAI_API_KEY
AI_PROVIDER=gemini    # default
```

---

## Generación de Reportes

### DOCX

- Usa `python-docx` con `Pruebas Hardening OpenClaw.docx` como plantilla de estilos
- Limpia el cuerpo del documento pero conserva la configuración de página y encabezados
- El encabezado muestra: **"Reporte de Escaneo de Seguridad"**
- Renderiza el Markdown del agente IA: H1/H2/H3, párrafos, listas, tablas, separadores
- Las celdas con nivel de riesgo (CRÍTICO/ALTO/MEDIO/BAJO) se colorean automáticamente

### PDF

- Se genera a partir del DOCX usando **LibreOffice headless**
- El PDF es idéntico a abrir el DOCX en Word y guardar como PDF
- Requiere `libreoffice-writer` instalado en el sistema

### Descarga sin análisis IA

Si el reporte no tiene `markdown_report` (análisis IA pendiente), el DOCX/PDF se genera igualmente con la portada y un mensaje indicando que falta el análisis.

---

## Modo Ataque — UI

> **Actualización 2026-06-17**: El `AttackDashboard` ahora incluye un panel de control de ataque funcional con selector de target/intrusividad, gestión de autorizaciones, y visualización en tiempo real del plan, terminal y evidencias.
> **Actualización 2026-06-18**: El modal de ejecución de vectores muestra terminal y resultado en split-view.

Accesible haciendo clic en el logo de Anubis en la cabecera. Cambia toda la interfaz a un tema rojo con el `AttackDashboard`:

- **Stat cards**: targets activos, vulnerabilidades totales, estado del sistema
- **Barra de severidad**: distribución visual de hallazgos crítico/alto/medio/bajo
- **Lista de targets**: con su último estado de escaneo
- **Mapa de nodos**: representación SVG de targets con líneas de conexión y puntos pulsantes por vulnerabilidad
- **Terminal FAB**: botón flotante de acceso rápido
- **Attack Control Panel**: panel completo de pentesting con:
  - Selector de target + nivel de intrusividad (passive/active/exploitive)
  - Gestión de autorizaciones (registro de `authorized_targets`, filtrado de vigentes)
  - Botón Launch que llama `POST /attack/runs` y recibe el plan DAG construido
  - **AttackPlanViewer**: lista de nodos del DAG con estado en tiempo real, badges de intrusividad y retroalimentación de confianza
  - **LiveTerminal**: terminal WebSocket que hace streaming de los logs del orquestador Celery vía Redis pub/sub
  - **EvidenceGallery**: grid de evidencias capturadas (paths a screenshots, JSON dumps)
  - Botón Abort para señalizar parada cooperativa entre nodos

### Modal de ejecución de vectores — split view (2026-06-18)

Al ejecutar un vector desde el plan IA, el modal pasa por tres fases:

| Fase | Ancho modal | Layout |
|------|-------------|--------|
| `idle` (formulario) | `max-w-2xl` | columna única — instrucciones + botones de modo |
| `running` (ejecutando) | `max-w-5xl` | izquierda: LiveTerminal en vivo · derecha: spinner "esperando resultado…" |
| `done` (completado) | `max-w-5xl` | izquierda: LiveTerminal con todos los logs · derecha: resultado completo |

En la fase `done` el panel derecho muestra: badge de estado (EXPLOTABLE / NO EXPLOTABLE / INCONCLUSO), resumen, evidencia técnica, comando clave, impacto de negocio, recomendación de mitigación y botones "Nueva prueba" / "Cerrar". El terminal **permanece visible** para poder revisar qué ejecutó la IA.

---

## Anubis Attack — Arquitectura del Módulo de Explotación

Esta sección documenta las dos piezas de infraestructura que sustentan el backend del módulo de ataque: el **modelo de autorización** y el **plan de ataque como DAG**. Ambas deben estar en producción antes de implementar o conectar los scripts de explotación individuales.

Los archivos relevantes son:

| Archivo | Rol |
|---------|-----|
| `backend/attack_models.py` | Modelos SQLAlchemy: `AuthorizedTarget`, `AttackRun`, `AttackResult` |
| `backend/attack_schemas.py` | Schemas Pydantic: `AttackNode`, `AttackPlan`, DTOs de API |
| `backend/attack_planner.py` | Motor de reglas N:M + constructor del DAG |
| `backend/attack_orchestrator.py` | Tarea Celery de ejecución + compuerta de autorización |

---

### 1. Modelo de Autorización (`authorized_targets`)

#### Motivación

Un framework que lanza SQLMap, Hydra y exploits de CVE necesita una compuerta dura al inicio de cada run que verifique que el target está explícitamente autorizado. Sin esta compuerta, un typo en la URL o una configuración incorrecta puede hacer que la cadena automatizada cause daño real en un sistema no autorizado.

#### Tabla `authorized_targets`

```
authorized_targets
├── id                    PK
├── domain_pattern        "*.empresa.com" | "192.168.1.0/24" | "host.local"
├── valid_from            DateTime con zona horaria
├── valid_until           DateTime con zona horaria
├── authorized_by         Usuario que firmó la autorización
├── scope_document        Ruta al PDF/contrato de alcance (nullable)
├── allowed_modules       JSON array: ["sqli","header_exploits"] — null = todos
├── allowed_intrusiveness "passive" | "active" | "exploitive"
├── notes                 Observaciones libres
└── created_at            Timestamp de creación
```

#### Cómo funciona la comprobación

La función `validate_scope()` en `attack_orchestrator.py` se ejecuta como **primera operación** de todo attack run, antes de cargar el plan o ejecutar ningún vector:

```python
auth_error = validate_scope(db, target.url, run.intrusiveness, run.authorized_target_id)
if auth_error:
    run.status = "failed"
    db.commit()
    return f"SCOPE_ERROR: {auth_error}"
```

La función verifica en orden:
1. Que el registro de autorización existe y no ha expirado (`valid_from` ≤ ahora ≤ `valid_until`).
2. Que el hostname del target coincide con `domain_pattern` (fnmatch para wildcards, comparación CIDR para rangos IP).
3. Que el nivel de intrusividad solicitado no supera `allowed_intrusiveness`.

Si se omite `authorized_target_id`, busca cualquier registro vigente que cubra el target. Si no encuentra ninguno, la operación se detiene con error.

#### Niveles de intrusividad

| Nivel | Qué permite | Ejemplos de vectores |
|-------|-------------|---------------------|
| `passive` | Solo lectura, sin modificar estado del target | TLS downgrade check, banner grabbing |
| `active` | Envía payloads, no extrae datos sensibles | SQLi verify, XSS con screenshot, header exploits |
| `exploitive` | Extracción/escalada completa | SQLi extract (dump de DB), CVE exploit, post-RCE loot |

Los niveles son acumulativos: un run `exploitive` puede ejecutar vectores `passive` y `active`. Los vectores cuyo nivel supera el del run se marcan automáticamente como `skipped`.

#### Patrón de autorización recomendado (API)

```http
POST /authorized-targets
Content-Type: application/json

{
  "domain_pattern": "*.testlab.internal",
  "valid_from": "2026-06-16T00:00:00Z",
  "valid_until": "2026-06-30T23:59:59Z",
  "authorized_by": "admin",
  "scope_document": "/docs/contrato_pentest_junio2026.pdf",
  "allowed_modules": ["header_exploits", "sqli", "xss_playwright"],
  "allowed_intrusiveness": "active",
  "notes": "Engagement trimestral — entorno de staging"
}
```

---

### 2. Plan de Ataque como DAG

#### Motivación

Una lista priorizada de vectores es insuficiente para modelar la realidad de un pentest: un bruteforce exitoso desbloquea ataques que requieren sesión autenticada; un SQLi confirmado habilita extracción de credenciales; un RCE abre post-explotación. Un DAG permite declarar estas dependencias y activar nodos automáticamente cuando sus precondiciones se cumplen en tiempo de ejecución.

#### Estructura de un `AttackNode`

```python
AttackNode(
    id                   = "sqli_verify_42",     # único dentro del plan
    vector_type          = "sqli",               # qué módulo ejecutar
    target_url           = "https://target.com",
    finding_id           = 42,                   # finding origen (nullable)
    finding_title        = "SQL Injection en /login",
    finding_severity     = "critical",
    finding_confidence   = 0.8,
    intrusiveness        = "active",
    requires_nodes       = [],                   # IDs de nodos que deben completarse primero
    requires_capabilities= [],                   # capacidades que deben estar disponibles
    provides             = ["db_read_access"],   # capacidades que desbloquea si confirma
    confidence_threshold = 0.6,                  # confianza mínima del finding para ejecutar
    timeout_seconds      = 600,
    params               = { "source_finding": {...} },
    status               = "planned",            # planned|running|completed|failed|aborted|skipped
    priority_score       = 56.0,                 # base_priority × severity_weight × confidence
)
```

#### Dependencias: `requires_nodes` vs `requires_capabilities`

| Campo | Tipo de dependencia | Cuándo usar |
|-------|---------------------|-------------|
| `requires_nodes` | Estructural — ID de nodo concreto | Cuando el segundo nodo necesita la salida específica del primero |
| `requires_capabilities` | Funcional — capacidad abstracta | Cuando el nodo necesita que *algún* vector anterior haya logrado algo (e.g. sesión autenticada) |

Las `requires_capabilities` se resuelven a `requires_nodes` en tiempo de construcción del plan (`build_attack_plan()`), de modo que el orquestador solo trabaja con IDs concretos en ejecución.

#### Capacidades del catálogo

| Capacidad | La provee | La consume |
|-----------|-----------|------------|
| `db_read_access` | `sqli_verify` | `sqli_extract` |
| `db_credentials` | `sqli_extract` | — |
| `authenticated_session` | `auth_bruteforce` | `idor_enumerate`, `priv_escalation` |
| `admin_session` | `priv_escalation` | — |
| `rce_access` | `cve_exploiter` | `post_rce_loot` |
| `system_credentials` | `post_rce_loot` | — |
| `enumerated_data` | `idor_enumerate` | — |

#### Ejemplo de DAG generado

```
findings del scan:
  #42 — SQLi en /login (zap, critical, confidence=0.8)
  #55 — Rate limit ausente en /auth (zap, high, confidence=0.7)
  #61 — CVE-2024-XXXX en Apache (nikto, critical, confidence=0.9)

DAG resultante (max_intrusiveness="exploitive"):

  sqli_verify_42  ──provides db_read_access──►  sqli_extract_capability
  auth_bruteforce_55  ──provides authenticated_session──►  idor_enumerate_?
                                                         ►  priv_escalation_capability
  cve_exploit_61  ──provides rce_access──►  post_rce_loot_capability
```

Orden de ejecución (topológico por priority_score):
1. `cve_exploit_61` (score=270.0) — sin dependencias, mayor prioridad
2. `sqli_verify_42` (score=140.0) — sin dependencias
3. `auth_bruteforce_55` (score=98.0) — sin dependencias
4. `post_rce_loot_capability` — espera `rce_access` (de `cve_exploit_61`)
5. `sqli_extract_capability` — espera `db_read_access` (de `sqli_verify_42`)
6. `idor_enumerate_?` + `priv_escalation_capability` — esperan `authenticated_session`

#### Cómo se construye el plan

`build_attack_plan()` en `attack_planner.py` ejecuta tres pasos:

**Paso 1 — Matching finding → regla (N:M)**

```python
for finding in findings:
    for rule in VECTOR_RULES:
        if rule.matches_finding(finding):
            node = rule.build_node(finding, target_url)
            # dedup por vector_type + finding_id
```

No es un diccionario 1:N. Cada regla tiene `conditions` con operadores (`__in`, `__contains`, `__gte`) que se evalúan contra los campos del finding. Un finding puede activar múltiples reglas; una regla puede ser activada por múltiples findings (se deduplica conservando el de mayor `priority_score`).

**Paso 2 — Reglas capability-triggered**

Reglas sin `conditions` (como `sqli_extract`, `post_rce_loot`) se añaden al plan si sus `requires_capabilities` ya están provistas por los nodos del paso 1.

**Paso 3 — Resolución de capacidades a IDs**

```python
capability_providers = {}
for n in nodes:
    for cap in n.provides:
        capability_providers.setdefault(cap, []).append(n.id)

for n in nodes:
    n.requires_nodes = [id for cap in n.requires_capabilities
                           for id in capability_providers.get(cap, [])]
```

#### Cálculo de `priority_score`

```
priority_score = base_priority × SEVERITY_WEIGHT[severity] × finding_confidence
```

| Severidad | Peso |
|-----------|------|
| critical  | 10   |
| high      | 7    |
| medium    | 4    |
| low       | 2    |
| info      | 0    |

Ejemplo: `sqli_verify` (base_priority=2.5) + critical (10) + confidence=0.8 → score=20.0

---

### 3. Motor de Ejecución (`execute_attack_run`)

La tarea Celery en `attack_orchestrator.py` ejecuta el DAG con el siguiente bucle:

```
while plan.has_pending_nodes():
    check abort_requested
    executable = plan.get_executable_nodes(completed_ids, failed_ids, available_capabilities)
    if not executable:
        mark remaining nodes as skipped
        break
    for node in sorted(executable, by priority_score desc):
        execute_vector(node)
        persist AttackResult
        if confirmed:
            available_capabilities.update(node.provides)
            update finding.confidence += delta
```

#### Abort cooperativo

El campo `attack_runs.abort_requested` actúa como señal de parada entre nodos. Entre cada nodo, el orquestador comprueba el valor actualizado de la DB. Si está activo:
- Envía `SIGTERM` al subproceso en curso (si existe).
- Marca todos los nodos pendientes como `aborted`.
- Actualiza el estado del run a `aborted`.

Los subprocesos de larga duración (SQLMap puede tardar horas) se registran en `_active_processes[run_id]` para poder terminarlos.

#### Retroalimentación de confianza

Tras cada nodo, `_update_finding_confidence()` ajusta `findings.confidence`:
- Vector **confirma** la vulnerabilidad → `confidence += max(delta, +0.1)`
- Vector **falla** → `confidence += min(delta, -0.05)`

Esto permite que sucesivas ejecuciones de attack afinen la confianza de los findings del scan, reduciendo el ruido de falsos positivos heredados de ZAP.

#### Contrato de los scripts de ataque

Cada módulo en `attack_scripts/` debe seguir este contrato:

```bash
python3 header_exploits.py <target_url> <params_json>
```

Salida stdout (JSON) al terminar:

```json
{
  "confirmed":        true,
  "confidence_delta": 0.2,
  "evidence_path":    "/reports/attack/run_1/header_exploits_evidence.png",
  "details":          { ... }
}
```

- `exit_code 0` = ejecución técnicamente correcta (puede ser `confirmed=false`)
- `exit_code != 0` = error de ejecución (se registra stderr como `error_message`)

---

### 4. Nuevas Tablas de Base de Datos

#### `authorized_targets`

| Columna | Tipo | Notas |
|---------|------|-------|
| `id` | Integer PK | |
| `domain_pattern` | String(255) | Wildcard, CIDR, o literal |
| `valid_from` | DateTime(tz) | Inicio del periodo de autorización |
| `valid_until` | DateTime(tz) | Fin del periodo — la compuerta lo verifica |
| `authorized_by` | String(100) | Usuario que firmó |
| `scope_document` | String(512) | Ruta al contrato/PDF (nullable) |
| `allowed_modules` | Text | JSON array de módulos permitidos (null = todos) |
| `allowed_intrusiveness` | String(20) | passive / active / exploitive |
| `notes` | Text | Observaciones libres (nullable) |
| `created_at` | DateTime(tz) | |

#### `attack_runs`

| Columna | Tipo | Notas |
|---------|------|-------|
| `id` | Integer PK | |
| `target_id` | Integer | FK → targets |
| `authorized_target_id` | Integer | FK → authorized_targets (nullable) |
| `plan_json` | Text | AttackPlan DAG serializado como JSON |
| `status` | String(20) | planned / running / completed / aborted / failed |
| `intrusiveness` | String(20) | Máximo nivel permitido en este run |
| `abort_requested` | Boolean | Señal de abort cooperativo |
| `created_by` | String(100) | Usuario que inició el run (nullable) |
| `started_at` | DateTime(tz) | |
| `completed_at` | DateTime(tz) | |
| `created_at` | DateTime(tz) | |

#### `attack_results`

| Columna | Tipo | Notas |
|---------|------|-------|
| `id` | Integer PK | |
| `run_id` | Integer | FK → attack_runs |
| `node_id` | String(100) | Coincide con `AttackNode.id` en el DAG |
| `vector_type` | String(50) | Módulo ejecutado |
| `status` | String(20) | planned / running / completed / failed / aborted / skipped |
| `output_json` | Text | Salida estructurada del módulo (nullable) |
| `evidence_path` | String(512) | Ruta a screenshot / pcap / dump (nullable) |
| `confirmed_finding` | Boolean | ¿Confirmó la vulnerabilidad? (nullable) |
| `confidence_delta` | Float | Ajuste aplicado a `findings.confidence` |
| `error_message` | Text | Mensaje de error si status=failed (nullable) |
| `started_at` / `completed_at` | DateTime(tz) | |
| `created_at` | DateTime(tz) | |

#### Cambio en tabla `findings`

Se añadió la columna `confidence (Float, nullable)` para permitir que el orquestador retroalimente la confianza de cada hallazgo.

```sql
ALTER TABLE findings ADD COLUMN confidence FLOAT;
```

---

### 5. Endpoints del Módulo de Ataque

> **Estado**: Todos conectados y operativos en `main.py` (implementado 2026-06-17).

#### Autorización

| Método | Ruta | Body / Params | Descripción |
|--------|------|--------------|-------------|
| `POST` | `/authorized-targets` | `AuthorizedTargetCreate` | Registra autorización |
| `GET` | `/authorized-targets` | — | Lista autorizaciones con campo `is_active` calculado en tiempo real |
| `DELETE` | `/authorized-targets/{id}` | — | Revoca autorización |

#### Attack Runs

| Método | Ruta | Body / Params | Descripción |
|--------|------|--------------|-------------|
| `POST` | `/attack/runs` | `AttackRunCreate` | Construye plan DAG y encola ejecución Celery (cola `attack`) |
| `GET` | `/attack/runs` | `target_id?` | Lista runs (filtrable por target) |
| `GET` | `/attack/runs/{id}` | — | Detalles del run + `node_count` + `result_count` + `plan_json` |
| `POST` | `/attack/runs/{id}/abort` | — | Pone `abort_requested=True` y `status="aborted"` |
| `GET` | `/attack/runs/{id}/results` | — | Lista `AttackResult` del run |

#### WebSocket — Terminal en vivo

```
WS /ws/attack/{run_id}
```

Streaming de logs del orquestador al frontend vía Redis pub/sub (canal `anubis:attack:run:{run_id}`, db=2). El frontend conecta automáticamente cuando hay un run activo.

#### Flujo típico de un attack run

```
1. POST /authorized-targets           → registrar alcance y firmante
2. POST /attack/runs                  → build_attack_plan() + encolar Celery
3. WS   /ws/attack/{id}               → conectar terminal para ver logs en tiempo real
4. GET  /attack/runs/{id}             → monitorear status del run (polling cada 4s desde UI)
5. (opcional) POST /attack/runs/{id}/abort  → señalizar parada cooperativa
6. GET  /attack/runs/{id}/results     → ver resultados por nodo con evidence_path
```

---

### 6. Scripts de Ataque (`attack_scripts/`)

> **Estado (2026-07-06)**: sin scripts implementados. `header_exploits.py` — único de los 10 vectores del catálogo que llegó a implementarse (2026-06-17) — se eliminó: el Vector Agent IA (`vector_agent.py`, ver sección siguiente) lo reemplaza con un enfoque más flexible, la IA razona y ejecuta comandos directamente en vez de depender de un script Python fijo por vector. Sin impacto en runs existentes (`attack_results` no tenía ningún registro histórico con `vector_type='header_exploits'`); la regla `header_verify` sigue generando el nodo en el DAG, y el orquestador lo marca `pending`/`skipped` igual que a los otros 9 vectores nunca escritos.

#### Contrato de todos los scripts

```bash
python3 <script>.py <target_url> <params_json>
```

```json
// stdout (exit_code=0):
{ "confirmed": bool, "confidence_delta": float, "evidence_path": "...", "details": {...} }
// exit_code != 0 → error de ejecución (mensaje en stderr)
```

Evidencias guardadas en: `/home/anubis/AnubisProject/reports/attack/<vector_type>/`

#### Scripts disponibles

| Script | Estado | Intrusividad | Qué hace |
|--------|--------|-------------|----------|
| `sqli.py` | ⏳ Pendiente | active | SQLMap contra endpoints marcados por ZAP/Nikto |
| `sqli_extract.py` | ⏳ Pendiente | exploitive | SQLMap --dump tras confirmar SQLi |
| `xss_playwright.py` | ⏳ Pendiente | active | Playwright para confirmar XSS con screenshot |
| `auth_bruteforce.py` | ⏳ Pendiente | active | Hydra/Patator en endpoints sin rate limiting |
| `idor_enumerate.py` | ⏳ Pendiente | active | Enumeración IDOR con sesión autenticada |
| `priv_escalation.py` | ⏳ Pendiente | exploitive | Escalada de privilegios post-autenticación |
| `tls_downgrade.py` | ⏳ Pendiente | passive | Verificación downgrade TLS vía testssl.sh |
| `cve_exploiter.py` | ⏳ Pendiente | exploitive | PoC de CVE con searchsploit |
| `post_rce_loot.py` | ⏳ Pendiente | exploitive | Recolección post-RCE |

Scripts pendientes: el orquestador los detecta (`pending: true` en output) y los registra como `skipped` sin fallar el run completo.

---

### 7. Agente de Vectores IA (`vector_agent.py`)

El agente de vectores es el componente de IA que toma un vector del plan DAG y lo ejecuta de forma autónoma en un loop de razonamiento → acción → resultado.

#### Flujo de ejecución

```
tasks.py: run_vector_agent_task()
    │
    ├─ Carga scan_context desde DB + JSONs de reporte del target
    │       (WhatWeb, ZAP, Headers, Nikto, Certs)
    │
    ├─ Llama a run_vector_agent(..., scan_context=...)
    │
    └─ Loop: while iterations < max_iter
            ├─ Construye prompt con historial + contexto
            ├─ Llama a Gemini (_call_ai)
            ├─ Parsea JSON de respuesta
            ├─ Si accion="ejecutar_comando": valida + ejecuta en bash
            └─ Si accion="finalizar": guarda resultado y rompe el loop
```

#### Modos de ejecución

| Modo | Iteraciones | Timeout por cmd | Objetivo |
|------|-------------|-----------------|----------|
| `quick` | 3 | 60 s | Confirmar que el vector existe (PoC mínimo) |
| `full` | 8 | 180 s | Explotar y documentar impacto real |

#### Contexto de escaneos previos (2026-06-18)

Antes de llamar al agente, `tasks.py` construye un bloque `scan_context` con los resultados de los módulos de reconocimiento ya ejecutados para ese target:

```python
# Fuentes en orden de preferencia: JSON de reporte → findings en DB
- STACK TECNOLÓGICO (WhatWeb):  todas las tecnologías detectadas
- VULNERABILIDADES ZAP:         hasta 20, con severidad y OWASP ID
- CABECERAS HTTP:               presentes y ausentes
- HALLAZGOS NIKTO:              hasta 15 findings con severidad
- PROTOCOLOS SSL/TLS DÉBILES:   SSLv2/3, TLS 1.0/1.1 si detectados
```

Este bloque se inyecta en el prompt inicial con la instrucción explícita **"usa esta información directamente — no repitas fingerprinting"**. El agente arranca en explotación desde la iteración 1.

#### Fase de explotación — no reconocimiento (2026-06-18)

El agente está concebido exclusivamente como módulo de **explotación**. El reconocimiento lo hacen los módulos dedicados (WhatWeb, ZAP, Nikto, etc.). Por eso:

- `whatweb`, `nikto`, `nmap`, `wafw00f` han sido **eliminados** de `ALLOWED_TOOLS`. Si la IA intenta usarlos, el validador los bloquea antes de ejecutar.
- El `SYSTEM_PROMPT_BASE` incluye la sección **"ROL — FASE DE EXPLOTACIÓN"** que lo prohíbe explícitamente.
- Las herramientas disponibles son únicamente las de ataque: `wpscan`, `sqlmap`, `nuclei`, `gobuster`, `ffuf`, `hydra`, `commix`, `curl`, `wget`, `testssl.sh`, `sslyze`, `dirb`, `openssl`.

#### Herramientas de explotación disponibles

| Herramienta | Uso principal |
|-------------|---------------|
| `curl` | Payloads HTTP: XSS, SQLi, LFI, SSRF, auth bypass |
| `wpscan` | Enumeración y explotación WordPress (plugins, CVEs, usuarios) |
| `sqlmap` | Explotación SQL (solo `--dbs`, `--tables`, `--dump --start=1 --stop=2`) |
| `nuclei` | CVEs y exploits conocidos vía templates |
| `gobuster` / `dirb` | Fuerza bruta de rutas y archivos sensibles |
| `ffuf` / `wfuzz` | Fuzzing de parámetros y rutas |
| `hydra` | Ataques de autenticación (máx. 20 intentos) |
| `commix` | Inyección OS (solo `whoami`, `id`, `hostname`, `uname`) |
| `testssl.sh` / `sslyze` | Explotación de configuraciones TLS débiles |

#### Validación de seguridad

`validate_command()` en `vector_agent.py` fue endurecida el 2026-06-30 tras detectar que un validador basado solo en "primer token" dejaba pasar cadenas como `curl url; cat /etc/shadow` o `curl url && python3 -c ...`. Antes de ejecutar cualquier comando verifica, en orden:

1. **Sin multilínea** (`\n`/`\r`) y sin sustitución/composición de comandos: `$()`, backticks, `<()`, `>()` — ningún validador de "primer token" las detecta, así que se bloquean directamente por presencia del patrón.
2. **Patrones prohibidos** vía `FORBIDDEN_PATTERNS` (`rm -`, `dd`, `mkfs`, `| bash`, `| sh`, `--os-shell`, etc.)
3. **Tokeniza con `shlex`** y separa el comando en sub-comandos por `;`, `&&`, `||`, `|` — **cada uno** debe empezar con una herramienta de `ALLOWED_TOOLS` (ya no solo el primero de toda la cadena). Ejecución en segundo plano (`&`) se rechaza porque evade el timeout.
4. Herramientas de lectura de archivos (`cat`, `head`, `grep`, ver `FILE_READING_TOOLS`) solo pueden apuntar a rutas dentro de `/tmp` — bloquea leer archivos arbitrarios del host que corre el agente.
5. Redirecciones (`>`, `>>`) a rutas absolutas fuera de `/tmp` también se rechazan.
6. Límites duros a `sqlmap`: `--threads` ≤ 5, `--level` ≤ 3, `--risk` ≤ 2 (antes el system prompt los pedía pero nada los hacía cumplir).

Si falla la validación, el agente recibe la razón puntual y debe proponer un comando alternativo en la siguiente iteración.

#### Resultado final

Al terminar (por `accion="finalizar"` o por agotar iteraciones), el agente retorna:

```json
{
  "estado":            "explotable" | "no_explotable" | "inconcluso",
  "resumen":           "1-2 oraciones para reporte ejecutivo",
  "evidencia_tecnica": "output exacto o fragmento relevante",
  "impacto_negocio":   "qué podría hacer un atacante real",
  "comando_clave":     "el comando que confirmó la vulnerabilidad",
  "recomendacion":     "pasos técnicos de mitigación",
  "iterations":        2
}
```

Este resultado se guarda en la tabla `vector_runs` y se muestra en el split-view del modal.

#### Tabla `vector_runs`

| Columna | Tipo | Notas |
|---------|------|-------|
| `id` | Integer PK | |
| `target_id` | FK → targets | |
| `vector_name` | String | nombre técnico del vector |
| `vector_titulo` | String | título legible |
| `vector_json` | Text | JSON completo del vector del plan IA |
| `mode` | String | `quick` / `full` |
| `instructions` | Text | instrucciones adicionales del operador |
| `status` | String | `pending` / `running` / `completed` / `failed` |
| `estado` | String | `explotable` / `no_explotable` / `inconcluso` |
| `resumen` | Text | |
| `evidencia_tecnica` | Text | |
| `impacto_negocio` | Text | |
| `comando_clave` | Text | |
| `recomendacion` | Text | |
| `iterations` | Integer | número de iteraciones usadas |
| `started_at` / `completed_at` / `created_at` | DateTime(tz) | |

#### WebSocket — Terminal en vivo del vector

```
WS /ws/vector-run/{run_id}
```

Canal Redis: `anubis:vector:{run_id}` (db=2). Cada línea publicada por `publish_fn()` en `vector_agent.py` llega al frontend en tiempo real. La conexión termina cuando el agente publica `[DONE]` o tras 600 s de inactividad.

---

### 8. Catálogo de Vectores y Capacidades

| `vector_type` | Intrusividad | Herramienta | Activa por | Provee |
|---------------|-------------|-------------|------------|--------|
| `header_exploits` | active | requests custom | headers high/critical | — |
| `sqli` | active | SQLMap | zap/nikto SQLi | `db_read_access` |
| `sqli_extract` | exploitive | SQLMap (--dump) | capability: `db_read_access` | `db_credentials` |
| `xss_playwright` | active | Playwright | zap/nikto XSS | — |
| `auth_bruteforce` | active | Hydra/Patator | rate limit ausente | `authenticated_session` |
| `idor_enumerate` | active | custom | IDOR finding + `authenticated_session` | `enumerated_data` |
| `priv_escalation` | exploitive | custom | capability: `authenticated_session` | `admin_session` |
| `tls_downgrade` | passive | testssl.sh | certs high/critical | — |
| `cve_exploiter` | exploitive | searchsploit + custom | CVE en título | `rce_access` |
| `post_rce_loot` | exploitive | custom | capability: `rce_access` | `system_credentials` |

---

## Limitaciones Conocidas

| Área | Limitación |
|------|-----------|
| Auth | Token hardcodeado estático, sin expiración |
| Frontend | URL del backend hardcodeada (`http://127.0.0.1:8000`) en todas las páginas |
| Scripts | Credenciales DB hardcodeadas en cada script de escaneo |
| PDF | Requiere LibreOffice instalado en el servidor |
| Tests | Sin tests (unitarios ni de integración) |
| Docker | Sin contenedores, setup manual |
| Logs | Solo `print()`, sin framework de logging estructurado |
| Rate limiting | Sin throttling en la API |
| TypeScript | Frontend en JSX puro, sin tipado |
