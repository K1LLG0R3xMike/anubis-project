Anubis Attack — Arquitectura y Fases

  Principio Fundamental

  El flujo es: Scan findings → Attack Plan → Exploit Execution → Evidence → Report. No re-escanea, consume los datos ya almacenados en la DB.

  ---
  Fase 1: Attack Planner (IA-driven)

  Qué es: Un módulo que toma los findings de la DB y genera un plan de ataque priorizado, decidiendo qué técnicas son viables contra cada target.

  Cómo funciona

  findings (DB) → attack_planner.py → attack_plan (JSON)

  El planner mapea findings a vectores de ataque:

  ┌─────────────────────────────────┬─────────────────────────────────────────────────────────────┐
  │         Finding en Scan         │                  Vector de Ataque generado                  │
  ├─────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ WAF: Cloudflare detectado       │ Técnicas de bypass WAF (encoding, fragmentation, slow-rate) │
  ├─────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Header X-Frame-Options: ausente │ Clickjacking exploit                                        │
  ├─────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Header CSP: ausente             │ XSS payload injection                                       │
  ├─────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Nikto: Server version expuesta  │ Buscar CVEs de esa versión exacta                           │
  ├─────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ ZAP: SQL Injection (medium)     │ SQLMap automatizado contra ese endpoint                     │
  ├─────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ WhatWeb: WordPress 5.8          │ WPScan con credenciales por defecto                         │
  ├─────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Kiterunner: /api/v1/admin       │ Fuerza bruta de autenticación, IDOR checks                  │
  ├─────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ TLS: SSLv3/TLSv1.0 habilitado   │ Downgrade attack, POODLE/BEAST                              │
  ├─────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Header HSTS: ausente            │ SSL stripping                                               │
  └─────────────────────────────────┴─────────────────────────────────────────────────────────────┘

  Implementación:

  # backend/attack_planner.py
  def generate_attack_plan(target_id: int) -> dict:
      findings = db.query(Finding).filter_by(target_id=target_id).all()

      plan = {
          "target_id": target_id,
          "attack_vectors": [],
          "priority_order": [],
          "estimated_duration": 0
      }

      for finding in findings:
          vectors = FINDING_TO_ATTACK_MAP.get(finding.module, [])
          # Filtrar por severidad y confianza
          plan["attack_vectors"].extend(vectors)

      # IA (Gemini) ordena por impacto/probabilidad de éxito
      plan["priority_order"] = ai_prioritize(plan["attack_vectors"])
      return plan

  ---
  Fase 2: Módulos de Explotación

  Nueva carpeta attack_scripts/ espejando scripts/, uno por vector:

  Módulos propuestos

  attack_scripts/
  ├── waf_bypass.py          # Técnicas de bypass (case variation, URL encoding, chunked)
  ├── header_exploits.py     # Clickjacking PoC, XSS via header injection
  ├── ssl_downgrade.py       # Test SSLv3/TLSv1.0 downgrade + BEAST/POODLE
  ├── sqli_tester.py         # SQLMap automatizado en endpoints ZAP marcados
  ├── xss_tester.py          # XSS payload testing en endpoints descubiertos por ZAP/Kiterunner
  ├── auth_bruteforce.py     # Hydra/Patator en /login o endpoints API de auth
  ├── idor_checker.py        # IDOR en endpoints API del Kiterunner (IDs secuenciales)
  ├── cve_exploiter.py       # Busca y prueba exploits públicos según versión detectada
  ├── dir_traversal.py       # Path traversal en rutas de Kiterunner
  └── csrf_tester.py         # CSRF en formularios sin token (ZAP findings)

  Cada módulo sigue el mismo patrón que los de scan:
  1. Recibe target_url + relevant_findings (contexto)
  2. Ejecuta herramienta (SQLMap, Hydra, curl, etc.) o código propio
  3. Guarda resultado en attack_results/ como JSON con evidencia
  4. Llama a db.save_attack_result(target_id, module, result)

  ---
  Fase 3: Motor de Orquestación

  Nueva tabla en DB: attack_runs

  attack_runs
  ├── id (PK)
  ├── target_id (FK)
  ├── plan_json     -- el plan generado por el planner
  ├── status        -- 'planned', 'running', 'completed', 'aborted'
  ├── started_at
  ├── completed_at
  └── created_at

  attack_results
  ├── id (PK)
  ├── attack_run_id (FK)
  ├── module        -- 'sqli', 'xss', 'waf_bypass', etc.
  ├── vector        -- descripción del ataque específico
  ├── status        -- 'exploited', 'failed', 'partial', 'blocked_by_waf'
  ├── evidence_path -- ruta a screenshot/request dump
  ├── cvss_score    -- calculado automáticamente
  ├── details_json
  └── executed_at

  Nuevos endpoints

  POST /attack/plan/{target_id}          → genera y guarda plan, retorna plan_json
  POST /attack/run/{attack_run_id}       → encola ejecución en Celery
  GET  /attack/runs/                     → lista todos los runs
  GET  /attack/runs/{id}                 → detalles + resultados
  POST /attack/runs/{id}/abort           → cancela ejecución
  GET  /attack/results/{target_id}       → todos los resultados de un target

  Tarea Celery

  # tasks.py (añadir)
  @app.task(bind=True)
  def run_attack_plan(self, attack_run_id: int):
      run = db.query(AttackRun).get(attack_run_id)
      plan = json.loads(run.plan_json)

      for vector in plan["priority_order"]:
          if run.status == "aborted":
              break

          module = load_attack_module(vector["module"])
          result = module.execute(
              target_url=run.target.url,
              findings=vector["relevant_findings"]
          )

          db.save_attack_result(attack_run_id, vector, result)
          self.update_state(state="PROGRESS", meta={"current": vector})

  ---
  Fase 4: Recolección de Evidencias

  Cada módulo debe capturar prueba de explotación:

  attack_results/
  ├── {target_name}/
  │   ├── sqli/
  │   │   ├── request.txt        # HTTP request completo
  │   │   ├── response.txt       # HTTP response con datos filtrados
  │   │   └── screenshot.png     # Via Playwright/Selenium headless
  │   ├── xss/
  │   │   ├── payload_fired.txt
  │   │   └── screenshot.png
  │   └── waf_bypass/
  │       ├── bypassed_request.txt
  │       └── raw_response.txt

  Para screenshots automatizados: Playwright (ya es Python) captura el navegador cuando el XSS se dispara, cuando el IDOR devuelve datos de otro usuario, etc.

  ---
  Fase 5: UI del AttackDashboard

  El AttackDashboard.jsx ya existe. Hay que añadirle:

  Panel de Control de Ataque

  ┌─────────────────────────────────────────────┐
  │  TARGET: api.victima.com    [PLAN] [EXECUTE] │
  ├──────────────────┬──────────────────────────┤
  │  ATTACK PLAN     │  LIVE TERMINAL           │
  │  ─────────────   │  ──────────────────────  │
  │  [1] SQLi ●●●●○  │  > Running sqli_tester   │
  │  [2] XSS  ●●●○○  │  > Testing endpoint /api │
  │  [3] IDOR ●●○○○  │  [!] SQLi FOUND - /login │
  │  [4] Bypass WAF  │  > Capturing evidence... │
  │                  │  > Saving screenshot...  │
  ├──────────────────┴──────────────────────────┤
  │  RESULTS: 2 Exploited │ 1 Partial │ 1 Failed│
  └─────────────────────────────────────────────┘

  Componentes nuevos:
  - AttackPlanViewer.jsx — árbol de vectores priorizados por la IA, con colores por probabilidad
  - LiveTerminal.jsx — WebSocket al backend que streamed logs de Celery en tiempo real
  - EvidenceGallery.jsx — grid de screenshots y request dumps por resultado
  - ExploitationReport.jsx — reporte de ataque (diferente del de scan), con CVSS por vuln confirmada

  WebSocket para terminal en vivo

  # main.py
  @app.websocket("/ws/attack/{run_id}")
  async def attack_websocket(websocket: WebSocket, run_id: int):
      await websocket.accept()
      # Suscribirse al canal Redis de la tarea Celery
      # Streamed logs línea a línea al frontend

  ---
  Orden de Implementación Sugerido

  ┌────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │ Semana │                                                Qué construir                                                │
  ├────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ 1      │ attack_planner.py + tabla attack_runs/attack_results + endpoint /attack/plan                                │
  ├────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ 2      │ Primeros 3 módulos: header_exploits.py, ssl_downgrade.py, waf_bypass.py (sin herramientas externas pesadas) │
  ├────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ 3      │ sqli_tester.py + xss_tester.py (SQLMap + Playwright) + tarea Celery                                         │
  ├────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ 4      │ WebSocket terminal en vivo + AttackPlanViewer.jsx + LiveTerminal.jsx                                        │
  ├────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ 5      │ EvidenceGallery.jsx + generación de Attack Report con IA                                                    │
  └────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ---
  Punto de Partida Más Rápido

  El módulo más sencillo de empezar porque no necesita herramientas externas es header_exploits.py:

  1. Lee findings de headers faltantes (ya en DB)
  2. Genera un HTML de PoC de clickjacking con <iframe> al target
  3. Verifica si CSP bloquea scripts inline con una petición curl
  4. Guarda evidencia como texto

  Eso valida toda la arquitectura (planner → módulo → evidencia → resultado en DB → UI) con código simple, antes de integrar SQLMap, Hydra, etc.

  ---
