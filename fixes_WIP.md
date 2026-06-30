🔴 Crítico

  1. [FIXED 2026-06-30] Los Attack Runs probablemente no se ejecutan nunca. main.py y attack_orchestrator.py encolan las tareas en la cola Celery "attack", pero celery_app.py solo declara las colas heavy, light y beat — y no
  hay ningún worker en el repo configurado para consumir attack. Resultado: POST /attack/runs crea el run en estado planned y la tarea Celery se queda esperando un worker que nunca llega. El README afirma
  que esto está "implementado y operativo desde 2026-06-17", pero parece que nunca se verificó en producción.
     → Fix: declarada Queue('attack') en celery_app.py + nuevo servicio systemd anubis-celery-attack.service (mismo patrón que heavy), habilitado y arrancado. Verificado end-to-end enviando una tarea de prueba a la cola y confirmando que el worker la recibe y ejecuta. README actualizado (tabla de colas + comandos de arranque).

  2. [FIXED 2026-06-30] El agente de vectores IA (vector_agent.py) tiene una validación de comandos insuficiente para lo que hace. execute_shell_command() corre con shell=True, y validate_command() solo revisa el primer token
  del comando contra ALLOWED_TOOLS más una lista corta de patrones prohibidos. Esto significa:
  - Encadenamiento (&&, ||, backticks, $()) no se filtra — solo ; parcialmente.
  - python3/python están en ALLOWED_TOOLS, lo que permite ejecución arbitraria vía python3 -c "..." sin tocar ningún patrón prohibido.
  - Los límites "blandos" (máx threads, intentos hydra, etc.) solo viven como instrucción de texto al LLM, sin enforcement real.

     Dado que este agente corre IA autónoma contra targets reales, esto es la compuerta de seguridad más débil del sistema — vale la pena endurecerla antes de seguir usándolo en exploitive mode.
     → Fix en backend/vector_agent.py:
       - validate_command() ahora tokeniza con shlex (respeta comillas) y separa el comando en sub-comandos por ; && || | — CADA sub-comando debe empezar con una herramienta de ALLOWED_TOOLS (antes solo se validaba el primer token de todo el string).
       - Bloqueados $(), ``, <(), >() (sustitución de comandos embebida en un argumento).
       - Bloqueado '&' suelto (background) — evadía el timeout de subprocess.run.
       - python3/python eliminados de ALLOWED_TOOLS (no estaban ni en el system prompt como herramienta disponible).
       - cat/head/grep restringidos a leer solo dentro de /tmp (antes podían apuntar a /etc/shadow, etc. sin que nada lo detectara).
       - Redirecciones (> / >>) a rutas absolutas fuera de /tmp bloqueadas.
       - Límites de sqlmap (--threads ≤5, --level ≤3, --risk ≤2) ahora se hacen cumplir programáticamente, no solo como instrucción de texto al LLM.
       - Verificado con 21 casos de prueba (bypasses conocidos bloqueados + comandos legítimos sin falsos positivos) y py_compile limpio.
       - Pendiente/no cubierto: límites de hydra (intentos) y flags de salida de otras herramientas (ej. -o de gobuster/ffuf) no se parsean por argumento; quedan solo cubiertos por el contrato ético del prompt.

    3. [FIXED 2026-06-30] [Detectado en vivo, run #12 contra celsiainternet.com] El vector agent moría en la 1ª iteración con "INCONCLUSO" vacío y un log engañoso de "Límite de 3 iteraciones alcanzado" aunque solo corrió 1.
     Causa: en vector_agent.py, cuando la IA responde accion="finalizar" pero "resultado_final" viene vacío/incompleto (probablemente la IA corta su propia generación a mitad de JSON), el código lo aceptaba como resultado válido (`{}` es falsy en Python) y rompía el loop inmediatamente; el bloque post-loop interpretaba ese final_result vacío como "se acabaron las iteraciones" y sobreescribía con el mensaje genérico — de ahí el mensaje contradictorio (1 iteración real vs "límite alcanzado"). El mismo problema existía si la IA pedía ejecutar un comando pero no lo incluía.
     → Fix: ahora si "resultado_final" no tiene al menos "estado" + "resumen", o si falta "comando" cuando accion="ejecutar_comando", el sistema NO acepta eso como final — le devuelve el problema a la IA como feedback en el historial y hace `continue` (reintenta dentro del presupuesto de iteraciones) en vez de `break`. El mensaje "Límite de X iteraciones alcanzado" ahora solo aparece cuando de verdad se agotaron las iteraciones.
     Verificado simulando las 3 respuestas de la IA (1ª finalizar vacío → reintenta, 2ª ejecuta wpscan real, 3ª finaliza con resultado completo) — el run llegó a las 3 iteraciones y concluyó "EXPLOTABLE" correctamente. Worker heavy reiniciado para recoger el cambio.

  3b. [FIXED 2026-06-30] [Detectado en vivo, run #13 — el fix 3 no era suficiente] Tras el fix anterior, el agente seguía muriendo en las 3 iteraciones con el mismo WARN, pese a que el razonamiento de la IA en cada iteración decía claramente que iba a ejecutar curl/wpscan.
     Causa real (confirmada llamando directamente a la API real de Gemini con el prompt exacto del vector): Gemini devuelve "resultado_final": null como placeholder en TODAS sus respuestas, incluso cuando accion="ejecutar_comando" y "comando" trae un valor real y válido (contradice lo que pide el prompt: "resultado_final solo se incluye cuando accion=finalizar"). El código original chequeaba `'resultado_final' in step` (¿existe la clave?) en vez de si tenía contenido — como la clave SIEMPRE existe (aunque sea null), TODA respuesta caía en la rama de "finalizar" y el comando real propuesto por la IA se descartaba sin ejecutarse nunca. finish_reason confirmado como STOP (no es un corte de tokens, es un hábito del modelo).
     → Fix: cambiado `'resultado_final' in step` por `step.get('resultado_final')` (chequeo de contenido truthy, no de existencia de clave). Verificado con la respuesta real capturada de Gemini: ahora enruta correctamente a "ejecutar_comando" y validate_command acepta el curl propuesto. Worker heavy reiniciado.

🟡 Medio

  3. "Kiterunner" es una feature fantasma. Está documentado en el README como módulo válido y ai_agent.py espera sus datos en el prompt, pero nunca se cableó: no hay /run-kiterunner, no está en SCRIPT_MAP
  ni en valid_modules. El informe IA siempre generará esa sección vacía.

  4. El "Attack Control Panel" completo no vive donde dice el README. El README lo describe dentro de AttackDashboard.jsx, pero en realidad toda esa funcionalidad (Launch, autorizaciones, AttackPlanViewer,
  LiveTerminal, EvidenceGallery, modal de vectores split-view) está en AttackTargets.jsx. AttackDashboard.jsx solo tiene las stat cards y el mapa SVG — y tiene botones decorativos sin onClick ("Export
  Reports", "QUICK SCAN", terminal FAB).

  5. Fuga de polling en el frontend. En AttackTargets.jsx (~línea 176-185), el setInterval que hace polling del estado del vector run se guarda en variable local, no en un ref. Si el modal se cierra o el
  componente se desmonta durante la fase running, el intervalo nunca se limpia: sigue pegándole al backend indefinidamente y puede intentar setState sobre un componente ya desmontado.

  6. SSRF / falta de escapado en header_exploits.py. target_url se pasa directo a requests.get(..., allow_redirects=True, verify=False) sin validar esquema ni bloquear IPs internas, y se interpola sin
  escapar en el HTML del PoC de clickjacking generado (riesgo si ese PoC se sirve después).

  🟢 Menor / cosas limpias

  - Sistema de locks Redis y colas heavy/light: implementado exactamente como documentado, sin problemas.
  - validate_scope() (compuerta de autorización) está bien implementado y es la primera operación de cada run, tal como se documenta.
  - attack_planner.py (DAG, resolución de capabilities, priority_score): fiel al README, sin sorpresas.
  - Solo discrepancias menores de documentación: el canal Redis del vector agent es anubis:vector:run:{id}, no anubis:vector:{id} como dice el README.
  - Hay código muerto/vestigial: run_scan_task en celery_app.py sin usar, cómputo desechado en AttackDashboard.jsx:99-112, ref wsRef muerta en LiveTerminal.jsx.
