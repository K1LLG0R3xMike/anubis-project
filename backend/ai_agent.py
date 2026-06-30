"""
AI Agent for Anubis Security Reports.
Generates a professional Markdown security report from scan findings.

Supported providers (swap by changing AI_PROVIDER in .env):
  - gemini   (default) — google-genai SDK
  - claude   — anthropic SDK  (pip install anthropic)
  - openai   — openai SDK     (pip install openai)
"""
import sys, os, json, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

AI_PROVIDER  = os.getenv("AI_PROVIDER", "gemini")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
CLAUDE_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_KEY   = os.getenv("OPENAI_API_KEY", "")

# Gemini supports multiple API keys for quota fallback.
# Set GEMINI_API_KEY for the primary key, then GEMINI_API_KEY_2, GEMINI_API_KEY_3, etc.
_GEMINI_KEYS = [v for k, v in sorted(os.environ.items())
                if k.startswith("GEMINI_API_KEY") and v.strip()]


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_prompt(report_type: str, snapshot: dict) -> str:
    from datetime import date
    today = date.today().strftime("%d/%m/%Y")

    targets = snapshot.get("targets", [])
    names   = [t.get("name", "") for t in targets]
    site_label = ", ".join(n for n in names if n) or "Objetivo de análisis"
    url_list   = "\n".join(f"- {t.get('url','')}" for t in targets if t.get("url")) or "- Sin URL especificada"

    def fmt_findings(findings_list, limit=25):
        if not findings_list:
            return "Sin datos registrados."
        lines = []
        for f in findings_list[:limit]:
            sev   = (f.get("severity") or "info").upper()
            title = f.get("title", "Sin título")
            desc  = (f.get("description") or "")[:300]
            lines.append(f"[{sev}] {title}: {desc}")
        return "\n".join(lines)

    data_blocks = []
    for t in targets:
        mods  = t.get("findings_by_module", {})
        block = f"""TARGET: {t.get('name','')} | URL: {t.get('url','')}
WAF detectado: {t.get('waf_detected', 'No verificado')}

SSL/TLS (testssl.sh):
{fmt_findings(mods.get('certs', []))}

Cabeceras HTTP:
{fmt_findings(mods.get('headers', []))}

Stack Tecnológico (WhatWeb):
{fmt_findings(mods.get('whatweb', []))}

OWASP ZAP:
{fmt_findings(mods.get('zap', []))}

Nikto:
{fmt_findings(mods.get('nikto', []))}

Kiterunner (Endpoints API):
{fmt_findings(mods.get('kiterunner', []))}"""
        data_blocks.append(block)

    type_note = {
        "executive":  "Nivel de detalle: EJECUTIVO — Prioriza hallazgos de alto impacto y recomendaciones de negocio.",
        "technical":  "Nivel de detalle: TÉCNICO — Sé exhaustivo, incluye comandos y configuraciones de remediación específicas.",
        "compliance": "Nivel de detalle: COMPLIANCE — Referencia controles OWASP Top 10, NIST CSF y CIS Controls en cada recomendación.",
        "full":       "Nivel de detalle: COMPLETO — Máximo detalle técnico, impacto de negocio y análisis de compliance.",
    }.get(report_type, "")

    data_section = "\n\n" + ("=" * 60 + "\n").join(data_blocks)

    return f"""Eres un experto en ciberseguridad ofensiva y defensiva. Tu tarea es generar un informe profesional de análisis de seguridad web a partir de los resultados de herramientas de escaneo proporcionados.

{type_note}

INSTRUCCIONES
Genera un informe en español con la siguiente estructura exacta. Usa formato Markdown.

ESTRUCTURA DEL INFORME

# 1. TÍTULO
Análisis de Seguridad Web: {site_label}
Fecha: {today}
Clasificación: Confidencial

# 2. INTRODUCCIÓN
Redacta un párrafo introductorio que mencione:
- El propósito del análisis
- Que se realizó desde una perspectiva de seguridad ofensiva no intrusiva
- Incluye siempre esta frase adaptada al contexto: "El objetivo de este análisis es identificar posibles vectores de ataque que puedan ser aprovechados por un actor malicioso y describir de forma clara los riesgos asociados a cada hallazgo."

# 3. ALCANCE
Indica que el análisis cubre los siguientes dominios/URLs:
{url_list}

Las técnicas aplicadas fueron:
- Identificación de Firewall de Aplicaciones Web (WAF)
- Análisis de certificados SSL/TLS (testssl.sh)
- Revisión de cabeceras de seguridad HTTP
- Identificación de stack tecnológico (WhatWeb)
- Análisis de vulnerabilidades web (OWASP ZAP)
- Escaneo de vulnerabilidades (Nikto)
- Descubrimiento de endpoints de API (Kiterunner)

# 4. HALLAZGOS

Para cada herramienta usa este formato exacto:

## 4.X <NOMBRE_HERRAMIENTA> — <SITIO>
**¿Qué se analiza?** Breve descripción de qué busca esta herramienta y por qué es relevante (2-3 líneas máximo).
**Resultado:** Resume el resultado del escaneo de forma clara y técnica.
**Nivel de riesgo:** [CRÍTICO / ALTO / MEDIO / BAJO / INFORMATIVO]
**Descripción del riesgo:** (Solo si hay hallazgos) Explica brevemente qué riesgo representa. Si no hay hallazgos negativos escribe: "✅ El sitio cumple con los mínimos de seguridad esperados para este control."
**Recomendación:** (Solo si hay hallazgos) Indica la acción correctiva concreta y priorizada. Si no hay hallazgos escribe: "No se requieren acciones correctivas en este control."

Genera las subsecciones:
- 4.1 WAF (Firewall de Aplicación Web): Si detectó WAF → riesgo INFORMATIVO, mencionar el nombre como capa de protección. Si no → riesgo MEDIO, recomendar WAF.
- 4.2 Certificados SSL/TLS: Evalúa versiones de protocolo (TLS 1.0/1.1 = riesgo ALTO), cifrados débiles, expiración, cadena.
- 4.3 Cabeceras de Seguridad HTTP: Evalúa Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Por cada ausente: riesgo MEDIO.
- 4.4 Stack Tecnológico (WhatWeb): Lista tecnologías detectadas. Si hay versiones desactualizadas o CVEs → riesgo ALTO.
- 4.5 OWASP ZAP: Clasifica por High/Medium/Low/Informational. Para cada High o Medium: riesgo y recomendación concreta.
- 4.6 Nikto: Destaca archivos sensibles, métodos HTTP peligrosos, versiones vulnerables.
- 4.7 Endpoints de API (Kiterunner): Lista endpoints con código HTTP. 200/201 sin auth → riesgo ALTO. 401/403 → riesgo BAJO. Sin datos → ✅.

# 5. RESUMEN DE HALLAZGOS

Genera esta tabla Markdown completa con los niveles de riesgo reales:

| # | Control | Herramienta | Nivel de Riesgo | Estado |
|---|---------|-------------|----------------|--------|
| 1 | WAF | wafw00f | [nivel real] | [✅ / ⚠️ / ❌] |
| 2 | SSL/TLS | testssl.sh | [nivel real] | [✅ / ⚠️ / ❌] |
| 3 | Cabeceras HTTP | custom | [nivel real] | [✅ / ⚠️ / ❌] |
| 4 | Stack tecnológico | WhatWeb | [nivel real] | [✅ / ⚠️ / ❌] |
| 5 | Vulnerabilidades web | OWASP ZAP | [nivel real] | [✅ / ⚠️ / ❌] |
| 6 | Escaneo de servidor | Nikto | [nivel real] | [✅ / ⚠️ / ❌] |
| 7 | Endpoints API | Kiterunner | [nivel real] | [✅ / ⚠️ / ❌] |

# 6. CONCLUSIONES
Redacta 1 párrafo (máximo 5 líneas) que:
- Resuma el nivel de madurez de seguridad del sitio analizado
- Mencione el hallazgo más crítico si existe
- Indique si el sitio representa un riesgo alto, medio o bajo para la organización
- Cierre con una recomendación de prioridad de remediación

---

DATOS DE ENTRADA
A continuación se proporcionan los resultados de los escaneos. Analízalos y genera el informe completo:

{data_section}

IMPORTANTE: Responde ÚNICAMENTE con el informe en Markdown. Sin texto adicional antes ni después. Sin bloques de código (no uses ```). El informe debe comenzar directamente con "# 1. TÍTULO".
"""


# ── Provider adapters ─────────────────────────────────────────────────────────

def _call_gemini(prompt: str) -> str:
    from google import genai
    last_err = None
    for key in _GEMINI_KEYS:
        try:
            client = genai.Client(api_key=key)
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
            return response.text
        except Exception as e:
            last_err = e
            print(f"[AI] Gemini key ...{key[-6:]} failed: {e} — trying next key")
    raise last_err or RuntimeError("No Gemini API keys configured")


def _call_claude(prompt: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=CLAUDE_KEY)
    response = client.messages.create(
        model=os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6"),
        max_tokens=8192,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def _call_openai(prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=OPENAI_KEY)
    response = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o"),
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content


def _call_ai(prompt: str) -> str:
    if AI_PROVIDER == "claude":
        return _call_claude(prompt)
    elif AI_PROVIDER == "openai":
        return _call_openai(prompt)
    else:
        return _call_gemini(prompt)


# ── Public entry point ────────────────────────────────────────────────────────

def analyze_report(report_type: str, snapshot: dict) -> dict:
    """
    Call the configured AI provider and return the ai_content dict.
    The AI generates a structured Markdown report stored in 'markdown_report'.
    Raises on API errors — caller should handle.
    """
    from datetime import datetime, timezone

    prompt = _build_prompt(report_type, snapshot)
    raw    = _call_ai(prompt)

    # Clean any accidental code fences the model may add
    raw = raw.strip()
    raw = re.sub(r'^```(?:markdown)?\s*', '', raw, flags=re.IGNORECASE)
    raw = re.sub(r'\s*```\s*$', '', raw)
    raw = raw.strip()

    return {
        "markdown_report":   raw,
        "ai_generated":      True,
        "ai_generated_at":   datetime.now(timezone.utc).isoformat(),
        # Legacy keys kept as empty for backward compatibility
        "executive_summary": None,
        "risk_narrative":    None,
        "business_impact":   None,
        "recommendations":   [],
        "compliance_gaps":   [],
        "compliance_narrative": None,
    }
