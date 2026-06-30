"""
Attack Planner — construye un AttackPlan (DAG) a partir de una lista de findings.

Diseño del motor de reglas:
  VECTOR_RULES es un catálogo declarativo de reglas N:M.
  Cada regla define condiciones sobre findings y produce un nodo del DAG.
  Las dependencias de capacidad (requires_capabilities) se resuelven en tiempo
  de construcción del plan, convirtiendo "necesito authenticated_session"
  en requires_nodes concretos (IDs de nodos que proveen esa capacidad).

Flujo de build_attack_plan():
  1. Paso 1 — Matching: para cada finding, evaluar qué reglas aplican.
  2. Paso 2 — Capacidades: añadir reglas sin condiciones cuyas requires_capabilities
               ya están provistas por los nodos del paso 1.
  3. Paso 3 — Resolución: convertir requires_capabilities en requires_nodes.
  4. Deduplicación: si dos findings activan el mismo vector_type sobre el mismo
               endpoint, conservar el de mayor priority_score.
"""
from __future__ import annotations

import uuid
from typing import Optional

from attack_schemas import AttackNode, AttackPlan, Intrusiveness, INTRUSIVENESS_RANK

# ─────────────────────────────────────────────
# Pesos para el cálculo de prioridad heurística
# ─────────────────────────────────────────────

SEVERITY_WEIGHT = {
    "critical": 10,
    "high":      7,
    "medium":    4,
    "low":       2,
    "info":      0,
}


# ─────────────────────────────────────────────
# Clase VectorRule
# ─────────────────────────────────────────────

class VectorRule:
    """
    Una regla de mapeo finding → vector de ataque.

    conditions: lista de dicts con operadores sufijados:
      __in        campo en lista de valores
      __contains  substring case-insensitive
      __gte / __lte  comparación numérica
      (sin sufijo)   igualdad exacta

    Si conditions está vacía, la regla es "capability-triggered":
    solo se activa si sus requires_capabilities ya están disponibles en el plan.
    """

    def __init__(
        self,
        rule_id: str,
        vector_type: str,
        description: str,
        intrusiveness: Intrusiveness,
        conditions: list[dict],
        provides: list[str],
        requires_capabilities: list[str],
        confidence_threshold: float,
        timeout_seconds: int,
        base_priority: float,
        params_template: dict | None = None,
    ):
        self.rule_id = rule_id
        self.vector_type = vector_type
        self.description = description
        self.intrusiveness = intrusiveness
        self.conditions = conditions
        self.provides = provides
        self.requires_capabilities = requires_capabilities
        self.confidence_threshold = confidence_threshold
        self.timeout_seconds = timeout_seconds
        self.base_priority = base_priority
        self.params_template = params_template or {}

    def matches_finding(self, finding: dict) -> bool:
        if not self.conditions:
            return False
        for cond in self.conditions:
            if not self._eval_condition(cond, finding):
                return False
        return True

    def _eval_condition(self, cond: dict, finding: dict) -> bool:
        for key, expected in cond.items():
            if key.endswith("__in"):
                field = key[:-4]
                if finding.get(field, "") not in expected:
                    return False
            elif key.endswith("__contains"):
                field = key[:-10]
                if expected.lower() not in (finding.get(field) or "").lower():
                    return False
            elif key.endswith("__gte"):
                field = key[:-5]
                if (finding.get(field) or 0) < expected:
                    return False
            elif key.endswith("__lte"):
                field = key[:-5]
                if (finding.get(field) or 0) > expected:
                    return False
            else:
                if str(finding.get(key, "")) != str(expected):
                    return False
        return True

    def build_node(self, finding: dict, target_url: str) -> AttackNode:
        finding_id = finding.get("id")
        node_id = f"{self.rule_id}_{finding_id or uuid.uuid4().hex[:6]}"
        severity = finding.get("severity", "medium")
        confidence = float(finding.get("confidence", 0.5))

        # priority_score = base_priority × severity_weight × confidence_finding
        priority = self.base_priority * SEVERITY_WEIGHT.get(severity, 4) * confidence

        return AttackNode(
            id=node_id,
            vector_type=self.vector_type,
            target_url=target_url,
            finding_id=finding_id,
            finding_title=finding.get("title", self.description),
            finding_severity=severity,
            finding_confidence=confidence,
            intrusiveness=self.intrusiveness,
            requires_capabilities=list(self.requires_capabilities),
            provides=list(self.provides),
            confidence_threshold=self.confidence_threshold,
            timeout_seconds=self.timeout_seconds,
            params={**self.params_template, "source_finding": finding},
            priority_score=round(priority, 3),
        )


# ─────────────────────────────────────────────
# Catálogo de reglas
# ─────────────────────────────────────────────
# Orden de lectura: cada regla documenta qué activa, qué nivel de intrusividad
# requiere, qué capacidades entrega y de cuáles depende.

VECTOR_RULES: list[VectorRule] = [
    # ── Cabeceras HTTP ───────────────────────────────────────────────────────
    VectorRule(
        rule_id="header_verify",
        vector_type="header_exploits",
        description="Verificar explotabilidad de cabeceras de seguridad ausentes",
        intrusiveness="active",
        conditions=[{"module": "headers", "severity__in": ["high", "critical"]}],
        provides=[],
        requires_capabilities=[],
        confidence_threshold=0.4,
        timeout_seconds=60,
        base_priority=1.5,
    ),

    # ── SQL Injection ────────────────────────────────────────────────────────
    VectorRule(
        rule_id="sqli_verify",
        vector_type="sqli",
        description="Verificación de SQL injection con SQLMap (nivel activo)",
        intrusiveness="active",
        conditions=[{"module__in": ["zap", "nikto"], "title__contains": "sql"}],
        provides=["db_read_access"],
        requires_capabilities=[],
        confidence_threshold=0.6,
        timeout_seconds=600,
        base_priority=2.5,
    ),
    VectorRule(
        rule_id="sqli_extract",
        vector_type="sqli_extract",
        description="Extracción completa de DB tras SQLi confirmado",
        intrusiveness="exploitive",
        conditions=[],  # capability-triggered: solo corre si sqli_verify confirma
        provides=["db_credentials"],
        requires_capabilities=["db_read_access"],
        confidence_threshold=0.0,
        timeout_seconds=1800,
        base_priority=2.0,
    ),

    # ── XSS ─────────────────────────────────────────────────────────────────
    VectorRule(
        rule_id="xss_verify",
        vector_type="xss_playwright",
        description="Confirmación de XSS con Playwright y evidencia de screenshot",
        intrusiveness="active",
        conditions=[{"module__in": ["zap", "nikto"], "title__contains": "xss"}],
        provides=[],
        requires_capabilities=[],
        confidence_threshold=0.5,
        timeout_seconds=120,
        base_priority=2.0,
    ),

    # ── Autenticación ────────────────────────────────────────────────────────
    VectorRule(
        rule_id="auth_bruteforce",
        vector_type="auth_bruteforce",
        description="Bruteforce de credenciales contra formulario sin rate limiting",
        intrusiveness="active",
        conditions=[{"module__in": ["zap", "nikto"], "title__contains": "rate limit"}],
        provides=["authenticated_session"],
        requires_capabilities=[],
        confidence_threshold=0.5,
        timeout_seconds=300,
        base_priority=2.0,
    ),

    # ── Post-autenticación ───────────────────────────────────────────────────
    VectorRule(
        rule_id="idor_enumerate",
        vector_type="idor_enumerate",
        description="Enumeración masiva de IDOR con sesión autenticada",
        intrusiveness="active",
        conditions=[{"title__contains": "idor"}],
        provides=["enumerated_data"],
        requires_capabilities=["authenticated_session"],
        confidence_threshold=0.5,
        timeout_seconds=300,
        base_priority=1.8,
    ),
    VectorRule(
        rule_id="priv_escalation",
        vector_type="priv_escalation",
        description="Escalada de privilegios aprovechando sesión activa",
        intrusiveness="exploitive",
        conditions=[],  # capability-triggered
        provides=["admin_session"],
        requires_capabilities=["authenticated_session"],
        confidence_threshold=0.0,
        timeout_seconds=180,
        base_priority=2.2,
    ),

    # ── TLS / Cifrado ────────────────────────────────────────────────────────
    VectorRule(
        rule_id="tls_verify",
        vector_type="tls_downgrade",
        description="Verificar viabilidad de downgrade TLS / SSL stripping",
        intrusiveness="passive",
        conditions=[{"module": "certs", "severity__in": ["high", "critical"]}],
        provides=[],
        requires_capabilities=[],
        confidence_threshold=0.4,
        timeout_seconds=60,
        base_priority=1.2,
    ),

    # ── CVE conocidos ────────────────────────────────────────────────────────
    VectorRule(
        rule_id="cve_exploit",
        vector_type="cve_exploiter",
        description="Explotación de CVE con PoC público",
        intrusiveness="exploitive",
        conditions=[{"title__contains": "cve"}],
        provides=["rce_access"],
        requires_capabilities=[],
        confidence_threshold=0.7,
        timeout_seconds=300,
        base_priority=3.0,
    ),

    # ── Post-RCE ─────────────────────────────────────────────────────────────
    VectorRule(
        rule_id="post_rce_loot",
        vector_type="post_rce_loot",
        description="Recolección de credenciales y archivos sensibles tras RCE",
        intrusiveness="exploitive",
        conditions=[],  # capability-triggered
        provides=["system_credentials"],
        requires_capabilities=["rce_access"],
        confidence_threshold=0.0,
        timeout_seconds=300,
        base_priority=2.8,
    ),
]


# ─────────────────────────────────────────────
# Constructor del DAG
# ─────────────────────────────────────────────

def build_attack_plan(
    findings: list[dict],
    target_url: str,
    max_intrusiveness: Intrusiveness = "active",
    confidence_threshold: float = 0.5,
) -> AttackPlan:
    """
    Construye un AttackPlan DAG a partir de una lista de findings.

    Args:
        findings:             Lista de dicts con campos: id, module, severity,
                              title, description, confidence (0.0–1.0).
        target_url:           URL del target sobre el que correrán los vectores.
        max_intrusiveness:    Techo de intrusividad. Reglas con nivel superior
                              son ignoradas.
        confidence_threshold: Umbral global mínimo de confianza. Reglas con
                              confidence_threshold propio más alto prevalecen.

    Returns:
        AttackPlan con nodos ordenados por priority_score descendente,
        con requires_nodes ya resueltos desde requires_capabilities.
    """
    max_rank = INTRUSIVENESS_RANK[max_intrusiveness]
    nodes: list[AttackNode] = []
    seen: dict[str, AttackNode] = {}  # dedup_key → nodo de mayor prioridad

    # ── Paso 1: Matching finding → regla ────────────────────────────────────
    for finding in findings:
        confidence = float(finding.get("confidence", 0.5))

        for rule in VECTOR_RULES:
            if INTRUSIVENESS_RANK[rule.intrusiveness] > max_rank:
                continue
            if not rule.conditions:
                continue  # capability-triggered, se maneja en el paso 2
            if confidence < max(rule.confidence_threshold, confidence_threshold):
                continue
            if not rule.matches_finding(finding):
                continue

            node = rule.build_node(finding, target_url)
            # Dedup: mismo vector_type + mismo finding → conservar mayor prioridad
            dedup_key = f"{rule.vector_type}_{finding.get('id', '')}"
            if dedup_key not in seen or node.priority_score > seen[dedup_key].priority_score:
                seen[dedup_key] = node

    nodes = list(seen.values())

    # ── Paso 2: Reglas capability-triggered ─────────────────────────────────
    # Determinar qué capacidades puede ofrecer el plan actual
    provided_by_plan: set[str] = set()
    for n in nodes:
        provided_by_plan.update(n.provides)

    for rule in VECTOR_RULES:
        if rule.conditions:
            continue  # ya procesada
        if INTRUSIVENESS_RANK[rule.intrusiveness] > max_rank:
            continue
        if not rule.requires_capabilities:
            continue
        if not all(cap in provided_by_plan for cap in rule.requires_capabilities):
            continue

        placeholder = {
            "id": None,
            "title": rule.description,
            "severity": "high",
            "confidence": 1.0,
            "module": "planner",
        }
        node = rule.build_node(placeholder, target_url)
        dedup_key = f"{rule.vector_type}_capability"
        if dedup_key not in seen:
            seen[dedup_key] = node
            nodes.append(node)

    # ── Paso 3: Resolver requires_capabilities → requires_nodes ─────────────
    # Mapa: capacidad → lista de IDs de nodos que la proveen
    capability_providers: dict[str, list[str]] = {}
    for n in nodes:
        for cap in n.provides:
            capability_providers.setdefault(cap, []).append(n.id)

    for n in nodes:
        provider_ids: list[str] = []
        for cap in n.requires_capabilities:
            provider_ids.extend(capability_providers.get(cap, []))
        n.requires_nodes = list(set(provider_ids))

    return AttackPlan(nodes=nodes, target_url=target_url)


def plan_from_target(
    db,
    target_id: int,
    max_intrusiveness: Intrusiveness = "active",
    confidence_threshold: float = 0.5,
    finding_ids: Optional[list[int]] = None,
) -> Optional[AttackPlan]:
    """
    Helper: carga los findings de un target desde la DB y construye el plan.
    Retorna None si no hay findings que activar.
    """
    from models import Finding, Target

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        return None

    query = db.query(Finding).filter(Finding.target_id == target_id)
    if finding_ids:
        query = query.filter(Finding.id.in_(finding_ids))
    raw_findings = query.all()

    findings = []
    for f in raw_findings:
        findings.append({
            "id":          f.id,
            "module":      f.module,
            "severity":    f.severity,
            "title":       f.title,
            "description": f.description,
            "confidence":  getattr(f, "confidence", 0.5) or 0.5,
        })

    plan = build_attack_plan(
        findings=findings,
        target_url=target.url,
        max_intrusiveness=max_intrusiveness,
        confidence_threshold=confidence_threshold,
    )
    return plan if plan.nodes else None
