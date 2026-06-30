"""
Attack Orchestrator — tarea Celery que ejecuta un AttackPlan DAG.

Comportamientos clave:
  - Valida scope/autorización como primera operación, antes de cualquier ejecución.
  - Ejecuta nodos en orden de priority_score, respetando requires_nodes y
    requires_capabilities.
  - Comprueba abort_requested entre cada nodo (abort cooperativo).
  - Nodos de larga duración (SQLMap) se terminan vía SIGTERM al detectar abort.
  - Retroalimenta la confianza del finding origen (confidence_delta) tras cada nodo.
  - Registra cada acción en attack_results para trazabilidad de auditoría.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from celery_app import celery_app
from attack_schemas import AttackNode, AttackPlan, INTRUSIVENESS_RANK


# ─────────────────────────────────────────────
# Redis pub/sub para live terminal (WebSocket)
# ─────────────────────────────────────────────

def _publish_log(run_id: int, message: str) -> None:
    """Publica un mensaje de log al canal Redis que el WebSocket del frontend escucha."""
    try:
        import redis as _rl
        r = _rl.Redis(host='localhost', port=6379, db=2, decode_responses=True)
        r.publish(f"anubis:attack:run:{run_id}", message)
        r.close()
    except Exception:
        pass


# ─────────────────────────────────────────────
# Validación de scope / autorización
# ─────────────────────────────────────────────

def _target_matches_pattern(target_url: str, pattern: str) -> bool:
    """
    Compara el hostname del target contra domain_pattern.
    Soporta:
      - CIDR:         "192.168.1.0/24"
      - Wildcard DNS: "*.empresa.com"
      - Literal:      "host.internal"
    """
    hostname = urlparse(target_url).hostname or target_url

    # Intentar CIDR
    try:
        net  = ipaddress.ip_network(pattern, strict=False)
        addr = ipaddress.ip_address(hostname)
        return addr in net
    except ValueError:
        pass

    # Wildcard / literal via fnmatch
    normalized = pattern.lstrip("*.")
    return fnmatch.fnmatch(hostname, pattern) or fnmatch.fnmatch(hostname, f"*.{normalized}")


def _intrusiveness_allowed(requested: str, allowed: str) -> bool:
    return INTRUSIVENESS_RANK[requested] <= INTRUSIVENESS_RANK[allowed]


def validate_scope(
    db,
    target_url: str,
    intrusiveness: str,
    authorized_target_id: Optional[int] = None,
) -> Optional[str]:
    """
    Compuerta de autorización. Debe llamarse antes de ejecutar cualquier vector.

    Retorna:
      None               si el target está autorizado para el nivel solicitado.
      str (error msg)    si la autorización falta, ha expirado o no cubre el nivel.

    Si authorized_target_id está especificado, valida ese registro concreto.
    En caso contrario, busca cualquier registro vigente que cubra el target.
    """
    from attack_models import AuthorizedTarget

    now = datetime.now(timezone.utc)

    if authorized_target_id:
        auth = db.query(AuthorizedTarget).filter(
            AuthorizedTarget.id == authorized_target_id
        ).first()
        if not auth:
            return f"Autorización {authorized_target_id} no encontrada"

        valid_from  = auth.valid_from.replace(tzinfo=timezone.utc)  if auth.valid_from.tzinfo  is None else auth.valid_from
        valid_until = auth.valid_until.replace(tzinfo=timezone.utc) if auth.valid_until.tzinfo is None else auth.valid_until

        if valid_from > now:
            return f"Autorización no vigente hasta {valid_from.isoformat()}"
        if valid_until < now:
            return f"Autorización expirada el {valid_until.isoformat()}"
        if not _target_matches_pattern(target_url, auth.domain_pattern):
            return (
                f"Target '{target_url}' no coincide con el patrón autorizado "
                f"'{auth.domain_pattern}'"
            )
        if not _intrusiveness_allowed(intrusiveness, auth.allowed_intrusiveness):
            return (
                f"Nivel de intrusividad '{intrusiveness}' supera el máximo "
                f"autorizado '{auth.allowed_intrusiveness}'"
            )
        return None

    # Buscar cualquier autorización vigente que cubra el target
    auths = db.query(AuthorizedTarget).all()
    for auth in auths:
        valid_from  = auth.valid_from.replace(tzinfo=timezone.utc)  if auth.valid_from.tzinfo  is None else auth.valid_from
        valid_until = auth.valid_until.replace(tzinfo=timezone.utc) if auth.valid_until.tzinfo is None else auth.valid_until
        if valid_from > now or valid_until < now:
            continue
        if not _target_matches_pattern(target_url, auth.domain_pattern):
            continue
        if _intrusiveness_allowed(intrusiveness, auth.allowed_intrusiveness):
            return None

    return (
        f"No existe autorización vigente para '{target_url}' "
        f"con nivel de intrusividad '{intrusiveness}'. "
        "Registra un authorized_target antes de ejecutar un attack run."
    )


# ─────────────────────────────────────────────
# Despacho de vectores
# ─────────────────────────────────────────────

ATTACK_SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "attack_scripts"
)

MODULE_MAP: dict[str, str] = {
    "header_exploits":  "header_exploits.py",
    "sqli":             "sqli.py",
    "sqli_extract":     "sqli_extract.py",
    "xss_playwright":   "xss_playwright.py",
    "auth_bruteforce":  "auth_bruteforce.py",
    "idor_enumerate":   "idor_enumerate.py",
    "priv_escalation":  "priv_escalation.py",
    "tls_downgrade":    "tls_downgrade.py",
    "cve_exploiter":    "cve_exploiter.py",
    "post_rce_loot":    "post_rce_loot.py",
}

# Proceso activo por run_id — permite enviar SIGTERM en caso de abort
_active_processes: dict[int, subprocess.Popen] = {}


def execute_vector(node: AttackNode, max_intrusiveness: str, run_id: int) -> dict:
    """
    Despacha la ejecución al script de ataque correspondiente.

    Contrato de los scripts:
      - Entrada:  argv[1]=target_url, argv[2]=params_json
      - Salida stdout (JSON):
          { confirmed: bool, confidence_delta: float,
            evidence_path?: str, details?: any }
      - exit_code 0  = ejecución correcta (puede ser confirmed=false)
      - exit_code != 0 = error de ejecución

    Si el nivel del nodo supera max_intrusiveness, retorna skipped sin ejecutar.
    """
    if INTRUSIVENESS_RANK[node.intrusiveness] > INTRUSIVENESS_RANK[max_intrusiveness]:
        return {
            "confirmed": False,
            "confidence_delta": 0.0,
            "skipped": True,
            "reason": (
                f"Intrusividad del vector ({node.intrusiveness}) supera "
                f"el máximo del run ({max_intrusiveness})"
            ),
        }

    script_name = MODULE_MAP.get(node.vector_type)
    if not script_name:
        return {
            "confirmed": False,
            "confidence_delta": 0.0,
            "error": f"vector_type desconocido: {node.vector_type}",
        }

    script_path = os.path.join(ATTACK_SCRIPTS_DIR, script_name)
    if not os.path.exists(script_path):
        return {
            "confirmed": False,
            "confidence_delta": 0.0,
            "error": f"Script no implementado aún: {script_name}",
            "pending": True,
        }

    params_json = json.dumps(node.params)
    proc = subprocess.Popen(
        ["python3", script_path, node.target_url, params_json],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _active_processes[run_id] = proc

    try:
        stdout, stderr = proc.communicate(timeout=node.timeout_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        _active_processes.pop(run_id, None)
        raise
    finally:
        _active_processes.pop(run_id, None)

    if proc.returncode == 0:
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {
                "confirmed": False,
                "confidence_delta": 0.0,
                "raw_output": stdout,
            }

    return {
        "confirmed": False,
        "confidence_delta": -0.1,
        "error": stderr or f"exit_code={proc.returncode}",
    }


# ─────────────────────────────────────────────
# Tarea Celery principal
# ─────────────────────────────────────────────

@celery_app.task(name="tasks.execute_attack_run", bind=True)
def execute_attack_run(self, run_id: int):
    """
    Ejecutor DAG de attack runs.

    Flujo:
      1. Compuerta de autorización (validate_scope) — falla duro si no pasa.
      2. Carga AttackPlan desde attack_runs.plan_json.
      3. Bucle DAG: obtener nodos ejecutables → ejecutar en orden de prioridad.
      4. Tras cada nodo: persistir AttackResult, actualizar confianza del finding,
         añadir capacidades provistas al conjunto disponible.
      5. Entre nodos: comprobar abort_requested. Si activo, enviar SIGTERM al
         subproceso en curso y marcar run como abortado.
      6. Al final: serializar el plan con los estados finales de cada nodo.
    """
    from database import SessionLocal
    from attack_models import AttackRun, AttackResult

    db = SessionLocal()
    run: Optional[AttackRun] = None

    try:
        run = db.query(AttackRun).filter(AttackRun.id == run_id).first()
        if not run:
            return f"AttackRun {run_id} no encontrado"

        # ── 1. Compuerta de autorización ─────────────────────────────────────
        from models import Target
        target = db.query(Target).filter(Target.id == run.target_id).first()
        if not target:
            run.status = "failed"
            db.commit()
            return f"Target {run.target_id} no encontrado"

        auth_error = validate_scope(
            db, target.url, run.intrusiveness, run.authorized_target_id
        )
        if auth_error:
            run.status = "failed"
            db.commit()
            _msg = f"[ERROR] SCOPE_ERROR run={run_id}: {auth_error}"
            print(_msg)
            _publish_log(run_id, _msg)
            return f"SCOPE_ERROR: {auth_error}"

        # ── 2. Carga del plan ─────────────────────────────────────────────────
        plan = AttackPlan.model_validate_json(run.plan_json)
        run.status = "running"
        run.started_at = datetime.now(timezone.utc)
        db.commit()
        _msg = f"[INICIO] Run {run_id} iniciado. Nodos: {len(plan.nodes)} — Target: {target.url}"
        print(_msg)
        _publish_log(run_id, _msg)

        # ── 3. Bucle DAG ──────────────────────────────────────────────────────
        completed_ids: set[str] = set()
        failed_ids: set[str] = set()
        available_capabilities: set[str] = set()

        while plan.has_pending_nodes():

            # ── Comprobación de abort ────────────────────────────────────────
            db.refresh(run)
            if run.abort_requested or run.status == "aborted":
                # Señalizar subproceso activo si existe
                active_proc = _active_processes.get(run_id)
                if active_proc and active_proc.poll() is None:
                    active_proc.terminate()

                for n in plan.nodes:
                    if n.status == "planned":
                        n.status = "aborted"
                run.status = "aborted"
                run.plan_json = plan.model_dump_json()
                db.commit()
                print(f"[Attack] Run {run_id} abortado")
                return f"Run {run_id} abortado"

            executable = plan.get_executable_nodes(
                completed_ids, failed_ids, available_capabilities
            )

            if not executable:
                # Nodos restantes con dependencias insatisfacibles → skipped
                for n in plan.nodes:
                    if n.status == "planned":
                        n.status = "skipped"
                        print(
                            f"[Attack] Nodo {n.id} skipped: "
                            f"dependencias no satisfechas "
                            f"(requires_nodes={n.requires_nodes}, "
                            f"requires_capabilities={n.requires_capabilities})"
                        )
                break

            for node in executable:
                # ── Registrar inicio ─────────────────────────────────────────
                node.status = "running"
                result = AttackResult(
                    run_id=run_id,
                    node_id=node.id,
                    vector_type=node.vector_type,
                    status="running",
                    started_at=datetime.now(timezone.utc),
                )
                db.add(result)
                db.commit()

                _msg = (
                    f"[{node.vector_type.upper()}] Iniciando nodo {node.id} "
                    f"(intrusiveness={node.intrusiveness}, priority={node.priority_score})"
                )
                print(_msg)
                _publish_log(run_id, _msg)

                try:
                    output = execute_vector(node, run.intrusiveness, run_id)

                    if output.get("skipped"):
                        node.status = "skipped"
                        result.status = "skipped"
                        result.error_message = output.get("reason")
                        _msg = f"[{node.vector_type.upper()}] → Skipped: {output.get('reason', '')}"
                        print(_msg); _publish_log(run_id, _msg)
                    elif output.get("pending"):
                        node.status = "skipped"
                        result.status = "skipped"
                        result.error_message = output.get("error")
                        _msg = f"[{node.vector_type.upper()}] → Pendiente (script no implementado aún)"
                        print(_msg); _publish_log(run_id, _msg)
                    else:
                        confirmed = bool(output.get("confirmed", False))
                        delta = float(output.get("confidence_delta", 0.0))

                        node.status = "completed"
                        result.status = "completed"
                        result.confirmed_finding = confirmed
                        result.confidence_delta = delta
                        result.output_json = json.dumps(output)
                        result.evidence_path = output.get("evidence_path")

                        completed_ids.add(node.id)

                        if confirmed:
                            available_capabilities.update(node.provides)
                            _update_finding_confidence(db, node.finding_id, max(delta, 0.1))
                            _msg = f"[{node.vector_type.upper()}] ✓ Confirmado. Capacidades desbloqueadas: {node.provides}"
                            print(_msg); _publish_log(run_id, _msg)
                        else:
                            _update_finding_confidence(db, node.finding_id, min(delta, -0.05))
                            _msg = f"[{node.vector_type.upper()}] ✗ No confirmado (posible falso positivo)"
                            print(_msg); _publish_log(run_id, _msg)

                except subprocess.TimeoutExpired:
                    node.status = "failed"
                    result.status = "failed"
                    result.error_message = f"Timeout tras {node.timeout_seconds}s"
                    failed_ids.add(node.id)
                    _msg = f"[{node.vector_type.upper()}] ✗ Timeout tras {node.timeout_seconds}s"
                    print(_msg); _publish_log(run_id, _msg)

                except Exception as exc:
                    node.status = "failed"
                    result.status = "failed"
                    result.error_message = str(exc)
                    failed_ids.add(node.id)
                    _msg = f"[{node.vector_type.upper()}] ✗ Error: {exc}"
                    print(_msg); _publish_log(run_id, _msg)

                result.completed_at = datetime.now(timezone.utc)
                db.commit()

        # ── 4. Finalizar ──────────────────────────────────────────────────────
        run.status = "completed"
        run.completed_at = datetime.now(timezone.utc)
        run.plan_json = plan.model_dump_json()
        db.commit()

        summary = plan.summary()
        _msg = f"[DONE] Run {run_id} completado. Resumen: {summary}"
        print(_msg)
        _publish_log(run_id, _msg)
        return f"Run {run_id} completado: {summary}"

    except Exception as exc:
        import traceback
        traceback.print_exc()
        try:
            db.rollback()
            if run:
                run.status = "failed"
                db.commit()
        except Exception:
            pass
        return f"Error crítico en run {run_id}: {exc}"

    finally:
        db.close()


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _update_finding_confidence(db, finding_id: Optional[int], delta: float) -> None:
    """
    Ajusta findings.confidence en delta, acotado a [0.0, 1.0].
    Si la columna confidence no existe en el modelo, la operación es silenciosa.
    """
    if not finding_id:
        return
    from models import Finding
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding or not hasattr(finding, "confidence"):
        return
    current = float(finding.confidence or 0.5)
    finding.confidence = round(max(0.0, min(1.0, current + delta)), 3)
    db.commit()
