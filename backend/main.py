from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from sqlalchemy.orm import Session
import models, database
from tasks import run_full_scan, run_individual_scan, analyze_report_with_ai
from scan_modules import discover_modules, module_label, get_module_queue, set_module_queue
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from typing import List, Optional
from datetime import datetime
import os
import subprocess
import json
import shutil
import hashlib
import redis as redis_lib
import time
from io import BytesIO
from fastapi import APIRouter, BackgroundTasks

# ── Cliente Redis para deduplicación de escaneos (db=1, separado del broker Celery) ──
_scan_redis = redis_lib.Redis(host='localhost', port=6379, db=1, decode_responses=True)

# TTL del lock: 90 minutos (safety net si el worker muere sin liberar el lock)
_LOCK_TTL = 5400

def _acquire_scan_lock(lock_key: str, module: str):
    """
    Intenta adquirir el lock de deduplicación.
    Lanza 409 si ya hay un escaneo del mismo módulo en cola o en curso.
    """
    acquired = _scan_redis.set(lock_key, "1", nx=True, ex=_LOCK_TTL)
    if not acquired:
        raise HTTPException(
            status_code=409,
            detail=f"Ya hay un escaneo '{module}' en cola o en curso. Espera a que termine antes de lanzar otro."
        )

def _enqueue_full_scan(module: str, queue: str):
    """Valida deduplicación y encola run_full_scan en la cola indicada."""
    lock_key = f"anubis:scan_lock:{module}"
    _acquire_scan_lock(lock_key, module)
    task = run_full_scan.apply_async(args=[module], queue=queue)
    return task

def _enqueue_individual_scan(module: str, url: str, queue: str, target_id: int = None):
    """Valida deduplicación y encola run_individual_scan en la cola indicada."""
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
    lock_key = f"anubis:scan_lock:individual:{module}:{url_hash}"
    _acquire_scan_lock(lock_key, f"{module}:{url}")
    task = run_individual_scan.apply_async(args=[module, url], kwargs={"target_id": target_id}, queue=queue)
    return task

# --- IMPORTACIONES ---
from sqlalchemy import text
from database import engine

# Crear tablas al iniciar (crea las que no existen, no toca las que ya están)
models.Base.metadata.create_all(bind=database.engine)

# Attack module — crear tablas de autorización y runs
import attack_models as _atk_models
_atk_models.Base.metadata.create_all(bind=database.engine)

# Migraciones incrementales — columnas añadidas en versiones posteriores
with engine.connect() as conn:
    conn.execute(text("ALTER TABLE schedules ADD COLUMN IF NOT EXISTS target_ids TEXT;"))
    conn.execute(text("ALTER TABLE schedules ADD COLUMN IF NOT EXISTS last_run TEXT;"))
    # reports.generated_at puede no existir si la tabla se creó antes de añadir la columna
    conn.execute(text("ALTER TABLE reports ADD COLUMN IF NOT EXISTS generated_at TIMESTAMP WITH TIME ZONE;"))
    # Attack module: columna confidence en findings para retroalimentación del orquestador
    conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence FLOAT;"))
    conn.commit()

app = FastAPI()

# Configuraci�n de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Handler explícito para que los errores (incluyendo 500) lleven headers CORS.
# Sin esto, excepciones no capturadas rompen la política CORS en el navegador.
from fastapi.responses import JSONResponse
from fastapi import WebSocket, WebSocketDisconnect
from starlette.exceptions import HTTPException as StarletteHTTPException

# Attack module imports
from attack_models import AuthorizedTarget, AttackRun, AttackResult
from attack_schemas import AuthorizedTargetCreate, AttackRunCreate, AttackPlan
from attack_planner import plan_from_target

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers={"Access-Control-Allow-Origin": "*"},
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    import traceback
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={"Access-Control-Allow-Origin": "*"},
    )

# --- CONFIGURACI�N DE RUTAS Y MONTAJES EST�TICOS ---
BASE_PATH = "/home/anubis/AnubisProject/reports"

def ensure_path(path):
    if not os.path.exists(path):
        os.makedirs(path)
    return path

# Montamos las carpetas de reportes
app.mount("/reports/whatweb", StaticFiles(directory=ensure_path(f"{BASE_PATH}/whatweb")), name="whatweb")
app.mount("/reports/headers", StaticFiles(directory=ensure_path(f"{BASE_PATH}/headers")), name="headers")
app.mount("/reports/certs", StaticFiles(directory=ensure_path(f"{BASE_PATH}/certs")), name="certs")
app.mount("/reports/waf", StaticFiles(directory=ensure_path(f"{BASE_PATH}/waf")), name="waf")
app.mount("/reports/nikto", StaticFiles(directory=ensure_path(f"{BASE_PATH}/nikto")), name="nikto")
# Ajuste espec�fico para ZAP: carpeta 'zap' dentro de reports
app.mount("/reports/zap", StaticFiles(directory=ensure_path(f"{BASE_PATH}/zap")), name="zap")

# Esquemas Pydantic
class TargetCreate(BaseModel):
    name: str
    url: str

class TargetOut(BaseModel):
    id: int
    name: str
    url: str
    status: str
    technologies: str = "Pendiente"
    waf_detected: Optional[str] = None
    last_scan: Optional[datetime] = None
    class Config:
        from_attributes = True

# --- ENDPOINTS ---

@app.get("/targets/", response_model=List[TargetOut])
def get_targets(db: Session = Depends(database.get_db)):
    return db.query(models.Target).order_by(models.Target.id).all()

@app.post("/targets/", response_model=TargetOut)
def create_target(target: TargetCreate, db: Session = Depends(database.get_db)):
    db_target = models.Target(name=target.name, url=target.url, status="Pendiente")
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    
    try:
        with open("/home/anubis/AnubisProject/reports/sitios.txt", "a") as f:
            f.write(f"{target.url}\n")
    except Exception as e:
        print(f"Error escribiendo sitios.txt: {e}")
        
    return db_target

@app.post("/login")
def login(data: dict):
    if data.get("username") == "admin" and data.get("password") == "anubis2026":
        return {"token": "token-anubis-2026"}
    raise HTTPException(status_code=401, detail="Credenciales incorrectas")

@app.get("/verify-token")
def verify_token(request: Request):
    auth = request.headers.get("Authorization", "")
    if auth == "Bearer token-anubis-2026":
        return {"valid": True}
    raise HTTPException(status_code=401, detail="Token inválido")

@app.delete("/targets/{target_id}")
def delete_target(target_id: int, db: Session = Depends(database.get_db)):
    target = db.query(models.Target).filter(models.Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Objetivo no encontrado")
    url_a_borrar = target.url.strip()

    # Cascade delete: target_id no es una FK real en el esquema, así que hay
    # que limpiar a mano cada tabla que lo referencia para no dejar huérfanos.
    db.query(models.Finding).filter(models.Finding.target_id == target_id).delete()
    db.query(models.VectorRun).filter(models.VectorRun.target_id == target_id).delete()
    db.query(models.AiAttackPlan).filter(models.AiAttackPlan.target_id == target_id).delete()

    run_ids = [r.id for r in db.query(AttackRun.id).filter(AttackRun.target_id == target_id).all()]
    if run_ids:
        db.query(AttackResult).filter(AttackResult.run_id.in_(run_ids)).delete(synchronize_session=False)
        db.query(AttackRun).filter(AttackRun.id.in_(run_ids)).delete(synchronize_session=False)

    # Schedule puede apuntar a varios targets a la vez (target_ids JSON); solo
    # se borra el schedule completo si este era el único target, si no se le
    # quita la referencia y se conserva para los demás.
    schedules = db.query(models.Schedule).filter(
        (models.Schedule.target_id == target_id) | (models.Schedule.target_ids.isnot(None))
    ).all()
    for s in schedules:
        ids = json.loads(s.target_ids) if s.target_ids else ([s.target_id] if s.target_id else [])
        if target_id not in ids:
            continue
        ids = [i for i in ids if i != target_id]
        if not ids:
            db.delete(s)
        else:
            s.target_ids = json.dumps(ids)
            s.target_id = ids[0]

    db.delete(target)
    db.commit()

    ruta_txt = "/home/anubis/AnubisProject/reports/sitios.txt"
    if os.path.exists(ruta_txt):
        try:
            with open(ruta_txt, "r") as f:
                lineas = f.readlines()
            lineas_filtradas = [linea for linea in lineas if linea.strip() != url_a_borrar]
            with open(ruta_txt, "w") as f:
                f.writelines(lineas_filtradas)
        except Exception as e:
            print(f"Error al actualizar sitios.txt: {e}")

    return {"message": "Objetivo eliminado de la BD y del archivo de texto"}

# --- ENDPOINTS DE SCHEDULES ---

class ScheduleCreate(BaseModel):
    target_ids: List[int]
    modules: List[str]
    scheduled_at: str
    repeat: str = "once"

def _parse_modules(raw: str) -> list:
    """Parsea el campo module como JSON array o string simple (compatibilidad)."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else [parsed]
    except Exception:
        return [raw]

def _resolve_schedule(s, db):
    """Construye el dict de respuesta para un schedule, resolviendo nombres de targets."""
    ids = json.loads(s.target_ids) if s.target_ids else ([s.target_id] if s.target_id else [])
    names = []
    for tid in ids:
        t = db.query(models.Target).filter(models.Target.id == tid).first()
        names.append(t.name if t else f"#{tid}")
    return {
        "id": s.id,
        "target_ids": ids,
        "target_name": ", ".join(names) if names else "Desconocido",
        "modules": _parse_modules(s.module),
        "scheduled_at": s.scheduled_at,
        "repeat": s.repeat,
    }

@app.get("/schedules/")
def get_schedules(db: Session = Depends(database.get_db)):
    schedules = db.query(models.Schedule).order_by(models.Schedule.scheduled_at).all()
    return [_resolve_schedule(s, db) for s in schedules]

@app.post("/schedules/")
def create_schedule(schedule: ScheduleCreate, db: Session = Depends(database.get_db)):
    # Los schedules corren vía run_sequential_scan, que ejecuta desde script_induvidual/
    # — un módulo solo presente en scripts/ (ej. kiterunner) no sirve aquí.
    modules = discover_modules()
    if not schedule.target_ids:
        raise HTTPException(status_code=400, detail="Debes seleccionar al menos un objetivo")
    if not schedule.modules:
        raise HTTPException(status_code=400, detail="Debes seleccionar al menos un módulo")
    invalid = [m for m in schedule.modules if not modules.get(m, {}).get("script_individual")]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Módulos no reconocidos o sin script en script_induvidual/: {invalid}")
    db_schedule = models.Schedule(
        target_id=schedule.target_ids[0],
        target_ids=json.dumps(schedule.target_ids),
        module=json.dumps(schedule.modules),
        scheduled_at=schedule.scheduled_at,
        repeat=schedule.repeat,
    )
    db.add(db_schedule)
    db.commit()
    db.refresh(db_schedule)
    return _resolve_schedule(db_schedule, db)

@app.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, db: Session = Depends(database.get_db)):
    schedule = db.query(models.Schedule).filter(models.Schedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule no encontrado")
    db.delete(schedule)
    db.commit()
    return {"message": "Schedule eliminado"}

# --- ENDPOINTS DE EJECUCIÓN DE SCRIPTS ---
# Genérico: cualquier script agregado a scripts/ (vía /upload-script o a mano)
# queda disponible aquí automáticamente, sin necesitar un endpoint por módulo.
@app.post("/run-{module}")
def run_full_scan_endpoint(module: str, db: Session = Depends(database.get_db)):
    info = discover_modules().get(module)
    if not info or not info["script_full"]:
        raise HTTPException(status_code=404, detail=f"Módulo '{module}' no disponible para escaneo de todos los targets (falta el script en scripts/)")
    queue = get_module_queue(db, module)
    task = _enqueue_full_scan(module, queue)
    return {"message": f"{module_label(module)} añadido a la cola {queue}", "task_id": task.id, "queue": queue}

# --- ENDPOINT ESCANEO INDIVIDUAL (desde el cohete en Targets) ---

class IndividualScanRequest(BaseModel):
    url: str
    target_id: Optional[int] = None

@app.post("/run-individual/{module}")
def run_individual_scan_endpoint(module: str, request: IndividualScanRequest, db: Session = Depends(database.get_db)):
    info = discover_modules().get(module)
    if not info or not info["script_individual"]:
        raise HTTPException(status_code=404, detail=f"Módulo '{module}' no disponible para escaneo individual (falta el script en script_induvidual/)")
    queue = get_module_queue(db, module)
    task = _enqueue_individual_scan(module, request.url, queue, request.target_id)
    return {
        "message": f"{module.upper()} individual añadido a la cola para {request.url}",
        "task_id": task.id,
        "queue": queue,
        "log_channel": f"anubis:scan:{module}:{request.target_id or hashlib.md5(request.url.encode()).hexdigest()[:8]}",
    }

# --- SCAN ENGINE: descubrimiento y configuración de módulos ---

@app.get("/system/scan-modules")
def list_scan_modules(db: Session = Depends(database.get_db)):
    """Módulos detectados en scripts/ y script_induvidual/, con su cola actual
    y si le falta la réplica en alguna de las dos carpetas."""
    modules = discover_modules()
    result = []
    for mid, info in sorted(modules.items()):
        result.append({
            "id": mid,
            "label": module_label(mid),
            "queue": get_module_queue(db, mid),
            "in_scripts": info["script_full"] is not None,
            "in_individual": info["script_individual"] is not None,
            "script_full": info["script_full"],
            "script_individual": info["script_individual"],
        })
    return result

class ScanModuleQueueUpdate(BaseModel):
    queue: str

@app.put("/system/scan-modules/{module_id}/queue")
def update_scan_module_queue(module_id: str, body: ScanModuleQueueUpdate, db: Session = Depends(database.get_db)):
    if module_id not in discover_modules():
        raise HTTPException(status_code=404, detail=f"Módulo '{module_id}' no encontrado")
    if body.queue not in ("light", "heavy"):
        raise HTTPException(status_code=400, detail="queue debe ser 'light' o 'heavy'")
    set_module_queue(db, module_id, body.queue)
    return {"id": module_id, "queue": body.queue}

# --- ENDPOINT ESTADO DE CELERY (monitor de workers/colas) ---

def _describe_task(name, args):
    args = args or []
    if name == "tasks.run_full_scan":
        mod = args[0] if args else None
        return module_label(mod) if mod else mod, "todos los targets"
    if name == "tasks.run_individual_scan":
        mod = args[0] if len(args) > 0 else None
        url = args[1] if len(args) > 1 else None
        return module_label(mod) if mod else mod, url
    if name == "tasks.run_sequential_scan":
        mod  = args[0] if len(args) > 0 else None
        urls = args[1] if len(args) > 1 else []
        n = len(urls) if isinstance(urls, list) else 0
        return module_label(mod) if mod else mod, f"{n} target(s)"
    if name == "tasks.execute_attack_run":
        run_id = args[0] if args else None
        return "Anubis Attack (DAG)", f"run #{run_id}" if run_id is not None else None
    if name == "tasks.run_vector_agent_task":
        run_id = args[0] if args else None
        return "Vector Agent IA", f"run #{run_id}" if run_id is not None else None
    if name == "tasks.analyze_report_with_ai":
        report_id = args[0] if args else None
        return "Análisis IA (Gemini)", f"report #{report_id}" if report_id is not None else None
    if name == "tasks.check_and_run_schedules":
        return "Scheduler", None
    return (name.split(".")[-1] if name else None), None

@app.get("/system/celery-status")
def get_celery_status():
    from celery_app import celery_app as _celery
    insp = _celery.control.inspect(timeout=2)
    active    = insp.active() or {}
    reserved  = insp.reserved() or {}
    scheduled = insp.scheduled() or {}
    stats     = insp.stats() or {}

    hostnames = sorted(set(active) | set(reserved) | set(scheduled) | set(stats))
    now = time.time()

    def _task_view(t):
        started = t.get("time_start")
        name = t.get("name")
        args = t.get("args") or []
        tool, detail = _describe_task(name, args)
        return {
            "id": t.get("id"),
            "name": name,
            "tool": tool,
            "detail": detail,
            "args": args,
            "kwargs": t.get("kwargs") or {},
            "elapsed_seconds": round(now - started, 1) if started else None,
        }

    workers = []
    for host in hostnames:
        workers.append({
            "hostname": host,
            "queue": host.split("@")[0],
            "status": "online",
            "active_tasks": [_task_view(t) for t in active.get(host, [])],
            "reserved_tasks": [_task_view(t) for t in reserved.get(host, [])],
            "scheduled_tasks": [_task_view(t["request"]) for t in scheduled.get(host, [])],
        })

    return {
        "online": len(workers) > 0,
        "workers": workers,
        "totals": {
            "workers_online": len(workers),
            "active_tasks": sum(len(w["active_tasks"]) for w in workers),
            "reserved_tasks": sum(len(w["reserved_tasks"]) for w in workers),
        },
    }

# --- ENDPOINTS DE HISTÓRICO Y COMPARACIÓN ---

@app.get("/findings/historical")
def get_historical(db: Session = Depends(database.get_db)):
    findings = (
        db.query(models.Finding)
        .order_by(models.Finding.scan_date.desc())
        .all()
    )
    targets_map = {t.id: t for t in db.query(models.Target).all()}

    groups: dict = {}
    for f in findings:
        day = str(f.scan_date)[:10] if f.scan_date else "unknown"
        key = (f.target_id, f.module, day)
        if key not in groups:
            target = targets_map.get(f.target_id)
            groups[key] = {
                "target_id": f.target_id,
                "target_name": target.name if target else f"#{f.target_id}",
                "module": f.module,
                "date": day,
                "findings": [],
            }
        groups[key]["findings"].append({
            "id": f.id,
            "severity": f.severity or "info",
            "title": f.title,
            "description": f.description,
            "scan_date": str(f.scan_date),
        })

    result = sorted(groups.values(), key=lambda x: x["date"], reverse=True)
    for g in result:
        g["count"] = len(g["findings"])
    return result


@app.get("/findings/compare")
def compare_findings(
    target_id: int,
    module: str,
    date_old: str,
    date_new: str,
    db: Session = Depends(database.get_db),
):
    def get_for_date(date_str: str):
        return [
            {"id": f.id, "severity": f.severity or "info", "title": f.title, "description": f.description}
            for f in db.query(models.Finding).filter(
                models.Finding.target_id == target_id,
                models.Finding.module == module,
            ).all()
            if f.scan_date and str(f.scan_date)[:10] == date_str
        ]

    old_findings = get_for_date(date_old)
    new_findings = get_for_date(date_new)
    old_titles = {f["title"] for f in old_findings}
    new_titles = {f["title"] for f in new_findings}

    return {
        "new":       [f for f in new_findings if f["title"] not in old_titles],
        "removed":   [f for f in old_findings if f["title"] not in new_titles],
        "unchanged": [f for f in new_findings if f["title"] in old_titles],
    }


# --- ENDPOINT UPLOAD DE SCRIPTS ---
# Un script subido aquí queda disponible en el Scan Engine automáticamente
# (ver discover_modules() en scan_modules.py) sin reiniciar nada.
from scan_modules import SCRIPTS_FULL_DIR, SCRIPTS_INDIVIDUAL_DIR

@app.post("/upload-script")
async def upload_script(
    file: UploadFile = File(...),
    destination: str = Form(...),
):
    if not file.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Solo se permiten archivos .py")
    if destination not in ("full", "individual"):
        raise HTTPException(status_code=400, detail="destination debe ser 'full' o 'individual'")
    dest_dir = SCRIPTS_FULL_DIR if destination == "full" else SCRIPTS_INDIVIDUAL_DIR
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, file.filename)
    with open(dest_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    return {"message": f"Script '{file.filename}' guardado", "path": dest_path}


# ─────────────────────────────────────────────────────────────────────────────
# REPORTS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

# OWASP Top 10 keyword mapping for auto-classification
_OWASP_MAP = {
    "A01": {"name": "Broken Access Control",                    "keywords": ["access control", "authorization", "privilege", "permission", "directory traversal", "path traversal", "idor"]},
    "A02": {"name": "Cryptographic Failures",                   "keywords": ["ssl", "tls", "https", "cipher", "certificate", "crypto", "encrypt", "weak protocol", "plaintext"]},
    "A03": {"name": "Injection",                                "keywords": ["sql injection", "xss", "cross-site scripting", "command injection", "ldap", "nosql", "inject", "script"]},
    "A04": {"name": "Insecure Design",                          "keywords": ["insecure design", "threat model", "design flaw", "missing security control"]},
    "A05": {"name": "Security Misconfiguration",                "keywords": ["misconfiguration", "default", "header", "csp", "hsts", "x-frame", "cors", "server version", "exposed", "banner"]},
    "A06": {"name": "Vulnerable and Outdated Components",       "keywords": ["outdated", "cve-", "vulnerable component", "old version", "deprecated", "end of life", "unpatched"]},
    "A07": {"name": "Identification and Authentication Failures","keywords": ["authentication", "login", "password", "session", "brute force", "credential", "token", "cookie"]},
    "A08": {"name": "Software and Data Integrity Failures",     "keywords": ["integrity", "supply chain", "unsigned", "deserialization", "tamper"]},
    "A09": {"name": "Security Logging and Monitoring Failures", "keywords": ["logging", "monitoring", "audit log", "no log", "trace", "alerting"]},
    "A10": {"name": "Server-Side Request Forgery (SSRF)",       "keywords": ["ssrf", "server-side request", "internal service", "request forgery", "internal network"]},
}


def _calculate_risk_score(severity_counts: dict) -> int:
    score = 100
    score -= severity_counts.get("critical", 0) * 30
    score -= severity_counts.get("high", 0) * 20
    score -= severity_counts.get("medium", 0) * 10
    score -= severity_counts.get("low", 0) * 5
    return max(0, score)


def _build_report_data(target_ids_list: list, scope: str, db: Session) -> dict:
    if scope == "all" or not target_ids_list:
        targets = db.query(models.Target).all()
    else:
        targets = [db.query(models.Target).filter(models.Target.id == tid).first() for tid in target_ids_list]
        targets = [t for t in targets if t]

    all_target_ids = [t.id for t in targets]
    findings = (
        db.query(models.Finding).filter(models.Finding.target_id.in_(all_target_ids)).all()
        if all_target_ids else []
    )

    global_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity or "info").lower()
        if sev in global_sev:
            global_sev[sev] += 1

    targets_data = []
    for t in targets:
        t_findings = [f for f in findings if f.target_id == t.id]
        by_module: dict = {}
        t_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in t_findings:
            sev = (f.severity or "info").lower()
            if sev in t_sev:
                t_sev[sev] += 1
            if f.module not in by_module:
                by_module[f.module] = []
            try:
                extra = json.loads(f.extra) if f.extra else {}
            except Exception:
                extra = {}
            by_module[f.module].append({
                "id": f.id,
                "severity": f.severity or "info",
                "title": f.title,
                "description": f.description or "",
                "extra": extra,
                "scan_date": str(f.scan_date)[:10] if f.scan_date else None,
            })
        targets_data.append({
            "id": t.id,
            "name": t.name,
            "url": t.url,
            "status": t.status,
            "waf_detected": t.waf_detected or "No verificado",
            "findings_by_module": by_module,
            "severity_counts": t_sev,
            "total_findings": len(t_findings),
            "risk_score": _calculate_risk_score(t_sev),
        })

    # OWASP Top 10 auto-mapping based on finding titles/descriptions
    owasp_mapping = {}
    for code, info in _OWASP_MAP.items():
        matched = []
        for f in findings:
            text_check = f"{f.title} {f.description or ''}".lower()
            if any(kw in text_check for kw in info["keywords"]):
                target = next((t for t in targets if t.id == f.target_id), None)
                matched.append({
                    "title": f.title,
                    "severity": f.severity or "info",
                    "target_name": target.name if target else f"#{f.target_id}",
                    "module": f.module,
                })
        owasp_mapping[code] = {
            "name": info["name"],
            "findings": matched,
            "status": "affected" if matched else "not_detected",
            "count": len(matched),
        }

    return {
        "targets": targets_data,
        "severity_counts": global_sev,
        "total_findings": len(findings),
        "total_targets": len(targets),
        "modules_scanned": list({f.module for f in findings}),
        "owasp_mapping": owasp_mapping,
        "affected_owasp_count": sum(1 for v in owasp_mapping.values() if v["status"] == "affected"),
        "risk_score": _calculate_risk_score(global_sev),
    }


def _default_ai_content() -> dict:
    return {
        "markdown_report":   None,
        "executive_summary": None,
        "risk_narrative":    None,
        "business_impact":   None,
        "recommendations":   [],
        "compliance_gaps":   [],
        "compliance_narrative": None,
        "ai_generated":      False,
        "ai_generated_at":   None,
        "ai_model":          None,
    }


def _serialize_report(r: models.Report) -> dict:
    try:
        snapshot = json.loads(r.findings_snapshot) if r.findings_snapshot else {}
    except Exception:
        snapshot = {}
    try:
        ai_content = json.loads(r.ai_content) if r.ai_content else _default_ai_content()
    except Exception:
        ai_content = _default_ai_content()
    try:
        target_ids = json.loads(r.target_ids) if r.target_ids else []
    except Exception:
        target_ids = []
    return {
        "id": r.id,
        "scope": r.scope,
        "target_ids": target_ids,
        "report_type": r.report_type,
        "title": r.title,
        "status": r.status,
        "created_at": str(r.created_at) if r.created_at else None,
        "generated_at": str(r.generated_at) if r.generated_at else None,
        "total_findings": snapshot.get("total_findings", 0),
        "total_targets": snapshot.get("total_targets", 0),
        "severity_counts": snapshot.get("severity_counts", {}),
        "risk_score": snapshot.get("risk_score", 0),
        "ai_enhanced": ai_content.get("ai_generated", False),
        "data": snapshot,
        "ai_content": ai_content,
    }


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ReportCreate(BaseModel):
    target_ids: List[int] = []   # empty list = all targets (when scope=="all")
    report_type: str             # executive | technical | compliance | full
    scope: str                   # single | all


class AIEnhanceRequest(BaseModel):
    executive_summary: Optional[str] = None
    risk_narrative: Optional[str] = None
    business_impact: Optional[str] = None
    remediation_timeline: Optional[str] = None
    recommendations: Optional[List[dict]] = None
    compliance_gaps: Optional[List[str]] = None
    compliance_narrative: Optional[str] = None
    ai_model: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/reports/generate")
def generate_report(data: ReportCreate, db: Session = Depends(database.get_db)):
    valid_types = {"executive", "technical", "compliance", "full"}
    if data.report_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Tipo no válido: {data.report_type}")

    scope = data.scope if data.scope in ("single", "all") else "all"

    try:
        report_data = _build_report_data(data.target_ids, scope, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte: {str(e)}")

    type_labels = {"executive": "Ejecutivo", "technical": "Técnico", "compliance": "Compliance", "full": "Completo"}
    now = datetime.utcnow()

    if scope == "all":
        title = f"Reporte {type_labels[data.report_type]} — Todos los Objetivos — {now.strftime('%Y-%m-%d %H:%M')}"
    else:
        names = [t["name"] for t in report_data["targets"]]
        title = f"Reporte {type_labels[data.report_type]} — {', '.join(names) or 'Sin objetivo'} — {now.strftime('%Y-%m-%d %H:%M')}"

    db_report = models.Report(
        scope=scope,
        target_ids=json.dumps(data.target_ids) if scope == "single" else None,
        report_type=data.report_type,
        title=title,
        status="ready",
        findings_snapshot=json.dumps(report_data),
        ai_content=json.dumps(_default_ai_content()),
        generated_at=now,
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return _serialize_report(db_report)


@app.get("/reports/")
def list_reports(db: Session = Depends(database.get_db)):
    reports = db.query(models.Report).order_by(models.Report.created_at.desc()).all()
    return [_serialize_report(r) for r in reports]


@app.get("/reports/{report_id}")
def get_report(report_id: int, db: Session = Depends(database.get_db)):
    r = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    return _serialize_report(r)


@app.delete("/reports/{report_id}")
def delete_report(report_id: int, db: Session = Depends(database.get_db)):
    r = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    db.delete(r)
    db.commit()
    return {"message": "Reporte eliminado"}


@app.get("/reports/{report_id}/download")
def download_report_pdf(report_id: int, db: Session = Depends(database.get_db)):
    r = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    try:
        snapshot   = json.loads(r.findings_snapshot) if r.findings_snapshot else {}
        ai_content = json.loads(r.ai_content)        if r.ai_content        else _default_ai_content()
    except Exception:
        snapshot, ai_content = {}, _default_ai_content()

    try:
        docx_bytes = _build_docx(r, snapshot, ai_content)
        pdf_bytes  = _docx_to_pdf(docx_bytes)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error generando PDF: {exc}")

    safe_title = "".join(c if c.isalnum() or c in "-_" else "_" for c in (r.title or "report"))[:60]
    filename   = f"anubis_{safe_title}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── PDF via LibreOffice ───────────────────────────────────────────────────────

def _docx_to_pdf(docx_bytes: bytes) -> bytes:
    """Convert DOCX bytes to PDF bytes using LibreOffice headless."""
    import tempfile, subprocess, pathlib
    with tempfile.TemporaryDirectory() as tmp:
        docx_path = pathlib.Path(tmp) / "report.docx"
        docx_path.write_bytes(docx_bytes)
        result = subprocess.run(
            ["libreoffice", "--headless", "--convert-to", "pdf",
             "--outdir", tmp, str(docx_path)],
            capture_output=True, timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        pdf_path = pathlib.Path(tmp) / "report.pdf"
        return pdf_path.read_bytes()


import re as _re


def _parse_md_blocks(text: str) -> list:
    """Parse a Markdown string into a list of typed block dicts."""
    blocks = []
    lines  = text.split('\n')
    i = 0
    while i < len(lines):
        raw      = lines[i]
        stripped = raw.strip()
        if (stripped.startswith('|') and
                i + 1 < len(lines) and
                _re.match(r'^\|[-| :]+\|', lines[i + 1].strip())):
            headers = [c.strip() for c in stripped.strip('|').split('|')]
            i += 2
            rows = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                row = [c.strip() for c in lines[i].strip().strip('|').split('|')]
                rows.append(row)
                i += 1
            blocks.append({"type": "table", "headers": headers, "rows": rows})
            continue
        if stripped.startswith('### '):
            blocks.append({"type": "h3", "text": stripped[4:]})
        elif stripped.startswith('## '):
            blocks.append({"type": "h2", "text": stripped[3:]})
        elif stripped.startswith('# '):
            blocks.append({"type": "h1", "text": stripped[2:]})
        elif stripped.startswith('- ') or stripped.startswith('* '):
            blocks.append({"type": "bullet", "text": stripped[2:]})
        elif _re.match(r'^---+$', stripped):
            blocks.append({"type": "hr"})
        elif not stripped:
            blocks.append({"type": "blank"})
        else:
            blocks.append({"type": "paragraph", "text": stripped})
        i += 1
    return blocks


# ─── DOCX BUILDER ─────────────────────────────────────────────────────────────

DOCX_TEMPLATE = "/home/anubis/AnubisProject/Pruebas Hardening OpenClaw.docx"

_SEV_LABEL_ES = {
    "critical": "CRÍTICO", "high": "ALTO",
    "medium": "MEDIO", "low": "BAJO", "info": "INFO",
}

_TYPE_LABEL_ES = {
    "executive": "REPORTE EJECUTIVO", "technical": "REPORTE TÉCNICO",
    "compliance": "REPORTE DE COMPLIANCE", "full": "REPORTE COMPLETO",
}


def _docx_clear(doc):
    from docx.oxml.ns import qn as _qn
    body = doc.element.body
    sectPr = body.find(_qn('w:sectPr'))
    for child in list(body):
        body.remove(child)
    if sectPr is not None:
        body.append(sectPr)


def _docx_update_header_title(doc, new_title: str):
    from docx.oxml.ns import qn as _qn
    hdr = doc.sections[0].header
    tbl = hdr._element.find('.//' + _qn('w:tbl'))
    if tbl is None:
        return
    texts = list(tbl.iter(_qn('w:t')))
    if texts:
        texts[0].text = new_title


def _docx_table_borders(table, color: str = "AAAAAA"):
    from docx.oxml.ns import qn as _qn
    from docx.oxml import OxmlElement
    tbl_pr = table._tbl.tblPr
    if tbl_pr is None:
        tbl_pr = OxmlElement('w:tblPr')
        table._tbl.insert(0, tbl_pr)
    borders = OxmlElement('w:tblBorders')
    for side in ('top', 'left', 'bottom', 'right', 'insideH', 'insideV'):
        el = OxmlElement(f'w:{side}')
        el.set(_qn('w:val'),   'single')
        el.set(_qn('w:sz'),    '4')
        el.set(_qn('w:space'), '0')
        el.set(_qn('w:color'), color)
        borders.append(el)
    tbl_pr.append(borders)


def _md_inline_docx(para, text: str):
    """Add runs to a python-docx paragraph, honouring **bold** and *italic* markers."""
    from docx.shared import RGBColor as _RGB
    pattern = _re.compile(r'\*\*(.+?)\*\*|\*(.+?)\*')
    last    = 0
    for m in pattern.finditer(text):
        if text[last:m.start()]:
            para.add_run(text[last:m.start()])
        if m.group().startswith('**'):
            run = para.add_run(m.group(1))
            run.bold = True
        else:
            run = para.add_run(m.group(2))
            run.italic = True
        last = m.end()
    if text[last:]:
        para.add_run(text[last:])


def _build_docx(r: models.Report, snapshot: dict, ai: dict) -> bytes:
    from docx import Document as DocxDoc
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    _RISK_RGB = {
        "CRÍTICO":    RGBColor(0xD3, 0x2F, 0x2F),
        "CRITICO":    RGBColor(0xD3, 0x2F, 0x2F),
        "ALTO":       RGBColor(0xE6, 0x51, 0x00),
        "MEDIO":      RGBColor(0xEF, 0x6C, 0x00),
        "BAJO":       RGBColor(0x15, 0x65, 0xC0),
        "INFORMATIVO":RGBColor(0x54, 0x6E, 0x7A),
    }
    _UNUSED_PRIO_RGB = {
        "critical": RGBColor(0xD3, 0x2F, 0x2F),
        "high":     RGBColor(0xE6, 0x51, 0x00),
        "medium":   RGBColor(0xEF, 0x6C, 0x00),
    }

    doc = DocxDoc(DOCX_TEMPLATE)
    _docx_clear(doc)
    _docx_update_header_title(doc, "Reporte de Escaneo de Seguridad")

    rtype    = r.report_type or "executive"
    type_lbl = _TYPE_LABEL_ES.get(rtype, rtype.upper())
    gen_date = (r.generated_at.strftime("%d/%m/%Y %H:%M")
                if r.generated_at and hasattr(r.generated_at, "strftime")
                else (str(r.generated_at)[:16] if r.generated_at else "—"))
    scope_str = ("Todos los objetivos" if r.scope == "all"
                 else f"{snapshot.get('total_targets', 1)} objetivo(s)")
    ai_str    = "Con análisis IA" if ai.get("ai_generated") else "Sin análisis IA"

    # ── PORTADA ───────────────────────────────────────────────────────────────
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("ANUBIS SCAN PLATFORM")
    run.bold = True
    run.font.size = Pt(22)
    run.font.color.rgb = RGBColor(0x1A, 0x1A, 0x2E)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(type_lbl.upper())
    run.bold = True
    run.font.size = Pt(16)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(r.title or "Reporte de Escaneo de Seguridad")
    run.font.size = Pt(13)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(f"Fecha: {gen_date}  |  Alcance: {scope_str}  |  {ai_str}")
    run.italic = True
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x54, 0x6E, 0x7A)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("CLASIFICACIÓN: CONFIDENCIAL")
    run.bold = True
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0xD3, 0x2F, 0x2F)

    doc.add_paragraph()

    # ── MARKDOWN BODY ─────────────────────────────────────────────────────────
    md_text = ai.get("markdown_report")
    if md_text:
        blocks = _parse_md_blocks(md_text)

        # Skip section 1 (TÍTULO) — already in the cover above
        skip_title = False
        skip_end   = False
        for i, blk in enumerate(blocks):
            bt  = blk["type"]
            bv  = blk.get("text", "")
            if not skip_end and bt == "h1" and ("1." in bv or "TÍTULO" in bv.upper()):
                skip_title = True
            elif skip_title and bt == "h1":
                skip_end   = True
                skip_title = False
            if skip_title:
                blk["_skip"] = True

        for blk in blocks:
            if blk.get("_skip"):
                continue
            bt = blk["type"]
            bv = blk.get("text", "")

            if bt == "h1":
                doc.add_heading(bv, level=1)

            elif bt == "h2":
                doc.add_heading(bv, level=2)

            elif bt == "h3":
                doc.add_heading(bv, level=3)

            elif bt == "bullet":
                p = doc.add_paragraph(style="List Paragraph")
                _md_inline_docx(p, bv)

            elif bt == "table":
                # Table block has "headers" + "rows" from _parse_md_blocks
                headers   = blk.get("headers", [])
                rows_data = blk.get("rows", [])
                all_rows  = ([headers] if headers else []) + rows_data
                if not all_rows:
                    continue
                ncols = len(all_rows[0])
                tbl   = doc.add_table(rows=len(all_rows), cols=ncols)
                _docx_table_borders(tbl)
                for ri, row in enumerate(all_rows):
                    for ci, cell_text in enumerate(row):
                        cell_para = tbl.cell(ri, ci).paragraphs[0]
                        clean     = cell_text.strip()
                        risk_key  = clean.upper().strip("*").strip()
                        rgb       = _RISK_RGB.get(risk_key)
                        if ri == 0:
                            run = cell_para.add_run(clean)
                            run.bold = True
                        elif rgb:
                            run = cell_para.add_run(clean)
                            run.bold  = True
                            run.font.color.rgb = rgb
                        else:
                            _md_inline_docx(cell_para, clean)
                doc.add_paragraph()

            elif bt == "hr":
                p = doc.add_paragraph()
                from docx.oxml.ns import qn as _qn
                from docx.oxml   import OxmlElement as _OE
                pPr  = p._p.get_or_add_pPr()
                pBdr = _OE("w:pBdr")
                bot  = _OE("w:bottom")
                bot.set(_qn("w:val"),   "single")
                bot.set(_qn("w:sz"),    "6")
                bot.set(_qn("w:space"), "1")
                bot.set(_qn("w:color"), "AAAAAA")
                pBdr.append(bot)
                pPr.append(pBdr)

            elif bt == "blank":
                doc.add_paragraph()

            else:  # paragraph
                if bv.strip():
                    p = doc.add_paragraph()
                    _md_inline_docx(p, bv)
    else:
        p = doc.add_paragraph()
        r2 = p.add_run("[ Análisis IA pendiente — genere el reporte con IA para ver el contenido ]")
        r2.italic = True
        r2.font.color.rgb = RGBColor(0x74, 0x75, 0x7F)

    # ── PIE ───────────────────────────────────────────────────────────────────
    doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r2 = p.add_run(f"Generado por Anubis Scan Platform  ·  {gen_date}  ·  Confidencial")
    r2.italic = True
    r2.font.size = Pt(8)
    r2.font.color.rgb = RGBColor(0x74, 0x75, 0x7F)

    buf = BytesIO()
    doc.save(buf)
    return buf.getvalue()


@app.get("/reports/{report_id}/download/docx")
def download_report_docx(report_id: int, db: Session = Depends(database.get_db)):
    r = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    try:
        snapshot   = json.loads(r.findings_snapshot) if r.findings_snapshot else {}
        ai_content = json.loads(r.ai_content)        if r.ai_content        else _default_ai_content()
    except Exception:
        snapshot, ai_content = {}, _default_ai_content()

    try:
        docx_bytes = _build_docx(r, snapshot, ai_content)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error generando DOCX: {exc}")

    safe_title = "".join(c if c.isalnum() or c in "-_" else "_" for c in (r.title or "report"))[:60]
    filename   = f"anubis_{safe_title}.docx"
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/reports/{report_id}/ai-analyze")
def ai_analyze_report(report_id: int, db: Session = Depends(database.get_db)):
    """
    Dispatch a Celery task that calls the AI agent and fills ai_content slots.
    Returns immediately — poll GET /reports/{id} until ai_enhanced=true.
    If the report is stuck in 'analyzing' for >2 min (worker crash/restart) it resets automatically.
    """
    from datetime import timezone as tz
    r = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    if r.status == "analyzing":
        # Use the precise start timestamp stored in ai_content when analysis began.
        # Fall back to generated_at for old records. If neither exists, allow retry.
        timeout_ok = True
        try:
            ai_content = json.loads(r.ai_content) if r.ai_content else {}
            started_at_str = ai_content.get("_ai_started_at")
            if started_at_str:
                ref = datetime.fromisoformat(started_at_str)
                if ref.tzinfo is None:
                    ref = ref.replace(tzinfo=tz.utc)
                elapsed = (datetime.now(tz.utc) - ref).total_seconds()
                timeout_ok = elapsed > 120
        except Exception:
            timeout_ok = True
        if not timeout_ok:
            raise HTTPException(status_code=409, detail="El reporte ya está siendo analizado. Espera unos segundos.")

    # Record the exact moment analysis starts so the timeout check above is accurate.
    try:
        ai_content = json.loads(r.ai_content) if r.ai_content else {}
    except Exception:
        ai_content = {}
    ai_content["_ai_started_at"] = datetime.now(tz.utc).isoformat()
    r.ai_content = json.dumps(ai_content, ensure_ascii=False)
    r.status = "analyzing"
    db.commit()

    task = analyze_report_with_ai.delay(report_id)
    return {"message": "Análisis IA iniciado", "task_id": task.id}


# ─────────────────────────────────────────────────────────────────────────────
# AI ATTACK PLANNER
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/attack/ai-plan/{target_id}")
def generate_ai_attack_plan(target_id: int, db: Session = Depends(database.get_db)):
    target = db.query(models.Target).filter(models.Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target no encontrado")

    findings = db.query(models.Finding).filter(models.Finding.target_id == target_id).all()

    findings_txt = ""
    for f in findings:
        findings_txt += f"[{(f.severity or 'info').upper()}] {f.title}: {(f.description or '')[:200]}\n"
    if not findings_txt:
        findings_txt = "Sin findings registrados todavía."

    prompt = f"""Eres un experto en pentesting y seguridad ofensiva. Tu tarea es analizar los findings de un escaneo y generar un plan de ataque estructurado para continuar el pentest.

TARGET:
- Nombre: {target.name}
- URL: {target.url}
- WAF detectado: {target.waf_detected or "No verificado"}
- Tecnologías: {getattr(target, 'technologies', None) or "No identificadas"}

FINDINGS DEL ESCANEO:
{findings_txt}

Genera un plan de ataque en formato JSON con la siguiente estructura exacta (sin texto adicional, solo JSON):
{{
  "resumen": "Resumen ejecutivo del plan en 2-3 oraciones",
  "razonamiento": "Análisis del contexto y por qué estos vectores son prioritarios",
  "vectores": [
    {{
      "nombre": "nombre_del_vector",
      "titulo": "Título legible",
      "prioridad": "critica|alta|media|baja",
      "intrusividad": "passive|active|exploitive",
      "justificacion": "Por qué atacar esto basado en los findings",
      "depende_de": ["nombre_vector_previo"],
      "finding_relacionado": "Título del finding que origina este vector"
    }}
  ]
}}

Ordena los vectores por prioridad descendente. Sé específico y técnico. Usa los findings reales como base."""

    try:
        from ai_agent import _call_ai
        raw = _call_ai(prompt)
        raw = raw.strip()
        # strip code fences if model adds them
        import re as _re
        raw = _re.sub(r'^```(?:json)?\s*', '', raw, flags=_re.IGNORECASE)
        raw = _re.sub(r'\s*```$', '', raw, flags=_re.IGNORECASE)
        plan = json.loads(raw)
    except json.JSONDecodeError:
        # if model doesn't return clean JSON, wrap the raw text
        plan = {
            "resumen": "Plan generado (texto libre)",
            "razonamiento": raw,
            "vectores": [],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error llamando a la IA: {str(e)}")

    plan["generated_at"] = datetime.now().isoformat()
    plan["target_id"] = target_id

    # Persistir — reemplaza cualquier plan anterior para este target
    db.query(models.AiAttackPlan).filter(models.AiAttackPlan.target_id == target_id).delete()
    db.add(models.AiAttackPlan(
        target_id    = target_id,
        plan_json    = json.dumps(plan, ensure_ascii=False),
        vector_count = len(plan.get("vectores", [])),
    ))
    db.commit()

    return plan


@app.get("/attack/ai-plan/{target_id}")
def get_ai_attack_plan(target_id: int, db: Session = Depends(database.get_db)):
    row = (db.query(models.AiAttackPlan)
             .filter(models.AiAttackPlan.target_id == target_id)
             .order_by(models.AiAttackPlan.generated_at.desc())
             .first())
    if not row:
        return None
    return json.loads(row.plan_json)


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK MODULE — Authorized Targets
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/authorized-targets", status_code=201)
def create_authorized_target(data: AuthorizedTargetCreate, db: Session = Depends(database.get_db)):
    auth = AuthorizedTarget(
        domain_pattern=data.domain_pattern,
        valid_from=data.valid_from,
        valid_until=data.valid_until,
        authorized_by=data.authorized_by,
        scope_document=data.scope_document,
        allowed_modules=json.dumps(data.allowed_modules) if data.allowed_modules else None,
        allowed_intrusiveness=data.allowed_intrusiveness,
        notes=data.notes,
    )
    db.add(auth)
    db.commit()
    db.refresh(auth)
    return _serialize_auth(auth)


@app.get("/authorized-targets")
def list_authorized_targets(db: Session = Depends(database.get_db)):
    auths = db.query(AuthorizedTarget).order_by(AuthorizedTarget.created_at.desc()).all()
    return [_serialize_auth(a) for a in auths]


@app.delete("/authorized-targets/{auth_id}")
def delete_authorized_target(auth_id: int, db: Session = Depends(database.get_db)):
    auth = db.query(AuthorizedTarget).filter(AuthorizedTarget.id == auth_id).first()
    if not auth:
        raise HTTPException(status_code=404, detail="Autorización no encontrada")
    db.delete(auth)
    db.commit()
    return {"message": "Autorización eliminada"}


def _serialize_auth(a: AuthorizedTarget) -> dict:
    from datetime import timezone as _tz
    now = datetime.now(_tz.utc)
    valid_from = a.valid_from.replace(tzinfo=_tz.utc) if a.valid_from and a.valid_from.tzinfo is None else a.valid_from
    valid_until = a.valid_until.replace(tzinfo=_tz.utc) if a.valid_until and a.valid_until.tzinfo is None else a.valid_until
    is_active = bool(valid_from and valid_until and valid_from <= now <= valid_until)
    return {
        "id": a.id,
        "domain_pattern": a.domain_pattern,
        "valid_from": str(a.valid_from),
        "valid_until": str(a.valid_until),
        "authorized_by": a.authorized_by,
        "scope_document": a.scope_document,
        "allowed_modules": json.loads(a.allowed_modules) if a.allowed_modules else None,
        "allowed_intrusiveness": a.allowed_intrusiveness,
        "notes": a.notes,
        "is_active": is_active,
        "created_at": str(a.created_at),
    }


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK MODULE — Attack Runs
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/attack/runs", status_code=201)
def create_attack_run(data: AttackRunCreate, db: Session = Depends(database.get_db)):
    target = db.query(models.Target).filter(models.Target.id == data.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target no encontrado")

    plan = plan_from_target(
        db=db,
        target_id=data.target_id,
        max_intrusiveness=data.intrusiveness,
        confidence_threshold=data.confidence_threshold,
        finding_ids=data.finding_ids,
    )
    if plan is None:
        raise HTTPException(
            status_code=422,
            detail="No hay findings que activar en este target con los parámetros indicados"
        )

    run = AttackRun(
        target_id=data.target_id,
        authorized_target_id=data.authorized_target_id,
        plan_json=plan.model_dump_json(),
        intrusiveness=data.intrusiveness,
        status="planned",
        abort_requested=False,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    # Encolar tarea Celery en cola "attack"
    from celery_app import celery_app as _celery
    _celery.send_task("tasks.execute_attack_run", args=[run.id], queue="attack")

    return {
        "id": run.id,
        "target_id": run.target_id,
        "status": run.status,
        "intrusiveness": run.intrusiveness,
        "node_count": len(plan.nodes),
        "plan_summary": plan.summary(),
        "plan_json": run.plan_json,
        "created_at": str(run.created_at),
    }


@app.get("/attack/runs")
def list_attack_runs(target_id: Optional[int] = None, db: Session = Depends(database.get_db)):
    q = db.query(AttackRun).order_by(AttackRun.created_at.desc())
    if target_id is not None:
        q = q.filter(AttackRun.target_id == target_id)
    return [_serialize_run(r, db) for r in q.all()]


@app.get("/attack/runs/{run_id}")
def get_attack_run(run_id: int, db: Session = Depends(database.get_db)):
    run = db.query(AttackRun).filter(AttackRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Attack run no encontrado")
    return _serialize_run(run, db)


@app.post("/attack/runs/{run_id}/abort")
def abort_attack_run(run_id: int, db: Session = Depends(database.get_db)):
    run = db.query(AttackRun).filter(AttackRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Attack run no encontrado")
    if run.status in ("completed", "aborted", "failed"):
        raise HTTPException(status_code=409, detail=f"El run ya está en estado '{run.status}'")
    run.abort_requested = True
    run.status = "aborted"
    db.commit()
    return {"message": f"Run {run_id} marcado para abortar"}


@app.get("/attack/runs/{run_id}/results")
def get_attack_results(run_id: int, db: Session = Depends(database.get_db)):
    run = db.query(AttackRun).filter(AttackRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Attack run no encontrado")
    results = db.query(AttackResult).filter(AttackResult.run_id == run_id).all()
    return [_serialize_result(r) for r in results]


def _serialize_run(run: AttackRun, db) -> dict:
    result_count = db.query(AttackResult).filter(AttackResult.run_id == run.id).count()
    try:
        plan = AttackPlan.model_validate_json(run.plan_json)
        node_count = len(plan.nodes)
        plan_summary = plan.summary()
    except Exception:
        node_count = 0
        plan_summary = {}
    return {
        "id": run.id,
        "target_id": run.target_id,
        "authorized_target_id": run.authorized_target_id,
        "status": run.status,
        "intrusiveness": run.intrusiveness,
        "abort_requested": run.abort_requested,
        "node_count": node_count,
        "result_count": result_count,
        "plan_summary": plan_summary,
        "plan_json": run.plan_json,
        "created_by": run.created_by,
        "started_at": str(run.started_at) if run.started_at else None,
        "completed_at": str(run.completed_at) if run.completed_at else None,
        "created_at": str(run.created_at) if run.created_at else None,
    }


def _serialize_result(r: AttackResult) -> dict:
    try:
        output = json.loads(r.output_json) if r.output_json else None
    except Exception:
        output = None
    return {
        "id": r.id,
        "run_id": r.run_id,
        "node_id": r.node_id,
        "vector_type": r.vector_type,
        "status": r.status,
        "output_json": output,
        "evidence_path": r.evidence_path,
        "confirmed_finding": r.confirmed_finding,
        "confidence_delta": r.confidence_delta,
        "error_message": r.error_message,
        "started_at": str(r.started_at) if r.started_at else None,
        "completed_at": str(r.completed_at) if r.completed_at else None,
        "created_at": str(r.created_at) if r.created_at else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# VECTOR AGENT — ejecución de vectores individuales con IA
# ─────────────────────────────────────────────────────────────────────────────

class VectorRunCreate(BaseModel):
    target_id: int
    vector: dict
    mode: str        # "quick" | "full"
    instructions: Optional[str] = ""


@app.post("/attack/vector-run")
def create_vector_run(body: VectorRunCreate, db: Session = Depends(database.get_db)):
    from tasks import run_vector_agent_task
    run = models.VectorRun(
        target_id     = body.target_id,
        vector_name   = body.vector.get('nombre', ''),
        vector_titulo = body.vector.get('titulo', ''),
        mode          = body.mode,
        instructions  = body.instructions or '',
        vector_json   = json.dumps(body.vector, ensure_ascii=False),
        status        = 'pending',
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    run_vector_agent_task.apply_async(args=[run.id], queue='heavy')
    return {'run_id': run.id, 'status': 'pending'}


@app.get("/attack/vector-run/{run_id}")
def get_vector_run(run_id: int, db: Session = Depends(database.get_db)):
    run = db.query(models.VectorRun).filter(models.VectorRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run no encontrado")
    return {
        'id':                run.id,
        'status':            run.status,
        'mode':              run.mode,
        'estado':            run.estado,
        'resumen':           run.resumen,
        'evidencia_tecnica': run.evidencia_tecnica,
        'impacto_negocio':   run.impacto_negocio,
        'comando_clave':     run.comando_clave,
        'recomendacion':     run.recomendacion,
        'iterations':        run.iterations,
        'started_at':        run.started_at.isoformat() if run.started_at else None,
        'completed_at':      run.completed_at.isoformat() if run.completed_at else None,
    }


@app.get("/attack/vector-runs")
def list_vector_runs(estado: Optional[str] = None, target_id: Optional[int] = None,
                      db: Session = Depends(database.get_db)):
    """Lista vector_runs completados, enriquecidos con datos del target.
    Usado por el findings de Anubis Attack para mostrar las explotaciones confirmadas
    por el agente IA (estado=explotable) con toda la info que muestra el modal de ejecución."""
    q = db.query(models.VectorRun).filter(models.VectorRun.status == 'completed')
    if estado:
        q = q.filter(models.VectorRun.estado == estado)
    if target_id:
        q = q.filter(models.VectorRun.target_id == target_id)
    runs = q.order_by(models.VectorRun.completed_at.desc()).all()

    target_ids = {r.target_id for r in runs}
    targets = {}
    if target_ids:
        for t in db.query(models.Target).filter(models.Target.id.in_(target_ids)).all():
            targets[t.id] = t

    result = []
    for r in runs:
        t = targets.get(r.target_id)
        result.append({
            'id':                r.id,
            'target_id':         r.target_id,
            'target_name':       t.name if t else None,
            'target_url':        t.url if t else None,
            'vector_name':       r.vector_name,
            'vector_titulo':     r.vector_titulo,
            'mode':              r.mode,
            'estado':            r.estado,
            'resumen':           r.resumen,
            'evidencia_tecnica': r.evidencia_tecnica,
            'impacto_negocio':   r.impacto_negocio,
            'comando_clave':     r.comando_clave,
            'recomendacion':     r.recomendacion,
            'iterations':        r.iterations,
            'started_at':        r.started_at.isoformat() if r.started_at else None,
            'completed_at':      r.completed_at.isoformat() if r.completed_at else None,
        })
    return result


@app.websocket("/ws/scan/{module}/{target_id}")
async def scan_log_ws(websocket: WebSocket, module: str, target_id: str):
    """Streaming de logs de un escaneo individual en tiempo real."""
    import redis.asyncio as aioredis
    await websocket.accept()
    r = aioredis.Redis(host='localhost', port=6379, db=2, decode_responses=True)
    pubsub = r.pubsub()
    channel = f"anubis:scan:{module}:{target_id}"
    await pubsub.subscribe(channel)
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                await websocket.send_text(data)
                if "[DONE]" in data or "[ERROR]" in data:
                    break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        try:
            await pubsub.unsubscribe(channel)
            await r.aclose()
        except Exception:
            pass


@app.websocket("/ws/vector-run/{run_id}")
async def vector_run_ws(websocket: WebSocket, run_id: int):
    import asyncio
    import redis.asyncio as aioredis

    IDLE_TIMEOUT = 600

    await websocket.accept()
    r = aioredis.Redis(host='localhost', port=6379, db=2, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"anubis:vector:run:{run_id}")
    try:
        while True:
            try:
                message = await asyncio.wait_for(pubsub.get_message(ignore_subscribe_messages=True), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                break
            if message is None:
                await asyncio.sleep(0.05)
                continue
            if message["type"] == "message":
                data = message["data"]
                await websocket.send_text(data)
                if "[DONE]" in data:
                    break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        try:
            await pubsub.unsubscribe(f"anubis:vector:run:{run_id}")
            await r.aclose()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK MODULE — WebSocket live terminal
# ─────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws/attack/{run_id}")
async def attack_websocket(websocket: WebSocket, run_id: int):
    """
    Streaming de logs del attack run al frontend vía WebSocket.
    El orquestador publica en canal Redis db=2: anubis:attack:run:{run_id}
    Cierra el loop al recibir [DONE] o tras 10 min sin mensajes (safety net).
    """
    import asyncio
    import redis.asyncio as aioredis

    IDLE_TIMEOUT = 600  # segundos sin mensajes antes de cerrar

    await websocket.accept()
    r = aioredis.Redis(host='localhost', port=6379, db=2, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"anubis:attack:run:{run_id}")
    try:
        while True:
            try:
                message = await asyncio.wait_for(pubsub.get_message(ignore_subscribe_messages=True), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                break
            if message is None:
                await asyncio.sleep(0.05)
                continue
            if message["type"] == "message":
                data = message["data"]
                await websocket.send_text(data)
                if "[DONE]" in data:
                    break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        try:
            await pubsub.unsubscribe(f"anubis:attack:run:{run_id}")
            await r.aclose()
        except Exception:
            pass


@app.post("/reports/{report_id}/ai-enhance")
def ai_enhance_report(report_id: int, data: AIEnhanceRequest, db: Session = Depends(database.get_db)):
    """
    Endpoint for the AI agent to inject generated content into a report.
    Accepts partial updates — only provided fields overwrite existing content.
    The agent should call this after analyzing the report's data snapshot.
    """
    r = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")

    try:
        ai_content = json.loads(r.ai_content) if r.ai_content else _default_ai_content()
    except Exception:
        ai_content = _default_ai_content()

    now = datetime.utcnow()

    if data.executive_summary is not None:
        ai_content["executive_summary"] = data.executive_summary
    if data.risk_narrative is not None:
        ai_content["risk_narrative"] = data.risk_narrative
    if data.business_impact is not None:
        ai_content["business_impact"] = data.business_impact
    if data.remediation_timeline is not None:
        ai_content["remediation_timeline"] = data.remediation_timeline
    if data.recommendations is not None:
        ai_content["recommendations"] = data.recommendations
    if data.compliance_gaps is not None:
        ai_content["compliance_gaps"] = data.compliance_gaps
    if data.compliance_narrative is not None:
        ai_content["compliance_narrative"] = data.compliance_narrative

    ai_content["ai_generated"] = True
    ai_content["ai_generated_at"] = str(now)
    ai_content["ai_model"] = data.ai_model or "unknown"

    r.ai_content = json.dumps(ai_content)
    db.commit()
    db.refresh(r)
    return _serialize_report(r)