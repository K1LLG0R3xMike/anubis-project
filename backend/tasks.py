# -*- coding: utf-8 -*-
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from celery_app import celery_app
import subprocess
import hashlib
import re
import redis as redis_lib

# Mismo cliente Redis que main.py usa para los locks (db=1)
_scan_redis = redis_lib.Redis(host='localhost', port=6379, db=1, decode_responses=True)
# Canal de logs de scan en tiempo real (db=2, mismo que attack)
_log_redis  = redis_lib.Redis(host='localhost', port=6379, db=2, decode_responses=True)

# Patrones de líneas ruidosas que no aportan al operador
_NOISE_PATTERNS = [
    re.compile(r'\bHTTP/\S+\s+4\d\d\b'),          # respuestas 4xx de ZAP
    re.compile(r'\bGET\s+\S+\s+HTTP/'),             # log de petición individual de ZAP
    re.compile(r'^\s*$'),                            # líneas vacías
    re.compile(r'^\s*\.\s*$'),                       # solo un punto
    re.compile(r'^\d{4}-\d{2}-\d{2}.*DEBUG'),        # DEBUG de java/ZAP
    re.compile(r'log4j|org\.zaproxy|java\.util'),    # stacktraces Java de ZAP
    re.compile(r'^\s+at\s+\w+\.\w+'),               # stack frame Java
]

def _is_noise(line: str) -> bool:
    for p in _NOISE_PATTERNS:
        if p.search(line):
            return True
    return False


def _stream_subprocess(cmd: list, channel: str, timeout: int = 4500) -> int:
    """
    Ejecuta cmd como subproceso, publica cada línea de stdout/stderr a Redis
    filtrando ruido (errores 4xx, stack frames Java, etc.).
    Retorna el código de salida.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    try:
        for raw in iter(proc.stdout.readline, b''):
            line = raw.decode('utf-8', errors='replace').rstrip()
            if not _is_noise(line):
                _log_redis.publish(channel, line)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        _log_redis.publish(channel, '[TIMEOUT] Escaneo superó el límite de tiempo')
    return proc.returncode

from scan_modules import discover_modules

@celery_app.task(name="tasks.run_full_scan")
def run_full_scan(module_type: str):
    scripts_dir = "/home/anubis/AnubisProject/scripts"
    script_name = discover_modules().get(module_type, {}).get("script_full")
    if not script_name:
        return f"Módulo {module_type} no reconocido"

    script_path = os.path.join(scripts_dir, script_name)
    try:
        process = subprocess.run(['python3', script_path], timeout=4500)
        return f"Resultado {module_type}: exit_code={process.returncode}"
    except subprocess.TimeoutExpired:
        return f"Timeout ejecutando {module_type}"
    except Exception as e:
        return f"Error ejecutando {module_type}: {str(e)}"
    finally:
        _scan_redis.delete(f"anubis:scan_lock:{module_type}")

@celery_app.task(name="tasks.run_individual_scan")
def run_individual_scan(module_type: str, target_url: str, target_id: int = None):
    scripts_dir = "/home/anubis/AnubisProject/script_induvidual"
    script_name = discover_modules().get(module_type, {}).get("script_individual")
    if not script_name:
        return f"Módulo {module_type} no reconocido"

    url_hash = hashlib.md5(target_url.encode()).hexdigest()[:8]
    channel  = f"anubis:scan:{module_type}:{target_id or url_hash}"

    script_path = os.path.join(scripts_dir, script_name)
    try:
        _log_redis.publish(channel, f"[INICIO] {module_type.upper()} → {target_url}")
        exit_code = _stream_subprocess(['python3', script_path, target_url], channel)
        status = "completado" if exit_code == 0 else f"error (exit {exit_code})"
        _log_redis.publish(channel, f"[DONE] Escaneo {status}")
        return f"Resultado {module_type} [{target_url}]: exit_code={exit_code}"
    except Exception as e:
        _log_redis.publish(channel, f"[ERROR] {e}")
        return f"Error ejecutando {module_type}: {str(e)}"
    finally:
        _scan_redis.delete(f"anubis:scan_lock:individual:{module_type}:{url_hash}")

@celery_app.task(name="tasks.run_sequential_scan")
def run_sequential_scan(module_type: str, target_urls: list):
    """Ejecuta un módulo sobre varios targets de forma secuencial (uno tras otro)."""
    scripts_dir = "/home/anubis/AnubisProject/script_induvidual"
    script_name = discover_modules().get(module_type, {}).get("script_individual")
    if not script_name:
        return f"Módulo {module_type} no reconocido"

    script_path = os.path.join(scripts_dir, script_name)
    results = []
    for url in target_urls:
        try:
            process = subprocess.run(['python3', script_path, url], timeout=4500)
            results.append(f"OK [{url}] exit_code={process.returncode}")
        except subprocess.TimeoutExpired:
            results.append(f"Timeout [{url}]")
        except Exception as e:
            results.append(f"Error [{url}]: {str(e)}")

    return " | ".join(results)

@celery_app.task(name="tasks.analyze_report_with_ai")
def analyze_report_with_ai(report_id: int):
    """
    Calls the configured AI provider (Gemini by default) to analyze a report's
    findings snapshot and injects the generated content into ai_content slots.
    """
    import json
    from datetime import datetime, timezone
    from database import SessionLocal
    from models import Report
    from ai_agent import analyze_report

    db = SessionLocal()
    try:
        r = db.query(Report).filter(Report.id == report_id).first()
        if not r:
            return f"Reporte {report_id} no encontrado"

        snapshot = json.loads(r.findings_snapshot) if r.findings_snapshot else {}
        ai_result = analyze_report(r.report_type, snapshot)

        try:
            ai_content = json.loads(r.ai_content) if r.ai_content else {}
        except Exception:
            ai_content = {}

        ai_content.update(ai_result)
        ai_content["ai_generated"]    = True
        ai_content["ai_generated_at"] = datetime.now(timezone.utc).isoformat()
        ai_content["ai_model"]        = __import__('os').getenv("AI_PROVIDER", "gemini")

        r.ai_content = json.dumps(ai_content, ensure_ascii=False)
        r.status     = "ready"
        db.commit()
        return f"Reporte {report_id} analizado con IA correctamente"

    except Exception as e:
        import traceback; traceback.print_exc()
        print(f"[AI] Error analizando reporte {report_id}: {e}")
        # Always reset status so the user can retry
        try:
            db.rollback()
            r2 = db.query(Report).filter(Report.id == report_id).first()
            if r2:
                r2.status = "ready"
                db.commit()
        except Exception:
            pass
        return f"Error: {e}"
    finally:
        db.close()


@celery_app.task(name="tasks.run_vector_agent_task", bind=True, max_retries=0, queue='heavy')
def run_vector_agent_task(self, run_id: int):
    import json
    from datetime import datetime, timezone
    from database import SessionLocal
    from models import VectorRun, Target
    import redis as redis_lib

    db = SessionLocal()
    r = redis_lib.Redis(host='localhost', port=6379, db=2, decode_responses=True)
    channel = f'anubis:vector:run:{run_id}'

    def publish(msg: str):
        r.publish(channel, msg)

    try:
        run = db.query(VectorRun).filter(VectorRun.id == run_id).first()
        if not run:
            return

        target = db.query(Target).filter(Target.id == run.target_id).first()
        if not target:
            publish("[ERROR] Target no encontrado en la base de datos")
            run.status = 'failed'
            db.commit()
            return

        run.status = 'running'
        run.started_at = datetime.now(timezone.utc)
        db.commit()

        vector = json.loads(run.vector_json) if run.vector_json else {}

        # ── Contexto de escaneos previos ──────────────────────────────────
        import json as _json
        from models import Finding as _Finding

        findings_db = db.query(_Finding).filter(_Finding.target_id == target.id).all()
        modules_map = {}
        for f in findings_db:
            modules_map.setdefault(f.module, []).append(f)

        ctx_parts = []
        reports_base = '/home/anubis/AnubisProject/reports'
        import re as _re
        _n = target.name.lower().strip()
        for _a, _b in [('á','a'),('é','e'),('í','i'),('ó','o'),('ú','u'),('ñ','n')]:
            _n = _n.replace(_a, _b)
        target_file = _re.sub(r'[^a-z0-9_]', '', _re.sub(r'\s+', '_', _n))

        # WhatWeb — tecnologías detectadas
        try:
            with open(f'{reports_base}/whatweb/{target_file}.json') as _f:
                ww = _json.load(_f)
            techs = ww.get('technologies', [])
            if techs:
                ctx_parts.append("STACK TECNOLÓGICO (WhatWeb):\n  " + ', '.join(techs))
        except Exception:
            if 'whatweb' in modules_map:
                ctx_parts.append("STACK TECNOLÓGICO:\n  " + ', '.join(f.title for f in modules_map['whatweb']))

        # ZAP — vulnerabilidades
        try:
            with open(f'{reports_base}/zap/{target_file}.json') as _f:
                zap = _json.load(_f)
            vulns = zap.get('vulnerabilities', [])[:20]
            if vulns:
                lines = [f"  [{v['severidad']}] {v['vulnerabilidad']} (OWASP: {v['owasp_id']})" for v in vulns]
                ctx_parts.append("VULNERABILIDADES ZAP:\n" + '\n'.join(lines))
        except Exception:
            if 'zap' in modules_map:
                lines = [f"  [{f.severity}] {f.title}" for f in modules_map['zap'][:20]]
                ctx_parts.append("VULNERABILIDADES ZAP:\n" + '\n'.join(lines))

        # Cabeceras HTTP
        try:
            with open(f'{reports_base}/headers/{target_file}.json') as _f:
                hdrs = _json.load(_f)
            sec = hdrs.get('security_headers', {})
            missing = [h for h, v in sec.items() if v.get('status') != 'Presente']
            present = [h for h, v in sec.items() if v.get('status') == 'Presente']
            lines = []
            if missing: lines.append(f"  Ausentes: {', '.join(missing)}")
            if present: lines.append(f"  Presentes: {', '.join(present)}")
            if lines:
                ctx_parts.append("CABECERAS HTTP:\n" + '\n'.join(lines))
        except Exception:
            pass

        # Nikto
        if 'nikto' in modules_map:
            lines = [f"  [{f.severity}] {f.title}" for f in modules_map['nikto'][:15]]
            if lines:
                ctx_parts.append("HALLAZGOS NIKTO:\n" + '\n'.join(lines))

        # SSL/TLS débil
        try:
            with open(f'{reports_base}/certs/{target_file}.json') as _f:
                certs = _json.load(_f)
            weak = [p for p, s in certs.get('protocols', {}).items()
                    if s == 'Soportado' and p in ('SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1')]
            if weak:
                ctx_parts.append(f"PROTOCOLOS SSL/TLS DÉBILES: {', '.join(weak)}")
        except Exception:
            pass

        scan_context = '\n\n'.join(ctx_parts)

        from vector_agent import run_vector_agent
        result = run_vector_agent(
            run_id=run_id,
            target_url=target.url,
            target_name=target.name,
            waf=target.waf_detected or 'No verificado',
            vector=vector,
            mode=run.mode,
            user_instructions=run.instructions or '',
            publish_fn=publish,
            scan_context=scan_context,
        )

        run.status = 'completed'
        run.estado = result.get('estado', 'inconcluso')
        run.resumen = result.get('resumen', '')
        run.evidencia_tecnica = result.get('evidencia_tecnica', '')
        run.impacto_negocio = result.get('impacto_negocio', '')
        run.comando_clave = result.get('comando_clave', '')
        run.recomendacion = result.get('recomendacion_mitigacion', '')
        run.iterations = result.get('iterations', 0)
        run.completed_at = datetime.now(timezone.utc)
        db.commit()

    except Exception as e:
        import traceback
        publish(f"[ERROR] Fallo inesperado del agente: {e}")
        traceback.print_exc()
        try:
            run = db.query(VectorRun).filter(VectorRun.id == run_id).first()
            if run:
                run.status = 'failed'
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


@celery_app.task(name="tasks.check_and_run_schedules")
def check_and_run_schedules():
    """Tarea periódica de Celery Beat: comprueba schedules y lanza los que toca."""
    import json
    from datetime import datetime, timedelta
    from database import SessionLocal
    from models import Schedule, Target
    from scan_modules import get_module_queue

    db = SessionLocal()
    now = datetime.now()
    current_minute = now.strftime("%Y-%m-%dT%H:%M")

    try:
        schedules = db.query(Schedule).all()
        for schedule in schedules:
            # Evitar doble disparo en el mismo minuto
            if schedule.last_run == current_minute:
                continue

            scheduled_dt = datetime.fromisoformat(schedule.scheduled_at)
            should_run = False

            if schedule.repeat == 'once':
                window_start = now.replace(second=0, microsecond=0)
                window_end = window_start + timedelta(minutes=1)
                should_run = window_start <= scheduled_dt < window_end
            elif schedule.repeat == 'daily':
                should_run = (scheduled_dt.hour == now.hour and
                              scheduled_dt.minute == now.minute)
            elif schedule.repeat == 'weekly':
                should_run = (scheduled_dt.weekday() == now.weekday() and
                              scheduled_dt.hour == now.hour and
                              scheduled_dt.minute == now.minute)
            elif schedule.repeat == 'monthly':
                should_run = (scheduled_dt.day == now.day and
                              scheduled_dt.hour == now.hour and
                              scheduled_dt.minute == now.minute)

            if not should_run:
                continue

            # Resolver IDs de targets
            if schedule.target_ids:
                target_ids = json.loads(schedule.target_ids)
            elif schedule.target_id:
                target_ids = [schedule.target_id]
            else:
                continue

            # Obtener URLs
            target_urls = []
            for tid in target_ids:
                target = db.query(Target).filter(Target.id == tid).first()
                if target:
                    target_urls.append(target.url)

            if target_urls:
                raw = schedule.module or '[]'
                try:
                    module_list = json.loads(raw) if raw.startswith('[') else [raw]
                except Exception:
                    module_list = [raw] if raw else []
                for mod in module_list:
                    queue = get_module_queue(db, mod)
                    run_sequential_scan.apply_async(args=[mod, target_urls], queue=queue)
                print(f"[Beat] Lanzados {len(module_list)} módulo(s) sobre {len(target_urls)} target(s)")

            # Limpiar o marcar según repetición
            if schedule.repeat == 'once':
                db.delete(schedule)
            else:
                schedule.last_run = current_minute
            db.commit()

    except Exception as e:
        print(f"[Beat] Error en check_and_run_schedules: {e}")
    finally:
        db.close()