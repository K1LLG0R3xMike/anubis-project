from celery import Celery
from celery.signals import worker_ready
from kombu import Queue
import subprocess

# Configuración con Redis
celery_app = Celery(
    'tasks',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0',
    include=['tasks'],
)

# ── Colas de ejecución ────────────────────────────────────────────────────────
# heavy: ZAP y Nikto (lanzan Firefox/GeckoDriver, consumen /tmp y CPU)
# light: WAF, WhatWeb, Headers, Certs (rápidos, sin dependencias pesadas)
# beat:  tareas periódicas del scheduler (nunca deben bloquearse)
#
# Para ejecución estrictamente serial de escaneos pesados, arrancar un worker
# dedicado a la cola heavy con concurrencia 1:
#   celery -A celery_app worker --queues=heavy --concurrency=1 --hostname=heavy@%h
celery_app.conf.task_queues = (
    Queue('heavy'),
    Queue('light'),
    Queue('beat'),
)
celery_app.conf.task_default_queue = 'light'

celery_app.conf.beat_schedule = {
    'check-schedules-every-minute': {
        'task': 'tasks.check_and_run_schedules',
        'schedule': 60.0,
        'options': {'queue': 'beat'},
    },
}
celery_app.conf.timezone = 'Europe/Madrid'
# Reducido de 4 a 2: máximo 2 escaneos simultáneos en el worker general.
# Con el worker dedicado a heavy (--concurrency=1) los escaneos pesados son seriales.
celery_app.conf.worker_concurrency = 2

@worker_ready.connect
def reset_stuck_analyzing_reports(sender, **kwargs):
    """On worker startup reset any report stuck in 'analyzing' (leftover from a crash)."""
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from database import SessionLocal
        from models import Report
        db = SessionLocal()
        stuck = db.query(Report).filter(Report.status == "analyzing").all()
        for r in stuck:
            r.status = "ready"
        if stuck:
            db.commit()
            print(f"[celery_app] Reset {len(stuck)} report(s) stuck in 'analyzing' state.")
        db.close()
    except Exception as e:
        print(f"[celery_app] Could not reset stuck reports on startup: {e}")


@celery_app.task
def run_scan_task(module_type):
    # Aquí es donde Celery ejecuta tus scripts actuales
    script_path = f"/home/anubis/AnubisProject/scripts/{module_type}.py"
    try:
        process = subprocess.Popen(['python3', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return f"Escaneo {module_type} completado con éxito"
    except Exception as e:
        return f"Error en {module_type}: {str(e)}"