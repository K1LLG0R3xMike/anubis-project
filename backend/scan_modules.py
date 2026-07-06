# -*- coding: utf-8 -*-
"""
Descubrimiento automático de módulos de escaneo a partir de los scripts
presentes en scripts/ (escaneo de todos los targets) y script_induvidual/
(escaneo de 1 target — también usado por run_sequential_scan/schedules).

Añadir un .py a cualquiera de las dos carpetas lo vuelve detectable en el
Scan Engine y en los endpoints /run-* sin tocar código. Antes había cinco
listas hardcodeadas independientes (SCRIPT_MAP, _HEAVY_MODULES, dos
valid_modules, _MODULE_TOOL_LABELS) que había que editar a mano una por una.
"""
import os
from sqlalchemy.orm import Session
import models

SCRIPTS_FULL_DIR = "/home/anubis/AnubisProject/scripts"
SCRIPTS_INDIVIDUAL_DIR = "/home/anubis/AnubisProject/script_induvidual"

# Helpers compartidos que importan los scripts de escaneo — no son módulos en sí.
_EXCLUDED_FILES = {"db_findings.py", "__init__.py"}

# El id de módulo no siempre coincide con el nombre del archivo (zap corre
# owasp.py) — se preserva a mano para no romper findings.module/reports ya
# existentes en la base de datos.
_FILENAME_TO_MODULE_ID = {"owasp.py": "zap"}

# Módulos que abren Firefox/GeckoDriver — heavy por defecto mientras no haya
# override en scan_module_configs.
DEFAULT_HEAVY_MODULES = {"zap", "nikto"}

_MODULE_LABELS = {
    "waf": "WAF Detector",
    "whatweb": "Stack Tecnológico",
    "headers": "HTTP Headers",
    "certs": "SSL Scan",
    "nikto": "Nikto Vulns",
    "zap": "OWASP ZAP",
}


def _scan_dir(path):
    """dict: module_id -> filename, para los .py válidos en `path`."""
    found = {}
    if not os.path.isdir(path):
        return found
    for fname in sorted(os.listdir(path)):
        if not fname.endswith(".py") or fname in _EXCLUDED_FILES:
            continue
        module_id = _FILENAME_TO_MODULE_ID.get(fname, fname[:-3].lower())
        found[module_id] = fname
    return found


def discover_modules():
    """dict: module_id -> {"script_full": filename|None, "script_individual": filename|None}"""
    full = _scan_dir(SCRIPTS_FULL_DIR)
    individual = _scan_dir(SCRIPTS_INDIVIDUAL_DIR)
    return {
        mid: {
            "script_full": full.get(mid),
            "script_individual": individual.get(mid),
        }
        for mid in (set(full) | set(individual))
    }


def module_label(module_id: str) -> str:
    return _MODULE_LABELS.get(module_id, module_id.replace("_", " ").title())


def get_module_queue(db: Session, module_id: str) -> str:
    cfg = db.query(models.ScanModuleConfig).filter_by(module_id=module_id).first()
    if cfg:
        return cfg.queue
    return "heavy" if module_id in DEFAULT_HEAVY_MODULES else "light"


def set_module_queue(db: Session, module_id: str, queue: str):
    if queue not in ("light", "heavy"):
        raise ValueError("queue debe ser 'light' o 'heavy'")
    cfg = db.query(models.ScanModuleConfig).filter_by(module_id=module_id).first()
    if cfg:
        cfg.queue = queue
    else:
        cfg = models.ScanModuleConfig(module_id=module_id, queue=queue)
        db.add(cfg)
    db.commit()
    return cfg
