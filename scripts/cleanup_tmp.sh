#!/bin/bash
# cleanup_tmp.sh — Limpieza de /tmp y reinicio seguro del worker heavy de Celery
#
# Monitorea el uso de /tmp. Si supera el umbral (90%), mata el daemon de ZAP
# (y sus GeckoDriver/Firefox huérfanos) y reinicia anubis-celery-heavy, que es
# el servicio systemd que lo hospeda. ZAP mantiene un daemon Java persistente
# entre escaneos (para no pagar el arranque de la JVM en cada scan); cuando ese
# daemon queda en un estado colgado, sigue abriendo y matando sesiones de
# Firefox por su cuenta y llena /tmp de perfiles huérfanos aunque no haya
# ningún escaneo real en curso. Matar solo firefox/geckodriver no alcanza:
# el daemon Java sigue vivo y vuelve a generar más en minutos.
#
# Flujo (Opción B):
#   1. Chequear uso de /tmp
#   2. Si > THRESHOLD: detectar tareas activas en la cola heavy (zap/nikto)
#   3. Si hay tareas activas en heavy: revocar solo esa cola y esperar drenaje
#   4. Matar el daemon de ZAP y los procesos Firefox/GeckoDriver huérfanos
#   5. Limpiar artefactos de /tmp
#   6. Reiniciar anubis-celery-heavy vía systemd
#
# Uso:
#   Cron (cada 5 min): */5 * * * * /home/anubis/AnubisProject/scripts/cleanup_tmp.sh
#   Manual:            bash /home/anubis/AnubisProject/scripts/cleanup_tmp.sh

# ── Configuración ──────────────────────────────────────────────────────────────
THRESHOLD=90                          # % de uso de /tmp que dispara la limpieza
DRAIN_WAIT=15                         # segundos a esperar tras revocar tareas activas
LOG_FILE="/home/anubis/AnubisProject/logs/cleanup_tmp.log"
CELERY_APP_DIR="/home/anubis/AnubisProject/backend"
VENV_PYTHON="${CELERY_APP_DIR}/venv/bin/python3"
VENV_CELERY="${CELERY_APP_DIR}/venv/bin/celery"
CELERY_SERVICE="anubis-celery-heavy"  # servicio systemd que hospeda el daemon de ZAP
ZAP_PATTERN="/usr/share/zaproxy/zap-.*\.jar"  # patrón del proceso java del daemon ZAP

# cron no exporta el bus de sesión del usuario; sin esto, todo "systemctl --user"
# ejecutado desde crontab falla silenciosamente (siempre reporta "inactive").
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${XDG_RUNTIME_DIR}/bus}"

# ── Helpers ────────────────────────────────────────────────────────────────────
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

tmp_usage() {
    df /tmp | awk 'NR==2 {gsub(/%/,"",$5); print $5}'
}

active_heavy_tasks() {
    # Cuenta solo las tareas activas del worker heavy@... (zap/nikto), sin tocar
    # el estado de las colas light/attack/beat.
    cd "$CELERY_APP_DIR" && \
    "$VENV_PYTHON" -c "
from celery_app import celery_app
active = celery_app.control.inspect(timeout=5).active() or {}
print(sum(len(tasks) for host, tasks in active.items() if host.startswith('heavy@')))
" 2>/dev/null || echo 0
}

# ── Main ───────────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")"

USAGE=$(tmp_usage)

if [ "$USAGE" -lt "$THRESHOLD" ]; then
    exit 0
fi

log "ALERTA: /tmp al ${USAGE}% (umbral: ${THRESHOLD}%) — iniciando limpieza"

# ── Paso 1: Abortar tareas activas de la cola heavy si las hay ────────────────
ACTIVE=$(active_heavy_tasks)
if [ "$ACTIVE" -gt 0 ]; then
    log "Hay ${ACTIVE} tarea(s) activa(s) en la cola heavy. Revocando pendientes de esa cola..."
    cd "$CELERY_APP_DIR" && \
        "$VENV_CELERY" -A celery_app purge -f -Q heavy 2>/dev/null && \
        log "Cola heavy vaciada. Esperando ${DRAIN_WAIT}s para drenaje de tareas en curso..."
    sleep "$DRAIN_WAIT"
else
    log "Cola heavy idle — sin tareas activas."
fi

# ── Paso 2: Matar el daemon de ZAP y Firefox/GeckoDriver huérfanos ────────────
ZAP_COUNT=$(pgrep -c -f "$ZAP_PATTERN" 2>/dev/null || echo 0)
FF_COUNT=$(pgrep -c -x firefox-esr 2>/dev/null || echo 0)
GD_COUNT=$(pgrep -c -x geckodriver 2>/dev/null || echo 0)

if [ "$ZAP_COUNT" -gt 0 ] || [ "$FF_COUNT" -gt 0 ] || [ "$GD_COUNT" -gt 0 ]; then
    log "Matando ${ZAP_COUNT} daemon(s) ZAP, ${FF_COUNT} firefox-esr y ${GD_COUNT} geckodriver..."
    # El daemon ZAP primero: es quien relanza firefox/geckodriver, matarlo evita
    # que reaparezcan procesos nuevos mientras se limpia.
    pkill -9 -f "$ZAP_PATTERN" 2>/dev/null
    pkill -9 -x geckodriver 2>/dev/null
    sleep 1
    pkill -9 -x firefox-esr 2>/dev/null
    sleep 1
    log "Daemon ZAP y procesos Firefox/GeckoDriver terminados."
else
    log "Sin daemon ZAP ni procesos Firefox/GeckoDriver activos."
fi

# ── Paso 3: Limpiar artefactos de /tmp ────────────────────────────────────────
log "Limpiando artefactos temporales de Firefox y Selenium..."

CLEANED=0
for pattern in \
    "/tmp/rust_mozprofile*" \
    "/tmp/userprofile*copy" \
    "/tmp/anonymous*webdriver-profile" \
    "/tmp/selenium-manager*" \
    "/tmp/pymp-*"
do
    # Contar antes de borrar
    COUNT=$(ls -d $pattern 2>/dev/null | wc -l)
    if [ "$COUNT" -gt 0 ]; then
        rm -rf $pattern 2>/dev/null
        log "  Eliminados ${COUNT} elemento(s): ${pattern}"
        CLEANED=$((CLEANED + COUNT))
    fi
done

log "Limpieza completada: ${CLEANED} elemento(s) eliminados."

# ── Paso 4: Reiniciar Celery ───────────────────────────────────────────────────
log "Reiniciando servicio Celery (${CELERY_SERVICE})..."
if systemctl --user is-active --quiet "$CELERY_SERVICE"; then
    systemctl --user restart "$CELERY_SERVICE"
    sleep 3
    if systemctl --user is-active --quiet "$CELERY_SERVICE"; then
        log "Celery reiniciado correctamente."
    else
        log "ERROR: Celery no pudo reiniciarse. Revisar: journalctl --user -u ${CELERY_SERVICE}"
    fi
else
    log "WARN: Servicio ${CELERY_SERVICE} no estaba activo — se omite reinicio."
fi

# ── Resumen final ─────────────────────────────────────────────────────────────
USAGE_AFTER=$(tmp_usage)
log "Uso de /tmp: ${USAGE}% → ${USAGE_AFTER}% | Intervención completada."
log "────────────────────────────────────────────────────"
