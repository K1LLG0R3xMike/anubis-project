#!/bin/bash
# cleanup_tmp.sh — Limpieza de /tmp y reinicio seguro de Celery
#
# Monitorea el uso de /tmp. Si supera el umbral (90%), limpia los artefactos
# de Firefox/GeckoDriver huérfanos y reinicia Celery con abort previo de tareas.
#
# Flujo (Opción B):
#   1. Chequear uso de /tmp
#   2. Si > THRESHOLD: detectar tareas Celery activas
#   3. Si hay tareas activas: revocar tareas pendientes y esperar drenaje
#   4. Matar procesos Firefox y GeckoDriver huérfanos
#   5. Limpiar artefactos de /tmp
#   6. Reiniciar el worker Celery vía systemd
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
CELERY_SERVICE="anubis-celery"       # nombre del servicio systemd

# ── Helpers ────────────────────────────────────────────────────────────────────
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

tmp_usage() {
    df /tmp | awk 'NR==2 {gsub(/%/,"",$5); print $5}'
}

active_celery_tasks() {
    # Devuelve el número de tareas activas en el worker
    cd "$CELERY_APP_DIR" && \
    "$VENV_CELERY" -A celery_app inspect active --timeout 5 2>/dev/null \
        | grep -c '"name"' || echo 0
}

# ── Main ───────────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")"

USAGE=$(tmp_usage)

if [ "$USAGE" -lt "$THRESHOLD" ]; then
    exit 0
fi

log "ALERTA: /tmp al ${USAGE}% (umbral: ${THRESHOLD}%) — iniciando limpieza"

# ── Paso 1: Abortar tareas activas si las hay ──────────────────────────────────
ACTIVE=$(active_celery_tasks)
if [ "$ACTIVE" -gt 0 ]; then
    log "Hay ${ACTIVE} tarea(s) activa(s) en Celery. Revocando tareas pendientes..."
    cd "$CELERY_APP_DIR" && \
        "$VENV_CELERY" -A celery_app purge -f 2>/dev/null && \
        log "Cola vaciada. Esperando ${DRAIN_WAIT}s para drenaje de tareas en curso..."
    sleep "$DRAIN_WAIT"
else
    log "Celery idle — sin tareas activas."
fi

# ── Paso 2: Matar Firefox y GeckoDriver huérfanos ─────────────────────────────
FF_COUNT=$(pgrep -c firefox-esr 2>/dev/null || echo 0)
GD_COUNT=$(pgrep -c geckodriver 2>/dev/null || echo 0)

if [ "$FF_COUNT" -gt 0 ] || [ "$GD_COUNT" -gt 0 ]; then
    log "Matando ${FF_COUNT} proceso(s) firefox-esr y ${GD_COUNT} geckodriver..."
    pkill -9 -x geckodriver 2>/dev/null
    sleep 1
    pkill -9 -x firefox-esr 2>/dev/null
    sleep 1
    # Limpiar zombies: matar procesos defunct si quedaron
    ZOMBIES=$(ps aux | awk '$8=="Z" && /firefox/ {print $2}')
    if [ -n "$ZOMBIES" ]; then
        log "Limpiando zombies: $ZOMBIES"
        # los zombies desaparecen al morir su padre (geckodriver ya fue matado)
    fi
    log "Procesos de Firefox/GeckoDriver terminados."
else
    log "Sin procesos Firefox/GeckoDriver activos."
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
