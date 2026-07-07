#!/bin/bash
# cleanup_zap_sessions.sh — Purga sesiones viejas de ZAP
#
# Contexto: start_zap() (scripts/owasp.py y script_induvidual/owasp.py) arranca
# ZAP con -newsession en cada reinicio del daemon, para no reusar la sesión
# default ("untitled1") que llegó a pesar 14.6 GB al no reiniciarse nunca desde
# abril, hasta que el propio ZAP se autoapagó por uso de memoria. Cada reinicio
# ahora crea una sesión nueva (anubis_<timestamp>.session*) — este script borra
# las que ya quedaron viejas y no están en uso, para no acumularlas sin límite.
#
# Uso:
#   Cron (diario): 0 4 * * * /home/anubis/AnubisProject/scripts/cleanup_zap_sessions.sh
#   Manual:        bash /home/anubis/AnubisProject/scripts/cleanup_zap_sessions.sh

RETENTION_DAYS=3
SESSION_DIR="/home/anubis/.ZAP/session"
LOG_FILE="/home/anubis/AnubisProject/logs/cleanup_zap_sessions.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

mkdir -p "$(dirname "$LOG_FILE")"

if [ ! -d "$SESSION_DIR" ]; then
    exit 0
fi

# Solo tocamos sesiones que arrancamos nosotros (prefijo anubis_), nunca
# "untitled*" u otras creadas a mano desde la UI de ZAP.
CANDIDATES=$(find "$SESSION_DIR" -maxdepth 1 -name 'anubis_*.session' -mtime "+${RETENTION_DAYS}")

if [ -z "$CANDIDATES" ]; then
    exit 0
fi

DELETED=0
while IFS= read -r sessionfile; do
    base=$(basename "$sessionfile" .session)

    # No borrar la sesión que ZAP tiene abierta ahora mismo (tiene .lck activo).
    if [ -e "${SESSION_DIR}/${base}.session.lck" ]; then
        log "Omitida (en uso por ZAP): ${base}"
        continue
    fi

    rm -f "${SESSION_DIR}/${base}".session*
    rm -rf "${SESSION_DIR}/${base}.session.tmp"
    log "Eliminada sesión vieja: ${base} (mtime > ${RETENTION_DAYS}d)"
    DELETED=$((DELETED + 1))
done <<< "$CANDIDATES"

log "Limpieza de sesiones ZAP completada: ${DELETED} sesión(es) eliminada(s)."
