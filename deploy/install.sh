#!/usr/bin/env bash
# Instala AnubisProject como servicios systemd --user en la máquina actual.
# Uso: ./deploy/install.sh
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="$HOME/.config/systemd/user"
TEMPLATE_DIR="$APP_DIR/deploy/systemd"
SERVICES=(anubis-backend anubis-frontend anubis-celery anubis-celery-heavy anubis-celery-attack anubis-celery-beat)

echo "==> Instalando AnubisProject en: $APP_DIR"

# ── Redis ──────────────────────────────────────────────────────────────────
if ! command -v redis-server >/dev/null 2>&1; then
    echo "!! redis-server no encontrado. Instalalo (ej: sudo apt install redis-server) antes de continuar."
    exit 1
fi
if ! redis-cli ping >/dev/null 2>&1; then
    echo "!! Redis no responde en localhost:6379. Arrancalo (sudo systemctl start redis) antes de continuar."
    exit 1
fi
echo "==> Redis OK"

# ── Backend: venv + dependencias ─────────────────────────────────────────────
if [ ! -d "$APP_DIR/backend/venv" ]; then
    echo "==> Creando virtualenv del backend"
    python3 -m venv "$APP_DIR/backend/venv"
fi
echo "==> Instalando dependencias del backend"
"$APP_DIR/backend/venv/bin/pip" install --upgrade pip -q
"$APP_DIR/backend/venv/bin/pip" install -r "$APP_DIR/backend/requirements.txt" -q

# ── Backend: .env ────────────────────────────────────────────────────────────
if [ ! -f "$APP_DIR/backend/.env" ]; then
    cp "$APP_DIR/backend/.env.example" "$APP_DIR/backend/.env"
    echo "!! Se creó backend/.env desde .env.example — completá las credenciales antes de arrancar los servicios."
fi

# ── Frontend: dependencias ───────────────────────────────────────────────────
NPM_BIN="$(command -v npm || true)"
if [ -z "$NPM_BIN" ]; then
    echo "!! npm no encontrado en PATH. Instalá Node.js antes de continuar."
    exit 1
fi
if [ ! -d "$APP_DIR/frontend/node_modules" ]; then
    echo "==> Instalando dependencias del frontend"
    (cd "$APP_DIR/frontend" && npm install)
fi

# ── Generar unit files a partir de los templates ─────────────────────────────
mkdir -p "$UNIT_DIR"
for svc in "${SERVICES[@]}"; do
    sed -e "s#__APP_DIR__#$APP_DIR#g" -e "s#__NPM_BIN__#$NPM_BIN#g" \
        "$TEMPLATE_DIR/$svc.service.template" > "$UNIT_DIR/$svc.service"
    echo "==> Generado $UNIT_DIR/$svc.service"
done

systemctl --user daemon-reload

echo "==> Habilitando y arrancando servicios"
systemctl --user enable --now "${SERVICES[@]}"

cat <<EOF

Listo. Estado de los servicios:
  systemctl --user status anubis-backend anubis-frontend anubis-celery anubis-celery-heavy anubis-celery-attack anubis-celery-beat

Para que los servicios sigan corriendo tras cerrar sesión (sin login gráfico activo):
  loginctl enable-linger $USER
EOF
