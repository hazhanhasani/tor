#!/usr/bin/env bash
set -Eeuo pipefail

MODE="install"
NON_INTERACTIVE=0
for arg in "$@"; do
  case "$arg" in
    --upgrade) MODE="upgrade" ;;
    --non-interactive) NON_INTERACTIVE=1 ;;
    *) echo "Unknown option: $arg"; exit 2 ;;
  esac
done

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh"; exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer supports Debian/Ubuntu with apt."; exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required."; exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR=/opt/tor-location-manager
ETC_DIR=/etc/tor-location-manager
DATA_DIR=/var/lib/tor-location-manager
BACKUP_DIR=/var/backups/tor-location-manager
ENV_FILE="$ETC_DIR/panel.env"
VERSION="$(tr -d '[:space:]' < "$SRC_DIR/VERSION")"

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid VERSION file"; exit 1; }
[[ -f "$SRC_DIR/pyproject.toml" && -f "$SRC_DIR/torpanel/app.py" ]] || { echo "Incomplete source tree"; exit 1; }

. /etc/os-release
case "${ID:-}" in debian|ubuntu) ;; *) echo "Unsupported distribution: ${ID:-unknown}"; exit 1 ;; esac
ARCH="$(dpkg --print-architecture)"
case "$ARCH" in amd64|arm64) ;; *) echo "Unsupported architecture: $ARCH"; exit 1 ;; esac
FREE_KB="$(df -Pk /opt 2>/dev/null | awk 'NR==2{print $4}' || true)"
[[ -z "$FREE_KB" || "$FREE_KB" -ge 300000 ]] || { echo "At least 300 MB free disk space is required."; exit 1; }

on_error() {
  rc=$?
  echo "Installation failed at line $1 (exit $rc)."
  exit "$rc"
}
trap 'on_error $LINENO' ERR

EXISTING=0
[[ -f "$ENV_FILE" ]] && EXISTING=1
if [[ $EXISTING -eq 1 ]]; then
  echo "Existing installation detected; persistent configuration will be preserved."
fi

echo "[1/7] Installing system dependencies..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y tor python3 python3-venv python3-pip curl ca-certificates unzip openssl sudo rsync util-linux

if ! id torpanel >/dev/null 2>&1; then
  useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin torpanel
fi

if ! command -v xray >/dev/null 2>&1; then
  echo "[2/7] Installing Xray-core..."
  tmp="$(mktemp)"
  curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$tmp"
  bash "$tmp" install
  rm -f "$tmp"
else
  echo "[2/7] Xray-core already installed."
fi

mkdir -p "$APP_DIR" "$ETC_DIR/instances" "$DATA_DIR/tor" "$BACKUP_DIR"
if systemctl is-active --quiet tor-location-panel.service 2>/dev/null; then
  systemctl stop tor-location-panel.service
fi

echo "[3/7] Installing application v$VERSION..."
rsync -a --delete \
  --exclude '.git' --exclude 'venv' --exclude '.venv-new' --exclude '.venv-old' \
  --exclude '__pycache__' --exclude '*.pyc' \
  "$SRC_DIR/" "$APP_DIR/"

NEW_VENV="$APP_DIR/.venv-new"
OLD_VENV="$APP_DIR/.venv-old"
rm -rf "$NEW_VENV" "$OLD_VENV"
python3 -m venv "$NEW_VENV"
"$NEW_VENV/bin/pip" install --disable-pip-version-check --upgrade pip wheel
"$NEW_VENV/bin/pip" install --disable-pip-version-check "$APP_DIR"
if [[ -d "$APP_DIR/venv" ]]; then mv "$APP_DIR/venv" "$OLD_VENV"; fi
mv "$NEW_VENV" "$APP_DIR/venv"
rm -rf "$OLD_VENV"

install -m 0755 "$APP_DIR/scripts/tor-location-manager-update" /usr/local/sbin/tor-location-manager-update
install -m 0644 "$APP_DIR/systemd/tor-location@.service" /etc/systemd/system/tor-location@.service
install -m 0644 "$APP_DIR/systemd/tor-location-gateway.service" /etc/systemd/system/tor-location-gateway.service
install -m 0644 "$APP_DIR/systemd/tor-location-panel.service" /etc/systemd/system/tor-location-panel.service

echo "[4/7] Configuring persistent settings..."
if [[ $EXISTING -eq 0 ]]; then
  ADMIN_USER="${TORPANEL_ADMIN_USERNAME:-admin}"
  ADMIN_PASS="${TORPANEL_ADMIN_PASSWORD:-$(openssl rand -base64 18 | tr -d '\n=/+' | head -c 20)}"
  SECRET_KEY="$(openssl rand -hex 32)"
  FERNET_KEY="$("$APP_DIR/venv/bin/python" - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
)"
  ADMIN_HASH="$("$APP_DIR/venv/bin/python" - "$ADMIN_PASS" <<'PY'
import sys
from werkzeug.security import generate_password_hash
print(generate_password_hash(sys.argv[1]))
PY
)"
  cat > "$ENV_FILE" <<EOF
TORPANEL_BIND=${TORPANEL_BIND:-0.0.0.0}
TORPANEL_PORT=${TORPANEL_PORT:-8787}
TORPANEL_ADMIN_USERNAME=${ADMIN_USER}
TORPANEL_ADMIN_PASSWORD_HASH=${ADMIN_HASH}
TORPANEL_FLASK_SECRET_KEY=${SECRET_KEY}
TORPANEL_FERNET_KEY=${FERNET_KEY}
TORPANEL_DB_PATH=${DATA_DIR}/panel.db
TORPANEL_BASE_DIR=${DATA_DIR}
TORPANEL_INSTANCE_DIR=${ETC_DIR}/instances
TORPANEL_TOR_DATA_DIR=${DATA_DIR}/tor
TORPANEL_GATEWAY_CONFIG=${ETC_DIR}/xray-gateway.json
TORPANEL_XRAY_BIN=$(command -v xray)
TORPANEL_HELPER_CMD=sudo -n ${APP_DIR}/venv/bin/python -m torpanel.helper apply
TORPANEL_UPDATE_REPO=hazhanhasani/tor
TORPANEL_VERSION_FILE=${APP_DIR}/VERSION
TORPANEL_UPDATE_STATE_PATH=${DATA_DIR}/update-state.json
TORPANEL_UPDATER_CMD=sudo -n $(command -v systemd-run) --unit=tor-location-manager-update --collect --property=Type=exec /usr/local/sbin/tor-location-manager-update
EOF
  cat > /root/tor-location-manager-credentials.txt <<EOF
URL: http://SERVER_IP:${TORPANEL_PORT:-8787}
Username: ${ADMIN_USER}
Password: ${ADMIN_PASS}
EOF
  chmod 0600 /root/tor-location-manager-credentials.txt
else
  ensure_env() {
    local key="$1" value="$2"
    grep -q "^${key}=" "$ENV_FILE" || printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  }
  ensure_env TORPANEL_UPDATE_REPO hazhanhasani/tor
  ensure_env TORPANEL_VERSION_FILE "$APP_DIR/VERSION"
  ensure_env TORPANEL_UPDATE_STATE_PATH "$DATA_DIR/update-state.json"
  ensure_env TORPANEL_UPDATER_CMD "sudo -n $(command -v systemd-run) --unit=tor-location-manager-update --collect --property=Type=exec /usr/local/sbin/tor-location-manager-update"
fi
chmod 0640 "$ENV_FILE"
chown root:torpanel "$ENV_FILE"

SYSTEMD_RUN="$(command -v systemd-run)"
cat > /etc/sudoers.d/tor-location-manager <<EOF
torpanel ALL=(root) NOPASSWD: ${APP_DIR}/venv/bin/python -m torpanel.helper apply
torpanel ALL=(root) NOPASSWD: ${SYSTEMD_RUN} --unit=tor-location-manager-update --collect --property=Type=exec /usr/local/sbin/tor-location-manager-update *
EOF
chmod 0440 /etc/sudoers.d/tor-location-manager
visudo -cf /etc/sudoers.d/tor-location-manager >/dev/null

echo "[5/7] Applying ownership and service permissions..."
touch "$DATA_DIR/panel.db"
chown -R torpanel:torpanel "$DATA_DIR"
mkdir -p "$DATA_DIR/tor"
chown -R debian-tor:debian-tor "$DATA_DIR/tor"
chown root:root "$ETC_DIR"
chmod 0755 "$ETC_DIR"
chown -R root:root "$ETC_DIR/instances"
chmod -R 0755 "$ETC_DIR/instances"

systemctl daemon-reload
systemctl enable tor-location-panel.service >/dev/null
systemctl restart tor-location-panel.service

echo "[6/7] Running health check..."
PANEL_PORT="$(awk -F= '$1=="TORPANEL_PORT"{print $2}' "$ENV_FILE" | tail -1)"
PANEL_PORT="${PANEL_PORT:-8787}"
HEALTHY=0
for _ in $(seq 1 15); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${PANEL_PORT}/healthz" >/dev/null 2>&1; then HEALTHY=1; break; fi
  sleep 1
done
if [[ $HEALTHY -ne 1 ]]; then
  systemctl status tor-location-panel.service --no-pager || true
  echo "Panel health check failed."
  exit 1
fi

echo "[7/7] Installation complete."
echo
echo "Tor Location Manager v$VERSION is ready."
echo "Panel: http://SERVER_IP:${PANEL_PORT}"
if [[ $EXISTING -eq 0 ]]; then
  echo "Username: ${ADMIN_USER}"
  echo "Password: ${ADMIN_PASS}"
  echo "Credentials: /root/tor-location-manager-credentials.txt"
else
  echo "Existing credentials, database and 3x-ui settings were preserved."
fi
echo "Updates: open the panel and use the بروزرسانی section after publishing a GitHub Release."
