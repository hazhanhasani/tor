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

APT_PROXY="${TORPANEL_APT_PROXY:-}"
DOWNLOAD_PROXY="${TORPANEL_DOWNLOAD_PROXY:-}"
PIP_INDEX_URL_CUSTOM="${TORPANEL_PIP_INDEX_URL:-}"
GITHUB_API_BASE="${TORPANEL_GITHUB_API_BASE:-https://api.github.com}"
RELEASE_MIRROR_BASE="${TORPANEL_RELEASE_MIRROR_BASE:-}"

apt_args=(-o Acquire::Retries=5 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)
if [[ -n "$APT_PROXY" ]]; then
  apt_args+=( -o "Acquire::http::Proxy=$APT_PROXY" -o "Acquire::https::Proxy=$APT_PROXY" )
fi
apt_update() { apt-get "${apt_args[@]}" update; }
apt_install() { DEBIAN_FRONTEND=noninteractive apt-get "${apt_args[@]}" install -y "$@"; }

pip_args=(--disable-pip-version-check --retries 5 --timeout 30)
if [[ -n "$PIP_INDEX_URL_CUSTOM" ]]; then
  pip_args+=(--index-url "$PIP_INDEX_URL_CUSTOM")
fi
if [[ -n "$DOWNLOAD_PROXY" ]]; then
  pip_args+=(--proxy "$DOWNLOAD_PROXY")
fi

EXISTING=0
[[ -f "$ENV_FILE" ]] && EXISTING=1
if [[ $EXISTING -eq 1 ]]; then
  echo "Existing installation detected; persistent configuration will be preserved."
fi

echo "[1/8] Checking system dependencies..."
NEED_APT=0
for cmd in tor python3 curl unzip openssl sudo rsync flock; do
  command -v "$cmd" >/dev/null 2>&1 || NEED_APT=1
done
if [[ "$MODE" == "upgrade" && $NEED_APT -eq 0 ]]; then
  echo "Core system dependencies are already present; skipping APT network access during upgrade."
else
  apt_update
  apt_install tor python3 python3-venv python3-pip curl ca-certificates unzip openssl sudo rsync util-linux
fi
if ! command -v obfs4proxy >/dev/null 2>&1; then
  if [[ "$MODE" == "upgrade" ]]; then
    echo "Warning: obfs4proxy is not installed. Direct Tor mode remains available."
    echo "Install obfs4proxy later if you enable bridge mode."
  elif apt-cache show obfs4proxy >/dev/null 2>&1; then
    apt_install obfs4proxy
  else
    echo "Warning: obfs4proxy is not available from the configured APT repositories."
    echo "Direct Tor mode will work; bridge mode requires obfs4proxy to be installed later."
  fi
fi

if ! id torpanel >/dev/null 2>&1; then
  useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin torpanel
fi

if ! command -v xray >/dev/null 2>&1; then
  echo "[2/8] Installing Xray-core through resilient official download paths..."
  chmod +x "$SRC_DIR/scripts/install-xray"
  TORPANEL_GITHUB_API_BASE="$GITHUB_API_BASE" \
  TORPANEL_DOWNLOAD_PROXY="$DOWNLOAD_PROXY" \
  TORPANEL_XRAY_URL="${TORPANEL_XRAY_URL:-}" \
  TORPANEL_XRAY_SHA256="${TORPANEL_XRAY_SHA256:-}" \
    bash "$SRC_DIR/scripts/install-xray"
else
  echo "[2/8] Xray-core already installed: $(command -v xray)"
fi

mkdir -p "$APP_DIR" "$ETC_DIR/instances" "$DATA_DIR/tor" "$BACKUP_DIR"
if systemctl is-active --quiet tor-location-panel.service 2>/dev/null; then
  systemctl stop tor-location-panel.service
fi

echo "[3/8] Installing application v$VERSION..."
rsync -a --delete \
  --exclude '.git' --exclude 'venv' --exclude '.venv-old' \
  --exclude '__pycache__' --exclude '*.pyc' \
  "$SRC_DIR/" "$APP_DIR/"

VENV_DIR="$APP_DIR/venv"
OLD_VENV="$APP_DIR/.venv-old"
VENV_READY=0

if [[ "$MODE" == "upgrade" && -x "$VENV_DIR/bin/python" ]]; then
  echo "Reusing the existing Python environment for a network-independent upgrade..."
  if "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --no-deps --no-build-isolation "$APP_DIR" \
      && "$VENV_DIR/bin/python" -m pip check; then
    VENV_READY=1
  else
    echo "Existing Python environment needs dependency repair; trying the configured package source."
  fi
fi

if [[ $VENV_READY -eq 0 ]]; then
  rm -rf "$OLD_VENV"
  if [[ -d "$VENV_DIR" ]]; then
    mv "$VENV_DIR" "$OLD_VENV"
  fi
  restore_old_venv() {
    rm -rf "$VENV_DIR"
    if [[ -d "$OLD_VENV" ]]; then
      mv "$OLD_VENV" "$VENV_DIR"
    fi
  }
  if ! python3 -m venv "$VENV_DIR"; then
    restore_old_venv
    echo "Failed to create Python virtual environment."
    exit 1
  fi
  if ! "$VENV_DIR/bin/python" -m pip install "${pip_args[@]}" --upgrade pip wheel; then
    restore_old_venv
    echo "Failed to prepare Python virtual environment."
    echo "On restricted networks set TORPANEL_DOWNLOAD_PROXY or TORPANEL_PIP_INDEX_URL and retry."
    exit 1
  fi
  if [[ -d "$APP_DIR/vendor/wheels" ]] && find "$APP_DIR/vendor/wheels" -maxdepth 1 -type f -name '*.whl' | grep -q .; then
    echo "Using bundled Python wheel cache."
    if ! "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check --no-index --find-links "$APP_DIR/vendor/wheels" "$APP_DIR"; then
      echo "Bundled wheel cache was not compatible with this host; falling back to configured package index."
      "$VENV_DIR/bin/python" -m pip install "${pip_args[@]}" "$APP_DIR" || { restore_old_venv; exit 1; }
    fi
  else
    if ! "$VENV_DIR/bin/python" -m pip install "${pip_args[@]}" "$APP_DIR"; then
      restore_old_venv
      echo "Failed to install application dependencies."
      echo "On restricted networks set TORPANEL_DOWNLOAD_PROXY or TORPANEL_PIP_INDEX_URL and retry."
      exit 1
    fi
  fi
  rm -rf "$OLD_VENV"
fi

install -m 0755 "$APP_DIR/scripts/tor-location-manager-update" /usr/local/sbin/tor-location-manager-update
install -m 0644 "$APP_DIR/systemd/tor-location@.service" /etc/systemd/system/tor-location@.service
install -m 0644 "$APP_DIR/systemd/tor-location-gateway.service" /etc/systemd/system/tor-location-gateway.service
install -m 0644 "$APP_DIR/systemd/tor-location-panel.service" /etc/systemd/system/tor-location-panel.service

echo "[4/8] Configuring persistent settings..."
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
TORPANEL_GITHUB_API_BASE=${GITHUB_API_BASE}
TORPANEL_RELEASE_MIRROR_BASE=${RELEASE_MIRROR_BASE}
TORPANEL_DOWNLOAD_PROXY=${DOWNLOAD_PROXY}
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
  ensure_env TORPANEL_GITHUB_API_BASE "$GITHUB_API_BASE"
  ensure_env TORPANEL_RELEASE_MIRROR_BASE "$RELEASE_MIRROR_BASE"
  ensure_env TORPANEL_DOWNLOAD_PROXY "$DOWNLOAD_PROXY"
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

echo "[5/8] Applying ownership and service permissions..."
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

echo "[6/8] Running panel health check..."
PANEL_PORT="$(awk -F= '$1=="TORPANEL_PORT"{print $2}' "$ENV_FILE" | tail -1)"
PANEL_PORT="${PANEL_PORT:-8787}"
HEALTHY=0
for _ in $(seq 1 20); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${PANEL_PORT}/healthz" >/dev/null 2>&1; then HEALTHY=1; break; fi
  sleep 1
done
if [[ $HEALTHY -ne 1 ]]; then
  systemctl status tor-location-panel.service --no-pager -l || true
  journalctl -u tor-location-panel.service -n 80 --no-pager || true
  echo "Panel health check failed."
  exit 1
fi

echo "[7/8] Checking restricted-network helpers..."
if command -v obfs4proxy >/dev/null 2>&1; then
  echo "obfs4 bridge transport is available for restricted networks."
else
  echo "Warning: obfs4 bridge transport is not installed. Direct Tor mode is still available."
fi
if [[ -n "$DOWNLOAD_PROXY" ]]; then
  echo "Download proxy is configured for GitHub/Python downloads."
fi
if [[ -n "$RELEASE_MIRROR_BASE" ]]; then
  echo "Custom release mirror is configured: $RELEASE_MIRROR_BASE"
fi

echo "[8/8] Installation complete."
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
echo "For Iran/restricted networks: open اتصال 3x-ui and configure Tor bridge mode if direct Tor bootstrap is blocked."
echo "Updates support official GitHub API asset fallback plus an optional custom release mirror/proxy."
