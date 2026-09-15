#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh"; exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer currently supports Debian/Ubuntu (apt)."; exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR=/opt/tor-location-manager
ETC_DIR=/etc/tor-location-manager
DATA_DIR=/var/lib/tor-location-manager

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y tor python3 python3-venv python3-pip curl ca-certificates unzip openssl sudo rsync

if ! id torpanel >/dev/null 2>&1; then
  useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin torpanel
fi

if ! command -v xray >/dev/null 2>&1; then
  echo "Installing Xray-core from the official XTLS installer..."
  tmp="$(mktemp)"
  curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$tmp"
  bash "$tmp" install
  rm -f "$tmp"
fi

mkdir -p "$APP_DIR" "$ETC_DIR/instances" "$DATA_DIR/tor"
rsync -a --delete --exclude '.git' --exclude 'venv' --exclude '__pycache__' "$SRC_DIR/" "$APP_DIR/"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip wheel
"$APP_DIR/venv/bin/pip" install "$APP_DIR"

install -m 0644 "$APP_DIR/systemd/tor-location@.service" /etc/systemd/system/tor-location@.service
install -m 0644 "$APP_DIR/systemd/tor-location-gateway.service" /etc/systemd/system/tor-location-gateway.service
install -m 0644 "$APP_DIR/systemd/tor-location-panel.service" /etc/systemd/system/tor-location-panel.service

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

cat > "$ETC_DIR/panel.env" <<EOF
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
EOF
chmod 0640 "$ETC_DIR/panel.env"
chown root:torpanel "$ETC_DIR/panel.env"

cat > /etc/sudoers.d/tor-location-manager <<EOF
torpanel ALL=(root) NOPASSWD: ${APP_DIR}/venv/bin/python -m torpanel.helper apply
EOF
chmod 0440 /etc/sudoers.d/tor-location-manager
visudo -cf /etc/sudoers.d/tor-location-manager >/dev/null

touch "$DATA_DIR/panel.db"
chown -R torpanel:torpanel "$DATA_DIR"
mkdir -p "$DATA_DIR/tor"
chown -R debian-tor:debian-tor "$DATA_DIR/tor"
chown root:root "$ETC_DIR"
chmod 0755 "$ETC_DIR"
chown -R root:root "$ETC_DIR/instances"
chmod -R 0755 "$ETC_DIR/instances"

cat > /root/tor-location-manager-credentials.txt <<EOF
URL: http://SERVER_IP:${TORPANEL_PORT:-8787}
Username: ${ADMIN_USER}
Password: ${ADMIN_PASS}
EOF
chmod 0600 /root/tor-location-manager-credentials.txt

systemctl daemon-reload
systemctl enable --now tor-location-panel.service

echo
echo "Tor Location Manager installed."
echo "Panel: http://SERVER_IP:${TORPANEL_PORT:-8787}"
echo "Username: ${ADMIN_USER}"
echo "Password: ${ADMIN_PASS}"
echo "Credentials were also saved to /root/tor-location-manager-credentials.txt"
echo
echo "Open the panel, configure the 3x-ui URL + API Token + this server's public IP/domain,"
echo "then create a location and assign one or more 3x-ui inbounds."
