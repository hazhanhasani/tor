#!/usr/bin/env bash
set -Eeuo pipefail

PANEL=""
TOKEN=""
NAME=""
ADVERTISE_HOST=""
INSECURE=0
ALLOW_HTTP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --panel) PANEL="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --name) NAME="${2:-}"; shift 2 ;;
    --advertise-host) ADVERTISE_HOST="${2:-}"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --allow-http) ALLOW_HTTP=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root or with sudo." >&2; exit 1; }
[[ -n "$PANEL" && -n "$TOKEN" && -n "$NAME" ]] || {
  echo "Usage: bootstrap --panel URL --token TOKEN --name NAME [--advertise-host HOST]" >&2
  exit 2
}
PANEL="${PANEL%/}"
case "$PANEL" in
  https://*) ;;
  http://*) [[ $ALLOW_HTTP -eq 1 ]] || { echo "HTTP controller requires --allow-http" >&2; exit 1; } ;;
  *) echo "Panel URL must begin with https:// or http://" >&2; exit 1 ;;
esac

command -v apt-get >/dev/null 2>&1 || { echo "Debian/Ubuntu with apt is required." >&2; exit 1; }

apt_args=(-o Acquire::Retries=5 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)
if [[ -n "${TLM_APT_PROXY:-}" ]]; then
  apt_args+=( -o "Acquire::http::Proxy=${TLM_APT_PROXY}" -o "Acquire::https::Proxy=${TLM_APT_PROXY}" )
fi

NEED_APT=0
for cmd in python3 curl wg wg-quick ping nft; do
  command -v "$cmd" >/dev/null 2>&1 || NEED_APT=1
done
if [[ $NEED_APT -eq 1 ]]; then
  echo "Installing WireGuard and node dependencies..."
  apt-get "${apt_args[@]}" update
  DEBIAN_FRONTEND=noninteractive apt-get "${apt_args[@]}" install -y \
    python3 curl ca-certificates wireguard-tools iproute2 iputils-ping nftables
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
AGENT="$TMP/tlm-node-agent.py"
curl_args=(--fail --location --silent --show-error --connect-timeout 10 --max-time 120 --retry 4 --retry-all-errors)
if [[ -n "${TLM_DOWNLOAD_PROXY:-}" ]]; then
  curl_args+=(--proxy "$TLM_DOWNLOAD_PROXY")
fi
if [[ $INSECURE -eq 1 ]]; then
  curl_args+=(-k)
fi

echo "Downloading node agent from controller..."
curl "${curl_args[@]}" "$PANEL/api/tunnels/agent.py" -o "$AGENT"
chmod 0700 "$AGENT"

args=(install --panel "$PANEL" --token "$TOKEN" --name "$NAME")
[[ -n "$ADVERTISE_HOST" ]] && args+=(--advertise-host "$ADVERTISE_HOST")
[[ $INSECURE -eq 1 ]] && args+=(--insecure)
[[ $ALLOW_HTTP -eq 1 ]] && args+=(--allow-http)

python3 "$AGENT" "${args[@]}"

echo
echo "Node installation completed."
echo "Status: systemctl status tor-location-node-agent --no-pager -l"
echo "Logs:   journalctl -u tor-location-node-agent -f"
