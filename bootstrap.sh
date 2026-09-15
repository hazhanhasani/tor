#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: curl ... | sudo bash"; exit 1
fi

REPO="hazhanhasani/tor"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
API="https://api.github.com/repos/$REPO/releases/latest"
JSON="$TMP/release.json"
curl -fsSL -H 'Accept: application/vnd.github+json' -H 'User-Agent: TorLocationManager-Bootstrap' "$API" -o "$JSON"
readarray -t META < <(python3 - "$JSON" <<'PY'
import json, sys
obj=json.load(open(sys.argv[1], encoding='utf-8'))
tag=obj.get('tag_name') or ''
asset=f'tor-location-manager-{tag}.tar.gz'
sum_asset=asset+'.sha256'
assets={a.get('name'):a.get('browser_download_url') for a in obj.get('assets',[])}
if not tag or asset not in assets or sum_asset not in assets:
    raise SystemExit('latest release is missing verified installer assets')
print(tag); print(asset); print(assets[asset]); print(assets[sum_asset])
PY
)
TAG="${META[0]}"; ASSET="${META[1]}"
echo "Installing Tor Location Manager $TAG"
curl -fL --retry 3 "${META[2]}" -o "$TMP/$ASSET"
curl -fL --retry 3 "${META[3]}" -o "$TMP/$ASSET.sha256"
(cd "$TMP" && sha256sum -c "$ASSET.sha256")
mkdir "$TMP/extract"
tar -xzf "$TMP/$ASSET" -C "$TMP/extract"
SRC="$(find "$TMP/extract" -mindepth 1 -maxdepth 1 -type d | head -n1)"
exec bash "$SRC/install.sh"
