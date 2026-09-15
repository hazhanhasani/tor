#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: curl ... | sudo bash"; exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "This bootstrap supports Debian/Ubuntu with apt."; exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 ca-certificates
fi
command -v curl >/dev/null 2>&1 || { apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates; }

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
python3 - "$TMP/$ASSET" "$TMP/extract" <<'PY'
import pathlib, sys, tarfile
archive, dest=sys.argv[1:]
root=pathlib.Path(dest).resolve()
with tarfile.open(archive, 'r:gz') as tf:
    for member in tf.getmembers():
        target=(root/member.name).resolve()
        if target != root and root not in target.parents:
            raise SystemExit('unsafe archive path')
        if member.issym() or member.islnk():
            raise SystemExit('links are not allowed in installer archive')
    tf.extractall(root)
PY
SRC="$(find "$TMP/extract" -mindepth 1 -maxdepth 1 -type d | head -n1)"
[[ -n "$SRC" && -f "$SRC/install.sh" ]] || { echo "Invalid release package"; exit 1; }
exec bash "$SRC/install.sh"
