#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root: curl ... | sudo bash"; exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "This bootstrap supports Debian/Ubuntu with apt."; exit 1
fi

APT_PROXY="${TORPANEL_APT_PROXY:-}"
DOWNLOAD_PROXY="${TORPANEL_DOWNLOAD_PROXY:-}"
API_BASE="${TORPANEL_GITHUB_API_BASE:-https://api.github.com}"
MIRROR_BASE="${TORPANEL_RELEASE_MIRROR_BASE:-}"
apt_args=(-o Acquire::Retries=5 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)
if [[ -n "$APT_PROXY" ]]; then
  apt_args+=( -o "Acquire::http::Proxy=$APT_PROXY" -o "Acquire::https::Proxy=$APT_PROXY" )
fi
apt_update() { apt-get "${apt_args[@]}" update; }
apt_install() { DEBIAN_FRONTEND=noninteractive apt-get "${apt_args[@]}" install -y "$@"; }

if ! command -v python3 >/dev/null 2>&1; then
  apt_update
  apt_install python3 ca-certificates
fi
if ! command -v curl >/dev/null 2>&1; then
  apt_update
  apt_install curl ca-certificates
fi

REPO="hazhanhasani/tor"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
API="${API_BASE%/}/repos/$REPO/releases/latest"
JSON="$TMP/release.json"

curl_common=(--silent --show-error --location --connect-timeout 10 --max-time 180 --retry 4 --retry-delay 2 --retry-all-errors)
if [[ -n "$DOWNLOAD_PROXY" ]]; then
  curl_common+=(--proxy "$DOWNLOAD_PROXY")
fi

http_fetch() {
  local url="$1" out="$2"
  curl "${curl_common[@]}" --fail "$url" -o "$out"
}

api_asset_fetch() {
  local url="$1" out="$2"
  curl "${curl_common[@]}" --fail \
    -H 'Accept: application/octet-stream' \
    -H 'User-Agent: TorLocationManager-Bootstrap' \
    "$url" -o "$out"
}

HTTP_CODE="$(curl "${curl_common[@]}" -o "$JSON" -w '%{http_code}' \
  -H 'Accept: application/vnd.github+json' \
  -H 'User-Agent: TorLocationManager-Bootstrap' \
  "$API" || true)"

safe_extract() {
  local archive="$1" dest="$2"
  mkdir -p "$dest"
  python3 - "$archive" "$dest" <<'PY'
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
}

verify_sha() {
  local file="$1" expected="$2"
  local actual
  actual="$(sha256sum "$file" | awk '{print $1}')"
  [[ -n "$expected" && "$actual" == "$expected" ]]
}

if [[ "$HTTP_CODE" == "200" ]]; then
  readarray -t META < <(python3 - "$JSON" <<'PY'
import json, sys
obj=json.load(open(sys.argv[1], encoding='utf-8'))
tag=obj.get('tag_name') or ''
asset=f'tor-location-manager-{tag}.tar.gz'
sum_asset=asset+'.sha256'
assets={a.get('name'):a for a in obj.get('assets',[]) if isinstance(a, dict)}
pkg=assets.get(asset)
chk=assets.get(sum_asset)
if not tag or not pkg:
    raise SystemExit('latest release is missing installer package')
print(tag)
print(asset)
print(pkg.get('browser_download_url') or '')
print(pkg.get('url') or '')
print(pkg.get('digest') or '')
print((chk or {}).get('browser_download_url') or '')
print((chk or {}).get('url') or '')
PY
  )
  TAG="${META[0]}"; ASSET="${META[1]}"
  PACKAGE="$TMP/$ASSET"
  CHECKSUM="$TMP/$ASSET.sha256"
  echo "Installing verified Tor Location Manager $TAG"

  downloaded=0
  if [[ -n "$MIRROR_BASE" ]] && http_fetch "${MIRROR_BASE%/}/$TAG/$ASSET" "$PACKAGE"; then
    echo "Downloaded release package from configured mirror."
    downloaded=1
  elif [[ -n "${META[2]}" ]] && http_fetch "${META[2]}" "$PACKAGE"; then
    downloaded=1
  elif [[ -n "${META[3]}" ]] && api_asset_fetch "${META[3]}" "$PACKAGE"; then
    echo "Direct release download was unavailable; GitHub API asset fallback succeeded."
    downloaded=1
  fi
  [[ $downloaded -eq 1 ]] || { echo "Could not download release package." >&2; exit 1; }

  expected=""
  checksum_ok=0
  if [[ -n "$MIRROR_BASE" ]] && http_fetch "${MIRROR_BASE%/}/$TAG/$ASSET.sha256" "$CHECKSUM"; then
    expected="$(awk '{print $1}' "$CHECKSUM" | head -n1)"
  elif [[ -n "${META[5]}" ]] && http_fetch "${META[5]}" "$CHECKSUM"; then
    expected="$(awk '{print $1}' "$CHECKSUM" | head -n1)"
  elif [[ -n "${META[6]}" ]] && api_asset_fetch "${META[6]}" "$CHECKSUM"; then
    expected="$(awk '{print $1}' "$CHECKSUM" | head -n1)"
  elif [[ "${META[4]}" == sha256:* ]]; then
    expected="${META[4]#sha256:}"
    echo "Checksum asset could not be fetched; verifying against GitHub's signed release metadata digest."
  fi
  if verify_sha "$PACKAGE" "$expected"; then
    checksum_ok=1
  fi
  [[ $checksum_ok -eq 1 ]] || { echo "Release SHA-256 verification failed or no trusted digest was available." >&2; exit 1; }
  safe_extract "$PACKAGE" "$TMP/extract"
elif [[ "$HTTP_CODE" == "404" ]]; then
  echo "No official GitHub Release exists yet."
  echo "Installing the current main snapshot for the initial deployment..."
  echo "Future upgrades will use verified Release assets with SHA-256."
  SNAPSHOT="$TMP/main.tar.gz"
  if ! http_fetch "https://codeload.github.com/$REPO/tar.gz/refs/heads/main" "$SNAPSHOT"; then
    echo "Snapshot download failed. On restricted networks configure TORPANEL_DOWNLOAD_PROXY or publish a Release." >&2
    exit 1
  fi
  safe_extract "$SNAPSHOT" "$TMP/extract"
else
  echo "GitHub API request failed with HTTP $HTTP_CODE"
  echo "Restricted-network options: TORPANEL_DOWNLOAD_PROXY, TORPANEL_GITHUB_API_BASE, TORPANEL_RELEASE_MIRROR_BASE."
  [[ -s "$JSON" ]] && cat "$JSON"
  exit 1
fi

SRC="$(find "$TMP/extract" -mindepth 1 -maxdepth 1 -type d | head -n1)"
[[ -n "$SRC" && -f "$SRC/install.sh" ]] || { echo "Invalid installer package"; exit 1; }
exec bash "$SRC/install.sh"
