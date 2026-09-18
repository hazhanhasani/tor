#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root"; exit 1; }

for unit in $(systemctl list-unit-files 'tor-location@*.service' --no-legend 2>/dev/null | awk '{print $1}'); do
  systemctl disable --now "$unit" 2>/dev/null || true
done
systemctl disable --now tor-location-gateway.service tor-location-panel.service tor-location-panel-redirect.service tor-location-panel-tls-sync.timer 2>/dev/null || true
rm -f /etc/systemd/system/tor-location@.service /etc/systemd/system/tor-location-gateway.service /etc/systemd/system/tor-location-panel.service /etc/systemd/system/tor-location-panel-redirect.service /etc/systemd/system/tor-location-panel-tls-sync.service /etc/systemd/system/tor-location-panel-tls-sync.timer /etc/sudoers.d/tor-location-manager
systemctl daemon-reload
echo "Services removed. Data remains in /var/lib/tor-location-manager and /etc/tor-location-manager."
echo "Remove those directories manually only if you no longer need the database or credentials."
