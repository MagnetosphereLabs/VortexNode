#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ $# -eq 0 || "${1:-}" == --delete-data ]] || { echo 'Usage: uninstall.sh [--delete-data]' >&2; exit 1; }
exec 9>/run/vortex-node-install.lock
flock -n 9 || { echo 'An installation or update is running.' >&2; exit 1; }
read -r -p 'Permanently uninstall and delete all Node accounts, Chat history, uploaded files, vaults and configuration? Type DELETE: ' confirm </dev/tty
[[ "$confirm" == DELETE ]] || { echo 'Uninstall cancelled; data and services retained.'; exit 1; }
systemctl disable --now vortex-node.service vortex-node.socket vortex-media.service 2>/dev/null || true
rm -f /etc/systemd/system/vortex-node.service /etc/systemd/system/vortex-node.socket /etc/systemd/system/vortex-media.service /etc/systemd/system/vortex-node.slice
rm -f /etc/vortex-node-media.yaml
systemctl daemon-reload
rm -f /etc/nginx/conf.d/vortex-node.conf /etc/letsencrypt/renewal-hooks/deploy/vortex-node
if command -v nginx >/dev/null; then nginx -t && systemctl reload nginx; fi
rm -rf /opt/vortex-node
rm -rf /var/lib/vortex-node
rm -f /etc/vortex-node.json
echo 'All Node accounts, Chat data, vaults and configuration deleted.'
echo 'Vortex Node removed. Existing Nginx sites, Nginx itself and other certificates were preserved.'
