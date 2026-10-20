#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ $# -eq 0 || "${1:-}" == --delete-data ]] || { echo 'Usage: uninstall.sh [--delete-data]' >&2; exit 1; }
exec 9>/run/vortex-node-install.lock
flock -n 9 || { echo 'An installation or update is running.' >&2; exit 1; }
systemctl disable --now vortex-node.service vortex-node.socket vortex-media.service 2>/dev/null || true
rm -f /etc/systemd/system/vortex-node.service /etc/systemd/system/vortex-node.socket /etc/systemd/system/vortex-media.service /etc/systemd/system/vortex-node.slice
rm -f /etc/vortex-node-media.yaml
systemctl daemon-reload
rm -f /etc/nginx/conf.d/vortex-node.conf /etc/letsencrypt/renewal-hooks/deploy/vortex-node
if command -v nginx >/dev/null; then nginx -t && systemctl reload nginx; fi
rm -rf /opt/vortex-node
if [[ "${1:-}" == --delete-data ]]; then
  read -r -p 'Permanently delete all encrypted Node vaults? Type DELETE: ' confirm </dev/tty
  if [[ "$confirm" == DELETE ]]; then rm -rf /var/lib/vortex-node; rm -f /etc/vortex-node.json; else echo 'Encrypted data and configuration retained.'; fi
else
  echo 'Encrypted data retained in /var/lib/vortex-node; configuration retained in /etc/vortex-node.json for reinstallation.'
fi
echo 'Vortex Node removed. Existing Nginx sites, Nginx itself and other certificates were preserved.'
