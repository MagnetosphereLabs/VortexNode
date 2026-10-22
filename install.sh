#!/usr/bin/env bash
# Vortex Node: install or manually update. No application auto-updater is installed.
set -Eeuo pipefail
umask 077
ACTION="${1:-install}"
[[ $# -eq 0 ]] || shift
REPOSITORY=""
APPLICATIONS=""
SOURCE_REF=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPOSITORY="${2:?Missing GitHub repository URL}"; shift 2;;
    --apps) APPLICATIONS="${2:?Choose chat or both}"; shift 2;;
    --ref) SOURCE_REF="${2:?Missing release tag, branch or commit}"; shift 2;;
    *) echo "Unknown argument: $1" >&2; exit 1;;
  esac
done
[[ -z "$APPLICATIONS" || "$APPLICATIONS" == chat || "$APPLICATIONS" == both ]] || { echo '--apps must be chat or both.' >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo 'Run this installer with sudo.' >&2; exit 1; }
[[ "$ACTION" == install || "$ACTION" == update ]] || { echo 'Usage: install.sh install --repo GITHUB_URL | install.sh update' >&2; exit 1; }
[[ -r /etc/os-release ]] || { echo 'Ubuntu is required.' >&2; exit 1; }
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" =~ ^(22\.04|24\.04|26\.04)$ ]] || { echo 'Supported systems: Ubuntu 22.04, 24.04 and 26.04 LTS with systemd.' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemd is required.' >&2; exit 1; }
exec 9>/run/vortex-node-install.lock
flock -n 9 || { echo 'Another Vortex Node installation is running.' >&2; exit 1; }
ROOT=/opt/vortex-node
CONFIG=/etc/vortex-node.json
DATA=/var/lib/vortex-node
SITE=/etc/nginx/conf.d/vortex-node.conf
WEBROOT=/var/lib/vortex-node-acme
WORK=$(mktemp -d /var/tmp/vortex-node.XXXXXXXX)
SUCCESS=0
CHANGED_SITE=0
HAD_SITE=0
OLD_RELEASE=""
STOPPED=0
PUBLISHED=0
if [[ -L "$ROOT/current" ]]; then OLD_RELEASE=$(readlink -f "$ROOT/current"); fi
finish() {
  local code=$?
  if [[ $SUCCESS != 1 ]]; then
    echo 'Installation did not complete. Existing encrypted data has been preserved.' >&2
    if [[ $CHANGED_SITE == 1 ]]; then
      if [[ $HAD_SITE == 1 ]]; then cp "$WORK/prior-nginx.conf" "$SITE"; else rm -f "$SITE"; fi
      nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
    fi
    if [[ $PUBLISHED == 0 && -n "$OLD_RELEASE" && -d "$OLD_RELEASE" ]]; then
      ln -sfn "$OLD_RELEASE" "$ROOT/current.restore"
      mv -Tf "$ROOT/current.restore" "$ROOT/current"
      systemctl start vortex-node.socket || true
      systemctl restart vortex-node.service || true
    fi
    if [[ $PUBLISHED == 1 ]]; then
      echo 'The new release remains selected to protect the current encrypted format. Review journalctl -u vortex-node before retrying the update.' >&2
    fi
  fi
  rm -rf -- "$WORK"
  exit "$code"
}
trap finish EXIT

echo 'Preparing Vortex Node…'
if [[ -f "$CONFIG" ]]; then
  mapfile -t SAVED < <(python3 - "$CONFIG" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
for k in ('repository','domain','email','listen','node_id','bridge'): print(c[k])
print('both' if c.get('vault_enabled',True) else 'chat')
print(c.get('source_ref','main'))
PY
  )
  REPOSITORY="${REPOSITORY:-${SAVED[0]}}"
  DOMAIN="${SAVED[1]}"; EMAIL="${SAVED[2]}"; LISTEN="${SAVED[3]}"; NODE_ID="${SAVED[4]}"; BRIDGE="${SAVED[5]}"
  APPLICATIONS="${APPLICATIONS:-${SAVED[6]}}"
  SOURCE_REF="${SOURCE_REF:-${SAVED[7]}}"
  ACTION=update
else
  for owned_path in "$SITE" /etc/systemd/system/vortex-node.service /etc/systemd/system/vortex-node.socket; do
    [[ ! -e "$owned_path" ]] || { echo "An existing configuration occupies $owned_path. It was left untouched." >&2; exit 1; }
  done
  [[ "$ACTION" != update ]] || { echo 'No Node installation found.' >&2; exit 1; }
  if [[ -z "$APPLICATIONS" ]]; then
    read -r -p 'Applications: Chat and Vault [1], Chat only [2] (default 1): ' APP_CHOICE </dev/tty
    case "$APP_CHOICE" in ''|1) APPLICATIONS=both;; 2) APPLICATIONS=chat;; *) echo 'Choose 1 or 2.' >&2; exit 1;; esac
  fi
  read -r -p 'Domain or subdomain pointing to this server: ' DOMAIN </dev/tty
  read -r -p 'Email for your HTTPS certificate account: ' EMAIL </dev/tty
  echo 'HTTPS certificates use the Let’s Encrypt subscriber agreement: https://letsencrypt.org/repository/'
  read -r -p 'Accept the certificate subscriber agreement? [y/N]: ' TERMS </dev/tty
  [[ "$TERMS" =~ ^[Yy]$ ]] || { echo 'Certificate terms were not accepted.' >&2; exit 1; }
  NODE_ID=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
  BRIDGE=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
fi
[[ "$REPOSITORY" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$ ]] || { echo 'Supply --repo with your public GitHub repository HTTPS URL.' >&2; exit 1; }
SOURCE_REF="${SOURCE_REF:-main}"
[[ "$SOURCE_REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ && "$SOURCE_REF" != *..* ]] || { echo 'Invalid source ref.' >&2; exit 1; }
DOMAIN=$(python3 - "$DOMAIN" <<'PY'
import re,sys
s=sys.argv[1].rstrip('.').encode('idna').decode().lower()
assert len(s)<=253 and '.' in s and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in s.split('.')),'Invalid domain'
print(s)
PY
)
[[ "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ && "$EMAIL" != -* ]] || { echo 'Enter a valid certificate email.' >&2; exit 1; }
if [[ ! -f "$CONFIG" ]] && command -v ss >/dev/null; then
  LISTENERS=$(ss -H -ltnp '( sport = :80 or sport = :443 )' || true)
  if [[ -n "$LISTENERS" ]] && printf '%s\n' "$LISTENERS" | grep -v nginx >/dev/null; then
    echo 'Another web server owns port 80 or 443. Keep that server running and configure an Nginx-compatible host before installing.' >&2; exit 1
  fi
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --no-install-recommends nginx certbot ca-certificates curl git build-essential pkg-config python3 openssl util-linux
getent ahosts "$DOMAIN" >/dev/null || { echo 'The domain does not resolve. Point its DNS to this VPS first.' >&2; exit 1; }
python3 - "$DATA" <<'PY'
import os,shutil,sys
p=sys.argv[1]
while not os.path.exists(p):p=os.path.dirname(p)
assert shutil.disk_usage(p).free>10_500_000_000,'At least 10.5 GB free is required, including the protected 10 GB buffer.'
PY
NGINX_DUMP=$(nginx -T 2>&1)
[[ "$NGINX_DUMP" == *'/etc/nginx/conf.d/'* ]] || { echo 'Nginx must include /etc/nginx/conf.d/*.conf. No existing configuration was edited.' >&2; exit 1; }
if [[ ! -f "$CONFIG" ]]; then
  # Inspect the effective configuration rather than overwriting an existing host.
  printf '%s' "$NGINX_DUMP" > "$WORK/nginx-effective.txt"
  python3 - "$DOMAIN" "$WORK/nginx-effective.txt" <<'PY'
import re,sys
host=sys.argv[1];text=open(sys.argv[2]).read()
for line in re.findall(r'\bserver_name\s+([^;]+);',text):
 assert host not in line.split(),f'{host} already belongs to an Nginx virtual host; use a separate subdomain.'
PY
fi
id vortex-node >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin vortex-node
id vortex-build >/dev/null 2>&1 || useradd --system --home-dir /var/cache/vortex-node-build --create-home --shell /usr/sbin/nologin vortex-build
install -d -m 700 -o vortex-node -g vortex-node "$DATA"
install -d -m 755 "$ROOT/releases" "$WEBROOT/.well-known/acme-challenge"
install -d -m 700 -o vortex-build -g vortex-build /var/cache/vortex-node-build

echo 'Downloading and compiling the Node as an unprivileged build user…'
git init --quiet "$WORK/source"
git -C "$WORK/source" -c protocol.file.allow=never fetch --depth 1 --quiet "$REPOSITORY" "$SOURCE_REF"
git -C "$WORK/source" checkout --quiet --detach FETCH_HEAD
COMMIT=$(git -C "$WORK/source" rev-parse HEAD)
SOURCE="$WORK/source"
[[ ! -f "$SOURCE/VortexNode/Cargo.toml" ]] || SOURCE="$SOURCE/VortexNode"
[[ -f "$SOURCE/Cargo.toml" && -f "$SOURCE/Cargo.lock" && -f "$SOURCE/src/main.rs" ]] || { echo 'The repository is missing the Node Rust sources or Cargo.lock.' >&2; exit 1; }
[[ -f "$SOURCE/clients.lock.json" ]] || { echo 'This Node revision has no verified Chat release. The existing installation was not changed.' >&2; exit 1; }
chmod 755 "$WORK"
chmod -R a+rX "$WORK/source"
if [[ ! -x /var/cache/vortex-node-build/cargo/bin/cargo ]]; then
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 https://sh.rustup.rs -o "$WORK/rustup.sh"
  chmod 644 "$WORK/rustup.sh"
  runuser -u vortex-build -- env CARGO_HOME=/var/cache/vortex-node-build/cargo RUSTUP_HOME=/var/cache/vortex-node-build/rustup sh "$WORK/rustup.sh" -y --no-modify-path --profile minimal --default-toolchain stable
fi
runuser -u vortex-build -- env PATH=/var/cache/vortex-node-build/cargo/bin:/usr/sbin:/usr/bin:/sbin:/bin CARGO_HOME=/var/cache/vortex-node-build/cargo RUSTUP_HOME=/var/cache/vortex-node-build/rustup CARGO_TARGET_DIR=/var/cache/vortex-node-build/target /var/cache/vortex-node-build/cargo/bin/cargo build --manifest-path "$SOURCE/Cargo.toml" --release --locked
RELEASE="$ROOT/releases/$COMMIT"
install -d -m 755 "$RELEASE"
install -m 755 /var/cache/vortex-node-build/target/release/vortex-node "$RELEASE/vortex-node.new"
mv -f "$RELEASE/vortex-node.new" "$RELEASE/vortex-node"
echo 'Installing the verified Vortex Chat web client…'
python3 "$SOURCE/scripts/install-chat-client.py" "$SOURCE/clients.lock.json" "$RELEASE/chat"
# Atomic replacement also makes running the installed updater safe.
install -m 755 "$SOURCE/install.sh" "$ROOT/install.sh.new"
mv -f "$ROOT/install.sh.new" "$ROOT/install.sh"
install -m 755 "$SOURCE/uninstall.sh" "$ROOT/uninstall.sh.new"
mv -f "$ROOT/uninstall.sh.new" "$ROOT/uninstall.sh"

# Backend and frontend always come from the same checked-out Node commit.
[[ -f "$SOURCE/Vortex Vault.html" ]] || { echo 'This Node release is missing its bundled Vortex Vault.html.' >&2; exit 1; }
cp "$SOURCE/Vortex Vault.html" "$WORK/vault.html"
grep -q 'id="vortexPagedStorage"' "$WORK/vault.html" || { echo 'The bundled Vault does not support this Node storage format.' >&2; exit 1; }
install -m 644 "$WORK/vault.html" "$RELEASE/vault.html"
if [[ "$ACTION" == update && -f "$DATA/node.sqlite" ]]; then
  # Do not kill an active seven-hour delivery during an application update.
  runuser -u vortex-node -- python3 - "$DATA/node.sqlite" <<'PY'
import sqlite3,sys,time
c=sqlite3.connect(sys.argv[1]);t=int(time.time())
active=c.execute("SELECT COUNT(*) FROM shares WHERE (state='uploading' AND created>?) OR (state='ready' AND expires>?) OR (state='receiving' AND deadline>?)",(t-86400,t,t)).fetchone()[0]
assert active==0,'A delivery is active. Finish or revoke it in Vault Settings before updating.'
if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='object_jobs'").fetchone():
 assert c.execute("SELECT COUNT(*) FROM object_jobs WHERE deadline>?",(t,)).fetchone()[0]==0,'An encrypted save is active. Let it finish before updating.'
PY
  systemctl stop vortex-node.socket vortex-node.service
  STOPPED=1
  runuser -u vortex-node -- python3 - "$DATA/node.sqlite" <<'PY_FINAL'
import sqlite3,sys,time
c=sqlite3.connect(sys.argv[1]);t=int(time.time())
assert c.execute("SELECT COUNT(*) FROM shares WHERE (state='uploading' AND created>?) OR (state='ready' AND expires>?) OR (state='receiving' AND deadline>?)",(t-86400,t,t)).fetchone()[0]==0,'A delivery started during the update. Retry after it finishes.'
if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='object_jobs'").fetchone():
 assert c.execute("SELECT COUNT(*) FROM object_jobs WHERE deadline>?",(t,)).fetchone()[0]==0,'An encrypted save started during the update. Let it finish and retry.'
PY_FINAL
  runuser -u vortex-node -- python3 - "$DATA/node.sqlite" "$DATA/update-backup.sqlite" <<'PY'
import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as source,sqlite3.connect(sys.argv[2]) as dest:source.backup(dest)
PY
else
  LISTEN=$(python3 - <<'PY'
import secrets,socket
for _ in range(100):
 port=49152+secrets.randbelow(16384)
 with socket.socket() as s:
  try:s.bind(('127.0.0.1',port))
  except OSError:continue
  print(f'127.0.0.1:{port}');break
else:raise SystemExit('No available private port')
PY
)
fi
python3 - "$CONFIG" "$REPOSITORY" "$DOMAIN" "$EMAIL" "$LISTEN" "$NODE_ID" "$BRIDGE" "$APPLICATIONS" "$SOURCE_REF" <<'PY'
import json,os,sys
path,repo,domain,email,listen,node,bridge,applications,source_ref=sys.argv[1:]
previous=json.load(open(path)) if os.path.exists(path) else {}
c={**previous,**dict(repository=repo,source_ref=source_ref,domain=domain,email=email,listen=listen,node_id=node,bridge=bridge,data_dir='/var/lib/vortex-node',vault_html='/opt/vortex-node/current/vault.html',reserve_bytes=previous.get('reserve_bytes',10_000_000_000),vault_enabled=applications=='both')}
c['public_url']='https://'+domain
c['chat_web_dir']='/opt/vortex-node/current/chat'
for key in ('media','media_ports'):
 if key in previous:c[key]=previous[key]
tmp=path+'.new'
with open(tmp,'w') as f:json.dump(c,f)
os.chmod(tmp,0o640);os.replace(tmp,path)
PY
chown root:vortex-node "$CONFIG"
cat > /etc/systemd/system/vortex-node.socket <<EOF
[Unit]
Description=Vortex Node private socket
[Socket]
ListenStream=$LISTEN
NoDelay=true
Backlog=128
[Install]
WantedBy=sockets.target
EOF
CPU_BUDGET=$(( $(nproc) * 70 ))
read -r MEMORY_HIGH MEMORY_MAX < <(python3 - <<'PY_MEMORY'
from pathlib import Path
ram=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:')))*1024
# Honour an enclosing cgroup instead of assuming all host RAM is available.
for path in ('/sys/fs/cgroup/memory.max','/sys/fs/cgroup/memory/memory.limit_in_bytes'):
 try:
  value=Path(path).read_text().strip()
  if value!='max':ram=min(ram,int(value))
 except (OSError,ValueError):pass
gib=1024**3
limit=min(ram*7//10,ram-2*gib) if ram>=4*gib else ram*7//10
print(limit*85//100,limit)
PY_MEMORY
)
. "$SOURCE/media/setup.sh"
prepare_media
python3 - "$CONFIG" "$WORK/media.json" <<'PY_MEDIA'
import json,sys,os
p=sys.argv[1];c=json.load(open(p));c.update(json.load(open(sys.argv[2])));tmp=p+".new"
with open(tmp,"w") as f:json.dump(c,f)
os.chmod(tmp,0o640);os.replace(tmp,p)
PY_MEDIA
chown root:vortex-node "$CONFIG"
cat > /etc/systemd/system/vortex-node.service <<EOF
[Unit]
Description=Vortex Node encrypted storage and relay
Requires=vortex-node.socket
After=network.target vortex-node.socket
[Service]
User=vortex-node
Group=vortex-node
Slice=vortex-node.slice
ExecStart=/opt/vortex-node/current/vortex-node serve --config /etc/vortex-node.json
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
ReadWritePaths=/var/lib/vortex-node
LimitNOFILE=4096
TasksMax=128
[Install]
WantedBy=multi-user.target
EOF
if [[ -f "$SITE" ]]; then cp "$SITE" "$WORK/prior-nginx.conf"; HAD_SITE=1; fi
CHANGED_SITE=1
IPV6_HTTP=""; IPV6_HTTPS=""
if [[ -s /proc/net/if_inet6 ]]; then IPV6_HTTP='listen [::]:80;'; IPV6_HTTPS='listen [::]:443 ssl;'; fi
write_http_site() {
cat > "$SITE" <<EOF
limit_conn_zone \$binary_remote_addr zone=vortex_peer:1m;
limit_conn_zone \$server_name zone=vortex_host:1m;
limit_req_zone \$binary_remote_addr zone=vortex_media_requests:1m rate=20r/s;
server {
    listen 80;
    $IPV6_HTTP
    server_name $DOMAIN;
    access_log off;
    location ^~ /.well-known/acme-challenge/ { root $WEBROOT; default_type text/plain; }
    location / { return 308 https://\$host\$request_uri; }
}
EOF
}
write_http_site
nginx -t
systemctl enable --now nginx
systemctl reload nginx
if [[ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
  certbot certonly --webroot -w "$WEBROOT" -d "$DOMAIN" --cert-name "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive
fi
cat >> "$SITE" <<EOF
server {
    listen 443 ssl;
    $IPV6_HTTPS
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;
    access_log off;
    error_log /var/log/nginx/vortex-node-error.log warn;
    limit_conn vortex_peer 128;
    limit_conn vortex_host 1024;
    client_max_body_size 17m;
    client_body_timeout 30s;
    send_timeout 60s;
    add_header Strict-Transport-Security "max-age=15552000" always;
    location ^~ /chat/relay/ {
        limit_req zone=vortex_media_requests burst=100 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:$MEDIA_HTTP/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 3600s;
        proxy_buffering off;
    }
    location / {
        proxy_pass http://$LISTEN;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_read_timeout 90s;
    }
}
EOF
nginx -t
media_certificates
install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/vortex-node <<'EOF'
#!/bin/sh
set -eu
/usr/sbin/nginx -t && /bin/systemctl reload nginx
expected_domain=$(python3 -c 'import json;print(json.load(open("/etc/vortex-node.json"))["domain"])')
if [ "${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/$expected_domain" ] && [ -d /var/lib/vortex-node/media-certs ]; then
 install -m 600 -o vortex-node -g vortex-node "$RENEWED_LINEAGE/fullchain.pem" /var/lib/vortex-node/media-certs/fullchain.pem
 install -m 600 -o vortex-node -g vortex-node "$RENEWED_LINEAGE/privkey.pem" /var/lib/vortex-node/media-certs/privkey.pem
 /bin/systemctl try-restart vortex-media.service
fi
EOF
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/vortex-node
systemctl enable --now certbot.timer
ln -sfn "$RELEASE" "$ROOT/current.new"
mv -Tf "$ROOT/current.new" "$ROOT/current"
if [[ ! -f "$DATA/node.sqlite" ]] || ! runuser -u vortex-node -- python3 - "$DATA/node.sqlite" <<'PYACCOUNT'
import sqlite3,sys
try:
 c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)
 sys.exit(0 if c.execute('SELECT COUNT(*) FROM accounts').fetchone()[0] else 1)
except sqlite3.Error:sys.exit(1)
PYACCOUNT
then
  runuser -u vortex-node -- "$ROOT/current/vortex-node" setup --data "$DATA" </dev/tty
fi
systemctl daemon-reload
systemctl enable --now vortex-node.socket
systemctl enable vortex-node.service vortex-media.service
PUBLISHED=1
systemctl restart vortex-node.service vortex-media.service
systemctl reload nginx
for attempt in $(seq 1 30); do
  if curl -fsS --max-time 2 "http://$LISTEN/health" >/dev/null; then break; fi
  [[ $attempt != 30 ]] || { echo 'Node health check failed. Review journalctl -u vortex-node.' >&2; exit 1; }
  sleep 1
done
for attempt in $(seq 1 20); do
  if curl -fsS --max-time 2 "http://127.0.0.1:$MEDIA_HTTP/" >/dev/null; then break; fi
  [[ $attempt != 20 ]] || { echo 'Chat media relay health check failed. Review journalctl -u vortex-media.' >&2; exit 1; }
  sleep 1
done
SUCCESS=1
echo
echo "Vortex Node is ready: https://$DOMAIN"
echo "Vortex:               https://$DOMAIN"
echo "Chat:                 https://$DOMAIN/chat/"
echo "Media firewall ports: UDP $MEDIA_UDP, $MEDIA_TURN_UDP; TCP $MEDIA_TCP, $MEDIA_TURN_TLS"
echo 'Manual update:       sudo /opt/vortex-node/install.sh update'
echo 'Uninstall:           sudo /opt/vortex-node/uninstall.sh'

