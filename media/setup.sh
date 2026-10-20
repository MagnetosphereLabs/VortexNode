#!/usr/bin/env bash
# Sourced by install.sh. The pinned media relay is shipped in this repository.
set -Eeuo pipefail
prepare_media() {
 local architecture
 case "$(uname -m)" in x86_64) architecture=amd64;; aarch64|arm64) architecture=arm64;; *) echo 'Chat calls require an amd64 or arm64 Ubuntu host.' >&2; return 1;; esac
 (cd "$SOURCE/media" && sha256sum --check --status SHA256SUMS)
 mkdir -p "$WORK/media-unpack"
 tar -xzf "$SOURCE/media/livekit_1.13.10_linux_$architecture.tar.gz" -C "$WORK/media-unpack" --no-same-owner
 install -m 755 "$WORK/media-unpack/livekit-server" "$RELEASE/vortex-media"
 python3 - "$CONFIG" "$WORK/media.json" "$DOMAIN" <<'PY'
import json,sys,secrets,socket
old={}
try:old=json.load(open(sys.argv[1]))
except FileNotFoundError:pass
media=old.get('media',{})
ports=old.get('media_ports',{})
chosen=set()
def available(key,preferred,udp=False):
 if key in ports:return ports[key]
 for port in [preferred]+[secrets.randbelow(16000)+40000 for _ in range(100)]:
  if port in chosen:continue
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
   try:s.bind(('0.0.0.0',port))
   except OSError:continue
   chosen.add(port);return port
 raise SystemExit('No available media ports')
ports=dict(http=available('http',secrets.randbelow(16000)+40000),udp=available('udp',7882,True),tcp=available('tcp',7881),turn_udp=available('turn_udp',3478,True),turn_tls=available('turn_tls',5349))
media=dict(url='wss://'+sys.argv[3]+'/chat/relay',http='http://127.0.0.1:'+str(ports['http']),key=media.get('key') or secrets.token_urlsafe(18),secret=media.get('secret') or secrets.token_urlsafe(48))
json.dump(dict(media=media,media_ports=ports),open(sys.argv[2],'w'))
PY
 read -r MEDIA_HTTP MEDIA_UDP MEDIA_TCP MEDIA_TURN_UDP MEDIA_TURN_TLS < <(python3 - "$WORK/media.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]))['media_ports'];print(*(p[k] for k in ('http','udp','tcp','turn_udp','turn_tls')))
PY
 )
 python3 - "$WORK/media.json" "$DOMAIN" /etc/vortex-node-media.yaml <<'PY'
import json,sys,socket,ipaddress
c=json.load(open(sys.argv[1]));p=c['media_ports'];m=c['media'];domain=sys.argv[2]
addresses=list(dict.fromkeys(r[4][0] for r in socket.getaddrinfo(domain,None,socket.AF_UNSPEC)))
global_addresses=[a for a in addresses if ipaddress.ip_address(a).is_global]
address=next((a for a in global_addresses if ipaddress.ip_address(a).version==4),next(iter(global_addresses),addresses[0]))
# Only the signalling listener binds to loopback. RTC/TURN must be publicly reachable.
text=f'''port: {p['http']}
bind_addresses: ["127.0.0.1"]
rtc:
  node_ip: "{address}"
  use_external_ip: false
  tcp_port: {p['tcp']}
  udp_port: {p['udp']}
  enable_loopback_candidate: false
  allow_tcp_fallback: true
turn:
  enabled: true
  domain: "{domain}"
  udp_port: {p['turn_udp']}
  tls_port: {p['turn_tls']}
  cert_file: /var/lib/vortex-node/media-certs/fullchain.pem
  key_file: /var/lib/vortex-node/media-certs/privkey.pem
keys:
  "{m['key']}": "{m['secret']}"
logging:
  level: warn
'''
# The HTTP listener is loopback-only; public traffic reaches it through Nginx.
open(sys.argv[3],'w').write(text)
PY
 chown root:vortex-node /etc/vortex-node-media.yaml
 chmod 640 /etc/vortex-node-media.yaml
 # One shared budget for the Node and media relay, rather than 70% each.
 cat > /etc/systemd/system/vortex-node.slice <<EOF
[Unit]
Description=Vortex shared resource budget
[Slice]
CPUQuota=$CPU_BUDGET%
MemoryHigh=$MEMORY_HIGH
MemoryMax=$MEMORY_MAX
MemorySwapMax=0
TasksMax=512
EOF
 cat > /etc/systemd/system/vortex-media.service <<'EOF'
[Unit]
Description=Vortex end-to-end encrypted media relay
After=network-online.target
Wants=network-online.target
[Service]
User=vortex-node
Group=vortex-node
Slice=vortex-node.slice
ExecStart=/opt/vortex-node/current/vortex-media --config /etc/vortex-node-media.yaml
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
RestrictSUIDSGID=true
CapabilityBoundingSet=
LimitNOFILE=16384
[Install]
WantedBy=multi-user.target
EOF
 # Never replace a firewall policy. Add only the ports owned by Vortex.
 if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
   ufw allow "$MEDIA_UDP/udp" comment 'Vortex media'
   ufw allow "$MEDIA_TCP/tcp" comment 'Vortex media'
   ufw allow "$MEDIA_TURN_UDP/udp" comment 'Vortex TURN'
   ufw allow "$MEDIA_TURN_TLS/tcp" comment 'Vortex TURN'
 fi
}
media_certificates() {
 install -d -m 700 -o vortex-node -g vortex-node "$DATA/media-certs"
 install -m 600 -o vortex-node -g vortex-node "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$DATA/media-certs/fullchain.pem"
 install -m 600 -o vortex-node -g vortex-node "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$DATA/media-certs/privkey.pem"
}
