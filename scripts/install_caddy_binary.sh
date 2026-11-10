#!/bin/sh
# Install a validated custom binary without starting traffic or choosing TLS/sites.
set -eu
ARTIFACT=${1:?usage: install_caddy_binary.sh /path/to/caddy}
"$ARTIFACT" list-modules | grep -qx 'http.handlers.waf'
getent group caddy >/dev/null || groupadd --system caddy
id caddy >/dev/null 2>&1 || useradd --system --gid caddy --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
install -m 0755 "$ARTIFACT" /usr/local/bin/caddy
install -d -m 0750 -o root -g caddy /etc/caddy
install -d -m 0750 -o caddy -g caddy /var/lib/caddy /var/log/caddy /var/log/coraza
cat > /etc/systemd/system/caddy.service <<'UNIT'
[Unit]
Description=Caddy with Coraza WAF
Documentation=https://caddyserver.com/docs/
Wants=network-online.target
After=network-online.target waf-poc-firewall.service
ConditionPathExists=/etc/caddy/Caddyfile

[Service]
Type=notify
User=caddy
Group=caddy
WorkingDirectory=/var/lib/caddy
Environment=XDG_DATA_HOME=/var/lib/caddy
Environment=XDG_CONFIG_HOME=/var/lib/caddy
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force
TimeoutStopSec=30s
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/caddy /var/log/caddy /var/log/coraza

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
/usr/local/bin/caddy version
sha256sum /usr/local/bin/caddy
printf '%s\n' 'Binary and service installed; service not started. TLS/backend configuration pending.'
