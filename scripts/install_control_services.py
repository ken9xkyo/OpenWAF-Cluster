#!/usr/bin/env python3
import grp
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys

node = socket.gethostname()
ips = {'waf-cluster-1': '192.168.11.100', 'waf-cluster-2': '192.168.11.202'}
assert node in ips
source = Path(sys.argv[1])
if subprocess.run(['getent', 'passwd', 'waf-control'], stdout=subprocess.DEVNULL).returncode:
    subprocess.run(['useradd', '--system', '--user-group', '--home-dir', '/var/lib/waf-control', '--shell', '/usr/sbin/nologin', 'waf-control'], check=True)


def directory(path, user, group, mode=0o750):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
    path.chmod(mode)


def copy(name, target, user='root', group='root', mode=0o600):
    target = Path(target)
    shutil.copyfile(source / name, target)
    os.chown(target, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
    target.chmod(mode)


directory('/etc/waf-control', 'root', 'waf-control')
directory('/etc/waf-control/pki', 'root', 'waf-control')
directory('/var/lib/waf-control', 'waf-control', 'waf-control')
directory('/var/lib/waf-agent', 'caddy', 'caddy')
directory('/etc/waf-agent', 'root', 'caddy')
directory('/etc/waf-agent/pki', 'root', 'caddy')
for name in ['ca.crt', 'server.crt', 'server.key']:
    copy(name, '/etc/waf-control/pki/' + name, 'waf-control', 'waf-control', 0o400 if name.endswith('.key') else 0o644)
copy('signing.key', '/etc/waf-control/release-signing.key', 'waf-control', 'waf-control', 0o400)
copy('control.env', '/etc/waf-control/control.env')
copy('agent.json', '/etc/waf-agent/agent.json', 'root', 'caddy', 0o640)
copy('signing.pub', '/etc/waf-agent/signing.pub', 'root', 'caddy', 0o644)
for name in ['ca.crt', 'agent.crt', 'agent.key']:
    copy(name, '/etc/waf-agent/pki/' + name, 'root', 'caddy', 0o640)

base = '''[Unit]
After=network-online.target waf-control-firewall.service
Wants=network-online.target waf-control-firewall.service
[Service]
User=waf-control
Group=waf-control
WorkingDirectory=/opt/waf-control/app
EnvironmentFile=/etc/waf-control/control.env
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/waf-control
MemoryMax=768M
UMask=0077
'''
commands = {
    'waf-control': '/opt/waf-control/venv/bin/uvicorn control.app:app --host 127.0.0.1 --port 9000 --no-proxy-headers --no-access-log',
    'waf-agent-api': '/opt/waf-control/venv/bin/uvicorn control.app:agent_app --host '+ips[node]+' --port 9443 --no-proxy-headers --no-access-log --ssl-certfile /etc/waf-control/pki/server.crt --ssl-keyfile /etc/waf-control/pki/server.key --ssl-ca-certs /etc/waf-control/pki/ca.crt --ssl-cert-reqs 2'
}
for name, command in commands.items():
    Path('/etc/systemd/system/'+name+'.service').write_text(base+'ExecStart='+command+'\n[Install]\nWantedBy=multi-user.target\n')
Path('/etc/systemd/system/waf-agent.service').write_text('''[Unit]
Description=Signed configuration pull agent for Caddy
After=network-online.target caddy.service waf-agent-api.service
Wants=network-online.target caddy.service
[Service]
User=caddy
Group=caddy
WorkingDirectory=/opt/waf-control/app
Environment=AGENT_CONFIG=/etc/waf-agent/agent.json
Environment=XDG_DATA_HOME=/var/lib/caddy
Environment=XDG_CONFIG_HOME=/var/lib/caddy
ExecStart=/opt/waf-control/venv/bin/python -m control.agent
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/waf-agent /var/lib/caddy /var/log/caddy /var/log/coraza
MemoryMax=768M
UMask=0077
[Install]
WantedBy=multi-user.target
''')
subprocess.run(['systemctl', 'daemon-reload'], check=True)
subprocess.run(['systemctl', 'enable', '--now', 'waf-control', 'waf-agent-api', 'waf-agent'], check=True)
print('Control UI/API and mTLS agent services installed on ' + node)
