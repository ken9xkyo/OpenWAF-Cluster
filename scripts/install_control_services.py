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

# Runtime processes are managed only by Docker Compose.
subprocess.run([sys.executable, str(Path(__file__).with_name('install_control_compose.py'))], check=True)
print('Control credentials provisioned and Compose services installed on ' + node)
