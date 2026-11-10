#!/usr/bin/env python3
"""Sync Caddy-managed public certificates to both POC TLS directories."""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess


def read_pem(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        assert stat.S_ISREG(os.fstat(f.fileno()).st_mode)
        content = f.read(100001)
        assert len(content) <= 100000
        return content.decode('ascii')


with open('/run/waf-cert-sync.lock', 'w') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    base = Path('/var/lib/caddy/caddy/certificates/acme-v02.api.letsencrypt.org-directory')
    items = []
    if base.exists():
        for directory in base.iterdir():
            domain = directory.name
            if directory.is_symlink() or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]', domain):
                continue
            crt, key = directory / (domain + '.crt'), directory / (domain + '.key')
            if crt.exists() and key.exists():
                items.append({'domain': domain, 'certificate': read_pem(crt), 'key': read_pem(key)})
    if items:
        payload = json.dumps(items)
        for args in [
            ['/opt/waf-control/venv/bin/python', '/usr/local/lib/waf-poc/install-certificates.py'],
            ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes',
             '-o', 'HostKeyAlias=118.107.78.18', 'root@192.168.11.202',
             '/opt/waf-control/venv/bin/python /usr/local/lib/waf-poc/install-certificates.py']
        ]:
            result = subprocess.run(args, input=payload, text=True, capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError('Certificate synchronization failed; next timer run will retry')
        print('Certificate synchronization successful for ' + str(len(items)) + ' domain(s)')
    else:
        print('No issued certificate available yet')
