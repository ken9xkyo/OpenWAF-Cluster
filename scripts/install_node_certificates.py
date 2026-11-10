#!/usr/bin/env python3
"""Root-owned receiver; reads certificate pairs on stdin, never logs keys."""
import grp
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from cryptography import x509
from cryptography.hazmat.primitives import serialization

root = Path('/etc/caddy/tls')
root.mkdir(mode=0o750, parents=True, exist_ok=True)
gid = grp.getgrnam('caddy').gr_gid
os.chown(root, 0, gid)
root.chmod(0o750)
changed = []
marker = root / '.reload-required'
for item in json.load(sys.stdin):
    domain = item['domain']
    assert re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]', domain) and '..' not in domain
    cert = item['certificate'].encode()
    key = item['key'].encode()
    assert len(cert) < 100000 and len(key) < 100000
    parsed = x509.load_pem_x509_certificate(cert)
    names = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert domain in names
    private = serialization.load_pem_private_key(key, None)
    fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert private.public_key().public_bytes(*fmt) == parsed.public_key().public_bytes(*fmt)
    if (root / (domain + '.crt')).exists() and (root / (domain + '.crt')).read_bytes() == cert and (root / (domain + '.key')).read_bytes() == key:
        continue
    for suffix, content in [('.crt', cert), ('.key', key)]:
        target = root / (domain + suffix)
        stage = target.with_suffix(suffix + '.new')
        fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
        os.chown(stage, 0, gid)
        os.chmod(stage, 0o640)
        stage.replace(target)
    changed.append(domain)
if changed:
    marker.touch(mode=0o600)
if marker.exists() and subprocess.run(['systemctl', 'is-active', '--quiet', 'caddy']).returncode == 0:
    result = subprocess.run(['systemctl', 'reload', 'caddy'], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('Certificate installed, but Caddy reload failed')
    marker.unlink()
print(json.dumps({'certificates_updated': changed}))
