"""mTLS pull agent with signed manifests, drift reconciliation and last-known-good."""
import base64
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time

from cryptography.hazmat.primitives import serialization
import httpx

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logging.getLogger('httpx').setLevel(logging.WARNING)
CONFIG = json.loads(Path(os.environ.get('AGENT_CONFIG', '/etc/waf-agent/agent.json')).read_text())
ROOT = Path('/var/lib/waf-agent')
ROOT.mkdir(exist_ok=True)
CURRENT = Path('/var/lib/caddy/active/Caddyfile')
STATE = ROOT / 'state.json'
PUBLIC = serialization.load_pem_public_key(Path(CONFIG['signing_public_key']).read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def atomic(path, content):
    temp = path.with_suffix(path.suffix + '.new')
    temp.write_text(content)
    temp.chmod(0o600)
    temp.replace(path)


def command(args):
    p = subprocess.run(args, cwd='/var/lib/caddy', capture_output=True, text=True, timeout=45)
    if p.returncode:
        raise RuntimeError(p.stderr[-550:] or 'Caddy command failed')


def runtime_digest():
    r = httpx.get('http://127.0.0.1:2019/config/', timeout=5, trust_env=False)
    r.raise_for_status()
    return hashlib.sha256(canonical(r.json())).hexdigest()


def wire_health():
    ip = CONFIG['address']
    context = ssl.create_default_context()
    with socket.create_connection((ip, 8443), timeout=5) as sock:
        sock.sendall(f'PROXY TCP4 {ip} {ip} 40001 8443\r\n'.encode())
        with context.wrap_socket(sock, server_hostname=CONFIG['hostname']) as tls:
            tls.sendall(f'GET /_waf_health HTTP/1.1\r\nHost: {CONFIG["hostname"]}\r\nConnection: close\r\n\r\n'.encode())
            response = tls.recv(1024)
            if b' 200 ' not in response.split(b'\r\n')[0]:
                raise RuntimeError('TLS health-check did not return 200')


def apply(manifest, state):
    config = manifest['config']
    stage = ROOT / f'release-{manifest["revision"]}-{manifest["generation"]}.Caddyfile'
    atomic(stage, config)
    command(['/usr/local/bin/caddy', 'validate', '--config', str(stage), '--adapter', 'caddyfile'])
    previous = CURRENT.read_text() if CURRENT.exists() else None
    try:
        command(['/usr/local/bin/caddy', 'reload', '--config', str(stage), '--adapter', 'caddyfile'])
        wire_health()
        fingerprint = runtime_digest()
        if previous:
            atomic(ROOT / 'last-known-good.Caddyfile', previous)
        atomic(CURRENT, config)
        state.update(revision=manifest['revision'], generation=manifest['generation'],
                     digest=manifest['sha256'], runtime_digest=fingerprint)
        logging.info('Applied revision %s generation %s', manifest['revision'], manifest['generation'])
        old_files = sorted(ROOT.glob('release-*.Caddyfile'), key=lambda p: p.stat().st_mtime)
        for old in old_files[:-20]:
            old.unlink()
    except Exception:
        if previous:
            rollback = ROOT / 'rollback.Caddyfile'
            atomic(rollback, previous)
            command(['/usr/local/bin/caddy', 'reload', '--config', str(rollback), '--adapter', 'caddyfile'])
        raise


def collect_events(state):
    pending = state.setdefault('pending_events', [])
    offsets = state.setdefault('log_offsets', {})
    for file in Path('/var/log/coraza').glob('site-*.json'):
        stat = file.stat()
        pos = offsets.get(file.name, {'inode': stat.st_ino, 'offset': 0})
        if pos['inode'] != stat.st_ino or pos['offset'] > stat.st_size:
            pos = {'inode': stat.st_ino, 'offset': 0}
        with file.open() as stream:
            stream.seek(pos['offset'])
            for _ in range(100):
                before = stream.tell()
                line = stream.readline(1000001)
                if not line:
                    break
                if len(line) > 1000000:
                    while line and not line.endswith('\n'):
                        line = stream.readline(1000001)
                    logging.warning('Skipped oversized audit record')
                    continue
                if not line.endswith('\n'):
                    stream.seek(before)
                    break
                try:
                    event = json.loads(line)
                    tx = event.get('transaction') or {}
                    request = tx.get('request') or {}
                    rules = sorted({int(m['data']['id']) for m in (event.get('messages') or [])
                                    if isinstance(m, dict) and (m.get('data') or {}).get('id')})
                    # Coraza's JSON writer may serialize matched-rule metadata
                    # in error_message while leaving the data field null.
                    if not rules:
                        rules = sorted({int(rid) for m in (event.get('messages') or []) if isinstance(m, dict)
                                        for rid in re.findall(r'\[id "(\d+)"\]', m.get('error_message') or '')})
                    if rules:
                        pending.append({'event_key': str(tx.get('id') or sha(line)),
                                        'site_id': int(file.stem.split('-')[1]),
                                        'client_ip': tx.get('client_ip', ''), 'rule_ids': rules[:100],
                                        'interrupted': bool(tx.get('is_interrupted')),
                                        'request_method': str(request.get('method') or '')[:32],
                                        'request_uri': str(request.get('uri') or '')[:16384],
                                        'request_host': str(tx.get('server_id') or '')[:512],
                                        'request_protocol': str(request.get('protocol') or '')[:32]})
                except (ValueError, TypeError, KeyError):
                    logging.warning('Skipped malformed audit record')
            pos['offset'] = stream.tell()
        offsets[file.name] = pos
    if len(pending) > 1000:
        logging.warning('WAF event queue capped at 1000; source logs retain original events')
        state['pending_events'] = pending[-1000:]


def main():
    state = json.loads(STATE.read_text()) if STATE.exists() else {'generation': -1}
    context = ssl.create_default_context(cafile=CONFIG['ca'])
    context.load_cert_chain(CONFIG['certificate'], CONFIG['key'])
    client = httpx.Client(verify=context, timeout=12, trust_env=False,
                          headers={'Authorization': 'Bearer ' + CONFIG['token']})
    last_error = None
    while True:
        error = None
        endpoint = None
        try:
            response = None
            for candidate in CONFIG['controllers']:
                try:
                    response = client.get(candidate + '/agent/desired')
                    response.raise_for_status()
                    endpoint = candidate
                    break
                except httpx.HTTPError:
                    continue
            if not endpoint:
                raise RuntimeError('Controllers unavailable; keeping running configuration')
            package = response.json()
            manifest = package.get('manifest')
            drift = state.get('runtime_digest') is not None and runtime_digest() != state['runtime_digest']
            if manifest:
                PUBLIC.verify(base64.b64decode(package['signature']), canonical(manifest))
                if manifest['node_id'] != CONFIG['node_id'] or sha(manifest['config']) != manifest['sha256']:
                    raise RuntimeError('Manifest node/hash verification failed')
                if manifest['generation'] < state.get('generation', -1):
                    raise RuntimeError('Rejected stale generation')
                file_drift = not CURRENT.exists() or sha(CURRENT.read_text()) != manifest['sha256']
                if manifest['generation'] != state.get('generation') or file_drift or drift:
                    apply(manifest, state)
            wire_health()
        except Exception as e:
            error = str(e)[:550]
            if error != last_error:
                logging.warning('%s', error)
        try:
            collect_events(state)
            if endpoint:
                sent = state.get('pending_events', [])[:100]
                result = client.post(endpoint + '/agent/heartbeat', json={
                    'revision': state.get('revision'), 'digest': state.get('digest', ''),
                    'health': 'error' if error else 'healthy', 'detail': error or 'Config verified; TLS health 200',
                    'events': sent})
                result.raise_for_status()
                state['pending_events'] = state.get('pending_events', [])[len(sent):]
            atomic(STATE, json.dumps(state))
        except Exception as e:
            logging.warning('Heartbeat/event delivery failed: %s', str(e)[:200])
        last_error = error
        time.sleep(5)


if __name__ == '__main__':
    main()
