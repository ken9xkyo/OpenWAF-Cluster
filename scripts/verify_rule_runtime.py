#!/usr/bin/env python3
"""Verify per-rule toggles using a generated policy on an isolated Coraza listener."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from control.render import render

results = {}
with tempfile.TemporaryDirectory(prefix='rule-runtime-') as tmp:
    folder = Path(tmp)
    for name, excluded, expected in [('enabled', [], 403), ('disabled', [913100], 200), ('re_enabled', [], 403)]:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        site = dict(id=1, hostname='rule.example.com', backend_ip='192.0.2.10', backend_port=3000,
                    mode='On', paranoia=1, excluded_rules=excluded, exception_reason='Test scanner exception')
        config = render('waf-cluster-1', [site], 'test')
        directives = config.split('directives `', 1)[1].split('`', 1)[0]
        directives = directives.replace('/var/log/coraza/site-1.json', str(folder / 'audit.json'))
        path = folder / 'Caddyfile'
        path.write_text('{\nadmin off\nauto_https off\norder coraza_waf first\n}\n'
                        f'http://:{port} {{\nbind 127.0.0.1\ncoraza_waf {{\nload_owasp_crs\ndirectives `'
                        + directives + '`\n}\nrespond "ok" 200\n}\n')
        with (folder / 'runtime.log').open('w') as log:
            process = subprocess.Popen(['/usr/local/bin/caddy', 'run', '--config', str(path), '--adapter', 'caddyfile'],
                                       cwd=folder, stdout=log, stderr=log)
            def request(agent):
                req = urllib.request.Request(f'http://127.0.0.1:{port}/',
                                             headers={'Host': site['hostname'], 'Accept': 'text/html', 'User-Agent': agent})
                try:
                    with urllib.request.urlopen(req, timeout=3) as response:
                        return response.status
                except urllib.error.HTTPError as error:
                    return error.code
            try:
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None:
                        raise RuntimeError((folder / 'runtime.log').read_text()[-1500:])
                    try:
                        clean = request('RuleRegression/1.0')
                        break
                    except (OSError, urllib.error.URLError):
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.1)
                assert clean == 200, (name, 'clean', clean)
                scanner = request('sqlmap/1.0')
                assert scanner == expected, (name, scanner, expected)
                results[name] = {'clean': clean, 'scanner': scanner, 'excluded_rules': excluded}
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
print(json.dumps(results, indent=2))
