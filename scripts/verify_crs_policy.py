#!/usr/bin/env python3
"""Exercise generated policy with the installed Coraza on an isolated listener."""
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from control.render import render

site = dict(id=1, hostname='policy.example.com', backend_ip='192.0.2.10',
            backend_port=3000, mode='On', paranoia=1)
cases = [
    ('defaults', {}, 'On', 1, 403),
    ('high_threshold', {'inbound_anomaly_score_threshold': 10000}, 'On', 1, 200),
    ('detection_only', {}, 'DetectionOnly', 1, 200),
    ('observe_pl4', {'detection_paranoia_level': 4}, 'On', 1, 403),
    ('custom_scores_pl3', {'critical_anomaly_score': 7, 'error_anomaly_score': 6,
                          'warning_anomaly_score': 5, 'notice_anomaly_score': 4,
                          'outbound_anomaly_score_threshold': 8,
                          'detection_paranoia_level': 4}, 'On', 3, 403),
]
results = {}
with tempfile.TemporaryDirectory(prefix='crs-policy-') as tmp:
    root = Path(tmp)
    for name, settings, mode, pl, expected in cases:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        config = render('waf-cluster-1', [dict(site, mode=mode, paranoia=pl, crs_settings=settings)], 'test')
        directives = config.split('directives `', 1)[1].split('`', 1)[0]
        directives = directives.replace('/var/log/coraza/site-1.json', str(root / 'audit.json'))
        # Probe actual initialized transaction variables in addition to SQLi behavior.
        for index, (key, value) in enumerate({'blocking_paranoia_level': pl,
                                             'detection_paranoia_level': settings.get('detection_paranoia_level', pl),
                                             **settings}.items()):
            directives += f'\nSecRule TX:{key} "!@eq {value}" "id:{110000 + index},phase:1,deny,status:418,nolog"\n'
        path = root / 'Caddyfile'
        path.write_text('{\nadmin off\nauto_https off\norder coraza_waf first\n}\n'
                        f'http://:{port} {{\nbind 127.0.0.1\ncoraza_waf {{\nload_owasp_crs\ndirectives `'
                        + directives + '`\n}\nrespond "ok" 200\n}\n')
        with (root / 'runtime.log').open('w') as log:
            process = subprocess.Popen(['/usr/local/bin/caddy', 'run', '--config', str(path), '--adapter', 'caddyfile'],
                                       cwd=root, stdout=log, stderr=log)
            def request(query):
                url = f'http://127.0.0.1:{port}/?' + urllib.parse.urlencode({'q': query})
                req = urllib.request.Request(url, headers={'Host': site['hostname'], 'Accept': 'text/html',
                                                          'User-Agent': 'PolicyRegression/1.0'})
                try:
                    with urllib.request.urlopen(req, timeout=3) as response:
                        return response.status
                except urllib.error.HTTPError as error:
                    return error.code
            try:
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None:
                        raise RuntimeError((root / 'runtime.log').read_text()[-1500:])
                    try:
                        clean = request('ordinary')
                        break
                    except (OSError, urllib.error.URLError):
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.1)
                assert clean == 200, (name, 'clean', clean)
                attack = request("1' OR '1'='1 -- ")
                assert attack == expected, (name, 'SQLi', attack, expected)
                results[name] = {'clean': clean, 'sqli': attack}
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
print(json.dumps(results, indent=2))
