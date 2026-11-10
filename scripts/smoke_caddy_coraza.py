#!/usr/bin/env python3
"""Check embedded CRS detection/blocking using an isolated loopback listener."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def request(path):
    try:
        req = urllib.request.Request('http://127.0.0.1:18081' + path,
                                     headers={'Host': 'waf-smoke.example', 'Accept': 'text/html',
                                              'User-Agent': 'WAFPOCSmoke/1.0'})
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


binary = str(Path(sys.argv[1]).resolve())
results = {}
with tempfile.TemporaryDirectory(prefix='waf-smoke-') as tmp:
    folder = Path(tmp)
    for mode in ['DetectionOnly', 'On']:
        config = folder / 'Caddyfile'
        audit = folder / (mode + '-audit.log')
        config.write_text('''{
    admin off
    auto_https off
    order coraza_waf first
}
http://:18081 {
    bind 127.0.0.1
    coraza_waf {
        load_owasp_crs
        directives `
            Include @coraza.conf-recommended
            Include @crs-setup.conf.example
            SecRuleEngine ''' + mode + '''
            SecAuditEngine On
            SecAuditLogFormat JSON
            SecAuditLog ''' + str(audit) + '''
            Include @owasp_crs/*.conf
        `
    }
    respond "waf-smoke-ok" 200
}
''')
        validation = subprocess.run([binary, 'validate', '--config', str(config), '--adapter', 'caddyfile'],
                                    capture_output=True, text=True, cwd=folder)
        if validation.returncode:
            raise RuntimeError(validation.stdout + validation.stderr)
        with (folder / (mode + '-runtime.log')).open('w') as log:
            process = subprocess.Popen([binary, 'run', '--config', str(config), '--adapter', 'caddyfile'],
                                       stdout=log, stderr=log, cwd=folder)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        raise RuntimeError((folder / (mode + '-runtime.log')).read_text())
                    try:
                        clean = request('/?q=ordinary-search')
                        break
                    except (OSError, urllib.error.URLError):
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(0.2)
                attack = request('/?' + urllib.parse.urlencode({'q': "1' OR '1'='1 -- "}))
                assert clean == 200, (mode, 'clean', clean)
                expected = 200 if mode == 'DetectionOnly' else 403
                assert attack == expected, (mode, 'attack', attack)
                results[mode] = {'clean_status': clean, 'sqli_status': attack}
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        events = [json.loads(line) for line in audit.read_text().splitlines() if line.strip()]
        assert any('942' in json.dumps(e) for e in events), 'SQLi rule evidence missing'
        results[mode]['sqli_rule_evidence'] = True
print(json.dumps(results, indent=2))
