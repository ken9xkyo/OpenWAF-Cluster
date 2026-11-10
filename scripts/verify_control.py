#!/usr/bin/env python3
"""End-to-end checks against the authorized POC, restoring DetectionOnly.

No credentials, cookies, tokens or private keys are printed or saved in results.
"""
import copy
import datetime as dt
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import httpx
import psycopg

ROOT = Path(__file__).resolve().parents[1]
credentials = json.loads(Path('/etc/waf-control/bootstrap.json').read_text())
client = httpx.Client(base_url='http://127.0.0.1:9000', timeout=90, trust_env=False)
checks = {}


def call(path, method='GET', body=None):
    response = client.request(method, path, json=body)
    response.raise_for_status()
    return response.json()


def wait_for(predicate, label, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        view = call('/api/overview')
        if predicate(view):
            print(label, flush=True)
            return view
        time.sleep(1)
    raise RuntimeError('Timed out: ' + label)


def ready(view, rid, nodes=2):
    return sum(n['actual_revision'] == rid and n['health'] == 'healthy' and n['online'] for n in view['nodes']) >= nodes


def promote_and_wait(did, rid):
    wait_for(lambda d: any(n['id']=='waf-cluster-1' and n['actual_revision']==rid and n['health']=='healthy' and n['online'] for n in d['nodes']), 'Canary healthy r'+str(rid))
    call('/api/deployments/'+str(did)+'/promote', 'POST')
    return wait_for(lambda d: ready(d, rid) and any(x['id']==did and x['state']=='complete' for x in d['deployments']), 'Both nodes healthy r'+str(rid))


assert client.get('/api/overview').status_code == 401
login = call('/api/login', 'POST', {'username':'admin','password':credentials['admin_password']})
assert client.post('/api/revisions', json={'note':'CSRF negative check'}).status_code == 403
client.headers['X-CSRF-Token'] = login['csrf']
checks['authentication_and_csrf'] = 'passed'
original = call('/api/overview')
site = original['sites'][0]
site_id = site.pop('id')
original_revision = original['nodes'][0]['actual_revision']
assert original_revision and ready(original, original_revision)
invalid = dict(site, backend_ip='127.0.0.1')
assert client.put('/api/sites/'+str(site_id), json=invalid).status_code == 422
checks['backend_allowlist'] = 'passed'

viewer_password = secrets.token_urlsafe(24)
viewer = call('/api/users', 'POST', {'username':'poc-verification-viewer','password':viewer_password,'role':'viewer'})
with httpx.Client(base_url='http://127.0.0.1:9000', trust_env=False) as limited:
    response = limited.post('/api/login', json={'username':'poc-verification-viewer','password':viewer_password})
    response.raise_for_status()
    limited.headers['X-CSRF-Token'] = response.json()['csrf']
    assert limited.get('/api/overview').status_code == 200
    assert limited.post('/api/revisions', json={'note':'Viewer must not publish'}).status_code == 403
    call('/api/users/'+str(viewer['id']), 'PATCH', {'enabled':False})
    assert limited.get('/api/overview').status_code == 401
with psycopg.connect(host='192.168.11.100', dbname='wafcontrol', user='wafapp', password=credentials['database_password'], sslmode='verify-full', sslrootcert='/etc/waf-control/pki/ca.crt') as conn:
    conn.execute('DELETE FROM users WHERE id=%s', (viewer['id'],))
checks['rbac_and_session_revocation'] = 'passed'

agent = json.loads(Path('/etc/waf-agent/agent.json').read_text())
context = ssl.create_default_context(cafile=agent['ca'])
context.load_cert_chain(agent['certificate'], agent['key'])
with httpx.Client(verify=context, trust_env=False, headers={'Authorization':'Bearer '+agent['token']}) as agent_client:
    response = agent_client.get('https://192.168.11.100:9443/agent/desired')
    response.raise_for_status()
    package = response.json()
    import base64
    key = serialization.load_pem_public_key(Path(agent['signing_public_key']).read_bytes())
    canonical = lambda p: json.dumps(p, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    key.verify(base64.b64decode(package['signature']), canonical(package['manifest']))
    tampered = copy.deepcopy(package['manifest']);tampered['config'] += '\n# tampered\n'
    try:
        key.verify(base64.b64decode(package['signature']), canonical(tampered))
        raise AssertionError('Tampered manifest accepted')
    except InvalidSignature:
        pass
checks['signed_manifest_tamper_rejection'] = 'passed'
try:
    httpx.get('https://192.168.11.100:9443/agent/desired', verify=ssl.create_default_context(cafile=agent['ca']), trust_env=False, timeout=5)
    raise AssertionError('Agent TLS accepted a client without certificate')
except httpx.HTTPError:
    checks['agent_mtls_required'] = 'passed'

blocking = dict(site, mode='On')
test_revision = None
test_deployment = None
try:
    call('/api/sites/'+str(site_id), 'PUT', blocking)
    revision = call('/api/revisions', 'POST', {'note':'POC verification: SQLi blocking and two-node rollout'})
    test_revision = revision['id']
    assert client.post('/api/revisions/'+str(test_revision)+'/deploy').status_code == 409
    call('/api/revisions/'+str(test_revision)+'/approve', 'POST')
    deployment = call('/api/revisions/'+str(test_revision)+'/deploy', 'POST')
    test_deployment = deployment['id']
    promote_and_wait(test_deployment, test_revision)
    checks['validated_approval_canary_rollout'] = 'passed'
    transport = httpx.HTTPTransport(local_address='118.107.78.206')
    with httpx.Client(transport=transport, trust_env=False, timeout=15) as browser:
        assert browser.get('https://test-waf.vtccloud.vn/').status_code == 200
        nodes = set()
        for _ in range(6):
            response = browser.get('https://test-waf.vtccloud.vn/', headers={'Connection':'close'})
            assert response.status_code == 200
            nodes.add(response.headers.get('x-waf-node'))
        assert nodes == {'waf-cluster-1','waf-cluster-2'}, nodes
        response = browser.get('https://test-waf.vtccloud.vn/', params={'q':"1' OR '1'='1 -- "},
                               headers={'X-Forwarded-For':'203.0.113.99','Accept':'text/html','User-Agent':'WAF-POC-Verification/1.0'})
        assert response.status_code == 403, response.status_code
    checks['live_https_sqli_blocking'] = 'passed'
    checks['https_balances_both_nodes'] = 'passed'
    events = wait_for(lambda d: any(e['client_ip']=='118.107.78.206' and e['interrupted'] and any(str(x).startswith('942') for x in e['rule_ids']) for e in d['events']), 'SQLi audit shows real source IP, ignores spoofed XFF')
    checks['coraza_real_client_ip_and_audit'] = 'passed'
finally:
    call('/api/sites/'+str(site_id), 'PUT', site)
    view = call('/api/overview')
    active = next((d for d in view['deployments'] if d['state'] in {'canary','rollout'}), None)
    if active:
        call('/api/deployments/'+str(active['id'])+'/abort', 'POST')
    if test_revision:
        deployment = call('/api/revisions/'+str(original_revision)+'/rollback', 'POST')
        promote_and_wait(deployment['id'], original_revision)
        checks['rollback_to_detection_only'] = 'passed'

current = Path('/var/lib/caddy/active/Caddyfile')
expected = current.read_text()
current.write_text(expected+'\n# harmless drift verification\n')
deadline = time.monotonic()+30
while current.read_text()!=expected:
    assert time.monotonic()<deadline, 'Agent did not restore config drift'
    time.sleep(1)
checks['agent_reconciles_file_drift'] = 'passed'

try:
    subprocess.run(['systemctl','stop','postgresql@16-main'],check=True)
    assert client.get('/healthz').status_code == 503
    for _ in range(3):
        r = httpx.get('https://test-waf.vtccloud.vn/',trust_env=False,timeout=10)
        assert r.status_code == 200
    checks['data_plane_survives_database_outage'] = 'passed'
finally:
    subprocess.run(['systemctl','start','postgresql@16-main'],check=True)
wait_for(lambda d: ready(d,original_revision), 'Control plane recovered; original revision remains healthy')
report = {'completed_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'checks':checks,
          'active_revision':original_revision,'mode':'DetectionOnly'}
(ROOT/'reports/2026-11-10/control-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2),flush=True)
