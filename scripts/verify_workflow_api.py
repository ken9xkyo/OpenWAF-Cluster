#!/usr/bin/env python3
"""Exercise real lifecycle SQL in a temporary schema; never changes WAF nodes.

Run with the control environment loaded and the control venv. Requires database
schema creation privileges and the installed Caddy/Coraza validation binary.
"""
import hashlib
import json
import os
from pathlib import Path
import uuid
from unittest.mock import patch

import psycopg
from psycopg.rows import dict_row
from fastapi.testclient import TestClient
from control.app import app, agent_app, current_user, node_identity


def main():
    schema = 'verify_workflow_' + uuid.uuid4().hex
    connection = os.environ['DATABASE_URL']
    with psycopg.connect(connection, autocommit=True) as admin:
        admin.execute('CREATE SCHEMA ' + schema)
        try:
            def isolated_db():
                return psycopg.connect(connection, row_factory=dict_row, options='-c search_path=' + schema)
            with isolated_db() as conn:
                conn.execute(Path('control/schema.sql').read_text())
                conn.execute("INSERT INTO users(id,username,password_hash,role) VALUES(1,'isolated-admin','unused','admin')")
                for node in ['waf-cluster-1', 'waf-cluster-2']:
                    conn.execute('INSERT INTO nodes(id,address,token_hash) VALUES(%s,%s,%s)', (node, '192.0.2.1', 'unused'))
            identity = {'id': 'waf-cluster-1'}
            app.dependency_overrides[current_user] = lambda: {'id': 1, 'username': 'isolated-admin', 'role': 'admin'}
            agent_app.dependency_overrides[node_identity] = lambda: identity
            with patch('control.app.db', isolated_db), patch.dict(os.environ, {'BACKEND_ALLOWLIST': '192.0.2.0/24'}):
                client, agent = TestClient(app), TestClient(agent_app)
                def call(path, body=None, method='POST'):
                    response = client.request(method, path, json=body)
                    assert response.status_code == 200, response.text
                    return response.json()
                def view():
                    return call('/api/overview', method='GET')
                site = dict(hostname='workflow.example.test', backend_ip='192.0.2.10', backend_port=3000,
                            mode='DetectionOnly', paranoia=1, enabled=True, excluded_rules=[], exception_reason='', crs_settings={})
                sid = call('/api/sites', site)['id']
                assert view()['workflow']['stage'] == 'draft'
                digest = view()['workflow']['draft_digest']
                rid = call('/api/revisions', {'note': 'Isolated workflow validation', 'draft_digest': digest})['id']
                assert view()['workflow']['stage'] == 'checked'
                call(f'/api/revisions/{rid}/approve')
                assert view()['workflow']['stage'] == 'approved'
                did = call(f'/api/revisions/{rid}/deploy')['id']
                assert view()['workflow']['stage'] == 'canary'
                config = call(f'/api/revisions/{rid}', method='GET')['configs']
                def heartbeat(node, valid=True, health='healthy'):
                    identity['id'] = node
                    sha = hashlib.sha256(config[node].encode()).hexdigest() if valid else '0' * 64
                    response = agent.post('/agent/heartbeat', json={'revision': rid, 'digest': sha, 'health': health})
                    assert response.status_code == 200, response.text
                heartbeat('waf-cluster-1', valid=False)
                assert view()['workflow']['stage'] == 'canary'
                assert view()['nodes'][1]['desired_revision'] is None
                heartbeat('waf-cluster-1', health='error')
                assert view()['workflow']['stage'] == 'canary'
                heartbeat('waf-cluster-1')
                assert view()['workflow']['stage'] == 'rollout'
                assert view()['nodes'][1]['desired_revision'] == rid
                heartbeat('waf-cluster-2', valid=False)
                assert view()['workflow']['stage'] == 'rollout'
                heartbeat('waf-cluster-2')
                assert view()['workflow']['stage'] == 'complete'
                assert view()['workflow']['sites'][0]['applied']
                audit = view()['audit']
                assert any(a['action'] == 'deployment.auto_promote' for a in audit)
                heartbeat('waf-cluster-2', health='drift')
                assert view()['workflow']['stage'] == 'attention'
                heartbeat('waf-cluster-2')
                site['mode'] = 'On'
                call(f'/api/sites/{sid}', site, method='PUT')
                assert view()['workflow']['stage'] == 'draft'
                assert view()['workflow']['sites'][0]['nodes'][0]['changed_fields'] == ['Chế độ WAF']
                response = client.post('/api/revisions', json={'note': 'Stale configuration', 'draft_digest': digest})
                assert response.status_code == 409
                did = call(f'/api/revisions/{rid}/rollback')['id']
                call(f'/api/deployments/{did}/abort')
                heartbeat('waf-cluster-1')
                assert view()['workflow']['active_deployment'] is None
                app.dependency_overrides[current_user] = lambda: {'id': 1, 'username': 'viewer', 'role': 'viewer'}
                assert client.post(f'/api/revisions/{rid}/approve').status_code == 403
                print(json.dumps(dict(draft=True, real_caddy_validation=True, approval=True,
                                      auto_promote=True, digest_guard=True, drift=True, complete=True,
                                      site_diff=True, stale_draft=True, abort=True, viewer_readonly=True)))
        finally:
            app.dependency_overrides.clear()
            agent_app.dependency_overrides.clear()
            admin.execute('DROP SCHEMA ' + schema + ' CASCADE')


if __name__ == '__main__':
    main()
