"""Request metadata ingestion and history API regression checks."""
import ast
import json
import logging
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from control.app import app, agent_app, current_user, node_identity


class HistoryTests(unittest.TestCase):
    def test_collects_url_without_headers_and_handles_legacy_records(self):
        # Load the collector without starting the agent or reading its identity keys.
        tree = ast.parse(Path('control/agent.py').read_text())
        collector = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'collect_events')
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            request = {'uri': '/search?q=%3Cscript%3E&tag=a&tag=b', 'method': 'POST',
                       'protocol': 'HTTP/2.0', 'headers': {'Cookie': ['secret']}, 'body': 'secret'}
            event = {'transaction': {'id': 'tx-1', 'server_id': 'example.test',
                                    'request': request, 'client_ip': '192.0.2.1'},
                     'messages': [{'error_message': '[id "942100"]'}]}
            legacy = {'transaction': {'id': 'tx-2'}, 'messages': [{'data': {'id': 941100}}]}
            (folder / 'site-1.json').write_text(json.dumps(event)+'\n'+json.dumps(legacy)+'\n')
            namespace = {'Path': lambda _: folder, 'json': json, 're': re, 'logging': logging}
            exec(compile(ast.Module(body=[collector], type_ignores=[]), '<collector>', 'exec'), namespace)
            state = {}
            namespace['collect_events'](state)
            first, second = state['pending_events']
            self.assertEqual(first['request_uri'], request['uri'])
            self.assertEqual(first['request_method'], 'POST')
            self.assertEqual(first['request_host'], 'example.test')
            self.assertNotIn('secret', json.dumps(first))
            self.assertEqual(second['request_uri'], '')
            namespace['collect_events'](state)
            self.assertEqual(len(state['pending_events']), 2)

    def test_search_escapes_literal_wildcards_and_includes_url(self):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = {'total': 51}
        conn.execute.return_value.fetchall.return_value = []
        app.dependency_overrides[current_user] = lambda: {'username': 'viewer', 'role': 'viewer'}
        try:
            with patch('control.app.db') as db:
                db.return_value.__enter__.return_value = conn
                response = TestClient(app).get('/api/history/waf', params={'q': '/x?rate=10%_a', 'page': 9})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['page'], 3)
            queries = [call.args for call in conn.execute.call_args_list]
            self.assertIn('e.request_uri ILIKE %s', queries[-1][0])
            self.assertIn('%/x?rate=10\\%\\_a%', queries[-1][1])
        finally:
            app.dependency_overrides.clear()

    def test_heartbeat_accepts_old_agents_and_persists_request_metadata(self):
        conn = MagicMock()
        conn.execute.return_value.fetchone.return_value = None
        agent_app.dependency_overrides[node_identity] = lambda: {'id': 'node-1'}
        base = dict(event_key='tx', site_id=1, client_ip='192.0.2.2', rule_ids=[942100], interrupted=True)
        try:
            with patch('control.app.db') as db:
                db.return_value.__enter__.return_value = conn
                client = TestClient(agent_app)
                for event in [base, dict(base, request_uri='/search?q=a', request_method='GET',
                                         request_host='example.test', request_protocol='HTTP/2.0')]:
                    self.assertEqual(client.post('/agent/heartbeat', json={'health': 'healthy', 'events': [event]}).status_code, 200)
                inserts = [call.args for call in conn.execute.call_args_list if call.args[0].startswith('INSERT')]
                self.assertEqual(inserts[0][1][-4:], ('', '', '', ''))
                self.assertEqual(inserts[1][1][-4:], ('GET', '/search?q=a', 'example.test', 'HTTP/2.0'))
                too_long = dict(base, request_uri='x' * 16385)
                self.assertEqual(client.post('/agent/heartbeat', json={'health': 'healthy', 'events': [too_long]}).status_code, 422)
        finally:
            agent_app.dependency_overrides.clear()

    def test_history_requires_login(self):
        self.assertEqual(TestClient(app).get('/api/history/waf').status_code, 401)


if __name__ == '__main__':
    unittest.main()
