"""Configuration lifecycle and automatic two-node rollout regression checks."""
import copy
import hashlib
import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from control.app import Note, advance_deployment, revision
from control.workflow import deployment_status, node_ready, snapshot_digest


def fixture():
    sites = [dict(id=1, hostname='example.test', backend_ip='192.0.2.1', backend_port=3000,
                  mode='DetectionOnly', paranoia=1, enabled=True, excluded_rules=[], exception_reason='', crs_settings={})]
    r = dict(id=7, snapshot=copy.deepcopy(sites), configs={'waf-cluster-1': 'config-1', 'waf-cluster-2': 'config-2'},
             validated=True, approved_at='2026-11-10T00:00:00Z')
    nodes = [dict(id=node, actual_revision=7, desired_revision=7, actual_digest=hashlib.sha256(config.encode()).hexdigest(),
                  health='healthy', online=True) for node, config in r['configs'].items()]
    return sites, r, nodes


class WorkflowTests(unittest.TestCase):
    def test_draft_changes_and_per_site_node_comparison(self):
        sites, r, nodes = fixture()
        sites[0]['mode'] = 'On'
        w = deployment_status(sites, nodes, [r], [])
        self.assertEqual(w['stage'], 'draft')
        self.assertIsNone(w['revision_id'])
        self.assertEqual(w['pending_sites'], 1)
        self.assertEqual(w['sites'][0]['nodes'][0]['changed_fields'], ['Chế độ WAF'])
        self.assertFalse(w['applied'])

    def test_new_website_and_empty_cluster(self):
        sites, r, nodes = fixture()
        sites.append(dict(sites[0], id=2, hostname='new.example.test'))
        w = deployment_status(sites, nodes, [r], [])
        self.assertEqual(w['pending_sites'], 1)
        self.assertEqual(w['sites'][1]['nodes'][1]['changed_fields'], ['Website mới'])
        self.assertTrue(w['sites'][0]['applied'])
        self.assertFalse(deployment_status([], [], [], [])['applied'])

    def test_complete_needs_agent_evidence_not_historical_completion(self):
        sites, r, nodes = fixture()
        deployments = [dict(id=3, revision_id=7, state='complete')]
        self.assertEqual(deployment_status(sites, nodes, [r], deployments)['stage'], 'complete')
        for change in [dict(online=False), dict(health='drift'), dict(actual_digest='wrong')]:
            with self.subTest(change=change):
                changed = copy.deepcopy(nodes)
                changed[1].update(change)
                self.assertFalse(deployment_status(sites, changed, [r], deployments)['applied'])
                self.assertFalse(node_ready(changed[1], r))

    def test_each_lifecycle_stage_and_aborted_retry(self):
        sites, r, nodes = fixture()
        nodes[1]['actual_revision'] = None
        r['approved_at'] = None
        self.assertEqual(deployment_status(sites, nodes, [r], [])['stage'], 'checked')
        r['approved_at'] = 'now'
        self.assertEqual(deployment_status(sites, nodes, [r], [])['stage'], 'approved')
        for state in ['canary', 'rollout', 'aborted']:
            self.assertEqual(deployment_status(sites, nodes, [r], [dict(id=3, revision_id=7, state=state)])['stage'], state)

    def test_old_snapshots_and_rule_order_do_not_create_false_drafts(self):
        sites, r, _ = fixture()
        del r['snapshot'][0]['crs_settings']
        sites[0]['excluded_rules'] = [942100, 941100]
        r['snapshot'][0]['excluded_rules'] = [941100, 942100]
        self.assertEqual(snapshot_digest(sites), snapshot_digest(r['snapshot']))
        sites[0]['crs_settings'] = {'critical_anomaly_score': 7}
        self.assertNotEqual(snapshot_digest(sites), snapshot_digest(r['snapshot']))

    def test_automatic_promotion_and_completion_are_separate_transitions(self):
        _, r, nodes = fixture()
        for state in ['canary', 'rollout']:
            with self.subTest(state=state):
                conn = MagicMock()
                conn.execute.return_value.fetchone.side_effect = [dict(id=3, revision_id=7, state=state), r]
                conn.execute.return_value.fetchall.return_value = nodes
                advance_deployment(conn)
                queries = [call.args[0] for call in conn.execute.call_args_list]
                if state == 'canary':
                    self.assertTrue(any("SET state='rollout'" in q for q in queries))
                    self.assertTrue(any("generation=generation+1 WHERE id='waf-cluster-2'" in q for q in queries))
                    self.assertFalse(any("SET state='complete'" in q for q in queries))
                else:
                    self.assertTrue(any("SET state='complete'" in q for q in queries))

    def test_automatic_promotion_waits_for_correct_healthy_node_one(self):
        _, r, nodes = fixture()
        for change in [dict(online=False), dict(health='error'), dict(actual_digest='bad'), dict(actual_revision=6), dict(desired_revision=6)]:
            with self.subTest(change=change):
                conn = MagicMock()
                conn.execute.return_value.fetchone.side_effect = [dict(id=3, revision_id=7, state='canary'), r]
                changed = copy.deepcopy(nodes)
                changed[0].update(change)
                conn.execute.return_value.fetchall.return_value = changed
                advance_deployment(conn)
                self.assertFalse(any(call.args[0].startswith('UPDATE') for call in conn.execute.call_args_list))

    def test_stale_validation_dialog_cannot_validate_an_unseen_draft(self):
        sites, _, _ = fixture()
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = sites
        with patch('control.app.db') as db:
            db.return_value.__enter__.return_value = conn
            with self.assertRaises(HTTPException) as result:
                revision(Note(note='Validate stale draft', draft_digest='0' * 64), user={'id': 1})
        self.assertEqual(result.exception.status_code, 409)
        self.assertEqual(conn.execute.call_count, 1)


if __name__ == '__main__':
    unittest.main()
