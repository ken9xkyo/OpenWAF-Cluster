"""Catalog fidelity, rule selection safety and API permission regression tests."""
from pathlib import Path
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from control.app import app, current_user
from control.render import render, validate_site
from control.rules import rule_catalog, rules_by_id, validate_rule_exclusions
from scripts.build_rule_catalog import action_values, build, statements, tokens


class CatalogTests(unittest.TestCase):
    def test_all_ids_unique_and_security_rules_have_metadata(self):
        catalog = rule_catalog()
        self.assertEqual(catalog['version'], 'OWASP_CRS/4.25.0')
        self.assertEqual(len(catalog['rules']), 625)
        self.assertEqual(len(rules_by_id()), len(catalog['rules']))
        selectable = [r for r in catalog['rules'] if r['selectable']]
        self.assertEqual(len(selectable), 341)
        self.assertTrue(all(r['pl'] in (1, 2, 3, 4) and r['description'] and r['tags'] for r in selectable))
        self.assertEqual(rules_by_id()[942100]['pl'], 1)
        self.assertIn('libinjection', rules_by_id()[942100]['description'])
        self.assertFalse(rules_by_id()[949110]['selectable'])

    def test_chain_source_includes_children(self):
        rule = rules_by_id()[920170]
        self.assertEqual(rule['chain_length'], 2)
        self.assertIn('SecRule REQUEST_HEADERS:Content-Length', rule['source'])
        rule = rules_by_id()[949111]
        self.assertIn('SecRule TX:EARLY_BLOCKING "@eq 1"', rule['source'])

    def test_generated_catalog_matches_installed_sources(self):
        root = Path('/root/go/pkg/mod/github.com/corazawaf/coraza-coreruleset/v4@v4.25.0/rules')
        if not root.exists():
            self.skipTest('Source CRS module is not installed on this host')
        result = build(root)
        catalog = rule_catalog()
        self.assertEqual(result['source_sha256'], catalog['source_sha256'])
        self.assertEqual([{k: v for k, v in rule.items() if k != 'group_label'} for rule in catalog['rules']], result['rules'])

    def test_selection_over_50_rules_and_system_rule_protection(self):
        ids = [r['id'] for r in rule_catalog()['rules'] if r['selectable']]
        self.assertEqual(validate_rule_exclusions(ids, 'Tuning test'), sorted(ids))
        self.assertEqual(validate_rule_exclusions([942100, 942100], 'Tuning'), [942100])
        for selected, reason in (([949110], 'Disable blocking'), ([901001], 'Disable initialization'),
                                 ([942100], ''), ([True], 'Invalid type'), (['942100'], 'Invalid type')):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                validate_rule_exclusions(selected, reason)
        self.assertEqual(validate_rule_exclusions([999998], 'Legacy exception'), [999998])

    def test_exclusions_follow_crs_include_for_both_nodes(self):
        site = dict(id=1, hostname='rules.example.com', backend_ip='192.0.2.10', backend_port=3000,
                    mode='On', paranoia=1, excluded_rules=[942100, 941100], exception_reason='Test tuning')
        validate_site(site, ['192.0.2.0/24'])
        for node in ('waf-cluster-1', 'waf-cluster-2'):
            config = render(node, [site], 'test')
            self.assertIn('SecRuleRemoveById 941100 942100', config)
            self.assertLess(config.index('Include @owasp_crs/*.conf'), config.index('SecRuleRemoveById'))

    def test_parser_handles_escapes_and_commas(self):
        args = tokens('SecRule ARGS "@rx \\"quoted\\"" "id:123456,msg:\'hello, world\',tag:\'paranoia-level/2\'"')
        self.assertEqual(len(args), 4)
        self.assertEqual(action_values(args[-1], 'msg'), ['hello, world'])
        self.assertEqual(action_values(args[-1], 'id'), ['123456'])
        records = list(statements('# Comment\nSecAction \\\n  "id:123456,pass"\n'))
        self.assertEqual(records[0][0], 2)
        self.assertIn('id:123456', records[0][2])


class RuleAPITests(unittest.TestCase):
    def tearDown(self):
        app.dependency_overrides.clear()

    def test_catalog_requires_authentication(self):
        with TestClient(app) as client:
            self.assertEqual(client.get('/api/rules').status_code, 401)
            self.assertEqual(client.get('/api/rules/942100').status_code, 401)

    def test_viewer_can_inspect_but_cannot_save(self):
        app.dependency_overrides[current_user] = lambda: dict(id=1, username='viewer', role='viewer')
        with TestClient(app) as client:
            catalog = client.get('/api/rules')
            self.assertEqual(catalog.status_code, 200)
            self.assertEqual(len(catalog.json()['rules']), 625)
            self.assertNotIn('source', catalog.json()['rules'][0])
            rule = client.get('/api/rules/920170')
            self.assertEqual(rule.status_code, 200)
            self.assertIn('Content-Length', rule.json()['source'])
            self.assertEqual(client.get('/api/rules/999998').status_code, 404)
            self.assertEqual(client.patch('/api/sites/1/rules', json=dict(excluded_rules=[], exception_reason='',
                expected_excluded_rules=[], expected_exception_reason='')).status_code, 403)

    def test_invalid_selections_fail_before_database_access(self):
        app.dependency_overrides[current_user] = lambda: dict(id=1, username='engineer', role='engineer')
        with TestClient(app) as client, patch('control.app.db') as db:
            for excluded, reason in (([949110], 'Wrong'), ([942100], ''), ([True], 'Wrong')):
                response = client.patch('/api/sites/1/rules', json=dict(excluded_rules=excluded, exception_reason=reason,
                                       expected_excluded_rules=[], expected_exception_reason=''))
                self.assertEqual(response.status_code, 422)
            db.assert_not_called()


if __name__ == '__main__':
    unittest.main()
