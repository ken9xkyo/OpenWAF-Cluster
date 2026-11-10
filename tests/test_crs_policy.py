"""Regression checks for CRS overrides; run with the control-plane venv."""
import os
import unittest

from fastapi import HTTPException
from pydantic import ValidationError

from control.app import Site, site_values
from control.render import NODES, POLICY_PARAMETERS, render, validate_site


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.site = dict(id=42, hostname='policy.example.com', backend_ip='192.0.2.10',
                         backend_port=3000, mode='On', paranoia=2)

    def validate(self, settings):
        return validate_site(dict(self.site, crs_settings=settings), ['192.0.2.0/24'])

    def test_old_sites_and_snapshots_use_defaults(self):
        self.assertEqual(validate_site(self.site, ['192.0.2.0/24'])['crs_settings'], {})
        config = render('waf-cluster-1', [self.site], 'old')
        self.assertIn('setvar:tx.blocking_paranoia_level=2', config)
        self.assertNotIn('setvar:tx.detection_paranoia_level=', config)
        self.assertNotIn('setvar:tx.inbound_anomaly_score_threshold=', config)

    def test_selected_overrides_precede_crs_rules_on_both_nodes(self):
        settings = {'detection_paranoia_level': 4, 'inbound_anomaly_score_threshold': 8}
        site = self.validate(settings)
        for node in NODES:
            config = render(node, [site], 'test')
            for key, value in settings.items():
                self.assertIn(f'setvar:tx.{key}={value}', config)
                self.assertLess(config.index(f'setvar:tx.{key}='), config.index('Include @owasp_crs/*.conf'))
            self.assertNotIn('setvar:tx.critical_anomaly_score=', config)
            self.assertEqual(config, render(node, [site], 'test'))

    def test_reject_unknown_variables_and_non_integer_values(self):
        for settings in ({'untrusted': 1}, {'notice_anomaly_score': True},
                         {'notice_anomaly_score': '2'}, {'notice_anomaly_score': 2.5}, [], None):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                self.validate(settings)
        for value in (True, '2', 2.5):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                Site(**dict(self.site_without_id(), crs_settings={'notice_anomaly_score': value}))

    def site_without_id(self):
        return {key: value for key, value in self.site.items() if key != 'id'}

    def test_parameter_bounds(self):
        for key, spec in POLICY_PARAMETERS.items():
            for value in (spec['min'] - 1, spec['max'] + 1):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.validate({key: value})
            self.validate({key: spec['max']})

    def test_detection_cannot_be_below_blocking(self):
        with self.assertRaisesRegex(ValueError, 'PL phát hiện'):
            self.validate({'detection_paranoia_level': 1})
        with self.assertRaises(ValueError):
            render('waf-cluster-1', [dict(self.site, crs_settings={'detection_paranoia_level': 1})], 'test')

    def test_api_returns_422_for_invalid_settings(self):
        from unittest.mock import patch
        with patch.dict(os.environ, BACKEND_ALLOWLIST='192.0.2.0/24'):
            for settings in ({'not_a_crs_variable': 4}, {'detection_paranoia_level': 1}):
                with self.subTest(settings=settings), self.assertRaises(HTTPException) as error:
                    site_values(Site(**dict(self.site_without_id(), crs_settings=settings)))
                self.assertEqual(error.exception.status_code, 422)


if __name__ == '__main__':
    unittest.main()
