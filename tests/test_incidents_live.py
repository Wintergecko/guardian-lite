import importlib.machinery
import json
import os
import pathlib
import stat
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('guardian_live_test', str(ROOT / 'sbin/guardian-helper'))
h = loader.load_module()


@unittest.skipUnless(os.geteuid() == 0, 'Security integration tests require root on isolated runner')
class IncidentsLiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name) / 'guardian'
        self.vhosts = pathlib.Path(self.tmp.name) / 'vhosts'
        self.vhosts.mkdir()
        self.original_root = h.ROOT
        self.original_vhosts = h.VHOSTS
        self.original_incident = h.INCIDENT_LOG
        self.original_alerts = h.ALERT_FILE
        self.original_monitor = h.MONITOR_CONFIG
        h.ROOT = self.root
        h.VHOSTS = self.vhosts
        h.INCIDENT_LOG = self.root / 'incidents.jsonl'
        h.ALERT_FILE = self.root / 'alerts.json'
        h.MONITOR_CONFIG = self.root / 'realtime.json'
        self.addCleanup(self.reset)
        h.prepare_dir()

    def reset(self):
        h.ROOT = self.original_root
        h.VHOSTS = self.original_vhosts
        h.INCIDENT_LOG = self.original_incident
        h.ALERT_FILE = self.original_alerts
        h.MONITOR_CONFIG = self.original_monitor

    def test_incident_log_safe_permissions_and_export(self):
        h.incident_log('file_change', 'warning', 'example.com', 'Test change', 'wp-includes/index.php')
        h.incident_log('operator', 'info', detail='Test operation')
        entries = h.incident_list()
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]['type'], 'operator')
        self.assertEqual(entries[1]['path'], 'wp-includes/index.php')
        self.assertEqual(stat.S_IMODE(h.INCIDENT_LOG.stat().st_mode), 0o600)
        self.assertNotIn('payload', entries[0])

    def test_email_settings_validation_and_off_by_default(self):
        self.assertFalse(h.alert_settings()['enabled'])
        with self.assertRaises(ValueError):
            h.set_alert_settings('oops\nBcc: attacker@example.com', True)
        saved = h.set_alert_settings('admin@example.com', True)
        self.assertTrue(saved['alerts']['enabled'])
        self.assertEqual(h.alert_settings()['recipient'], 'admin@example.com')
        with self.assertRaises(ValueError):
            h.alert_test() if not h.binary(h.MAIL_PATHS) else h.set_alert_settings('bad', True)
        h.set_alert_settings('', False)
        self.assertFalse(h.alert_settings()['enabled'])

    def test_monitor_config_never_starts_by_default(self):
        self.assertEqual(h.monitor_config(), {})
        with self.assertRaises(ValueError):
            h.monitor_set('bad/../../domain', 'on')
        with self.assertRaises(ValueError):
            h.monitor_set('example.com', 'toggle')

    def test_monitor_domain_enable_disable_with_mocked_launch(self):
        domain = 'example.com'
        docroot = self.vhosts / domain / 'httpdocs'
        docroot.mkdir(parents=True)
        # Site root must belong to non-root owner; no ownership modification required for this mocked test.
        with mock.patch.object(h, 'site_docroot', return_value=(docroot, 1001, 1001)):
            with mock.patch.object(h, 'monitor_launch', return_value=True) as launcher:
                result = h.monitor_set(domain, 'on')
                self.assertTrue(result['enabled'])
                self.assertEqual(h.monitor_config(), {domain: True})
                launcher.assert_called_once_with(domain)
                h.monitor_set(domain, 'off')
                self.assertEqual(h.monitor_config(), {})
