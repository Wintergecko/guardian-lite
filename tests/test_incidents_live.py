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
        self.original_alert_queue = h.ALERT_QUEUE_FILE
        self.original_alert_queue_lock = h.ALERT_QUEUE_LOCK
        self.original_monitor = h.MONITOR_CONFIG
        h.ROOT = self.root
        h.VHOSTS = self.vhosts
        h.INCIDENT_LOG = self.root / 'incidents.jsonl'
        h.ALERT_FILE = self.root / 'alerts.json'
        h.ALERT_QUEUE_FILE = self.root / 'alerts-outbox.json'
        h.ALERT_QUEUE_LOCK = self.root / 'alerts-outbox.lock'
        h.MONITOR_CONFIG = self.root / 'realtime.json'
        self.addCleanup(self.reset)
        h.prepare_dir()

    def reset(self):
        h.ROOT = self.original_root
        h.VHOSTS = self.original_vhosts
        h.INCIDENT_LOG = self.original_incident
        h.ALERT_FILE = self.original_alerts
        h.ALERT_QUEUE_FILE = self.original_alert_queue
        h.ALERT_QUEUE_LOCK = self.original_alert_queue_lock
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

    def test_failed_email_is_queued_then_retried_with_transport_status(self):
        h.set_alert_settings('admin@example.com', True)
        with mock.patch.object(h, 'notify_alert', side_effect=ValueError('mail transport unavailable')):
            event = h.incident_log('malware_detected', 'critical', 'example.com', 'ClamAV test signature')
        status = h.alert_queue_status()
        self.assertEqual(status['pending'], 1)
        self.assertEqual(status['failed'], 0)
        self.assertEqual(stat.S_IMODE(h.ALERT_QUEUE_FILE.stat().st_mode), 0o600)
        with mock.patch.object(h, 'notify_alert', return_value=True) as send:
            result = h.alert_queue_process(force=True)
        self.assertEqual(result['delivered'], 1)
        self.assertEqual(h.alert_queue_status()['pending'], 0)
        send.assert_called_once()

    def test_alert_queue_is_bounded_and_invalid_records_fail_closed(self):
        entries = []
        for index in range(h.MAX_ALERT_QUEUE):
            event = {'id': '%032x' % index, 'type': 'malware_detected', 'time': h.utc_now(),
                     'severity': 'critical', 'domain': 'example.com', 'path': 'wp-content/a.php',
                     'detail': 'ClamAV signature'}
            entries.append({'id': event['id'], 'event': event, 'created_epoch': time.time(),
                            'attempts': 0, 'next_attempt': time.time() + 3600,
                            'last_error': '', 'state': 'pending'})
        h.alert_queue_write(entries)
        overflow = {'id': 'f' * 32, 'type': 'malware_detected', 'time': h.utc_now(), 'severity': 'critical',
                    'domain': 'example.com', 'path': 'wp-content/b.php', 'detail': 'ClamAV signature'}
        with self.assertRaisesRegex(ValueError, 'Warteschlange voll'):
            h.alert_queue_add(overflow, 'mail transport unavailable')
        h.alert_queue_write([{}])
        with self.assertRaisesRegex(ValueError, 'ungueltigen Datensatz'):
            h.alert_queue_read()
        self.assertIn('error', h.alert_queue_status())

    def test_alert_queue_failure_backs_off_and_can_be_manually_retried(self):
        h.set_alert_settings('admin@example.com', True)
        event = {'id': 'a' * 32, 'type': 'malware_detected', 'time': h.utc_now(), 'severity': 'critical',
                 'domain': 'example.com', 'path': 'wp-content/a.php', 'detail': 'ClamAV signature'}
        h.alert_queue_add(event, 'mail transport unavailable')
        with mock.patch.object(h, 'notify_alert', side_effect=ValueError('still offline')):
            result = h.alert_queue_process(force=True)
        self.assertEqual(result['failed'], 1)
        queued = h.alert_queue_read()[0]
        self.assertEqual(queued['attempts'], 1)
        self.assertEqual(queued['state'], 'pending')
        self.assertGreater(queued['next_attempt'], time.time())
        self.assertEqual(h.alert_queue_status()['pending'], 1)
        queued['attempts'] = h.MAX_ALERT_ATTEMPTS - 1
        queued['next_attempt'] = 0
        h.alert_queue_write([queued])
        with mock.patch.object(h, 'notify_alert', side_effect=ValueError('still offline')):
            result = h.alert_queue_process()
        self.assertEqual(result['failed'], 1)
        self.assertEqual(h.alert_queue_status()['failed'], 1)
        with mock.patch.object(h, 'notify_alert', return_value=True):
            result = h.alert_queue_process(force=True)
        self.assertEqual(result['delivered'], 1)
        self.assertEqual(h.alert_queue_status()['failed'], 0)

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
