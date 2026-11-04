"""Unit tests that need no Plesk server and do not touch host service state."""
import importlib.machinery
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import time
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).resolve().parents[1] / 'sbin' / 'guardian-helper'
loader = importlib.machinery.SourceFileLoader('guardian_helper', str(PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


class GuardianTests(unittest.TestCase):
    def test_accepts_normal_domain_and_punycode(self):
        self.assertTrue(helper.valid_domain('example.com'))
        self.assertTrue(helper.valid_domain('xn--bcher-kva.de'))
        self.assertTrue(helper.valid_domain('www.example.co.uk'))

    def test_rejects_injection_and_path_traversal(self):
        for domain in ('../etc/passwd', '/etc', '$(id).org', 'bad;rm -rf /',
                       '-x.example.com', 'domain', 'a..b.com', 'a_.com',
                       '--help', '', 'a' * 254 + '.com'):
            with self.subTest(domain=domain):
                self.assertFalse(helper.valid_domain(domain))

    def test_rejects_docroot_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = pathlib.Path(tmp)
            vhosts = home / 'vhosts'
            root = vhosts / 'example.com'
            root.mkdir(parents=True)
            (root / 'httpdocs').symlink_to('/etc')
            with mock.patch.object(helper, 'VHOSTS', vhosts), \
                     mock.patch.object(helper, 'plesk_hosting_path', return_value=(str(root / 'httpdocs'), str(root))):
                with self.assertRaisesRegex(ValueError, 'ausserhalb'):
                    helper.site_docroot('example.com')

    def test_rejects_root_owned_docroot(self):
        with tempfile.TemporaryDirectory() as tmp:
            vhosts = pathlib.Path(tmp) / 'vhosts'
            root = vhosts / 'example.com'
            (root / 'httpdocs').mkdir(parents=True)
            # In root containers, valid vhosts owned by root are refused.
            with mock.patch.object(helper, 'VHOSTS', vhosts), \
                     mock.patch.object(helper, 'plesk_hosting_path', return_value=(str(root / 'httpdocs'), str(root))):
                if (root / 'httpdocs').stat().st_uid == 0:
                    with self.assertRaisesRegex(ValueError, 'root-eigen'):
                        helper.site_docroot('example.com')

    def test_fail2ban_parsing(self):
        def fake_execute(args, timeout=5):
            if args[-1] == 'status':
                return subprocess.CompletedProcess(args, 0, 'Status\n`- Jail list:\tsshd, plesk-login\n', '')
            return subprocess.CompletedProcess(args, 0, 'Currently banned:\t2\n', '')
        with mock.patch.object(helper, 'binary', return_value='/usr/bin/fail2ban-client'), \
             mock.patch.object(helper, 'execute', side_effect=fake_execute):
            result = helper.fail2ban_status()
        self.assertTrue(result['running'])
        self.assertEqual(result['jail_count'], 2)
        self.assertEqual(result['banned_total'], 4)

    def test_firewall_detects_installed_but_inactive_plesk_firewall(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = pathlib.Path(tmp) / 'settings'
            settings.touch()
            def fake_execute(args, timeout=5):
                return subprocess.CompletedProcess(args, 3, 'inactive\n', '')
            with mock.patch.object(helper, 'FIREWALL_SETTINGS', settings), \
                     mock.patch.object(helper, 'binary', return_value='/usr/bin/systemctl'), \
                     mock.patch.object(helper, 'execute', side_effect=fake_execute):
                result = helper.firewall_status()
        self.assertTrue(result['installed'])
        self.assertTrue(result['status_known'])
        self.assertFalse(result['plesk_firewall_active'])

    def test_firewall_checks_both_current_and_legacy_service_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = pathlib.Path(tmp) / 'settings'
            settings.touch()
            def fake_execute(args, timeout=5):
                if args[-1] == 'plesk-firewall':
                    return subprocess.CompletedProcess(args, 4, '', 'not-found')
                return subprocess.CompletedProcess(args, 0, 'active\n', '')
            with mock.patch.object(helper, 'FIREWALL_SETTINGS', settings), \
                     mock.patch.object(helper, 'binary', return_value='/usr/bin/systemctl'), \
                     mock.patch.object(helper, 'execute', side_effect=fake_execute):
                result = helper.firewall_status()
        self.assertTrue(result['installed'])
        self.assertTrue(result['plesk_firewall_active'])
        self.assertEqual(result['service'], 'psa-firewall')

    def test_guardian_firewall_rules_only_lists_its_own_valid_custom_denies(self):
        rows = [
            {'id': 41, 'class': 'custom', 'name': 'Guardian Lite managed deny 203.0.113.25/32',
             'direction': 'input', 'action': 'deny', 'from': ['203.0.113.25'], 'ports': ''},
            {'id': 42, 'class': 'custom', 'name': 'Other tool rule', 'direction': 'input',
             'action': 'deny', 'from': ['203.0.113.26'], 'ports': ''},
            {'id': 43, 'class': 'custom', 'name': 'Guardian Lite managed deny 203.0.113.0/24',
             'direction': 'input', 'action': 'allow', 'from': ['203.0.113.0/24'], 'ports': ''},
            {'id': 44, 'class': 'custom', 'name': 'Guardian Lite managed port allow tcp 2222 203.0.113.25/32',
             'direction': 'input', 'action': 'allow', 'from': ['203.0.113.25'], 'ports': '2222/tcp'},
            {'id': 45, 'class': 'custom', 'name': 'Guardian Lite managed port deny udp 53 203.0.113.0/24',
             'direction': 'input', 'action': 'deny', 'from': ['203.0.113.0/24'], 'ports': '53/udp'},
            {'id': 46, 'class': 'custom', 'name': 'Guardian Lite managed port allow tcp 2222 203.0.113.25/32',
             'direction': 'input', 'action': 'deny', 'from': ['203.0.113.25'], 'ports': '2222/tcp'},
        ]
        with mock.patch.object(helper, 'binary', return_value='/usr/bin/plesk'), \
             mock.patch.object(helper, 'execute', return_value=subprocess.CompletedProcess(
                 ['plesk'], 0, json.dumps(rows), '')):
            result = helper.firewall_rules()
        self.assertTrue(result['available'])
        self.assertEqual([item['id'] for item in result['rules']], ['45', '41', '44'])
        self.assertEqual(result['rules'][0]['network'], '203.0.113.0/24')
        self.assertEqual(result['rules'][1]['kind'], 'ip_deny')
        self.assertEqual(result['rules'][2]['ports'], '2222/tcp')

    def test_guardian_firewall_rules_displays_confirmed_expiry(self):
        row = {'id': 41, 'class': 'custom', 'name': 'Guardian Lite managed deny 203.0.113.25/32',
               'direction': 'input', 'action': 'deny', 'from': ['203.0.113.25'], 'ports': ''}
        with tempfile.TemporaryDirectory() as tmp:
            expiry_path = pathlib.Path(tmp) / 'firewall-expiries.json'
            expires = int(time.time()) + 3600
            helper.write_json(expiry_path, {'203.0.113.25/32': expires})
            with mock.patch.object(helper, 'FIREWALL_EXPIRIES', expiry_path), \
                 mock.patch.object(helper, 'binary', return_value='/usr/bin/plesk'), \
                 mock.patch.object(helper, 'execute', return_value=subprocess.CompletedProcess(
                     ['plesk'], 0, json.dumps([row]), '')):
                result = helper.firewall_rules()
        self.assertEqual(result['rules'][0]['expires_epoch'], expires)
        self.assertEqual(result['rules'][0]['expires_at'], helper.datetime.datetime.fromtimestamp(
            expires, helper.datetime.timezone.utc).isoformat())

    def test_guardian_firewall_ban_stages_native_rule_and_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            root = base / 'guardian'
            root.mkdir(mode=0o700)
            settings = base / 'settings'
            settings.touch()
            calls = []
            rows = [json.dumps([])]
            def fake_execute(args, timeout=5):
                calls.append(args)
                if args[-1] == '--list-json':
                    return subprocess.CompletedProcess(args, 0, rows[0], '')
                return subprocess.CompletedProcess(args, 0, '', '')
            with mock.patch.object(helper, 'ROOT', root), \
                 mock.patch.object(helper, 'FIREWALL_PENDING', root / 'firewall-pending.json'), \
                 mock.patch.object(helper, 'FIREWALL_EXPIRIES', root / 'firewall-expiries.json'), \
                 mock.patch.object(helper, 'FIREWALL_SETTINGS', settings), \
                 mock.patch.object(helper, 'PLESK_BINARIES', ('/usr/bin/plesk',)), \
                 mock.patch.object(helper, 'SYSTEMCTL_PATHS', ()), \
                 mock.patch.object(helper, 'firewall_status', return_value={'plesk_firewall_active': True}), \
                 mock.patch.object(helper, 'binary', side_effect=lambda paths: paths[0] if paths else None), \
                 mock.patch.object(helper, 'execute', side_effect=fake_execute), \
                 mock.patch.object(helper, 'incident_log'):
                result = helper.firewall_action('ban', '203.0.113.25', '198.51.100.8', 3600)
                self.assertEqual(result['state'], 'awaiting_confirmation')
                self.assertEqual(result['network'], '203.0.113.25/32')
                self.assertEqual(result['ttl_seconds'], 3600)
                self.assertTrue((root / 'firewall-pending.json').is_file())
                self.assertTrue(any('--apply' in call for call in calls))
                confirmed = helper.firewall_action('confirm')
                self.assertEqual(confirmed['state'], 'confirmed')
                expires = helper.read_json(root / 'firewall-expiries.json', {})['203.0.113.25/32']
                self.assertGreater(expires, time.time())
                self.assertFalse((root / 'firewall-pending.json').exists())
                rows[0] = json.dumps([{
                    'id': 41, 'class': 'custom', 'name': 'Guardian Lite managed deny 203.0.113.25/32',
                    'direction': 'input', 'action': 'deny', 'from': ['203.0.113.25'], 'ports': '',
                }])
                removed = helper.firewall_action('unban', '203.0.113.25', '198.51.100.8')
                self.assertEqual(removed['state'], 'awaiting_confirmation')
                self.assertTrue(any('--remove-rules' in call and '41' in call for call in calls))
                cancelled = helper.firewall_action('cancel')
                self.assertEqual(cancelled['state'], 'cancelled')
                self.assertFalse((root / 'firewall-pending.json').exists())
                self.assertIn('203.0.113.25/32', helper.read_json(root / 'firewall-expiries.json', {}))
                helper.firewall_action('unban', '203.0.113.25')
                helper.firewall_action('confirm')
                self.assertNotIn('203.0.113.25/32', helper.read_json(root / 'firewall-expiries.json', {}))

    def test_guardian_port_firewall_rules_stage_and_remove_only_owned_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            root = base / 'guardian'
            root.mkdir(mode=0o700)
            settings = base / 'settings'
            settings.touch()
            calls = []
            rows = [json.dumps([])]
            def fake_execute(args, timeout=5):
                calls.append(args)
                if args[-1] == '--list-json':
                    return subprocess.CompletedProcess(args, 0, rows[0], '')
                return subprocess.CompletedProcess(args, 0, '', '')
            with mock.patch.object(helper, 'ROOT', root), \
                 mock.patch.object(helper, 'FIREWALL_PENDING', root / 'firewall-pending.json'), \
                 mock.patch.object(helper, 'FIREWALL_EXPIRIES', root / 'firewall-expiries.json'), \
                 mock.patch.object(helper, 'FIREWALL_SETTINGS', settings), \
                 mock.patch.object(helper, 'PLESK_BINARIES', ('/usr/bin/plesk',)), \
                 mock.patch.object(helper, 'SYSTEMCTL_PATHS', ()), \
                 mock.patch.object(helper, 'firewall_status', return_value={'plesk_firewall_active': True}), \
                 mock.patch.object(helper, 'binary', side_effect=lambda paths: paths[0] if paths else None), \
                 mock.patch.object(helper, 'execute', side_effect=fake_execute), \
                 mock.patch.object(helper, 'incident_log'):
                result = helper.firewall_action('port-allow', '203.0.113.25', '198.51.100.8',
                                                0, '2222', 'tcp')
                self.assertEqual(result['state'], 'awaiting_confirmation')
                set_call = next(call for call in calls if '--set-rule' in call)
                self.assertIn('-action', set_call)
                self.assertEqual(set_call[set_call.index('-action') + 1], 'allow')
                self.assertEqual(set_call[set_call.index('-ports') + 1], '2222/tcp')
                self.assertEqual(set_call[set_call.index('-remote-addresses') + 1], '203.0.113.25/32')
                helper.firewall_action('confirm')
                rows[0] = json.dumps([{
                    'id': 77, 'class': 'custom',
                    'name': 'Guardian Lite managed port allow tcp 2222 203.0.113.25/32',
                    'direction': 'input', 'action': 'allow', 'from': ['203.0.113.25'], 'ports': '2222/tcp',
                }])
                removed = helper.firewall_action('port-remove', '77')
                self.assertEqual(removed['state'], 'awaiting_confirmation')
                self.assertTrue(any('--remove-rules' in call and '77' in call for call in calls))
                helper.firewall_action('confirm')

    def test_guardian_port_firewall_rejects_broad_allow_and_admin_lockout(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = pathlib.Path(tmp) / 'settings'
            settings.touch()
            with mock.patch.object(helper, 'FIREWALL_SETTINGS', settings), \
                 mock.patch.object(helper, 'PLESK_BINARIES', ('/usr/bin/plesk',)), \
                 mock.patch.object(helper, 'SYSTEMCTL_PATHS', ()), \
                 mock.patch.object(helper, 'binary', side_effect=lambda paths: paths[0] if paths else None), \
                 mock.patch.object(helper, 'firewall_status', return_value={'plesk_firewall_active': True}):
                with self.assertRaisesRegex(ValueError, 'einzelne IPv4- oder IPv6-Adresse'):
                    helper._firewall_action('port-allow', '203.0.113.0/24', '', 0, '22', 'tcp')
                with self.assertRaisesRegex(ValueError, 'Admin-Verbindungs-IP'):
                    helper._firewall_action('port-deny', '198.51.100.8', '198.51.100.8', 0, '22', 'tcp')
                with self.assertRaisesRegex(ValueError, 'Port oder Transportprotokoll'):
                    helper._firewall_action('port-deny', '203.0.113.25', '198.51.100.8', 0, '70000', 'tcp')

    def test_guardian_firewall_expiry_scheduler_unbans_only_due_guardian_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            expired = '203.0.113.25/32'
            future = '203.0.113.26/32'
            helper.write_json(root / 'firewall-expiries.json', {expired: 100, future: int(time.time()) + 86400})
            calls = []
            def action(operation, target='', remote_address='', ttl_seconds=0):
                calls.append((operation, target))
                return {'state': 'awaiting_confirmation' if operation == 'unban' else 'confirmed'}
            with mock.patch.object(helper, 'ROOT', root), \
                 mock.patch.object(helper, 'FIREWALL_PENDING', root / 'firewall-pending.json'), \
                 mock.patch.object(helper, 'FIREWALL_EXPIRIES', root / 'firewall-expiries.json'), \
                 mock.patch.object(helper, 'firewall_rules', return_value={
                     'available': True, 'limited': False, 'rules': [{'network': expired}]}), \
                 mock.patch.object(helper, 'firewall_action', side_effect=action), \
                 mock.patch.object(helper.os, 'geteuid', return_value=0), \
                 mock.patch.object(helper, 'incident_log'):
                result = helper.firewall_expiry_tick()
            self.assertEqual(result['removed'], 1)
            self.assertEqual(calls, [('unban', expired), ('confirm', '')])

    def test_guardian_firewall_expiry_scheduler_caps_backlog_at_ten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            networks = ['203.0.113.%d/32' % host for host in range(1, 12)]
            helper.write_json(root / 'firewall-expiries.json', {network: 100 for network in networks})
            calls = []
            def action(operation, target='', remote_address='', ttl_seconds=0):
                calls.append((operation, target))
                return {'state': 'awaiting_confirmation' if operation == 'unban' else 'confirmed'}
            with mock.patch.object(helper, 'ROOT', root), \
                 mock.patch.object(helper, 'FIREWALL_PENDING', root / 'firewall-pending.json'), \
                 mock.patch.object(helper, 'FIREWALL_EXPIRIES', root / 'firewall-expiries.json'), \
                 mock.patch.object(helper, 'firewall_rules', return_value={
                     'available': True, 'limited': False,
                     'rules': [{'network': network} for network in networks]}), \
                 mock.patch.object(helper, 'firewall_action', side_effect=action), \
                 mock.patch.object(helper.os, 'geteuid', return_value=0), \
                 mock.patch.object(helper, 'incident_log'):
                result = helper.firewall_expiry_tick()
            self.assertEqual(result['removed'], 10)
            self.assertEqual(result['remaining_due'], 1)
            self.assertEqual(len(calls), 20)

    def test_guardian_firewall_rejects_admin_lockout_and_broad_cidr(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = pathlib.Path(tmp) / 'settings'
            settings.touch()
            with mock.patch.object(helper, 'FIREWALL_SETTINGS', settings), \
                 mock.patch.object(helper, 'PLESK_BINARIES', ('/usr/bin/plesk',)), \
                 mock.patch.object(helper, 'SYSTEMCTL_PATHS', ()), \
                 mock.patch.object(helper, 'binary', side_effect=lambda paths: paths[0] if paths else None), \
                 mock.patch.object(helper, 'firewall_status', return_value={'plesk_firewall_active': True}):
                with self.assertRaisesRegex(ValueError, 'Admin-Verbindungs-IP'):
                    helper.firewall_action('ban', '198.51.100.8', '198.51.100.8')
                with self.assertRaisesRegex(ValueError, 'Ungueltige Sperrdauer'):
                    helper._firewall_action('ban', '203.0.113.25', '198.51.100.8', 7200)
        with self.assertRaisesRegex(ValueError, 'Zu grosses Netz'):
            helper._firewall_target('203.0.0.0/16')

    def test_unknown_command_returns_error(self):
        with mock.patch.object(helper, 'respond', return_value=1) as reply:
            self.assertEqual(helper.main(['shell', 'rm', '-rf', '/']), 1)
            self.assertFalse(reply.call_args.args[0]['ok'])

    def test_firewall_port_cli_routes_only_fixed_operation_arguments(self):
        with mock.patch.object(helper, 'firewall_action', return_value={'ok': True}) as action, \
                mock.patch.object(helper, 'respond', return_value=0):
            self.assertEqual(helper.main(['firewall-action', 'port-allow', '203.0.113.25',
                                          '198.51.100.8', '2222', 'tcp']), 0)
            action.assert_called_with('port-allow', '203.0.113.25', '198.51.100.8', 0, '2222', 'tcp')
            self.assertEqual(helper.main(['firewall-action', 'port-remove', '77']), 0)
            action.assert_called_with('port-remove', '77', '', 0, '', '')


if __name__ == '__main__':
    unittest.main()
