"""Unit tests that need no Plesk server and do not touch host service state."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import stat
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
            return subprocess.CompletedProcess(args, 0,
                'Currently banned:\t2\nBanned IP list:\t192.0.2.10, 2001:db8::10, not-an-ip\n', '')
        with mock.patch.object(helper, 'binary', return_value='/usr/bin/fail2ban-client'), \
             mock.patch.object(helper, 'execute', side_effect=fake_execute):
            result = helper.fail2ban_status()
        self.assertTrue(result['running'])
        self.assertEqual(result['jail_count'], 2)
        self.assertEqual(result['banned_total'], 4)
        self.assertEqual(result['jails'][0]['banned_ips'], ['192.0.2.10', '2001:db8::10'])
        self.assertTrue(result['jails'][0]['banned_ips_available'])

    def test_fail2ban_jail_details_return_effective_values_without_raw_regex(self):
        outputs = {
            'maxretry': '5\n',
            'findtime': '600\n',
            'bantime': '-1\n',
            'failregex': 'The following regular expression are defined:\n|- [0]: ^Failed login\n|- [1]: ^Invalid user\n',
            'actions': 'The jail ssh has the following actions:\niptables\n',
        }
        def fake_execute(args, timeout=5):
            self.assertEqual(args[:3], ['/usr/bin/fail2ban-client', 'get', 'ssh'])
            self.assertEqual(timeout, 3)
            return subprocess.CompletedProcess(args, 0, outputs[args[3]], '')
        with mock.patch.object(helper.os, 'geteuid', return_value=0), \
             mock.patch.object(helper, 'binary', return_value='/usr/bin/fail2ban-client'), \
             mock.patch.object(helper, 'fail2ban_status', return_value={
                 'running': True, 'jails': [{'name': 'ssh'}]}), \
             mock.patch.object(helper, 'fail2ban_read_override', return_value=(b'', False)), \
             mock.patch.object(helper, 'fail2ban_backup_list', return_value=[]), \
             mock.patch.object(helper, 'execute', side_effect=fake_execute):
            result = helper.fail2ban_jail_details('ssh')
        self.assertEqual(result, {'ok': True, 'jail': 'ssh', 'settings': {
            'maxretry': 5, 'findtime': 600, 'bantime': -1,
            'filter_regex_count': 2, 'actions': ['iptables']}, 'managed': False,
            'override_sha256': helper.hashlib.sha256(b'').hexdigest(), 'backups': []})
        self.assertNotIn('Failed login', json.dumps(result))

    def test_fail2ban_jail_details_reject_invalid_or_inactive_jails(self):
        with mock.patch.object(helper.os, 'geteuid', return_value=0), \
             mock.patch.object(helper, 'binary', return_value='/usr/bin/fail2ban-client'), \
             mock.patch.object(helper, 'execute') as execute:
            with self.assertRaises(ValueError):
                helper.fail2ban_jail_details('../ssh')
            self.assertFalse(execute.called)
            with mock.patch.object(helper, 'fail2ban_status', return_value={
                    'running': True, 'jails': [{'name': 'ssh'}]}):
                with self.assertRaises(ValueError):
                    helper.fail2ban_jail_details('missing')
            self.assertFalse(execute.called)

    def test_fail2ban_override_is_restricted_to_validated_guardian_values(self):
        source = b'# Guardian Lite managed Fail2ban overrides\n\n[ssh]\nmaxretry = 5\nfindtime = 600\nbantime = -1\n'
        self.assertEqual(helper.fail2ban_parse_override(source), {
            'ssh': {'maxretry': 5, 'findtime': 600, 'bantime': -1}})
        self.assertEqual(helper.fail2ban_serialize_override(
            helper.fail2ban_parse_override(source)), source)
        for invalid in (
                b'[ssh]\nmaxretry = 5\n',
                b'# foreign configuration\n\n[ssh]\nmaxretry = 5\nfindtime = 600\nbantime = 60\n',
                b'# Guardian Lite managed Fail2ban overrides\n\n[ssh]\nmaxretry = 0\nfindtime = 600\nbantime = 60\n',
                b'# Guardian Lite managed Fail2ban overrides\n\n[ssh]\nmaxretry = 5\nfindtime = 600\nbantime = 60\nignoreip = 192.0.2.1\n'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                helper.fail2ban_parse_override(invalid)

    def test_fail2ban_update_backs_up_before_atomic_override_and_verifies(self):
        settings = {'maxretry': 7, 'findtime': 900, 'bantime': 1800}
        previous = {'maxretry': 5, 'findtime': 600, 'bantime': 300}
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = pathlib.Path(tmp) / 'fail2ban.lock'
            def open_lock():
                return os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            with mock.patch.object(helper.os, 'geteuid', return_value=0), \
                 mock.patch.object(helper, 'binary', return_value='/usr/bin/fail2ban-client'), \
                 mock.patch.object(helper, 'fail2ban_active_jail'), \
                 mock.patch.object(helper, 'fail2ban_prepare_backup_dir'), \
                 mock.patch.object(helper, 'fail2ban_open_lock', side_effect=open_lock), \
                 mock.patch.object(helper, 'fail2ban_read_override', return_value=(b'', False)), \
                 mock.patch.object(helper, 'fail2ban_runtime_settings', return_value=previous), \
                 mock.patch.object(helper, 'fail2ban_store_backup', return_value='a' * 32) as backup, \
                 mock.patch.object(helper, 'fail2ban_write_override') as write, \
                 mock.patch.object(helper, 'fail2ban_apply_and_verify', return_value=settings) as verify, \
                 mock.patch.object(helper, 'incident_log'):
                result = helper.fail2ban_update_jail('ssh', settings, helper.hashlib.sha256(b'').hexdigest())
        self.assertTrue(result['ok'])
        self.assertEqual(result['backup_id'], 'a' * 32)
        self.assertEqual(backup.call_args.args[:3], ('ssh', b'', False))
        write.assert_called_once_with(helper.fail2ban_serialize_override({'ssh': settings}))
        verify.assert_called_once_with('/usr/bin/fail2ban-client', 'ssh', settings)

    def test_fail2ban_update_rolls_back_after_apply_failure(self):
        settings = {'maxretry': 7, 'findtime': 900, 'bantime': 1800}
        previous = {'maxretry': 5, 'findtime': 600, 'bantime': 300}
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = pathlib.Path(tmp) / 'fail2ban.lock'
            def open_lock():
                return os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            with mock.patch.object(helper.os, 'geteuid', return_value=0), \
                 mock.patch.object(helper, 'binary', return_value='/usr/bin/fail2ban-client'), \
                 mock.patch.object(helper, 'fail2ban_active_jail'), \
                 mock.patch.object(helper, 'fail2ban_prepare_backup_dir'), \
                 mock.patch.object(helper, 'fail2ban_open_lock', side_effect=open_lock), \
                 mock.patch.object(helper, 'fail2ban_read_override', return_value=(b'', False)), \
                 mock.patch.object(helper, 'fail2ban_runtime_settings', return_value=previous), \
                 mock.patch.object(helper, 'fail2ban_store_backup', return_value='a' * 32), \
                 mock.patch.object(helper, 'fail2ban_write_override'), \
                 mock.patch.object(helper, 'fail2ban_restore_override') as restore, \
                 mock.patch.object(helper, 'fail2ban_apply_and_verify',
                                   side_effect=[ValueError('invalid config'), previous]) as verify, \
                 mock.patch.object(helper, 'incident_log'):
                with self.assertRaisesRegex(ValueError, 'wurde zurueckgerollt'):
                    helper.fail2ban_update_jail('ssh', settings, helper.hashlib.sha256(b'').hexdigest())
        restore.assert_called_once_with(b'', False)
        self.assertEqual(verify.call_count, 2)

    def test_fail2ban_restore_preserves_overrides_for_other_jails(self):
        backup_id = 'b' * 32
        previous = {'maxretry': 5, 'findtime': 600, 'bantime': 300}
        current_settings = {'maxretry': 7, 'findtime': 900, 'bantime': 1800}
        before = helper.fail2ban_serialize_override({'ssh': previous})
        current = helper.fail2ban_serialize_override({
            'ssh': current_settings,
            'ftp': {'maxretry': 3, 'findtime': 400, 'bantime': 500}})
        backup = {'id': backup_id, 'jail': 'ssh', 'before_exists': True,
                  'before_content': before.decode('utf-8'), 'before_settings': previous}
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = pathlib.Path(tmp) / 'fail2ban.lock'
            def open_lock():
                return os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            original_lstat = pathlib.Path.lstat
            def fake_lstat(path):
                if path.name == backup_id + '.json':
                    return type('FileInfo', (), {
                        'st_mode': stat.S_IFREG | 0o600, 'st_uid': 0, 'st_nlink': 1})()
                return original_lstat(path)
            with mock.patch.object(helper.os, 'geteuid', return_value=0), \
                 mock.patch.object(helper, 'binary', return_value='/usr/bin/fail2ban-client'), \
                 mock.patch.object(helper, 'fail2ban_active_jail'), \
                 mock.patch.object(helper, 'fail2ban_prepare_backup_dir'), \
                 mock.patch.object(helper, 'fail2ban_open_lock', side_effect=open_lock), \
                 mock.patch.object(helper, 'fail2ban_read_override', return_value=(current, True)), \
                 mock.patch.object(helper, 'fail2ban_runtime_settings', return_value=current_settings), \
                 mock.patch.object(helper, 'fail2ban_store_backup', return_value='c' * 32), \
                 mock.patch.object(helper, 'fail2ban_restore_override') as restore, \
                 mock.patch.object(helper, 'fail2ban_apply_and_verify', return_value=previous), \
                 mock.patch.object(helper, 'incident_log'), \
                 mock.patch.object(pathlib.Path, 'lstat', fake_lstat), \
                 mock.patch.object(helper, 'read_json', return_value=backup):
                result = helper.fail2ban_restore_jail(
                    'ssh', backup_id, helper.hashlib.sha256(current).hexdigest())
        self.assertTrue(result['ok'])
        restored, existed = restore.call_args.args
        self.assertTrue(existed)
        self.assertEqual(helper.fail2ban_parse_override(restored), {
            'ssh': previous,
            'ftp': {'maxretry': 3, 'findtime': 400, 'bantime': 500}})

    def test_crowdsec_decisions_are_bounded_and_validated(self):
        payload = [{
            'scope': 'Ip', 'value': '198.51.100.23', 'type': 'ban',
            'scenario': 'crowdsecurity/ssh-bf', 'origin': 'crowdsec', 'duration': '4h'},
            {'scope': 'range', 'value': '2001:db8::/64', 'type': 'ban'},
            {'scope': 'username', 'value': 'root', 'type': 'ban'},
            {'scope': 'ip', 'value': 'not-an-ip', 'type': 'ban'}]
        def fake_execute(args, timeout=5):
            if args[1:3] == ['decisions', 'list']:
                self.assertEqual(timeout, 5)
                self.assertEqual(args[1:4], ['decisions', 'list', '--output'])
                return subprocess.CompletedProcess(args, 0, json.dumps(payload), '')
            if args[1:3] == ['is-active', 'crowdsec']:
                return subprocess.CompletedProcess(args, 3, 'inactive\n', '')
            return subprocess.CompletedProcess(args, 0, '', '')
        with mock.patch.object(helper, 'binary', return_value='/usr/bin/cscli'), \
             mock.patch.object(helper, 'execute', side_effect=fake_execute):
            result = helper.crowdsec_status()
        self.assertTrue(result['installed'])
        self.assertTrue(result['available'])
        self.assertEqual(result['decision_count'], 4)
        self.assertEqual(len(result['decisions']), 2)
        self.assertEqual(result['decisions'][0]['ip'], '198.51.100.23')
        self.assertEqual(result['decisions'][1]['network'], '2001:db8::/64')
        self.assertEqual(result['decisions'][1]['ip'], '')

    def test_crowdsec_unavailable_or_invalid_json_is_not_reported_as_empty(self):
        with mock.patch.object(helper, 'binary', return_value='/usr/bin/cscli'), \
             mock.patch.object(helper, 'execute', return_value=subprocess.CompletedProcess(
                 ['/usr/bin/cscli'], 1, '', 'permission denied')):
            failed = helper.crowdsec_status()
        with mock.patch.object(helper, 'binary', return_value='/usr/bin/cscli'), \
             mock.patch.object(helper, 'execute', return_value=subprocess.CompletedProcess(
                 ['/usr/bin/cscli'], 0, 'not json', '')):
            invalid = helper.crowdsec_status()
        self.assertTrue(failed['installed'])
        self.assertFalse(failed['available'])
        self.assertFalse(invalid['available'])

    def test_crowdsec_appsec_status_checks_local_listener_and_apache_without_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            acquisition = pathlib.Path(tmp) / 'appsec.yaml'
            bouncer = pathlib.Path(tmp) / 'bouncer.conf'
            acquisition.write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\n')
            bouncer.write_text('CrowdsecAPIKey secret-must-not-leak\nCrowdsecAppsec On\n'
                               'CrowdsecAppsecURL http://127.0.0.1:7422\n')
            def fake_binary(paths):
                if paths == helper.CROWDSEC_PATHS:
                    return '/usr/bin/cscli'
                if paths == helper.SYSTEMCTL_PATHS:
                    return '/usr/bin/systemctl'
                return '/usr/sbin/apache2ctl'
            def fake_execute(args, timeout=5):
                if args[1:3] == ['decisions', 'list']:
                    return subprocess.CompletedProcess(args, 0, '[]', '')
                if args[1:3] == ['is-active', 'crowdsec']:
                    return subprocess.CompletedProcess(args, 0, 'active\n', '')
                if 'DUMP_INCLUDES' in args:
                    return subprocess.CompletedProcess(args, 0, str(bouncer) + '\n', '')
                return subprocess.CompletedProcess(args, 0, ' crowdsec_module (shared)\n', '')
            with mock.patch.object(helper, 'CROWDSEC_APPSEC_CONFIG', acquisition), \
                 mock.patch.object(helper, 'CROWDSEC_BOUNCER_CONFIG', bouncer), \
                 mock.patch.object(helper, 'binary', side_effect=fake_binary), \
                 mock.patch.object(helper, 'execute', side_effect=fake_execute):
                result = helper.crowdsec_status()
        self.assertEqual(result['appsec'], {
            'engine_running': True, 'acquisition_configured': True,
            'loopback_listener': True, 'apache_module_loaded': True,
            'bouncer_config_included': True, 'forwarding_enabled': True})
        self.assertNotIn('secret-must-not-leak', json.dumps(result))

    def test_crowdsec_appsec_rejects_public_listener_and_commented_forwarding(self):
        with tempfile.TemporaryDirectory() as tmp:
            acquisition = pathlib.Path(tmp) / 'appsec.yaml'
            bouncer = pathlib.Path(tmp) / 'bouncer.conf'
            acquisition.write_text('source: appsec\nlisten_addr: 0.0.0.0:7422\n')
            bouncer.write_text('# CrowdsecAppsec On\n# CrowdsecAppsecURL http://127.0.0.1:7422\n')
            with mock.patch.object(helper, 'CROWDSEC_APPSEC_CONFIG', acquisition), \
                 mock.patch.object(helper, 'CROWDSEC_BOUNCER_CONFIG', bouncer), \
                 mock.patch.object(helper, 'binary', return_value=None):
                result = helper.crowdsec_appsec_status()
        self.assertTrue(result['acquisition_configured'])
        self.assertFalse(result['loopback_listener'])
        self.assertFalse(result['forwarding_enabled'])

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
        self.assertEqual(result['counts']['input_allow'], 2)
        self.assertEqual(result['counts']['input_deny'], 4)
        self.assertEqual(result['counts']['port_allow'], 1)
        self.assertEqual(len(result['inventory']), 6)
        self.assertEqual(result['inventory'][1]['name'], 'Other tool rule')

    def test_firewall_debug_is_off_by_default_and_can_be_toggled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / 'guardian'
            root.mkdir(mode=0o700)
            config, log, lock = root / 'firewall-debug.json', root / 'firewall-debug.jsonl', root / 'firewall-debug.lock'
            with mock.patch.object(helper, 'ROOT', root), \
                 mock.patch.object(helper, 'FIREWALL_DEBUG_CONFIG', config), \
                 mock.patch.object(helper, 'FIREWALL_DEBUG_LOG', log), \
                 mock.patch.object(helper, 'FIREWALL_DEBUG_LOCK', lock), \
                 mock.patch.object(helper.os, 'geteuid', return_value=0):
                self.assertFalse(helper.firewall_debug_status()['debug_enabled'])
                helper.firewall_debug_log('action', stage='ignored')
                self.assertFalse(log.exists())
                status = helper.firewall_debug_set(True)
                self.assertTrue(status['debug_enabled'])
                helper.firewall_debug_log('plesk-cli', stage='list', returncode=0,
                                          duration_ms=12, output_bytes=25)
                status = helper.firewall_debug_status()
                self.assertEqual(len(status['debug_events']), 2)
                self.assertEqual(status['debug_events'][-1]['output_bytes'], 25)
                helper.firewall_debug_set(False)
                self.assertFalse(helper.firewall_debug_status()['debug_enabled'])
                before = log.read_bytes()
                helper.firewall_debug_log('action', stage='after-disable')
                self.assertEqual(log.read_bytes(), before)
                self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_firewall_debug_rejects_unsafe_settings_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / 'firewall-debug.json'
            config.write_text('{"enabled":true}')
            config.chmod(0o644)
            with mock.patch.object(helper, 'FIREWALL_DEBUG_CONFIG', config):
                result = helper.firewall_debug_status()
            self.assertFalse(result['debug_enabled'])
            self.assertIn('unsichere Dateirechte', result['debug_error'])

    def test_global_debug_labels_cover_module_actions_without_logging_targets(self):
        self.assertEqual(helper.debug_action_stage(['scan-start', 'example.com']), 'scan-start')
        self.assertEqual(helper.debug_action_stage(['firewall-action', 'ban', '198.51.100.8']), 'firewall-ban')
        self.assertEqual(helper.debug_action_stage(['ip-action', 'ssh', '198.51.100.8', 'unban']), 'fail2ban-unban')
        self.assertEqual(helper.debug_action_stage(['firewall-action', 'ban', '198.51.100.8']),
                         helper.debug_action_stage(['firewall-action', 'ban', '203.0.113.19']))
        self.assertEqual(helper.debug_action_stage(['anything-secret', 'token']), 'helper')

    def test_updater_debug_hook_writes_only_fixed_action_and_duration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / 'guardian'
            root.mkdir(mode=0o700)
            with mock.patch.object(helper, 'ROOT', root), \
                 mock.patch.object(helper, 'FIREWALL_DEBUG_CONFIG', root / 'firewall-debug.json'), \
                 mock.patch.object(helper, 'FIREWALL_DEBUG_LOG', root / 'firewall-debug.jsonl'), \
                 mock.patch.object(helper, 'FIREWALL_DEBUG_LOCK', root / 'firewall-debug.lock'), \
                 mock.patch.object(helper.os, 'geteuid', return_value=0):
                helper.firewall_debug_set(True)
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(helper.main(['debug-event', 'check', '0', '15']), 0)
                event = helper.firewall_debug_status()['debug_events'][-1]
                self.assertEqual(event['stage'], 'updater-check')
                self.assertEqual(event['duration_ms'], 15)
                self.assertNotIn('domain', event)

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

    def test_guardian_firewall_exceptions_are_audited_and_block_future_guardian_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            allowlist = root / 'firewall-allowlist.json'
            with mock.patch.object(helper, 'ROOT', root), \
                 mock.patch.object(helper, 'FIREWALL_ALLOWLIST', allowlist), \
                 mock.patch.object(helper, 'firewall_rules', return_value={
                     'available': True, 'limited': False, 'rules': []}), \
                 mock.patch.object(helper, 'firewall_status', return_value={'plesk_firewall_active': True}), \
                 mock.patch.object(helper, 'incident_log') as log, \
                 mock.patch.object(helper.os, 'geteuid', return_value=0):
                added = helper.firewall_action('allowlist-add', '203.0.113.25', 'Admin VPN')
                self.assertEqual(added['network'], '203.0.113.25/32')
                self.assertEqual(helper.firewall_allowlist_entries()[0]['comment'], 'Admin VPN')
                self.assertEqual(log.call_count, 1)
                with self.assertRaisesRegex(ValueError, 'ueberschneidet sich'):
                    helper.firewall_action('allowlist-add', '203.0.113.0/24', 'Overlapping VPN')
                with self.assertRaisesRegex(ValueError, 'druckbare Zeichen'):
                    helper.firewall_action('allowlist-add', '198.51.100.5', 'bad\ncomment')
                removed = helper.firewall_action('allowlist-remove', '203.0.113.25')
                self.assertEqual(removed['network'], '203.0.113.25/32')
                self.assertEqual(helper.firewall_allowlist_entries(), [])

    def test_guardian_firewall_exception_blocks_overlapping_ban(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            settings = root / 'settings'
            settings.touch()
            with mock.patch.object(helper, 'ROOT', root), \
                 mock.patch.object(helper, 'FIREWALL_ALLOWLIST', root / 'firewall-allowlist.json'), \
                 mock.patch.object(helper, 'FIREWALL_PENDING', root / 'firewall-pending.json'), \
                 mock.patch.object(helper, 'FIREWALL_SETTINGS', settings), \
                 mock.patch.object(helper, 'PLESK_BINARIES', ('/usr/bin/plesk',)), \
                 mock.patch.object(helper, 'SYSTEMCTL_PATHS', ()), \
                 mock.patch.object(helper, 'firewall_status', return_value={'plesk_firewall_active': True}), \
                 mock.patch.object(helper, 'firewall_rules', return_value={
                     'available': True, 'limited': False, 'rules': [], 'pending': {}}), \
                 mock.patch.object(helper, 'binary', side_effect=lambda paths: paths[0] if paths else None), \
                 mock.patch.object(helper, 'execute') as execute, \
                 mock.patch.object(helper.os, 'geteuid', return_value=0):
                helper.write_json(root / 'firewall-allowlist.json', {'entries': [{
                    'network': '203.0.113.0/24', 'comment': 'Admin VPN', 'created_at': helper.utc_now()}]})
                with self.assertRaisesRegex(ValueError, 'Guardian-IP-Ausnahme'):
                    helper._firewall_action('ban', '203.0.113.25', '198.51.100.8', 0)
                with self.assertRaisesRegex(ValueError, 'Guardian-IP-Ausnahme'):
                    helper._firewall_action('port-deny', '203.0.113.25', '198.51.100.8', 0, '22', 'tcp')
                execute.assert_not_called()

    def test_corrupt_guardian_firewall_exception_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            exception_file = root / 'firewall-allowlist.json'
            helper.write_json(exception_file, {'entries': [{'network': '203.0.113.25/32'}]})
            with mock.patch.object(helper, 'FIREWALL_ALLOWLIST', exception_file):
                result = helper.firewall_rules()
            self.assertFalse(result['available'])
            self.assertIn('allowlist_error', result)

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

    def test_firewall_allowlist_cli_routes_fixed_arguments(self):
        with mock.patch.object(helper, 'firewall_action', return_value={'ok': True}) as action, \
                mock.patch.object(helper, 'respond', return_value=0):
            self.assertEqual(helper.main(['firewall-action', 'allowlist-add', '203.0.113.5', 'Admin VPN']), 0)
            action.assert_called_with('allowlist-add', '203.0.113.5', 'Admin VPN', 0, '', '')
            self.assertEqual(helper.main(['firewall-action', 'allowlist-remove', '203.0.113.5']), 0)
            action.assert_called_with('allowlist-remove', '203.0.113.5', '', 0, '', '')


if __name__ == '__main__':
    unittest.main()
