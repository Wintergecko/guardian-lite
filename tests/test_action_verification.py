"""Portable unit tests of the real helper functions with injected system boundaries.

Only selected function ASTs are compiled to avoid importing Linux-only fcntl and
resource on Windows. These tests do not establish Linux/Plesk integration support.
"""
import ast
import ipaddress
import pathlib
import re
import subprocess
import types
import unittest
from unittest import mock


SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'sbin/guardian-helper'


def functions():
    names = {'fail2ban_verify_ip', 'manual_ban', 'firewall_verify_pending', '_firewall_action'}
    parsed = ast.parse(SOURCE.read_text(encoding='utf-8'))
    module = ast.Module(body=[node for node in parsed.body
                             if isinstance(node, ast.FunctionDef) and node.name in names], type_ignores=[])
    scope = dict(ipaddress=ipaddress, subprocess=subprocess,
                 os=types.SimpleNamespace(geteuid=lambda: 0),
                 time=types.SimpleNamespace(sleep=mock.Mock(), time=mock.Mock(return_value=100)),
                 JAIL_NAME=re.compile(r'^[a-zA-Z0-9_.-]{1,80}$'),
                 FAIL2BAN_PATHS=('fail2ban-client',), PLESK_BINARIES=('plesk',),
                 binary=mock.Mock(side_effect=lambda paths: paths[0] if paths else None),
                 execute=mock.Mock(), incident_log=mock.Mock(),
                 fail2ban_status=mock.Mock(return_value={'jails': [{'name': 'sshd'}]}),
                 firewall_rules=mock.Mock(), firewall_status=mock.Mock(
                     return_value={'plesk_firewall_active': True}),
                 firewall_write_restriction=mock.Mock(return_value=None),
                 FIREWALL_SETTINGS=mock.Mock(is_file=mock.Mock(return_value=True)),
                 FIREWALL_CONFIRM_PIPE=mock.Mock(exists=mock.Mock(return_value=False)),
                 SYSTEMCTL_PATHS=(), FIREWALL_PENDING=mock.Mock(), FIREWALL_EXPIRIES=mock.Mock(),
                 read_json=mock.Mock(), write_json=mock.Mock())
    exec(compile(module, str(SOURCE), 'exec'), scope)
    return types.SimpleNamespace(**scope)


def result(stdout='', code=0):
    return subprocess.CompletedProcess([], code, stdout, '')


class Fail2banVerificationTests(unittest.TestCase):
    def setUp(self):
        self.h = functions()

    def test_ban_retries_until_exact_runtime_state_matches(self):
        self.h.execute.side_effect = [result('0'), result('1'), result('0'), result('1')]
        response = self.h.manual_ban('sshd', '2001:0db8::1', 'ban')
        self.assertTrue(response['verified'])
        self.assertEqual(response['verification_scope'], 'fail2ban-runtime')
        self.assertEqual(self.h.execute.call_args_list[1].args[0],
                         ['fail2ban-client', 'set', 'sshd', 'banip', '2001:db8::1'])
        self.h.time.sleep.assert_called_once_with(0.2)
        self.assertIn('verifiziert', self.h.incident_log.call_args.args[-1])

    def test_unban_uses_plesk_jail_scoped_cli(self):
        self.h.execute.side_effect = [result('1'), result(), result('0')]
        self.h.manual_ban('sshd', '203.0.113.25', 'unban')
        self.assertEqual(self.h.execute.call_args_list[1].args[0],
                         ['plesk', 'bin', 'ip_ban', '--unban', '203.0.113.25,sshd'])

    def test_non_plesk_unban_uses_direct_client(self):
        self.h.binary.side_effect = lambda paths: None if paths == ('plesk',) else paths[0]
        self.h.execute.side_effect = [result('1'), result(), result('0')]
        self.h.manual_ban('sshd', '203.0.113.25', 'unban')
        self.assertEqual(self.h.execute.call_args_list[1].args[0],
                         ['fail2ban-client', 'set', 'sshd', 'unbanip', '203.0.113.25'])

    def test_unsupported_probe_prevents_mutation(self):
        for response in (None, result('ERROR', 1), result(''), result('[]'), result('False')):
            with self.subTest(response=response):
                h = functions()
                h.execute.return_value = response
                with self.assertRaisesRegex(ValueError, 'keine Aenderung'):
                    h.manual_ban('sshd', '203.0.113.25', 'ban')
                self.assertEqual(h.execute.call_count, 1)

    def test_successful_command_with_unchanged_state_is_failure(self):
        for operation, state in (('ban', '0'), ('unban', '1')):
            with self.subTest(operation=operation):
                h = functions()
                h.execute.side_effect = [result(state), result(), result(state), result(state), result(state)]
                with self.assertRaisesRegex(ValueError, 'entspricht'):
                    h.manual_ban('sshd', '203.0.113.25', operation)
                self.assertIn('nicht verifiziert', h.incident_log.call_args.args[-1])

    def test_post_change_unknown_state_is_failure(self):
        self.h.execute.side_effect = [result('0'), result(), None]
        with self.assertRaisesRegex(ValueError, 'Zustand unbekannt'):
            self.h.manual_ban('sshd', '203.0.113.25', 'ban')
        self.assertIn('nicht verifiziert', self.h.incident_log.call_args.args[-1])

    def test_command_failure_is_audited(self):
        self.h.execute.side_effect = [result('0'), result('error', 1)]
        with self.assertRaisesRegex(ValueError, 'nicht bestaetigt'):
            self.h.manual_ban('sshd', '203.0.113.25', 'ban')
        self.assertEqual(self.h.execute.call_count, 2)
        self.assertEqual(self.h.incident_log.call_count, 2)

    def test_invalid_inputs_never_execute(self):
        for jail, ip, operation in [('sshd;id', '203.0.113.25', 'ban'),
                                    ('sshd', '127.0.0.1', 'ban'),
                                    ('sshd', '::1', 'ban'), ('sshd', '$(id)', 'ban'),
                                    ('sshd', '203.0.113.25', 'exec')]:
            with self.subTest(jail=jail, ip=ip, operation=operation):
                with self.assertRaises(ValueError):
                    self.h.manual_ban(jail, ip, operation)
        self.h.execute.assert_not_called()


class FirewallVerificationTests(unittest.TestCase):
    def setUp(self):
        self.h = functions()
        self.pending = {'state': 'awaiting_confirmation', 'action': 'ban', 'started_epoch': 90,
                        'network': '203.0.113.25/32', 'rule_name': 'Guardian Lite managed deny 203.0.113.25/32'}
        self.rule = {'name': self.pending['rule_name'], 'network': self.pending['network'],
                     'kind': 'ip_deny', 'action': 'deny'}
        self.raw = {'name': self.rule['name'], 'source': '203.0.113.25',
                    'class': 'custom', 'direction': 'input'}
        self.listing = {'available': True, 'rules': [self.rule], 'inventory': [self.raw]}
        self.h.firewall_rules.return_value = self.listing

    def test_expected_owned_rule_passes(self):
        self.h.firewall_verify_pending(self.pending)

    def test_incident_interlock_prevents_every_firewall_mutation(self):
        self.h.firewall_write_restriction.return_value = 'Blocked after failed live verification'
        for operation in ('ban', 'unban', 'port-allow', 'port-deny', 'port-remove',
                          'allowlist-add', 'allowlist-remove', 'confirm', 'cancel'):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(ValueError, 'Blocked'):
                    self.h._firewall_action(operation)
        self.h.execute.assert_not_called()

    def test_existing_native_activation_prevents_overlap(self):
        self.h.FIREWALL_CONFIRM_PIPE.exists.return_value = True
        with self.assertRaisesRegex(ValueError, 'Aktivierung oder Ruecknahme'):
            self.h._firewall_action('ban', '192.0.2.254', '198.51.100.1')
        self.h.execute.assert_not_called()

    def test_missing_changed_or_duplicate_rule_is_failure(self):
        for change in ({'rules': []}, {'inventory': []},
                       {'rules': [dict(self.rule, action='allow')]},
                       {'inventory': [self.raw, self.raw]},
                       {'inventory': [dict(self.raw, source='203.0.113.25, 198.51.100.1')]},
                       {'inventory': [dict(self.raw, direction='output')]},
                       {'available': False}, {'limited': True}, {'inventory_limited': True}):
            with self.subTest(change=change):
                self.h.firewall_rules.return_value = dict(self.listing, **change)
                with self.assertRaises(ValueError):
                    self.h.firewall_verify_pending(self.pending)

    def test_removed_rule_must_be_absent_even_if_parser_rejects_it(self):
        for action in ('unban', 'port-remove'):
            self.pending['action'] = action
            self.h.firewall_rules.return_value = dict(self.listing, rules=[])
            with self.assertRaises(ValueError):
                self.h.firewall_verify_pending(self.pending)
            self.h.firewall_rules.return_value = dict(self.listing, rules=[], inventory=[])
            self.h.firewall_verify_pending(self.pending)

    def test_port_and_protocol_must_match(self):
        self.pending.update(action='port-allow', port=443, protocol='tcp')
        self.rule.update(kind='port', action='allow', port=443, protocol='udp')
        with self.assertRaises(ValueError):
            self.h.firewall_verify_pending(self.pending)
        self.rule['protocol'] = 'tcp'
        self.h.firewall_verify_pending(self.pending)

    def test_failed_verification_never_confirms_or_writes_expiry(self):
        self.h.read_json.return_value = self.pending
        self.h.firewall_rules.return_value = dict(self.listing, rules=[])
        with self.assertRaisesRegex(ValueError, 'keine Bestaetigung'):
            self.h._firewall_action('confirm')
        self.h.execute.assert_not_called()
        self.h.write_json.assert_not_called()
        self.h.FIREWALL_PENDING.unlink.assert_not_called()

    def test_slow_inventory_does_not_confirm_after_deadline(self):
        self.h.read_json.return_value = self.pending
        self.h.time.time.side_effect = [100, 150]
        with self.assertRaisesRegex(ValueError, 'nach Verifikation abgelaufen'):
            self.h._firewall_action('confirm')
        self.h.execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
