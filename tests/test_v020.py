"""Security and workflow tests, run without Plesk or live firewall changes."""
import importlib.machinery
import importlib.util
import os
import pathlib
import tempfile
import time
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).resolve().parents[1] / 'sbin' / 'guardian-helper'
loader = importlib.machinery.SourceFileLoader('guardian_helper_v2', str(PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
h = importlib.util.module_from_spec(spec)
loader.exec_module(h)


class NewFeatureTests(unittest.TestCase):
    def test_safe_relative_rejects_escapes(self):
        for candidate in ('../data', '/etc/passwd', 'folder/../passwd', 'folder//file',
                          'foo\\bar', './data', 'trick\nname', 'file\x00bad', ''):
            with self.subTest(candidate=candidate):
                self.assertFalse(h.safe_relative(candidate))
        self.assertTrue(h.safe_relative('wp-content/plugins/test.php'))

    def test_waf_excludes_request_bodies(self):
        lines = [
            'Message: Access denied with code 403 [id "942100"] [client 203.0.113.8] [msg "secret"]',
            'POST /wp-admin HTTP/1.1 Authorization: Bearer mySecret',
            'Message: Warning [id "920100"] [client 2001:db8::1]'
        ]
        events = h.parse_waf_lines(lines)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]['rule'], '920100')
        self.assertEqual(events[1]['ip'], '203.0.113.8')
        self.assertTrue(events[1]['blocked'])
        self.assertNotIn('secret', str(events))

    def test_findings_ignore_outside_root_and_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / 'httpdocs'
            root.mkdir()
            (root / 'bad.php').write_bytes(b'TEST')
            text = (str(root) + '/bad.php: Test.Signature FOUND\n' +
                    str(root) + '/../etc/passwd: Test.Signature FOUND\n' +
                    '/etc/passwd: Test.Signature FOUND\n')
            findings = h.findings_from_log(root, text)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]['path'], 'bad.php')
            self.assertEqual(findings[0]['state'], 'found')

    def test_file_metadata_rejects_symlink_inside_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            docroot = pathlib.Path(tmp)
            (docroot / 'link.php').symlink_to('/etc/passwd')
            with self.assertRaises(OSError):
                h.file_metadata(docroot, 'link.php')
            (docroot / 'folder').symlink_to('/etc')
            with self.assertRaises(OSError):
                h.file_metadata(docroot, 'folder/passwd')

    def test_atomic_json_blocks_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            secret = root / 'secret.json'
            secret.write_text('{"ok":false}')
            (root / 'link.json').symlink_to(secret)
            self.assertIsNone(h.read_json(root / 'link.json'))
            h.write_json(root / 'link.json', {'safe': True})
            self.assertEqual(secret.read_text(), '{"ok":false}')
            self.assertTrue((root / 'link.json').is_file())
            self.assertFalse((root / 'link.json').is_symlink())

    def test_schedule_opt_in_off_by_default_and_toggle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with mock.patch.object(h, 'ROOT', root), \
                 mock.patch.object(h, 'site_docroot', return_value=(root, os.getuid(), os.getgid())), \
                 mock.patch.object(h.os, 'geteuid', return_value=0):
                self.assertEqual(h.schedules(), {})
                self.assertTrue(h.schedule_set('example.com', 'on')['enabled'])
                self.assertIn('example.com', h.schedules())
                self.assertFalse(h.schedule_set('example.com', 'off')['enabled'])
                self.assertNotIn('example.com', h.schedules())

    def test_manual_ban_requires_valid_jail_and_ip(self):
        fake = mock.Mock(return_value=mock.Mock(returncode=0))
        with mock.patch.object(h.os, 'geteuid', return_value=0), \
             mock.patch.object(h, 'binary', return_value='/usr/bin/fail2ban-client'), \
             mock.patch.object(h, 'fail2ban_status', return_value={'jails': [{'name': 'sshd'}]}), \
             mock.patch.object(h, 'execute', fake):
            self.assertTrue(h.manual_ban('sshd', '8.8.8.8', 'ban')['ok'])
            fake.assert_called_with(['/usr/bin/fail2ban-client', 'set', 'sshd', 'banip', '8.8.8.8'], 8)
            with self.assertRaises(ValueError):
                h.manual_ban('sshd', '127.0.0.1', 'ban')
            with self.assertRaises(ValueError):
                h.manual_ban('foo; rm -rf', '8.8.8.8', 'ban')
            with self.assertRaises(ValueError):
                h.manual_ban('ghost', '8.8.8.8', 'ban')

    def test_quarantine_and_restore_dont_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / 'guardian'
            site = pathlib.Path(tmp) / 'vhost'
            site.mkdir()
            original = site / 'bad.php'
            original.write_bytes(b'virus evidence')
            with mock.patch.object(h, 'ROOT', root), \
                 mock.patch.object(h, 'site_docroot', return_value=(site, os.getuid(), os.getgid())), \
                 mock.patch.object(h.os, 'geteuid', return_value=0):
                h.prepare_dir()
                meta, fd, _ = h.file_metadata(site, 'bad.php')
                os.close(fd)
                jobid = 'd' * 32
                h.save_job({'id': jobid, 'domain': 'example.com', 'status': 'finished',
                            'epoch': time.time(), 'findings': [{'path': 'bad.php',
                            'state': 'found', 'fingerprint': meta}]})
                self.assertTrue(h.quarantine_file(jobid, 0)['ok'])
                self.assertFalse(original.exists())
                self.assertEqual(h.load_job(jobid)['findings'][0]['state'], 'quarantined')
                original.write_text('replacement')
                with self.assertRaises(FileExistsError):
                    h.restore_file(jobid, 0)
                self.assertEqual(original.read_text(), 'replacement')
                original.unlink()
                self.assertTrue(h.restore_file(jobid, 0)['ok'])
                self.assertEqual(original.read_bytes(), b'virus evidence')

    def test_quarantine_refuses_modified_scan_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / 'guardian'
            site = pathlib.Path(tmp) / 'site'
            site.mkdir()
            original = site / 'bad.php'
            original.write_text('first')
            with mock.patch.object(h, 'ROOT', root), \
                 mock.patch.object(h, 'site_docroot', return_value=(site, os.getuid(), os.getgid())), \
                 mock.patch.object(h.os, 'geteuid', return_value=0):
                h.prepare_dir()
                meta, fd, _ = h.file_metadata(site, 'bad.php')
                os.close(fd)
                jobid = 'e' * 32
                h.save_job({'id': jobid, 'domain': 'example.com', 'status': 'finished',
                            'epoch': time.time(), 'findings': [{'path': 'bad.php',
                            'state': 'found', 'fingerprint': meta}]})
                original.write_text('changed')
                with self.assertRaisesRegex(ValueError, 'geaendert'):
                    h.quarantine_file(jobid, 0)
                self.assertTrue(original.exists())

    def test_file_watch_baseline_and_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / 'guardian'
            site = pathlib.Path(tmp) / 'site'
            site.mkdir()
            file = site / 'index.php'
            file.write_text('hello')
            with mock.patch.object(h, 'ROOT', root), \
                 mock.patch.object(h, 'site_docroot', return_value=(site, os.getuid(), os.getgid())):
                h.prepare_dir()
                self.assertEqual(h.watch_changes('example.com')['change_count'], 0)
                file.write_text('hello changed')
                state = h.watch_changes('example.com')
                self.assertEqual(state['change_count'], 1)
                self.assertEqual(state['last_changes'][0]['type'], 'geaendert')
                (site / 'new.php').write_text('another')
                state = h.watch_changes('example.com')
                self.assertEqual(state['last_changes'][0]['type'], 'neu')

    def test_rejects_unrecognized_worker_command(self):
        with mock.patch.object(h, 'respond', return_value=1) as reply:
            self.assertEqual(h.main(['run', '--all']), 1)
            self.assertEqual(reply.call_args.args[0]['ok'], False)


if __name__ == '__main__':
    unittest.main()
