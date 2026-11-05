"""Security and workflow tests, run without Plesk or live firewall changes."""
import importlib.machinery
import importlib.util
import json
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
    def test_scan_queue_is_fifo_and_dispatches_only_one_worker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            jobs = root / 'jobs'
            jobs.mkdir()
            ids = ['a' * 32, 'b' * 32]
            for jobid in ids:
                (jobs / (jobid + '.json')).write_text(json.dumps({
                    'id': jobid, 'domain': 'example-' + jobid[0] + '.com',
                    'trigger': 'schedule', 'status': 'queued', 'started_at': h.utc_now(),
                    'epoch': time.time(), 'pid': None, 'findings': []}))
            h.write_json(root / 'scan-queue.json', {'jobs': ids})
            scanfd = os.open(os.devnull, os.O_RDONLY)
            with mock.patch.object(h, 'ROOT', root), \
                 mock.patch.object(h, 'prepare_dir'), \
                 mock.patch.object(h, 'lock_scan', return_value=scanfd), \
                 mock.patch.object(h.subprocess, 'Popen', return_value=mock.Mock(pid=123)) as spawn:
                result = h.dispatch_next_scan()
                self.assertEqual(result['id'], ids[0])
                self.assertEqual(h.queued_jobs(), ids[1:])
                self.assertEqual(h.load_job(ids[0])['status'], 'starting')
                self.assertEqual(h.load_job(ids[1])['status'], 'queued')
                spawn.assert_called_once()
            os.close(scanfd)

    def test_scan_request_queues_when_another_scan_holds_global_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp) / 'guardian'
            (root / 'jobs').mkdir(parents=True)
            with mock.patch.object(h, 'ROOT', root), \
                 mock.patch.object(h, 'prepare_dir'), \
                 mock.patch.object(h.os, 'geteuid', return_value=0, create=True), \
                 mock.patch.object(h, 'site_docroot', return_value=(root, 1000, 1000)), \
                 mock.patch.object(h, 'binary', return_value='/usr/bin/clamscan'), \
                 mock.patch.object(h, 'dispatch_next_scan', return_value={'started': False, 'reason': 'busy'}):
                result = h.scan_start('example.com')
                self.assertEqual(result['status'], 'queued')
                self.assertEqual(h.load_job(result['id'])['status'], 'queued')
                self.assertEqual(h.scan_queue_status()['count'], 1)

    def test_scan_queue_is_bounded_and_deduplicates_queued_domain(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / 'jobs').mkdir()
            jobid = 'c' * 32
            h.write_json(root / 'jobs' / (jobid + '.json'), {
                'id': jobid, 'domain': 'example.com', 'trigger': 'manual', 'status': 'queued',
                'started_at': h.utc_now(), 'epoch': time.time(), 'findings': []})
            h.write_json(root / 'scan-queue.json', {'jobs': [jobid]})
            with mock.patch.object(h, 'ROOT', root), mock.patch.object(h, 'prepare_dir'):
                duplicate = h.enqueue_scan('example.com', 'manual')
                self.assertEqual(duplicate['id'], jobid)
                self.assertTrue(duplicate['duplicate'])
                full_ids = []
                for index in range(h.MAX_SCAN_QUEUE):
                    current = '%032x' % (index + 1000)
                    full_ids.append(current)
                    h.write_json(root / 'jobs' / (current + '.json'), {
                        'id': current, 'domain': 'd%d.example.com' % index, 'status': 'queued'})
                h.write_json(root / 'scan-queue.json', {'jobs': full_ids})
                with self.assertRaisesRegex(ValueError, 'Warteschlange voll'):
                    h.enqueue_scan('overflow.example.com', 'manual')

    def test_hourly_scheduler_enqueues_every_due_domain(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(h, 'ROOT', pathlib.Path(temp)), \
                 mock.patch.object(h.os, 'geteuid', return_value=0, create=True), \
                 mock.patch.object(h, 'prepare_dir'), \
                 mock.patch.object(h, 'firewall_expiry_tick', return_value={'remaining_due': 0}), \
                 mock.patch.object(h, 'dispatch_next_scan', return_value={'started': False}), \
                 mock.patch.object(h, 'schedules', return_value={
                     'a.example.com': {'enabled': True}, 'b.example.com': {'enabled': True}}), \
                 mock.patch.object(h, 'watch_changes'), \
                 mock.patch.object(h, 'monitor_config', return_value={}), \
                 mock.patch.object(h, 'prune_reports'), \
                 mock.patch.object(h, 'history', return_value=[]), \
                 mock.patch.object(h, 'site_docroot'), \
                 mock.patch.object(h, 'scan_start', return_value={'ok': True, 'status': 'queued'}) as start:
                result = h.scheduled_tick()
        self.assertEqual(result['accepted'], 2)
        self.assertEqual(start.call_args_list, [
            mock.call('a.example.com', 'schedule'), mock.call('b.example.com', 'schedule')])

    def test_hourly_scheduler_reports_queue_saturation(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(h, 'ROOT', pathlib.Path(temp)), \
                 mock.patch.object(h.os, 'geteuid', return_value=0, create=True), \
                 mock.patch.object(h, 'prepare_dir'), \
                 mock.patch.object(h, 'firewall_expiry_tick', return_value={'remaining_due': 0}), \
                 mock.patch.object(h, 'dispatch_next_scan', return_value={'started': False}), \
                 mock.patch.object(h, 'schedules', return_value={'full.example.com': {'enabled': True}}), \
                 mock.patch.object(h, 'watch_changes'), \
                 mock.patch.object(h, 'monitor_config', return_value={}), \
                 mock.patch.object(h, 'prune_reports'), \
                 mock.patch.object(h, 'history', return_value=[]), \
                 mock.patch.object(h, 'site_docroot'), \
                 mock.patch.object(h, 'scan_start', side_effect=ValueError('Scan-Warteschlange voll')), \
                 mock.patch.object(h, 'incident_log') as incident:
                result = h.scheduled_tick()
        self.assertEqual(result['deferred'], 1)
        self.assertIn('beim naechsten Lauf erneut geprueft', result['message'])
        incident.assert_called_once()

    def test_scheduler_keeps_24h_interval_beyond_visible_history(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / 'jobs').mkdir()
            now = time.time()
            for index in range(32):
                jobid = '%032x' % index
                report = {'id': jobid, 'domain': 'example.com', 'status': 'finished',
                          'trigger': 'schedule' if index == 0 else 'manual',
                          'started_at': h.utc_now(), 'findings': []}
                path = root / 'jobs' / (jobid + '.json')
                path.write_text(json.dumps(report))
                os.utime(path, (now + index, now + index))
            with mock.patch.object(h, 'ROOT', root), \
                 mock.patch.object(h.os, 'geteuid', return_value=0), \
                 mock.patch.object(h, 'prepare_dir'), \
                 mock.patch.object(h, 'prune_reports'), \
                 mock.patch.object(h, 'watch_changes'), \
                 mock.patch.object(h, 'monitor_config', return_value={}), \
                 mock.patch.object(h, 'schedules', return_value={'example.com': {'enabled': True}}), \
                 mock.patch.object(h, 'scan_start') as start:
                self.assertEqual(len(h.history()), 30)
                self.assertEqual(len(h.history(limit=None)), 32)
                h.scheduled_tick()
                start.assert_not_called()
                # An older scheduled report must still allow a due scan.
                path = root / 'jobs' / ('%032x.json' % 0)
                report = json.loads(path.read_text())
                report['started_at'] = (h.datetime.datetime.now(h.datetime.timezone.utc)
                                        - h.datetime.timedelta(days=2)).isoformat()
                path.write_text(json.dumps(report))
                with mock.patch.object(h, 'site_docroot'):
                    h.scheduled_tick()
                start.assert_called_once_with('example.com', 'schedule')

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

    def test_admin_tool_candidates_are_read_only_and_require_known_markers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp) / 'httpdocs'
            root.mkdir()
            adminer = root / 'adminer-4.8.1.php'
            adminer.write_bytes(b'<?php /* Adminer database management https://www.adminer.org */')
            tinyfm = root / 'filemanager.php'
            tinyfm.write_bytes(b'<?php // TinyFileManager web file manager')
            (root / 'adminer.php.bak').write_bytes(b'Adminer adminer.org')
            (root / 'adminer-copy.php').write_bytes(b'<?php echo "hello";')
            (root / 'linked-adminer.php').symlink_to(adminer)

            result = h.admin_tool_candidates(root)

            self.assertEqual({(item['tool'], item['path']) for item in result['findings']}, {
                ('Adminer', 'adminer-4.8.1.php'), ('TinyFileManager', 'filemanager.php')})
            self.assertTrue(all(len(item['sha256']) == 64 for item in result['findings']))
            self.assertTrue(result['incomplete'])  # Symlink skipped; never followed.
            self.assertFalse(result['truncated'])
            self.assertTrue(adminer.exists())
            self.assertTrue(tinyfm.exists())

    def test_admin_tool_candidate_scan_reports_bounds(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / 'adminer.php').write_bytes(b'<?php Adminer adminer.org' + b'x' * h.MAX_ADMIN_TOOL_FILE_BYTES)
            oversized = h.admin_tool_candidates(root)
            self.assertEqual(oversized['findings'], [])
            self.assertTrue(oversized['incomplete'])
            with mock.patch.object(h, 'MAX_ADMIN_TOOL_FILES', 0):
                result = h.admin_tool_candidates(root)
            self.assertEqual(result['findings'], [])
            self.assertTrue(result['incomplete'])
            self.assertTrue(result['truncated'])

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
            self.assertTrue(h.manual_ban('sshd', '127.0.0.1', 'unban')['ok'])
            fake.assert_called_with(['/usr/bin/fail2ban-client', 'set', 'sshd', 'unbanip', '127.0.0.1'], 8)
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

    def test_rapid_scan_caches_clean_files_and_invalidates_on_signature_change(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp) / 'guardian'
            (root / 'jobs').mkdir(parents=True)
            os.chmod(root, 0o700)
            os.chmod(root / 'jobs', 0o700)
            site = pathlib.Path(temp) / 'site'
            site.mkdir()
            file = site / 'index.php'
            file.write_text('<?php echo "clean";')
            calls = []

            def scan_command(args, **kwargs):
                calls.append(args)
                file_list = next((arg.split('=', 1)[1] for arg in args if arg.startswith('--file-list=')), None)
                self.assertIsNotNone(file_list)
                listed = pathlib.Path(file_list).read_bytes().splitlines()
                self.assertEqual(listed, [os.fsencode(str(file))])
                kwargs['stdout'].write(b'')
                return h.subprocess.CompletedProcess(args, 0)

            signatures = iter(['signature-v1', 'signature-v1', 'signature-v2'])
            reports = []
            for jobid in ('a' * 32, 'b' * 32, 'c' * 32):
                h.write_json(root / 'jobs' / (jobid + '.json'), {
                    'id': jobid, 'domain': 'example.com', 'status': 'starting',
                    'started_at': h.utc_now(), 'findings': []})
                inherited = os.open(os.devnull, os.O_RDONLY)
                with mock.patch.object(h, 'ROOT', root), \
                     mock.patch.object(h.os, 'geteuid', return_value=0), \
                     mock.patch.object(h, 'site_docroot', return_value=(site, os.getuid(), os.getgid())), \
                     mock.patch.object(h, 'binary', return_value='/usr/bin/clamscan'), \
                     mock.patch.object(h, 'clam_scan_identity', return_value=next(signatures)), \
                     mock.patch.object(h.subprocess, 'run', side_effect=scan_command), \
                     mock.patch.object(h, 'dispatch_next_scan', return_value={'started': False}):
                    h.scan_worker('example.com', jobid, inherited)
                    reports.append(h.load_job(jobid))

            self.assertEqual([report.get('status') for report in reports], ['finished', 'finished', 'finished'],
                             repr(reports))
            self.assertEqual(len(calls), 2, repr(reports))
            self.assertEqual(reports[0]['rapid_scan']['files_scanned'], 1)
            self.assertTrue(reports[0]['rapid_scan']['cache_updated'])
            self.assertEqual(reports[1]['rapid_scan']['cached_clean'], 1)
            self.assertEqual(reports[1]['rapid_scan']['files_scanned'], 0)
            self.assertEqual(reports[2]['rapid_scan']['files_scanned'], 1)
            self.assertEqual(reports[2]['rapid_scan']['cached_clean'], 0)

    def test_scan_inventory_skips_symlinks_and_rejects_uncertain_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / 'safe.php').write_text('safe')
            outside = root.parent / (root.name + '-outside')
            outside.write_text('outside')
            (root / 'link.php').symlink_to(outside)
            inventory, complete, reason = h.scan_file_inventory(root)
            self.assertTrue(complete, reason)
            self.assertEqual(set(inventory), {'safe.php'})

    def test_rejects_unrecognized_worker_command(self):
        with mock.patch.object(h, 'respond', return_value=1) as reply:
            self.assertEqual(h.main(['run', '--all']), 1)
            self.assertEqual(reply.call_args.args[0]['ok'], False)


if __name__ == '__main__':
    unittest.main()
