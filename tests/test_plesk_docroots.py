"""Regression tests for add-on-domain document roots and webspace isolation."""
import importlib.machinery
import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

HELPER = pathlib.Path(__file__).resolve().parents[1] / 'sbin' / 'guardian-helper'
loader = importlib.machinery.SourceFileLoader('guardian_docroot_tests', str(HELPER))
spec = importlib.util.spec_from_loader(loader.name, loader)
h = importlib.util.module_from_spec(spec)
loader.exec_module(h)


class PleskDocrootTests(unittest.TestCase):
    def test_db_query_resolves_addon_hosting_not_guesswork(self):
        captured = []
        def fake_exec(argv, timeout=5):
            captured.append((argv, timeout))
            return subprocess.CompletedProcess(argv, 0,
                '/var/www/vhosts/subscription.test/sites/addon/public\t/var/www/vhosts/subscription.test\n', '')
        with mock.patch.object(h, 'binary', return_value='/usr/sbin/plesk'), \
             mock.patch.object(h, 'execute', side_effect=fake_exec):
            docroot, home = h.plesk_hosting_path('addon.example.net')
        self.assertEqual(docroot, '/var/www/vhosts/subscription.test/sites/addon/public')
        self.assertEqual(home, '/var/www/vhosts/subscription.test')
        self.assertEqual(captured[0][0][:3], ['/usr/sbin/plesk', 'db', '-Ne'])
        self.assertIn("d.name = 'addon.example.net'", captured[0][0][-1])
        self.assertEqual(captured[0][1], 12)

    def test_rejects_domain_injection_before_cli(self):
        with mock.patch.object(h, 'binary') as binary:
            with self.assertRaisesRegex(ValueError, 'Domainname'):
                h.plesk_hosting_path("addon.com'; DROP TABLE domains;")
        binary.assert_not_called()

    def test_nonhosted_domain_fails_closed(self):
        with mock.patch.object(h, 'binary', return_value='/usr/sbin/plesk'), \
             mock.patch.object(h, 'execute', return_value=subprocess.CompletedProcess([], 0, '', '')):
            with self.assertRaisesRegex(ValueError, 'kein eindeutiges aktives'):
                h.plesk_hosting_path('forward.example.net')

    def test_addon_docroot_under_subscription_root(self):
        if os.geteuid() != 0:
            self.skipTest('Needs root to set up an unprivileged test owner')
        with tempfile.TemporaryDirectory() as tmp:
            vhosts = pathlib.Path(tmp) / 'vhosts'
            home = vhosts / 'subscription.example'
            target = home / 'sites' / 'addon' / 'public'
            target.mkdir(parents=True)
            os.chown(target, 65534, 65534)
            with mock.patch.object(h, 'VHOSTS', vhosts), \
                 mock.patch.object(h, 'plesk_hosting_path', return_value=(str(target), str(home))):
                resolved, uid, gid = h.site_docroot('addon.example.net')
            self.assertEqual(resolved, target)
            self.assertEqual((uid, gid), (65534, 65534))

    def test_symlink_to_other_subscription_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            vhosts = pathlib.Path(tmp) / 'vhosts'
            home = vhosts / 'primary.example'
            other = vhosts / 'other.example'
            home.mkdir(parents=True)
            other.mkdir()
            (home / 'site').symlink_to(other, target_is_directory=True)
            with mock.patch.object(h, 'VHOSTS', vhosts), \
                 mock.patch.object(h, 'plesk_hosting_path', return_value=(str(home / 'site'), str(home))):
                with self.assertRaisesRegex(ValueError, 'ausserhalb'):
                    h.site_docroot('addon.example.net')

    def test_site_root_cannot_be_equal_to_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            vhosts = pathlib.Path(tmp) / 'vhosts'
            home = vhosts / 'primary.example'
            home.mkdir(parents=True)
            with mock.patch.object(h, 'VHOSTS', vhosts), \
                 mock.patch.object(h, 'plesk_hosting_path', return_value=(str(home), str(home))):
                with self.assertRaisesRegex(ValueError, 'ausserhalb'):
                    h.site_docroot('primary.example')


if __name__ == '__main__':
    unittest.main()
