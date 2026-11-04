"""Unit tests that need no Plesk server and do not touch host service state."""
import importlib.machinery
import importlib.util
import pathlib
import subprocess
import tempfile
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

    def test_unknown_command_returns_error(self):
        with mock.patch.object(helper, 'respond', return_value=1) as reply:
            self.assertEqual(helper.main(['shell', 'rm', '-rf', '/']), 1)
            self.assertFalse(reply.call_args.args[0]['ok'])


if __name__ == '__main__':
    unittest.main()
