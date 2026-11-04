"""Offline unit tests for the opt-in GitHub updater (no network or root required)."""
import importlib.machinery
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / 'sbin' / 'guardian-updater'
loader = importlib.machinery.SourceFileLoader('guardian_updater', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
updater = importlib.util.module_from_spec(spec)
loader.exec_module(updater)


def create_zip(path, contents, kind=stat.S_IFREG):
    with zipfile.ZipFile(path, 'w') as z:
        for name, value in contents.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (kind | 0o644) << 16
            z.writestr(info, value)


class UpdaterTests(unittest.TestCase):
    def test_repo_validation(self):
        self.assertEqual(updater.valid_repo('Good-Owner/guardian-lite'), 'Good-Owner/guardian-lite')
        for bad in ('', 'repo', 'user/../path', 'user/repo?x=1', '/repo', '-bad/repo', 'user/.private', 'user/repo..git'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                updater.valid_repo(bad)

    def test_version_validation(self):
        self.assertEqual(updater.version_tuple('v1.2.3'), (1, 2, 3))
        self.assertTrue(updater.version_tuple('1.0.12') > updater.version_tuple('1.0.9'))
        for bad in ('1.2', 'v1.2.3-rc1', '1.2.3+build', 'random'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                updater.version_tuple(bad)

    def test_archive_accepts_correct_extension(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'good.zip'
            create_zip(p, {'meta.xml': '<module><id>guardian-lite</id><version>0.3.1</version></module>',
                           'sbin/guardian-updater': 'print(1)'})
            self.assertTrue(updater.verify_archive(p, '0.3.1'))

    def test_archive_rejects_zip_slip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'bad.zip'
            create_zip(p, {'meta.xml': '<module><id>guardian-lite</id><version>0.3.1</version></module>',
                           'sbin/guardian-updater': 'print(1)', '../evil.txt': 'attack'})
            with self.assertRaisesRegex(ValueError, 'Dateipfad'):
                updater.verify_archive(p, '0.3.1')

    def test_archive_rejects_wrong_version(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'bad.zip'
            create_zip(p, {'meta.xml': '<module><id>guardian-lite</id><version>0.3.0</version></module>',
                           'sbin/guardian-updater': 'print(1)'})
            with self.assertRaisesRegex(ValueError, 'Version'):
                updater.verify_archive(p, '0.3.1')

    def test_archive_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'bad.zip'
            create_zip(p, {'meta.xml': '<module><id>guardian-lite</id><version>0.3.1</version></module>',
                           'sbin/guardian-updater': 'print(1)'})
            with zipfile.ZipFile(p, 'a') as z:
                entry = zipfile.ZipInfo('htdocs/link')
                entry.create_system = 3
                entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(entry, '/etc/shadow')
            with self.assertRaisesRegex(ValueError, 'Symlink'):
                updater.verify_archive(p, '0.3.1')

    def test_redirect_rejects_non_github_hosts(self):
        handler = updater.StrictRedirects()
        for url in ('http://github.com/file', 'https://evil.example/file',
                    'https://github.com:1234/file', 'https://127.0.0.1/file'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(None, None, 302, 'moved', None, url)

    def test_check_requires_github_asset_digest(self):
        import json
        release = {'tag_name': 'v0.3.1', 'draft': False, 'prerelease': False,
                   'assets': [{'name': 'guardian-lite-0.3.1.zip', 'state': 'uploaded',
                               'size': 32000,
                               'browser_download_url': 'https://github.com/owner/guardian-lite/releases/download/v0.3.1/guardian-lite-0.3.1.zip',
                               'digest': 'sha256:' + 'a' * 64}]}
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, n): return json.dumps(release).encode()
        class Opener:
            def open(self, request, timeout): return Response()
        with mock.patch.object(updater, 'opener', return_value=Opener()):
            info = updater.fetch_release('owner/guardian-lite', '0.3.0')
            self.assertTrue(info['newer'])
            self.assertEqual(info['sha256'], 'a' * 64)
            release['assets'][0]['digest'] = None
            with self.assertRaisesRegex(ValueError, 'Pruefsumme'):
                updater.fetch_release('owner/guardian-lite', '0.3.0')


if __name__ == '__main__':
    unittest.main()
