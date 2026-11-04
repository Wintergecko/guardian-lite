import importlib.util
import pathlib
import os
import tempfile
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parents[1]/'security/php-runtime/handler_rollback.py'
spec = importlib.util.spec_from_file_location('guardian_php_rollback_test', SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(os.geteuid() == 0, 'root required for isolated handler config test')
class PhpRollbackTests(unittest.TestCase):
    def test_backup_rollback_refuses_unexpected_edits(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            ini = base/'8.3/etc/php.ini'
            ini.parent.mkdir(parents=True)
            ini.write_bytes(b'display_errors=Off\n')
            backup_dir = base/'backup'
            with mock.patch.object(mod, 'BASE', base), mock.patch.object(mod, 'BACKUPS', backup_dir):
                meta = mod.backup('8.3')
                self.assertEqual(meta['sha256'], mod.sha(ini.read_bytes()))
                ini.write_bytes(b'display_errors=On\n')
                with self.assertRaises(ValueError):
                    mod.restore('8.3', meta['backup'], '0'*64)
                result = mod.restore('8.3', meta['backup'], mod.sha(ini.read_bytes()))
                self.assertEqual(result['sha256'], meta['sha256'])
                self.assertEqual(ini.read_bytes(), b'display_errors=Off\n')

    def test_rejects_unsafe_paths(self):
        for value in ('../8.3', '/etc', '8.3/../', 'eight'):
            with self.assertRaises(ValueError):
                mod.php_ini(value)
