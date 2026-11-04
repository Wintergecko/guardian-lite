"""Opt-in native Snuffleupagus build/probe on an isolated CI VM, not a Plesk server."""
import importlib.machinery
import importlib.util
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('GUARDIAN_RUNTIME_BUILD') == '1', 'native build job only')
class RuntimeBuildTests(unittest.TestCase):
    def test_pinned_source_build_and_simulation_enforcement_rollback(self):
        loader = importlib.machinery.SourceFileLoader('guardian_runtime_build', str(ROOT / 'sbin/guardian-manager'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        m = importlib.util.module_from_spec(spec)
        loader.exec_module(m)
        with tempfile.TemporaryDirectory() as tmp:
            folder = pathlib.Path(tmp)
            os.chmod(folder, 0o755)
            php = folder / 'php'
            for name in ('bin', 'etc', 'lib/php/modules'):
                (php / name).mkdir(parents=True, exist_ok=True)
            for name in ('php', 'phpize', 'php-config'):
                source = pathlib.Path(shutil.which(name)).resolve()
                shutil.copy2(source, php / 'bin' / name)
            ini = php / 'etc/php.ini'
            original = b'; isolated runtime build test\n'
            ini.write_bytes(original)
            with mock.patch.object(m.h, 'ROOT', folder / 'guardian'), \
                 mock.patch.object(m.h, 'INCIDENT_LOG', folder / 'guardian/incidents.jsonl'), \
                 mock.patch.object(m, 'handler', return_value=php), \
                 mock.patch.object(m, 'reload_handler'):
                m.prepare()
                backup = m.php_backup('8.3')
                m.runtime_install('8.3')
                self.assertTrue((php / 'lib/php/modules/snuffleupagus.so').read_bytes().startswith(b'\x7fELF'))
                m.runtime_set('8.3', 'simulate', m.digest(ini.read_bytes()))
                self.assertIn(b'guardian-simulate.rules', ini.read_bytes())
                m.runtime_set('8.3', 'enforce', m.digest(ini.read_bytes()))
                self.assertIn(b'guardian-enforce.rules', ini.read_bytes())
                m.php_restore('8.3', backup['id'], m.digest(ini.read_bytes()))
                self.assertEqual(ini.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
