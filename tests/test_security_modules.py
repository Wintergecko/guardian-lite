import importlib.machinery
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('guardian_helper_v04', str(ROOT / 'sbin/guardian-helper'))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


class SecurityModulesTest(unittest.TestCase):
    def test_php_config_read_only_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            handlers = pathlib.Path(tmp)
            ini = handlers / '8.3/etc/php.ini'
            ini.parent.mkdir(parents=True)
            ini.write_text(';extension=snuffleupagus.so\n;sp.configuration_file=/tmp/no.rules\n')
            original_path = helper.pathlib.Path
            with mock.patch.object(helper.pathlib, 'Path', side_effect=lambda p: original_path(tmp) if p == '/opt/plesk/php' else original_path(p)):
                result = helper.php_runtime_status()
            self.assertFalse(result['confirmed'])
            self.assertEqual(result['config_count'], 1)
            self.assertFalse(result['configs'][0]['module_configured'])
            self.assertFalse(result['configs'][0]['rules_configured'])
            ini.write_text('extension=snuffleupagus.so\nsp.configuration_file=/etc/guardian.rules\n')
            with mock.patch.object(helper.pathlib, 'Path', side_effect=lambda p: original_path(tmp) if p == '/opt/plesk/php' else original_path(p)):
                result = helper.php_runtime_status()
            self.assertTrue(result['configs'][0]['module_configured'])
            self.assertTrue(result['configs'][0]['rules_configured'])
            self.assertFalse(result['confirmed'], 'Static config must not claim runtime protection')

    def test_http_status_never_claims_active_protection(self):
        status = helper.http_flood_status()
        self.assertFalse(status['protection_confirmed'])
        self.assertFalse(status['nginx_rate_module_detected'])

    def test_policy_files_packaged(self):
        self.assertTrue((ROOT / 'security/php-runtime/guardian.rules').is_file())
        self.assertTrue((ROOT / 'security/http-guard/guardian-modsecurity.conf').is_file())


if __name__ == '__main__':
    unittest.main()
