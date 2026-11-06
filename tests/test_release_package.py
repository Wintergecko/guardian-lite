import importlib.util
import pathlib
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guardian_release_build', ROOT / 'tools/build_release.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ReleasePackageTests(unittest.TestCase):
    def test_installable_zip_has_management_assets_and_linux_executables(self):
        version = ET.parse(ROOT / 'meta.xml').getroot().findtext('version')
        with tempfile.TemporaryDirectory() as tmp:
            path = build.build(pathlib.Path(tmp), 'v' + version)
            with zipfile.ZipFile(path) as archive:
                self.assertIsNone(archive.testzip())
                for name in ('meta.xml', 'MANAGEMENT.md', 'FEATURES.md', 'ARCHITEKTUR.md', 'SENTINEL-STATUS.md',
                             'plib/views/scripts/index/management.phtml', 'sbin/guardian-bot-guard.php',
                             'htdocs/sentinel/sentinel.js', 'htdocs/sentinel/sentinel.css'):
                    self.assertIn(name, archive.namelist())
                self.assertNotIn(b'\r\n', archive.read('security/README.md'))
                for name in ('guardian-helper', 'guardian-manager', 'guardian-updater', 'guardian-docker'):
                    filename = 'sbin/' + name
                    self.assertEqual(archive.read(filename).split(b'\n')[0], b'#!/usr/bin/python3')
                    self.assertEqual((archive.getinfo(filename).external_attr >> 16) & 0o777, 0o755)


if __name__ == '__main__':
    unittest.main()
