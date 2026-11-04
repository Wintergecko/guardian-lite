import pathlib
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TabsTests(unittest.TestCase):
    def test_panel_landmarks_exist(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        ids = ['guardian-overview', 'guardian-scan', 'guardian-shield',
               'guardian-network', 'guardian-updater', 'guardian-changes',
               'guardian-history', 'guardian-roadmap']
        for name in ids:
            self.assertEqual(view.count('id="' + name + '"'), 1, name)

    def test_progressive_enhancement_and_accessibility(self):
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        for expected in ('role', 'tablist', 'tabpanel', 'aria-selected',
                         'ArrowRight', 'ArrowLeft', 'Home', 'End',
                         'guardian_active_tab', 'hashchange', 'DOMContentLoaded'):
            self.assertIn(expected, js)
        self.assertNotIn('eval(', js)
        self.assertNotIn('innerHTML', js)
        self.assertIn('panel.hidden = !active;', js)

    def test_version_consistency(self):
        version = ET.parse(ROOT / 'meta.xml').getroot().findtext('version')
        self.assertEqual(version, '0.6.2')
        self.assertIn("GUARDIAN_VERSION = '" + version + "'",
                      (ROOT / 'plib/controllers/IndexController.php').read_text())
        self.assertIn('Guardian Lite <span>v' + version + '</span>',
                      (ROOT / 'plib/views/scripts/index/index.phtml').read_text())


if __name__ == '__main__':
    unittest.main()
