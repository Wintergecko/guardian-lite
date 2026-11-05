import pathlib
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TabsTests(unittest.TestCase):
    def test_panel_landmarks_exist(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        ids = ['guardian-overview', 'guardian-scan', 'guardian-shield',
               'guardian-network', 'guardian-runtime', 'guardian-webshield',
               'guardian-waf-events', 'guardian-fail2ban', 'guardian-firewall',
               'guardian-updater', 'guardian-changes', 'guardian-monitor',
               'guardian-history', 'guardian-incidents', 'guardian-roadmap']
        for name in ids:
            self.assertEqual(view.count('id="' + name + '"'), 1, name)
        management = (ROOT / 'plib/views/scripts/index/management.phtml').read_text()
        for name in ('guardian-php-config', 'guardian-webshield-config', 'guardian-turnstile',
                     'guardian-reputation', 'guardian-malware-repair', 'guardian-malware-ignore',
                     'guardian-cms-integrity', 'guardian-settings-storage',
                     'guardian-service-keys', 'guardian-management-diagnostics'):
            self.assertEqual(management.count('id="' + name + '"'), 1, name)

    def test_progressive_enhancement_and_accessibility(self):
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        for expected in ('guardian-menu', 'guardian-submenu', 'aria-expanded', 'aria-controls',
                         'data-menu-target', 'ArrowRight', 'ArrowLeft', 'Home', 'End',
                         'guardian_active_tab', 'hashchange', 'DOMContentLoaded', 'WebShield',
                         'Malware Scanner', 'Reputation Management'):
            self.assertIn(expected, js)
        self.assertNotIn('eval(', js)
        self.assertNotIn('innerHTML', js)
        self.assertIn('panel.hidden = !active;', js)
        self.assertIn('guardian-menu-static', view)
        self.assertIn('<main class="guardian-pages">', view)
        self.assertIn('id="guardian-firewall"', view)
        self.assertIn('href="#guardian-malware-repair"', view)
        self.assertIn('id="guardian-malware-repair"',
                      (ROOT / 'plib/views/scripts/index/management.phtml').read_text())

    def test_sidebar_groups_and_submenu_links_have_rendered_targets(self):
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        templates = (ROOT / 'plib/views/scripts/index/index.phtml').read_text() + \
            (ROOT / 'plib/views/scripts/index/management.phtml').read_text()
        for group in re.findall(r"sections:\s*\[([^\]]+)\]", js):
            for target in re.findall(r"'([^']+)'", group):
                self.assertIn('id="' + target + '"', templates, target)
        for target in re.findall(r"\['(guardian-[a-z-]+)',\s*'[^']+'\]", js):
            self.assertIn('id="' + target + '"', templates, target)

    def test_version_consistency(self):
        version = ET.parse(ROOT / 'meta.xml').getroot().findtext('version')
        self.assertEqual(version, '0.28.1')
        self.assertIn("GUARDIAN_VERSION = '" + version + "'",
                      (ROOT / 'plib/controllers/IndexController.php').read_text())
        self.assertIn('Guardian Lite <span>v' + version + '</span>',
                      (ROOT / 'plib/views/scripts/index/index.phtml').read_text())


if __name__ == '__main__':
    unittest.main()
