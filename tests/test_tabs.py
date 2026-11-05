import pathlib
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TabsTests(unittest.TestCase):
    def test_panel_landmarks_exist(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        ids = ['guardian-overview', 'guardian-scan', 'guardian-shield',
               'guardian-scan-start', 'guardian-scan-report',
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
                         'guardian_active_tab', 'hashchange', 'DOMContentLoaded', 'guardian-webshield',
                         'guardian_active_module', 'Malware Scanner', "label: 'Webschutz & PHP'"):
            self.assertIn(expected, js)
        self.assertNotIn('eval(', js)
        self.assertNotIn('innerHTML', js)
        self.assertIn('moduleViews[target].hidden = !active || target !== selected;', js)
        self.assertIn('var openMenu = null;', js)
        self.assertIn('submenu.hidden = openMenu !== group.id;', js)
        self.assertIn('guardian-menu-static', view)
        self.assertIn('<main class="guardian-pages">', view)
        self.assertLess(view.index('>Dashboard</summary>'), view.index('>Incidents</summary>'))
        self.assertLess(view.index('>Incidents</summary>'), view.index('>Firewall</summary>'))
        self.assertIn('guardian-menu-settings', view)
        self.assertIn('guardian-brand', view)
        self.assertIn('id="guardian-firewall"', view)
        self.assertIn('href="#guardian-malware-repair"', view)
        self.assertIn('id="guardian-malware-repair"',
                      (ROOT / 'plib/views/scripts/index/management.phtml').read_text())

    def test_sidebar_groups_and_submenu_links_have_rendered_targets(self):
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        templates = (ROOT / 'plib/views/scripts/index/index.phtml').read_text() + \
            (ROOT / 'plib/views/scripts/index/management.phtml').read_text()
        for target in re.findall(r"\['(guardian-[a-z-]+)',\s*'[^']+'\]", js):
            self.assertIn('id="' + target + '"', templates, target)

    def test_module_views_are_individual_and_scan_is_split(self):
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        self.assertIn("['guardian-scan-start', 'Scan starten']", js)
        self.assertIn("['guardian-scan-report', 'Letzter Bericht']", js)
        self.assertIn('view.appendChild(target);', js)
        self.assertIn('details:not([open])>ul{display:none!important}',
                      (ROOT / 'htdocs/css/guardian.css').read_text())

    def test_navigation_animations_respect_reduced_motion(self):
        css = (ROOT / 'htdocs/css/guardian.css').read_text()
        self.assertIn('@keyframes guardian-menu-enter', css)
        self.assertIn('@keyframes guardian-view-enter', css)
        self.assertIn('@media(prefers-reduced-motion:reduce)', css)
        self.assertIn('.guardian-module-view:not([hidden])', css)

    def test_version_consistency(self):
        version = ET.parse(ROOT / 'meta.xml').getroot().findtext('version')
        self.assertEqual(version, '0.28.9')
        self.assertIn("GUARDIAN_VERSION = '" + version + "'",
                      (ROOT / 'plib/controllers/IndexController.php').read_text())
        self.assertIn('<span>v' + version + '</span>',
                      (ROOT / 'plib/views/scripts/index/index.phtml').read_text())

    def test_optional_crowdsec_panel_is_read_only_and_uses_guardian_firewall_flow(self):
        helper = (ROOT / 'sbin/guardian-helper').read_text()
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        self.assertIn("'crowdsec': crowdsec_status()", helper)
        self.assertIn("'decisions', 'list', '--output', 'json'", helper)
        self.assertIn('freie IDS-Entscheidungen', view)
        self.assertIn("getActionUrl('index', 'ip')", view)
        self.assertIn('name="operation" value="permanent"', view)
        self.assertIn('Kostenlose CrowdSec-Installation fuer Linux', view)
        self.assertIn('Guardian installiert keinen zweiten Firewall-Bouncer', view)


if __name__ == '__main__':
    unittest.main()
