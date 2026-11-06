import pathlib
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TabsTests(unittest.TestCase):
    def test_panel_landmarks_exist(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        ids = ['guardian-overview', 'guardian-dashboard-top', 'guardian-scan', 'guardian-shield',
               'guardian-scan-start', 'guardian-scan-report',
               'guardian-network', 'guardian-runtime', 'guardian-webshield',
               'guardian-waf-events', 'guardian-events-table', 'guardian-event-search', 'guardian-event-range', 'guardian-fail2ban', 'guardian-firewall',
               'guardian-updater', 'guardian-changes', 'guardian-monitor',
               'guardian-history', 'guardian-incidents', 'guardian-roadmap', 'guardian-f2b-bulk', 'guardian-recommendations']
        for name in ids:
            self.assertEqual(view.count('id="' + name + '"'), 1, name)
        management = (ROOT / 'plib/views/scripts/index/management.phtml').read_text()
        for name in ('guardian-php-config', 'guardian-webshield-config', 'guardian-webshield-domains', 'guardian-turnstile',
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
                         'guardian_active_module', 'Malware Scanner', "label: 'Webschutz & PHP'",
                         "var incidentDashboard = root.querySelector('[data-incident-dashboard]');"):
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
        self.assertIn('data-country-counts=', view)
        self.assertIn('guardian-world-map', view)
        self.assertIn('IP-Geolokalisierung: DB-IP', view)
        self.assertIn("['guardian-dashboard-top', 'Angriffskarte & Status']", js)
        self.assertIn('data-country="' + 'US' + '"',
                      (ROOT / 'htdocs/img/world-map.svg').read_text())
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
        self.assertEqual(version, '0.28.40')
        self.assertIn("GUARDIAN_VERSION = '" + version + "'",
                      (ROOT / 'plib/controllers/IndexController.php').read_text())
        self.assertIn('<span>v' + version + '</span>',
                      (ROOT / 'plib/views/scripts/index/index.phtml').read_text())

    def test_optional_crowdsec_panel_is_read_only_and_uses_guardian_firewall_flow(self):
        helper = (ROOT / 'sbin/guardian-helper').read_text()
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        self.assertIn("'crowdsec': crowdsec", helper)
        self.assertIn("'decisions', 'list', '--output', 'json'", helper)
        self.assertIn('freie IDS-Entscheidungen', view)
        self.assertIn("getActionUrl('index', 'ip')", view)
        self.assertIn('name="operation" value="permanent"', view)
        self.assertIn('Kostenlose CrowdSec-Installation fuer Linux', view)
        self.assertIn('Guardian installiert keinen zweiten Firewall-Bouncer', view)
        management = (ROOT / 'plib/views/scripts/index/management.phtml').read_text()
        self.assertIn('CrowdSec AppSec', management)
        self.assertIn("'forwarding_enabled'", helper)

    def test_incident_dashboard_has_time_filters_stats_and_accessible_chart(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        helper = (ROOT / 'sbin/guardian-helper').read_text()
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        for item in ('data-incident-range="24h"', 'data-incident-range="7d"',
                     'data-incident-range="30d"', 'data-incident-count="critical"',
                     'data-incident-count="malware"', 'data-incident-chart',
                     'id="guardian-incidents-table"', 'id="guardian-incident-severity"'):
            self.assertIn(item, view)
        self.assertIn("'incidents': incident_list(200)", helper)
        self.assertIn('Date.parse(row.getAttribute(\'data-incident-time\')', js)
        self.assertIn('aria-label', js)

    def test_dashboard_has_local_blocked_ip_map_protection_ring_and_trend(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        helper = (ROOT / 'sbin/guardian-helper').read_text()
        svg = (ROOT / 'htdocs/img/world-map.svg').read_text()
        self.assertIn('guardian-protection-ring', view)
        self.assertIn('guardian-world-map', view)
        self.assertIn('guardian-dashboard-chart', view)
        self.assertIn("'blocked_ip_geo': blocked_ip_geo_status(fail2ban, crowdsec, waflog)", helper)
        self.assertIn('MAX_GEOIP_ADDRESSES = 500', helper)
        self.assertIn("add(address, 'fail2ban')", helper)
        self.assertIn("add(event.get('ip', ''), 'waf')", helper)
        self.assertIn('data-country="US"', svg)

    def test_management_results_are_readable_and_page_transition_does_not_fade(self):
        management = (ROOT / 'plib/views/scripts/index/management.phtml').read_text()
        css = (ROOT / 'htdocs/css/guardian.css').read_text()
        for title in ('Letzte Reputationsergebnisse', 'Diagnoseergebnis',
                      'Ergebnis der WordPress-Core-Pruefung', 'Ergebnis des CMS-Datenbank-Scans'):
            self.assertIn(title, management)
        self.assertNotIn('<pre><?= $esc(json_encode(', management)
        self.assertIn('.guardian-result-grid', css)
        self.assertIn('.guardian pre{color:#1e293b!important', css)
        self.assertNotIn('@keyframes guardian-view-enter{from{opacity:0', css)


if __name__ == '__main__':
    unittest.main()
