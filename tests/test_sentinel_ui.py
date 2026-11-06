import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class SentinelUiTests(unittest.TestCase):
    def test_react_shell_is_progressive_and_uses_server_rendered_status(self):
        template = (ROOT / 'plib/views/scripts/index/index.phtml').read_text(encoding='utf-8')
        app = (ROOT / 'ui/src/main.tsx').read_text(encoding='utf-8')
        tabs = (ROOT / 'htdocs/js/guardian-tabs.js').read_text(encoding='utf-8')
        styles = (ROOT / 'ui/src/styles.css').read_text(encoding='utf-8')
        self.assertIn('id="sentinel-app-root" hidden', template)
        self.assertIn('data-status=', template)
        self.assertIn('data-fail2ban-url=', template)
        self.assertIn('data-fail2ban-set-url=', template)
        self.assertIn('data-fail2ban-restore-url=', template)
        self.assertIn('data-incidents-export-url=', template)
        self.assertIn("'wafEvents' =>", template)
        self.assertIn("'incidents' => array_values", template)
        self.assertIn("array_slice(is_array($this->incidents) ? $this->incidents : [], 0, 200)", template)
        self.assertIn("'inventory' => array_values(array_map", template)
        self.assertIn("'inputAllow' => (int)($fw['counts']['input_allow'] ?? 0)", template)
        self.assertIn('data-csrf=', template)
        self.assertIn('JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP', template)
        self.assertIn('sentinel/sentinel.js', template)
        self.assertIn('sentinel/sentinel.css', template)
        self.assertIn('<h1>Sentinel Security', template)
        self.assertIn('<name>Sentinel Security</name>',
                      (ROOT / 'meta.xml').read_text(encoding='utf-8'))
        self.assertIn('guardian-menu-enhanced [data-menu-target]', app)
        self.assertIn('sentinel-ready', app)
        self.assertIn('Fail2ban · Jail-Details', app)
        self.assertIn('applyJailSettings', app)
        self.assertIn('restoreJailBackup', app)
        self.assertIn('override_sha256', app)
        self.assertIn('hidden={Boolean(activeTarget)}', app)
        self.assertIn('setActiveTarget(item.target)', app)
        self.assertIn("new CustomEvent('guardian:navigate'", app)
        self.assertIn('className="sentinel-route-header"', app)
        self.assertIn('function EventsModule(', app)
        self.assertIn('function PleskFirewallModule(', app)
        self.assertIn("activeTarget === 'guardian-firewall'", app)
        self.assertIn("target === 'guardian-firewall'", app)
        self.assertIn('firewall.inventoryLimited', app)
        self.assertIn('aria-labelledby="sentinel-firewall-rules-title"', app)
        self.assertIn("const THEME_STORAGE_KEY = 'guardian-lite.sentinel.theme'", app)
        self.assertIn('aria-pressed={darkMode}', app)
        self.assertIn("setAttribute('data-sentinel-theme'", app)
        self.assertIn('.guardian.sentinel-light .sentinel-react-content', styles)
        self.assertIn('.guardian.sentinel-dark {', styles)
        self.assertIn('window.localStorage.setItem(THEME_STORAGE_KEY', app)
        self.assertIn('.guardian.sentinel-dark .guardian-pages pre', styles)
        self.assertIn('function normalizeSeverity(', app)
        self.assertIn("['emergency', 'alert', 'critical', 'crit']", app)
        self.assertIn('labels.no', app)
        self.assertIn('sentinel-react-content', app)
        self.assertIn("target === 'guardian-waf-events' || target === 'guardian-incidents'", app)
        self.assertIn('aria-labelledby="sentinel-waf-events-title"', app)
        self.assertIn('aria-labelledby="sentinel-incidents-title"', app)
        self.assertIn('setInterval(() => window.location.reload(), 30000)', app)
        self.assertIn("exportLink.origin !== window.location.origin", app)
        self.assertIn("addEventListener('guardian:navigate'", tabs)
        self.assertIn('credentials: \'same-origin\'', app)
        self.assertIn('cache: \'no-store\'', app)
        self.assertIn("available' => empty($this->helperError)", template)
        self.assertNotIn('Beta-Version: Erst nach Snapshot auf Testsystem testen.', template)
        self.assertIn('ClamAV kann Malware uebersehen.', template)
        self.assertIn('Good-File-Reparatur muss separat pro Domain freigegeben werden.', template)
        self.assertNotIn('innerHTML', app)
        self.assertNotIn('eval(', app)
        self.assertIn('sentinel-dashboard-active .guardian-shell.sentinel-ready .guardian-pages', styles)
        self.assertIn('sentinel-module-active .guardian-shell.sentinel-ready .guardian-pages', styles)
        self.assertRegex(styles, r'\.sentinel-sidebar\s*\{[^}]*z-index:\s*20;')
        self.assertIn('left: calc(100% + 8px)', styles)
        self.assertIn('top: 100%; left: 0', styles)
        self.assertIn('.guardian.sentinel-enabled { width: 100%; max-width: none;', styles)
        self.assertIn('.guardian.sentinel-enabled .guardian-pages { width: auto; margin-left: 0;', styles)
        controller = (ROOT / 'plib/controllers/IndexController.php').read_text(encoding='utf-8')
        self.assertIn('function fail2banSetAction()', controller)
        self.assertIn('function fail2banRestoreAction()', controller)

    def test_every_react_navigation_target_has_a_server_rendered_panel(self):
        app = (ROOT / 'ui/src/main.tsx').read_text(encoding='utf-8')
        templates = (ROOT / 'plib/views/scripts/index/index.phtml').read_text(encoding='utf-8') + \
            (ROOT / 'plib/views/scripts/index/management.phtml').read_text(encoding='utf-8')
        tabs = (ROOT / 'htdocs/js/guardian-tabs.js').read_text(encoding='utf-8')
        targets = re.findall(r"target: '(guardian-[a-z-]+)'", app)
        self.assertTrue(targets)
        for target in targets:
            self.assertIn('id="' + target + '"', templates, target)
            self.assertIn("'" + target + "'", tabs, target)

    def test_react_build_and_release_workflows_are_configured(self):
        package = (ROOT / 'ui/package.json').read_text(encoding='utf-8')
        config = (ROOT / 'ui/vite.config.ts').read_text(encoding='utf-8')
        workflows = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8') + \
            (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8')
        self.assertIn('tsc --noEmit && vite build', package)
        self.assertIn('../htdocs/sentinel', config)
        self.assertEqual(workflows.count('npm ci && npm run build'), 2)
        self.assertTrue((ROOT / 'htdocs/sentinel/sentinel.js').is_file())
        self.assertTrue((ROOT / 'htdocs/sentinel/sentinel.css').is_file())


if __name__ == '__main__':
    unittest.main()
