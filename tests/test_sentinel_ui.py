import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class SentinelUiTests(unittest.TestCase):
    def test_react_shell_is_progressive_and_uses_server_rendered_status(self):
        template = (ROOT / 'plib/views/scripts/index/index.phtml').read_text(encoding='utf-8')
        app = (ROOT / 'ui/src/main.tsx').read_text(encoding='utf-8')
        tabs = (ROOT / 'htdocs/js/guardian-tabs.js').read_text(encoding='utf-8')
        self.assertIn('id="sentinel-app-root" hidden', template)
        self.assertIn('data-status=', template)
        self.assertIn('data-fail2ban-url=', template)
        self.assertIn('data-fail2ban-set-url=', template)
        self.assertIn('data-fail2ban-restore-url=', template)
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
        self.assertIn('credentials: \'same-origin\'', app)
        self.assertIn('cache: \'no-store\'', app)
        self.assertIn("available' => empty($this->helperError)", template)
        self.assertNotIn('innerHTML', app)
        self.assertNotIn('eval(', app)
        styles = (ROOT / 'ui/src/styles.css').read_text(encoding='utf-8')
        self.assertIn('sentinel-dashboard-active .guardian-shell.sentinel-ready .guardian-pages', styles)
        self.assertIn('sentinel-module-active .guardian-shell.sentinel-ready .guardian-pages', styles)
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
