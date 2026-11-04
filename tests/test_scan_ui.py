import pathlib
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ScanUiTests(unittest.TestCase):
    def test_every_form_uses_plesk_action_url(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        self.assertNotIn('$this->url(', view)
        for action in ('scan', 'schedule', 'monitor', 'alerts', 'ip', 'update-check'):
            self.assertIn("pm_Context::getActionUrl('index', '" + action + "')", view)

    def test_native_selection_is_readable(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        css = (ROOT / 'htdocs/css/guardian.css').read_text()
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        self.assertIn('id="guardian-domain"', view)
        self.assertIn('guardian-domain-selection-value', view)
        self.assertIn('color:#162c43!important', css)
        self.assertIn("domainSelect.addEventListener('change', showSelectedDomain)", js)

    def test_schedule_result_persists_and_returns_to_tab(self):
        controller = (ROOT / 'plib/controllers/IndexController.php').read_text()
        self.assertIn("'guardian_malware_last_action_v1'", controller)
        self.assertIn("#guardian-tab-malware", controller)
        self.assertIn("$this->finishMalwareAction('schedule'", controller)
        self.assertIn("$this->view->malwareAction", controller)
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        self.assertIn('guardian-action-feedback', view)

    def test_hosted_only_and_preserves_selected_domain(self):
        controller = (ROOT / 'plib/controllers/IndexController.php').read_text()
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        self.assertIn("$domain->hasHosting()", controller)
        self.assertIn("guardian_scan_selected_domain", controller)
        self.assertIn("$this->scanSelectedDomain === $domain", view)
        self.assertIn("$this->view->scanQueue", controller)
        self.assertIn('warten FIFO', view)

    def test_admin_tool_candidates_are_separate_and_never_automatically_removed(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        helper = (ROOT / 'sbin/guardian-helper').read_text()
        self.assertIn('Admin-Tools: manuelle Pruefung', view)
        self.assertIn('keine Malware-Einstufung', view)
        self.assertIn('admin_tool_candidates', helper)
        self.assertIn("'state': 'review'", helper)
        scanner = helper.split('def admin_tool_candidates', 1)[1].split('\ndef ignored_hash_set', 1)[0]
        self.assertNotIn('unlink(', scanner)
        self.assertNotIn('rmtree(', scanner)

    def test_versions(self):
        version = ET.parse(ROOT / 'meta.xml').getroot().findtext('version')
        self.assertEqual(version, '0.18.0')
        for file in ('plib/controllers/IndexController.php', 'plib/views/scripts/index/index.phtml'):
            self.assertIn(version, (ROOT / file).read_text())
