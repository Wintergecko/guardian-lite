import pathlib
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ScanUiTests(unittest.TestCase):
    def test_running_scan_shows_progress_and_refreshes(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        css = (ROOT / 'htdocs/css/guardian.css').read_text()
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        helper = (ROOT / 'sbin/guardian-helper').read_text()
        self.assertIn("['queued', 'starting', 'running']", view)
        self.assertIn('data-guardian-scan-running', view)
        self.assertIn('role="progressbar"', view)
        self.assertIn('.guardian-busy-track span', css)
        self.assertIn('@keyframes guardian-busy-slide', css)
        self.assertIn("root.querySelector('[data-guardian-scan-running]')", js)
        self.assertIn('window.location.reload()', js)
        rapid = helper.index("scan['rapid_scan'] = rapid_scan")
        self.assertIn('save_job(scan)', helper[rapid:rapid + 200])

    def test_job_status_is_a_table_with_badges_and_progress(self):
        management = (ROOT / 'plib/views/scripts/index/management.phtml').read_text()
        css = (ROOT / 'htdocs/css/guardian.css').read_text()
        self.assertNotIn("renderResult('Auftragsstatus'", management)
        self.assertIn('$renderJobs(', management)
        self.assertIn('guardian-job-table', management)
        self.assertIn("'finished' => ['Abgeschlossen', 'is-good']", management)
        self.assertIn("'error' => ['Fehler', 'is-bad']", management)
        self.assertIn('data-guardian-scan-running', management)
        self.assertIn('.guardian-state.is-bad', css)

    def test_long_operations_show_busy_bar_without_cancelled_confirms(self):
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        for operation in ('crs-stage', 'cloud-save', 'baseline-create', 'repair-set', 'wp-db-scan',
                          'cms-db-clamav-scan', 'retention-prune'):
            self.assertIn("'" + operation + "'", js)
        self.assertIn('update-apply', js)
        self.assertIn('if (event.defaultPrevented) return;', js)

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
        self.assertIn('.guardian select{display:block;box-sizing:border-box', css)
        self.assertIn('.guardian .guardian-formline select', css)
        self.assertIn('value="ban">', view)
        self.assertIn('Fail2Ban-Freigabe', view)
        self.assertIn('id="guardian-operation"', view)
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

    def test_global_ignore_is_labeled_and_disables_quarantine(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        self.assertIn("$currentGlobalIgnoreHashes = $management['global_ignore_hashes'] ?? []", view)
        self.assertIn('Global ignoriert (SHA-256)', view)
        self.assertIn("['found', 'quarantined'], true) && !$findingIgnored", view)

    def test_firewall_exception_is_scoped_to_guardian(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        self.assertIn('Guardian-IP-Ausnahmen', view)
        self.assertIn('hebt keine bereits bestehenden Regeln auf', view)

    def test_firewall_dashboard_and_debug_toggle_are_available(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        management_view = (ROOT / 'plib/views/scripts/index/management.phtml').read_text()
        controller = (ROOT / 'plib/controllers/IndexController.php').read_text()
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        self.assertIn('guardian-firewall-inventory', view)
        self.assertIn('guardian-plesk-port-inventory', view)
        self.assertIn('Alle Plesk-Portregeln', view)
        self.assertIn('Guardian-Portregeln', view)
        self.assertIn('guardian-firewall-search', view)
        self.assertIn('Greylist, Bot-Challenges', view)
        self.assertIn('debug-on', controller)
        self.assertIn('debug-off', controller)
        self.assertIn('firewallDebug', management_view)
        self.assertIn('Guardian-Moduldiagnose', management_view)
        self.assertIn('Guardian-Debugging einschalten', management_view)
        action = controller.split('public function firewallAction()', 1)[1]
        self.assertIn('$this->verifyPost();', action)
        self.assertIn("getElementById('guardian-firewall-inventory')", js)

    def test_fail2ban_lists_current_bans_and_offers_safe_actions(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        controller = (ROOT / 'plib/controllers/IndexController.php').read_text()
        helper = (ROOT / 'sbin/guardian-helper').read_text()
        self.assertIn("$jailInfo['banned_ips']", view)
        self.assertIn('name="operation" value="unban"', view)
        self.assertIn('value="permanent"', view)
        self.assertIn("['firewall-action', 'ban', $ip, $remote, '0']", controller)
        self.assertIn("'banned_ips_available': ip_match is not None", helper)

    def test_menus_group_existing_guardian_features(self):
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        management = (ROOT / 'plib/views/scripts/index/management.phtml').read_text()
        self.assertIn("['guardian-fail2ban', 'Alle Listen']", js)
        self.assertIn('class="guardian-select"', management)
        self.assertIn("['guardian-firewall', 'Plesk-Regeln']", js)
        self.assertIn("['guardian-ip-rules', 'IP-Regeln']", js)
        self.assertIn("['guardian-ports', 'Ports']", js)
        self.assertIn("['guardian-crowdsec', 'CrowdSec & Diagnose']", js)
        self.assertIn("['guardian-waf-events', 'Events']", js)
        self.assertIn("['guardian-incidents', 'Meldungen & Audit-Log']", js)
        self.assertIn("['guardian-malware-repair', 'Baselines & Wiederherstellung']", js)
        self.assertIn("['guardian-malware-ignore', 'Ignore List']", js)
        self.assertIn("['guardian-cms-integrity', 'CMS- & Cron-", js)
        self.assertIn("['guardian-runtime', 'PHP Runtime", js)
        self.assertIn("['guardian-php-config', 'Handler & Rollback']", js)
        self.assertIn("['guardian-reputation', 'IP-Reputation']", js)
        self.assertIn("label: 'Webschutz & PHP'", js)
        self.assertIn("['guardian-updater', 'Updates']", js)
        self.assertIn("['guardian-management', 'Firewall-Debugausgabe']", js)
        self.assertNotIn("['guardian-roadmap', 'Funktionsumfang']", js)

    def test_alert_delivery_queue_is_visible_and_admin_retry_is_csrf_protected(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        controller = (ROOT / 'plib/controllers/IndexController.php').read_text()
        self.assertIn("$alertDelivery['pending']", view)
        self.assertIn("getActionUrl('index', 'alerts-retry')", view)
        self.assertIn("$this->verifyPost();", controller.split('public function alertsRetryAction()', 1)[1])

    def test_owasp_crs_controls_require_explicit_stage_activation_and_rollback(self):
        view = (ROOT / 'plib/views/scripts/index/management.phtml').read_text()
        controller = (ROOT / 'plib/controllers/IndexController.php').read_text()
        manager = (ROOT / 'sbin/guardian-manager').read_text()
        self.assertIn('OWASP Core Rule Set', view)
        self.assertIn('crs-stage', controller)
        self.assertIn('crs-activate', controller)
        self.assertIn('crs-rollback', controller)
        self.assertIn('crs_verify_signature', manager)
        self.assertIn('crs_activation_configuration_failure_restores_previous_file',
                      (ROOT / 'tests/test_management.py').read_text())

    def test_versions(self):
        version = ET.parse(ROOT / 'meta.xml').getroot().findtext('version')
        self.assertEqual(version, '0.28.55')
        for file in ('plib/controllers/IndexController.php', 'plib/views/scripts/index/index.phtml'):
            self.assertIn(version, (ROOT / file).read_text())
