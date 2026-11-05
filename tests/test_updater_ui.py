import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class UpdaterUiTests(unittest.TestCase):
    def test_default_repo_can_be_used_without_saving(self):
        controller = (ROOT / 'plib/controllers/IndexController.php').read_text()
        self.assertIn("private const DEFAULT_UPDATE_REPO = 'Wintergecko/guardian-lite'", controller)
        self.assertIn("$repo = $this->updateRepository();", controller)
        self.assertIn("$this->view->updateRepo = $this->updateRepository();", controller)
        self.assertIn("return $saved !== '' ? $saved : self::DEFAULT_UPDATE_REPO;", controller)

    def test_check_button_is_unconditional(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        self.assertIn('>Auf neue Version pruefen</button>', view)
        self.assertNotIn("<?php if ($this->updateRepo !== ''): ?>", view)
        self.assertIn("pm_Context::getActionUrl('index', 'update-check')", view)
        self.assertIn('name="csrf"', view)

    def test_check_feedback_persists_and_is_visible(self):
        view = (ROOT / 'plib/views/scripts/index/index.phtml').read_text()
        controller = (ROOT / 'plib/controllers/IndexController.php').read_text()
        self.assertIn('guardian-update-check-form', view)
        self.assertIn('guardian-update-check-time', view)
        self.assertIn('Update-Pruefung fehlgeschlagen:', view)
        self.assertIn("pm_Settings::set(self::LAST_UPDATE_KEY, $data);", controller)
        self.assertIn("'#guardian-tab-updates'", controller)
        self.assertNotIn("$_SESSION['guardian_update_result']", controller)
        js = (ROOT / 'htdocs/js/guardian-tabs.js').read_text()
        self.assertIn("checkForm.addEventListener('submit'", js)

    def test_global_debug_includes_updater_outcome_hook(self):
        controller = (ROOT / 'plib/controllers/IndexController.php').read_text()
        helper = (ROOT / 'sbin/guardian-helper').read_text()
        self.assertIn("$this->helper(['debug-event', $stage", controller)
        self.assertIn("'updater-' + argv[1]", helper)


if __name__ == '__main__':
    unittest.main()
