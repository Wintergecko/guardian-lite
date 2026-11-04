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
        self.assertIn("'action' => 'update-check'", view)
        self.assertIn('name="csrf"', view)


if __name__ == '__main__':
    unittest.main()
