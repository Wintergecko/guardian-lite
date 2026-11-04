"""Real PHP request guard tests using a local test webserver, no cloud traffic."""
import base64
import hashlib
import hmac
import json
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('php'), 'PHP CLI required')
class BotGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.folder = pathlib.Path(cls.tmp.name)
        config = {'domain': 'example.com', 'sitekey': 'TEST_SITE_KEY', 'secret': 'TEST_SECRET', 'signing_key': 'x' * 64}
        template = (ROOT / 'sbin/guardian-bot-guard.php').read_text(encoding='utf-8')
        encoded = base64.b64encode(json.dumps(config).encode()).decode()
        guard = template.replace('/* GUARDIAN_CONFIG */', "$guardianConfig = json_decode(base64_decode('%s'), true);" % encoded)
        (cls.folder / 'guard.php').write_text(guard, encoding='utf-8')
        (cls.folder / 'router.php').write_text('<?php $_SERVER["HTTPS"]="on"; require __DIR__."/guard.php"; echo "APP_OK";', encoding='utf-8')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        cls.url = 'http://127.0.0.1:%d' % port
        cls.proc = subprocess.Popen([shutil.which('php'), '-S', '127.0.0.1:%d' % port, 'router.php'],
                                    cwd=cls.folder, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(cls.url + '/public.php', timeout=.2).close()
                break
            except (OSError, urllib.error.URLError):
                time.sleep(.05)
        else:
            cls.proc.terminate()
            raise RuntimeError('PHP server failed to start')

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        cls.tmp.cleanup()

    def request(self, path, cookie='', data=None):
        req = urllib.request.Request(self.url + path, headers={'User-Agent': 'GuardianTest', 'Cookie': cookie}, data=data)
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.read().decode()

    def test_public_routes_continue(self):
        self.assertEqual(self.request('/index.php'), (200, 'APP_OK'))

    def test_login_and_encoded_login_require_challenge(self):
        for path in ('/wp-login.php', '/%77p-login.php', '/login', '/administrator/'):
            code, body = self.request(path)
            self.assertEqual(code, 403)
            self.assertIn('cf-turnstile', body)
            self.assertNotIn('TEST_SECRET', body)
            self.assertNotIn('APP_OK', body)

    def test_forged_and_expired_cookies_do_not_bypass(self):
        for cookie in ('1.invalid', '%d.%s' % (int(time.time()) + 3600, 'a' * 64)):
            code, body = self.request('/wp-login.php', '__Host-guardian_clearance=' + cookie)
            self.assertEqual(code, 403)
            self.assertNotIn('APP_OK', body)

    def test_signed_cookie_allows_same_user_agent_only(self):
        expiry = str(int(time.time()) + 600)
        agent = hashlib.sha256(b'GuardianTest').hexdigest()
        signature = hmac.new(b'x' * 64, (expiry + ':' + agent).encode(), hashlib.sha256).hexdigest()
        cookie = '__Host-guardian_clearance=' + expiry + '.' + signature
        self.assertEqual(self.request('/wp-login.php', cookie), (200, 'APP_OK'))

    def test_post_without_clearance_is_never_forwarded(self):
        code, body = self.request('/wp-login.php', data=b'user=admin&password=test')
        self.assertEqual(code, 403)
        self.assertNotIn('APP_OK', body)


if __name__ == '__main__':
    unittest.main()
