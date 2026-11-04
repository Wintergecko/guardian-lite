"""Actual ModSecurity parsing and HTTP enforcement on an isolated local Apache."""
import importlib.machinery
import importlib.util
import os
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


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0 and
                     pathlib.Path('/usr/lib/apache2/modules/mod_security2.so').is_file(),
                     'isolated root Apache/ModSecurity runner required')
class WafHttpTests(unittest.TestCase):
    def test_real_http_limit_and_detection_mode(self):
        loader = importlib.machinery.SourceFileLoader('guardian_waf_http', str(ROOT / 'sbin/guardian-manager'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        m = importlib.util.module_from_spec(spec)
        loader.exec_module(m)
        for mode in ('enforce', 'detect'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                folder = pathlib.Path(tmp)
                os.chmod(folder, 0o755)
                (folder / 'data').mkdir(mode=0o777)
                os.chmod(folder / 'data', 0o777)
                (folder / 'index.html').write_text('GUARDIAN_OK')
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
                config = ('ServerRoot /etc/apache2\nServerName localhost\nPidFile %s/pid\n'
                          'Listen 127.0.0.1:%d\nUser www-data\nGroup www-data\n'
                          'LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so\n'
                          'LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so\n'
                          'LoadModule unique_id_module /usr/lib/apache2/modules/mod_unique_id.so\n'
                          'LoadModule security2_module /usr/lib/apache2/modules/mod_security2.so\n'
                          'ErrorLog %s/error.log\nDocumentRoot %s\n'
                          '<Directory %s>\nRequire all granted\n</Directory>\n'
                          'SecRuleEngine On\nSecRequestBodyAccess Off\nSecDataDir %s/data\n'
                          'SecDebugLog %s/debug.log\nSecDebugLogLevel 9\n') % (
                              tmp, port, tmp, tmp, tmp, tmp, tmp)
                conf = folder / 'apache.conf'
                conf.write_text(config + m.waf_rules('example.com', mode, 10))
                apache = shutil.which('apache2') or '/usr/sbin/apache2'
                result = subprocess.run([apache, '-t', '-f', str(conf)], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                proc = subprocess.Popen([apache, '-X', '-f', str(conf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    for _ in range(100):
                        with socket.socket() as sock:
                            if sock.connect_ex(('127.0.0.1', port)) == 0:
                                break
                        time.sleep(.05)
                    statuses = []
                    for _ in range(12):
                        request = urllib.request.Request('http://127.0.0.1:%d/index.html' % port,
                                                         headers={'Host': 'example.com'})
                        try:
                            with urllib.request.urlopen(request, timeout=3) as response:
                                statuses.append(response.status)
                        except urllib.error.HTTPError as error:
                            with error:
                                statuses.append(error.code)
                    if mode == 'enforce':
                        debug = (folder / 'debug.log').read_text(errors='replace')
                        summary = debug[-1500:] + '\n' + (folder / 'error.log').read_text(errors='replace')[-800:]
                        self.assertEqual(statuses[:10], [200] * 10)
                        self.assertEqual(statuses[10:], [429, 429], summary)
                    else:
                        self.assertEqual(statuses, [200] * 12)
                finally:
                    proc.terminate()
                    proc.wait(timeout=10)


if __name__ == '__main__':
    unittest.main()
