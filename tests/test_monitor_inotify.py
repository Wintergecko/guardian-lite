"""Isolated Linux smoke test; no Plesk or production website required."""
import importlib.machinery
import multiprocessing
import os
import pathlib
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
helper = importlib.machinery.SourceFileLoader('guardian_monitor_integration', str(ROOT/'sbin/guardian-helper')).load_module()


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Linux root CI runner required')
class InotifyIntegrationTests(unittest.TestCase):
    def test_file_write_triggers_event_without_modifying_site(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            prev = (helper.ROOT, helper.VHOSTS, helper.INCIDENT_LOG, helper.ALERT_FILE, helper.MONITOR_CONFIG)
            worker = None
            try:
                helper.ROOT = base/'guardian'
                helper.VHOSTS = base/'vhosts'
                helper.INCIDENT_LOG = helper.ROOT/'incidents.jsonl'
                helper.ALERT_FILE = helper.ROOT/'alerts.json'
                helper.MONITOR_CONFIG = helper.ROOT/'realtime.json'
                web = helper.VHOSTS/'example.com'/'httpdocs'
                web.mkdir(parents=True)
                os.chown(web, 65534, 65534)
                helper.prepare_dir()
                helper.write_json(helper.MONITOR_CONFIG, {'domains': {'example.com': True}})
                worker = multiprocessing.Process(target=helper.watch_worker, args=('example.com',))
                worker.start()
                for _ in range(80):
                    status = helper.read_json(helper.monitor_state_path('example.com'), {})
                    if status.get('state') in ('running', 'degraded'):
                        break
                    if not worker.is_alive():
                        self.fail('Monitor exited before starting')
                    time.sleep(.1)
                else:
                    self.fail('Monitor failed to start')
                target = web/'watch.php'
                data = '<?php echo "unchanged"; ?>'
                target.write_text(data)
                for _ in range(80):
                    if any(x['type']=='file_change' and x['path']=='watch.php' for x in helper.incident_list()):
                        break
                    time.sleep(.1)
                else:
                    self.fail('Live file event not recorded')
                self.assertEqual(target.read_text(), data)
                helper.write_json(helper.MONITOR_CONFIG, {'domains': {}})
                worker.join(timeout=6)
                self.assertEqual(worker.exitcode, 0, 'Worker did not shut down after disabling')
            finally:
                if worker is not None and worker.is_alive():
                    worker.terminate()
                    worker.join(timeout=3)
                (helper.ROOT, helper.VHOSTS, helper.INCIDENT_LOG,
                 helper.ALERT_FILE, helper.MONITOR_CONFIG) = prev
