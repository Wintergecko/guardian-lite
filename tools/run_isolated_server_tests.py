#!/usr/bin/env python3
"""Run a staged source copy in a transient, isolated systemd service.

No installation, service reload, package installation, or host firewall changes.
Requires Linux, root, systemd and existing Python/PHP/Apache test dependencies.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


RUNNER = r'''
import json, os, pathlib, subprocess, unittest
os.makedirs('/var/lib', exist_ok=True)
suite = unittest.defaultTestLoader.discover('tests')
result = unittest.TextTestRunner(verbosity=2).run(suite)
summary = {'run': result.testsRun, 'failures': len(result.failures),
           'errors': len(result.errors), 'skipped': len(result.skipped)}
print('TEST_SUMMARY ' + json.dumps(summary), flush=True)
if not result.wasSuccessful():
    raise SystemExit(1)
for script in ('php_management_smoke.php', 'php_scan_controller_smoke.php', 'plesk_updater_smoke.php'):
    subprocess.run(['php', 'tests/' + script], check=True)
for directory in ('htdocs', 'plib', 'sbin'):
    for path in sorted(pathlib.Path(directory).rglob('*')):
        if path.suffix in ('.php', '.phtml'):
            subprocess.run(['php', '-l', str(path)], check=True)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Linux and root are required')
    source = args.source.resolve(strict=True)
    if (source.parent != Path('/opt') or
            not re.fullmatch(r'guardian-integration-[a-f0-9]{12}', source.name)):
        parser.error('Source must be a dedicated /opt/guardian-integration-<12 hex digits> copy')
    for name in ('meta.xml', 'tests', 'sbin', 'LICENSE'):
        if not (source / name).exists():
            parser.error('Incomplete staged source: ' + name)
    properties = {
        'WorkingDirectory': str(source),
        'ProtectSystem': 'strict', 'ProtectHome': 'yes',
        'PrivateTmp': 'yes', 'PrivateNetwork': 'yes', 'PrivateDevices': 'yes',
        # /var and /run are fresh mounts: no host database, Fail2Ban or systemd sockets.
        'TemporaryFileSystem': '/run:ro /var:rw',
        'NoNewPrivileges': 'yes', 'RestrictNamespaces': 'yes',
        'ProtectKernelTunables': 'yes', 'ProtectKernelModules': 'yes',
        'ProtectControlGroups': 'yes',
        'RuntimeMaxSec': '300', 'MemoryMax': '1G', 'TasksMax': '128', 'CPUQuota': '100%',
        'CapabilityBoundingSet': ('CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH '
                                  'CAP_FOWNER CAP_FSETID CAP_SETGID CAP_SETUID CAP_KILL CAP_SYS_RESOURCE'),
    }
    command = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
               '--unit=guardian-isolated-tests-' + uuid.uuid4().hex[:12]]
    for key, value in properties.items():
        command.extend(['-p', key + '=' + value])
    command.extend(['--setenv=PYTHONDONTWRITEBYTECODE=1', '--setenv=PYTHONUTF8=1',
                    '/usr/bin/python3', '-c', RUNNER])
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=330)
    print(result.stdout, end='')
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
