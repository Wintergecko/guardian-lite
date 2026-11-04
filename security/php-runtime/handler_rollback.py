#!/usr/bin/env python3
"""Manually invoked safety utility: backup and guarded rollback for Plesk PHP ini.

This does not install Snuffleupagus, touch FPM services, or enable runtime policies.
Never override a php.ini changed since backup without explicit expected SHA-256.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

BASE = Path('/opt/plesk/php')
BACKUPS = Path('/var/lib/guardian-lite/php-handler-backups')
VERSION = re.compile(r'^[5-9]\.[0-9]{1,2}$')


def php_ini(version):
    if not VERSION.fullmatch(version):
        raise ValueError('Nur PHP-Versionsangaben X.Y erlaubt.')
    return BASE / version / 'etc/php.ini'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_ini(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Datei fehlt oder ist ein Symlink.')
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > 2_000_000 or st.st_uid != 0:
        raise ValueError('Unerwartete PHP-Konfigurationsdatei; kein Zugriff.')
    return path.read_bytes(), st


def backup(version):
    if os.geteuid() != 0:
        raise ValueError('Root-Rechte erforderlich.')
    source = php_ini(version)
    data, st = check_ini(source)
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BACKUPS.is_symlink() or BACKUPS.stat().st_uid != 0:
        raise ValueError('Unsicheres Backup-Verzeichnis.')
    os.chmod(BACKUPS, 0o700)
    token = uuid.uuid4().hex
    path = BACKUPS / (version.replace('.', '-') + '-' + token + '.ini')
    with path.open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    meta = {'version': version, 'sha256': sha(data), 'mode': stat.S_IMODE(st.st_mode),
            'backup': path.name}
    with (BACKUPS / (path.stem + '.json')).open('x', encoding='utf-8') as output:
        os.chmod(output.name, 0o600)
        json.dump(meta, output)
    return meta


def restore(version, backup_file, expected_current):
    if os.geteuid() != 0:
        raise ValueError('Root-Rechte erforderlich.')
    if not re.fullmatch(r'[5-9]-[0-9]{1,2}-[a-f0-9]{32}\.ini', backup_file):
        raise ValueError('Ungueltiger Backup-Dateiname.')
    if not re.fullmatch(r'[a-f0-9]{64}', expected_current):
        raise ValueError('Erwartete aktuelle SHA-256 fehlt.')
    source = php_ini(version)
    current, st = check_ini(source)
    if sha(current) != expected_current:
        raise ValueError('PHP-Konfiguration wurde seit dem Check veraendert; kein Rollback.')
    entry = BACKUPS / backup_file
    if entry.is_symlink() or entry.stat().st_uid != 0:
        raise ValueError('Backup ist nicht root-owned oder ist ein Symlink.')
    meta_path = BACKUPS / (entry.stem + '.json')
    if meta_path.is_symlink() or meta_path.stat().st_uid != 0:
        raise ValueError('Backup-Metadaten ungueltig.')
    meta = json.loads(meta_path.read_text(encoding='utf-8'))
    if meta.get('version') != version or meta.get('backup') != backup_file:
        raise ValueError('Backup gehoert nicht zum PHP-Handler.')
    backup_data = entry.read_bytes()
    if sha(backup_data) != meta['sha256']:
        raise ValueError('Backup-Pruefsumme stimmt nicht.')
    temp = source.with_name('php.ini.guardian-' + uuid.uuid4().hex)
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), meta['mode'] & 0o777)
            output.write(backup_data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(str(temp), str(source))
    finally:
        temp.unlink(missing_ok=True)
    return {'restored': backup_file, 'sha256': sha(backup_data),
            'note': 'PHP-FPM/Apache Dienst noch kontrolliert neu starten; Websites testen.'}


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    a = sub.add_parser('backup')
    a.add_argument('version')
    b = sub.add_parser('rollback')
    b.add_argument('version')
    b.add_argument('backup_file')
    b.add_argument('expected_current_sha256')
    args = parser.parse_args()
    try:
        result = (backup(args.version) if args.action == 'backup' else
                  restore(args.version, args.backup_file, args.expected_current_sha256))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, 'FEHLER: %s\n' % exc)


if __name__ == '__main__':
    main()
