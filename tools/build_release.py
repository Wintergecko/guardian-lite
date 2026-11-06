#!/usr/bin/env python3
"""Build a minimal Plesk extension ZIP (with meta.xml at ZIP root)."""
import argparse
import hashlib
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOP_FILES = ('meta.xml', 'README.md', 'CHANGES.md', 'DESCRIPTION.md', 'SECURITY.md', 'MANAGEMENT.md',
             'FEATURES.md', 'ARCHITEKTUR.md', 'SENTINEL-STATUS.md', 'LICENSE')
TOP_DIRS = ('htdocs', 'plib', 'sbin', 'security')


def build(dest, tag=None):
    root = ET.parse(str(ROOT / 'meta.xml')).getroot()
    version = (root.findtext('version') or '').strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('meta.xml version must be numeric semantic X.Y.Z')
    if root.findtext('id') != 'guardian-lite':
        raise ValueError('meta.xml ID must be guardian-lite')
    if tag is not None and tag != 'v' + version:
        raise ValueError('Tag %s must match meta.xml v%s' % (tag, version))
    files = [ROOT / name for name in TOP_FILES]
    for dirname in TOP_DIRS:
        files.extend(p for p in (ROOT / dirname).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    for file in files:
        if not file.is_file() or file.is_symlink():
            raise ValueError('Required file missing or is symlink: ' + str(file))
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / ('guardian-lite-' + version + '.zip')
    with zipfile.ZipFile(out, 'w') as z:
        for file in files:
            rel = file.relative_to(ROOT).as_posix()
            mode = 0o755 if rel in ('sbin/guardian-helper', 'sbin/guardian-updater', 'sbin/guardian-manager') else 0o644
            info = zipfile.ZipInfo(rel, date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            data = file.read_bytes()
            if rel in TOP_FILES or rel in ('sbin/guardian-helper', 'sbin/guardian-updater', 'sbin/guardian-manager') or file.suffix in ('.py', '.php', '.phtml', '.css', '.js', '.md', '.rules', '.conf', '.example'):
                # A Windows checkout must still produce executable Unix shebangs.
                data = data.replace(b'\r\n', b'\n')
            z.writestr(info, data, compresslevel=9)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    checksum = dest / (out.name + '.sha256')
    checksum.write_text('%s  %s\n' % (digest, out.name), encoding='utf-8')
    print(str(out))
    print('SHA256', digest)
    return out


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default=str(ROOT / 'dist'))
    parser.add_argument('--tag', default=None)
    args = parser.parse_args()
    try:
        build(Path(args.out).resolve(), args.tag)
    except (ValueError, OSError, ET.ParseError) as e:
        print('ERROR:', e, file=sys.stderr)
        sys.exit(1)
