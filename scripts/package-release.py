#!/usr/bin/env python3
"""Assemble Linux release assets from an already built native executable."""
import argparse
import gzip
import hashlib
from pathlib import Path
import re
import shutil
import struct
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--notices', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--arch', required=True, choices=('amd64', 'arm64'))
    parser.add_argument('--epoch', required=True, type=int)
    args = parser.parse_args()
    if (not re.fullmatch(r'v?\d[0-9A-Za-z.+-]*', args.version)
            or 'dirty' in args.version or args.epoch < 0):
        parser.error('invalid or dirty release version (or negative epoch)')

    files = {'gr8s': args.binary, 'NOTICES': args.notices}
    for name in ('README.md', 'LICENSE', 'NOTICE', 'install.sh',
                 'gr8s-killall.sh', 'gr8s-uninstall.sh'):
        files[name] = args.root / name
    for name, path in files.items():
        if not path.is_file() or path.stat().st_size == 0:
            parser.error(f'missing or empty {name}: {path}')
    with args.binary.open('rb') as binary:
        header = binary.read(64)
    if len(header) < 64 or header[:6] != b'\x7fELF\x02\x01':
        parser.error('binary must be a little-endian ELF64 executable')
    if struct.unpack_from('<H', header, 18)[0] != {'amd64': 62, 'arm64': 183}[args.arch]:
        parser.error('ELF architecture does not match requested architecture')

    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw = args.output_dir / f'gr8s-linux-{args.arch}'
    shutil.copyfile(args.binary, raw)
    raw.chmod(0o755)
    digest = hashlib.sha256(raw.read_bytes()).hexdigest()
    raw.with_suffix('.sha256').write_text(f'{digest}  {raw.name}\n')
    prefix = f'gr8s-{args.version.removeprefix("v")}-linux-{args.arch}'
    with (args.output_dir / f'{prefix}.tar.gz').open('wb') as output:
        with gzip.GzipFile(fileobj=output, filename='', mode='wb', mtime=args.epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as bundle:
                for name, path in sorted(files.items()):
                    member = tarfile.TarInfo(f'{prefix}/{name}')
                    member.size = path.stat().st_size
                    member.mode = 0o755 if name == 'gr8s' or name.endswith('.sh') else 0o644
                    member.mtime = args.epoch
                    with path.open('rb') as contents:
                        bundle.addfile(member, contents)


if __name__ == '__main__':
    main()
