#!/usr/bin/env python3
"""Exercise release artifact assembly and its rejection of invalid inputs."""
import hashlib
import gzip
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

PACKAGER = Path(__file__).with_name('package-release.py')


class ReleasePackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ('README.md', 'LICENSE', 'NOTICE', 'NOTICES'):
            (self.root / name).write_text(name + '\n')
        for name in ('install.sh', 'gr8s-killall.sh', 'gr8s-uninstall.sh'):
            (self.root / name).write_text('#!/bin/sh\nexit 0\n')
        self.binary = self.root / 'gr8s'
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', header, 18, 62)
        self.binary.write_bytes(header + b'release payload')
        self.binary.chmod(0o755)
        self.output = self.root / 'dist'

    def package(self, *, version='v1.37.2-gr8s.0', arch='amd64'):
        return subprocess.run([
            sys.executable, str(PACKAGER), '--root', str(self.root),
            '--binary', str(self.binary), '--notices', str(self.root / 'NOTICES'),
            '--output-dir', str(self.output), '--version', version,
            '--arch', arch, '--epoch', '1234567890',
        ], capture_output=True, text=True)

    def test_archive_and_installer_asset_have_the_same_executable(self):
        result = self.package()
        self.assertEqual(result.returncode, 0, result.stderr)
        raw = self.output / 'gr8s-linux-amd64'
        self.assertEqual(raw.read_bytes(), self.binary.read_bytes())
        archive = self.output / 'gr8s-1.37.2-gr8s.0-linux-amd64.tar.gz'
        prefix = 'gr8s-1.37.2-gr8s.0-linux-amd64/'
        with tarfile.open(archive) as bundle:
            self.assertEqual(set(bundle.getnames()), {
                prefix + name for name in ('gr8s', 'README.md', 'LICENSE', 'NOTICE',
                                          'NOTICES', 'install.sh', 'gr8s-killall.sh',
                                          'gr8s-uninstall.sh')})
            self.assertEqual(bundle.extractfile(prefix + 'gr8s').read(), raw.read_bytes())
            for member in bundle.getmembers():
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertEqual(member.mtime, 1234567890)
                self.assertEqual(member.mode, 0o755 if member.name.endswith(('gr8s', '.sh')) else 0o644)
        checksum = self.output / 'gr8s-linux-amd64.sha256'
        good = subprocess.run(['sha256sum', '-c', checksum.name], cwd=self.output, capture_output=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        raw.write_bytes(raw.read_bytes() + b'corrupt')
        bad = subprocess.run(['sha256sum', '-c', checksum.name], cwd=self.output, capture_output=True)
        self.assertNotEqual(bad.returncode, 0, 'corrupt release asset passed its checksum')

    def test_same_inputs_produce_identical_archive_bytes(self):
        self.assertEqual(self.package().returncode, 0)
        archive = next(self.output.glob('*.tar.gz'))
        first = hashlib.sha256(archive.read_bytes()).digest()
        for item in self.output.iterdir():
            item.unlink()
        (self.root / 'LICENSE').touch()
        self.assertEqual(self.package().returncode, 0)
        self.assertEqual(hashlib.sha256(archive.read_bytes()).digest(), first)

    def test_rejects_wrong_architecture_without_creating_assets(self):
        result = self.package(arch='arm64')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('architecture', result.stderr)
        self.assertFalse(self.output.exists())

    def test_arm64_elf_is_packaged_as_arm64(self):
        data = bytearray(self.binary.read_bytes())
        struct.pack_into('<H', data, 18, 183)
        self.binary.write_bytes(data)
        result = self.package(arch='arm64')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.output / 'gr8s-linux-arm64').is_file())

    def test_rejects_missing_or_empty_license_notices(self):
        for content in (None, ''):
            with self.subTest(content=content):
                if content is None:
                    (self.root / 'NOTICES').unlink()
                else:
                    (self.root / 'NOTICES').write_text(content)
                result = self.package()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('NOTICES', result.stderr)
                self.assertFalse(self.output.exists())

    def test_rejects_dirty_and_path_like_versions(self):
        for version in ('v1.37.2+dirty', '../escape', 'bad version', ''):
            with self.subTest(version=version):
                result = self.package(version=version)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('version', result.stderr)
                self.assertFalse(self.output.exists())

    def test_rejects_non_elf_binary(self):
        self.binary.write_text('#!/bin/sh\nexit 0\n')
        result = self.package()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ELF', result.stderr)
        self.assertFalse(self.output.exists())

    def test_notices_include_precompressed_dashboard_licenses_once(self):
        scripts = self.root / 'scripts'
        scripts.mkdir()
        collector = scripts / 'collect-notices.sh'
        shutil.copyfile(PACKAGER.with_name('collect-notices.sh'), collector)
        assets = self.root / 'assets' / 'dashboard'
        assets.mkdir(parents=True)
        license_text = b'Unique dashboard dependency license\n'
        (assets / 'one.LICENSE.txt.gz').write_bytes(gzip.compress(license_text))
        (assets / 'two.LICENSE.txt.gz').write_bytes(gzip.compress(license_text))
        tool = self.root / 'ocicl'
        tool.write_text('#!/bin/sh\nprintf "Lisp dependency licenses\\n"\n')
        tool.chmod(0o755)
        result = subprocess.run(['sh', str(collector), 'collected-notices'],
                                env={**os.environ, 'PATH': f'{self.root}:{os.environ["PATH"]}'},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        contents = (self.root / 'collected-notices').read_text()
        self.assertEqual(contents.count(license_text.decode()), 1)
        self.assertIn('Lisp dependency licenses', contents)


if __name__ == '__main__':
    unittest.main()
