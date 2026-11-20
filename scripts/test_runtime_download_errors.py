"""Check runtime installer failures without downloading or building binaries."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DownloadErrors(unittest.TestCase):
    def test_failed_download_is_reported_before_copying(self):
        for failing_module in ('containerd', 'grpc'):
            with self.subTest(module=failing_module), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                fake_go = directory / 'go'
                fake_go.write_text('''#!/usr/bin/env python3
import json, os, sys
module = sys.argv[-1]
failed = os.environ['FAIL_MODULE'] in module
print(json.dumps({'Error': 'registry unavailable'} if failed else {'Dir': '/unused-source'}))
sys.exit(23 if failed else 0)
''')
                fake_go.chmod(0o755)
                result = subprocess.run(
                    ['sh', str(ROOT / 'scripts/install-containerd.sh'), str(directory / 'bundle')],
                    env=dict(os.environ, PATH=tmp + os.pathsep + os.environ['PATH'],
                             FAIL_MODULE=failing_module),
                    capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('registry unavailable', result.stderr)
                self.assertIn('download', result.stderr.lower())
                self.assertNotIn('cannot stat', result.stderr)
                self.assertEqual(list((directory / 'bundle/bin').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
