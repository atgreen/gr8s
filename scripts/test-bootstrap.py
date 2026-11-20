#!/usr/bin/env python3
"""Exercise lock resolution in fresh Lisp processes with conflicting host registries."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    def test_checkout_lock_provenance(self):
        code = '''
        (with-open-file (stream (merge-pathnames "ocicl.csv" (uiop:getcwd)))
          (loop for line = (read-line stream nil) while line do
            (let* ((fields (mapcar (lambda (field) (string-trim '(#\\Space) field))
                                  (uiop:split-string line :separator '(#\\,))))
                   (relative (third fields))
                   (name (pathname-name relative))
                   (expected (if (equal name "cl+ssl") #P"cl+ssl.asd"
                                 (merge-pathnames relative #P"ocicl/")))
                   (actual (nth-value 2 (asdf:locate-system name))))
              (assert (equal (truename expected) (truename actual)) ()
                      "Wrong source for ~A: ~A, expected ~A" name actual expected))))
        '''
        result = subprocess.run(
            ["sbcl", "--noinform", "--no-sysinit", "--no-userinit", "--non-interactive",
             "--load", str(ROOT / "scripts/bootstrap.lisp"), "--eval", code],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_locked_resolution_and_missing_dependency(self):
        with tempfile.TemporaryDirectory(prefix="gr8s-bootstrap-") as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "ocicl/pinned").mkdir(parents=True)
            (root / "host").mkdir()
            shutil.copyfile(ROOT / "scripts/bootstrap.lisp", root / "scripts/bootstrap.lisp")
            (root / "ocicl.csv").write_text(
                "sample, registry/sample@sha256:test, pinned/sample.asd\n"
                "cl_plus_ssl, registry/tls@sha256:test, pinned/cl+ssl.asd\n"
            )
            for path in ["ocicl/pinned/sample.asd", "ocicl/pinned/cl+ssl.asd",
                         "host/sample.asd", "host/cl+ssl.asd", "cl+ssl.asd"]:
                (root / path).write_text(f'(asdf:defsystem "{Path(path).stem}")\n')
            env = dict(os.environ, CL_SOURCE_REGISTRY=str(root / "host") + "//")
            command = ["sbcl", "--noinform", "--no-sysinit", "--no-userinit", "--non-interactive",
                       "--load", str(root / "scripts/bootstrap.lisp"), "--eval",
                       '(format t "RESULT ~A ~A~%" (nth-value 2 (asdf:locate-system "sample")) '
                       '(nth-value 2 (asdf:locate-system "cl+ssl")))']
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(str(root / "ocicl/pinned/sample.asd"), result.stdout)
            self.assertIn(str(root / "cl+ssl.asd"), result.stdout)
            (root / "ocicl/pinned/sample.asd").unlink()
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Locked dependency sample is missing", result.stderr)
            self.assertNotIn("RESULT", result.stdout)


if __name__ == "__main__":
    unittest.main()
