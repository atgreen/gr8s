#!/usr/bin/env python3
"""Verify the Gateway runner invokes the upstream suite and preserves failures."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

RUNNER = Path(__file__).resolve().parents[1] / 'deploy/conformance/run-conformance.sh'

class GatewayRunnerTest(unittest.TestCase):
    def run_suite(self, exit_code):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'conformance'
            binary.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\nexit "$TEST_EXIT"\n')
            binary.chmod(0o755)
            capture = root / 'args'
            env = dict(os.environ, KUBECONFIG=str(root / 'kubeconfig'),
                       GATEWAY_CONFORMANCE_BINARY=str(binary),
                       GATEWAY_CONFORMANCE_REPORT=str(root / 'report.yaml'),
                       GR8S_VERSION='candidate-test', CAPTURE=str(capture),
                       TEST_EXIT=str(exit_code))
            result = subprocess.run(['sh', str(RUNNER), 'gateway'], env=env,
                                    capture_output=True, text=True)
            self.assertTrue(capture.exists(), 'Gateway suite was never executed')
            args = capture.read_text().splitlines()
            self.assertIn('--gateway-class=gr8s', args)
            self.assertIn('--conformance-profiles=GATEWAY-HTTP', args)
            self.assertIn('--supported-features=Gateway,HTTPRoute,ReferenceGrant', args)
            self.assertIn('--report-output=' + str(root / 'report.yaml'), args)
            self.assertIn('--version=candidate-test', args)
            self.assertFalse(any(a.startswith('--skip-tests') for a in args))
            return result

    def test_invokes_official_suite(self):
        self.assertEqual(self.run_suite(0).returncode, 0)

    def test_preserves_suite_failure(self):
        self.assertEqual(self.run_suite(7).returncode, 7)

if __name__ == '__main__':
    unittest.main()
