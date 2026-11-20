"""Native smoke helpers must probe readiness using their TLS kubeconfig."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent


def load_helper(filename):
    spec = importlib.util.spec_from_file_location(filename, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NativeReadiness(unittest.TestCase):
    def test_smoke_helpers_use_authenticated_api(self):
        for filename, classname, method, response in (
            ('test-storage-native.py', 'NativeStorageSmoke', 'kubectl', SimpleNamespace(returncode=0, stdout='ok\n')),
            ('test-resource-management.py', 'Smoke', 'k', SimpleNamespace(returncode=0, stdout='ok\n')),
            ('test-kubectl-validation.py', 'Server', 'kubectl', (0, 'ok\n', '')),
        ):
            with self.subTest(helper=filename), tempfile.TemporaryDirectory() as tmp:
                module = load_helper(filename)
                helper = getattr(module, classname).__new__(getattr(module, classname))
                root = Path(tmp)
                helper.root = helper.dir = helper.directory = root
                helper.config = root / 'kubeconfig'
                helper.config.touch()
                helper.state = root / 'state'
                helper.binary = helper.executable = '/unused/gr8s'
                helper.args = SimpleNamespace(binary='/unused/gr8s')
                helper.port = helper.api = 12345
                helper.node_port = helper.node = 12346
                helper.env = {'KUBECONFIG': str(helper.config)}
                helper.log = Mock()
                helper.process = None
                failure = (1, '', 'not ready') if isinstance(response, tuple) else SimpleNamespace(returncode=1, stdout='')
                query = Mock(side_effect=[module.subprocess.TimeoutExpired('kubectl', 5), failure, response])
                setattr(helper, method, query)
                with patch.object(module.subprocess, 'Popen', return_value=Mock(poll=Mock(return_value=None))), \
                     patch.object(module.time, 'sleep'), \
                     patch('urllib.request.urlopen', side_effect=AssertionError('plaintext HTTP bypasses TLS kubeconfig')):
                    helper.start()
                self.assertEqual(query.call_count, 3)
                for call in query.call_args_list:
                    self.assertIn('/readyz', call.args)
                    self.assertIn('--raw', call.args)
                    self.assertEqual(call.kwargs['timeout'], 5)


if __name__ == '__main__':
    unittest.main()
