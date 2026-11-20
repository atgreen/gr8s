#!/usr/bin/env python3
"""CLI transport smoke test using a fixture kubectl; never contacts a cluster."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as directory:
    fake = Path(directory) / 'kubectl'
    fake.write_text('''#!/usr/bin/env python3
import json, sys
kind = sys.argv[sys.argv.index('get') + 1]
resource = {'metadata': {'name': 'example', 'namespace': 'test', 'uid': 'u1', 'resourceVersion': '1'}}
if kind == 'node':
    resource['status'] = {'conditions': [{'type': 'DiskPressure', 'status': 'True'}]}
elif kind == 'deployment':
    resource['status'] = {'conditions': [{'type': 'Progressing', 'status': 'False', 'reason': 'ProgressDeadlineExceeded'}]}
elif kind == 'event':
    resource.update(type='Warning', reason='FailedMount')
else:
    sys.exit(1)
print(json.dumps(resource))
''')
    fake.chmod(0o755)
    env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'])
    for kind, expected in [('node', 'node-DiskPressure-True'),
                           ('deployment', 'deployment-Progressing-False'),
                           ('event', 'event-FailedMount')]:
        result = subprocess.run([str(root / 'scripts/gr8s-diagnose'), kind + '/example',
                                 '--kubeconfig', '/unused-fixture', '-n', 'test', '--json'],
                                env=env, capture_output=True, text=True)
        assert result.returncode == 1, result.stderr
        report = json.loads(result.stdout)
        assert report['findings'][0]['code'] == expected, report
    print('CLI Node, Deployment and Event fixture tests passed.')
