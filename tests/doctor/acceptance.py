#!/usr/bin/env python3
"""Exercise the read-only diagnostic against an explicitly selected disposable cluster."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

config = sys.argv[1]
namespace = 'diagnose-' + uuid.uuid4().hex[:8]
root = Path(__file__).resolve().parents[2]

def kubectl(*args, obj=None):
    result = subprocess.run(['kubectl', '--kubeconfig', config, '-n', namespace,
                             *args], input=json.dumps(obj) if obj else None,
                            text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout

def apply(obj):
    kubectl('apply', '-f', '-', obj=obj)

def diagnose(expected, code=None, kubeconfig=None, pod="web"):
    result = subprocess.run([str(root / 'scripts/gr8s-diagnose'), 'pod/' + pod,
                             '--kubeconfig', kubeconfig or config, '-n', namespace, '--json'],
                            text=True, capture_output=True)
    report = json.loads(result.stdout)
    if expected == 'no-findings':
        # The expanded catalog can independently report Pod scheduling/readiness.
        assert report['status'] in ('no-findings', 'findings'), report
        assert not any(f['code'] in ('missing-resource', 'missing-key')
                       for f in report['findings']), report
    else:
        assert report['status'] == expected, report
    assert result.returncode == {'no-findings': 0, 'findings': 1, 'incomplete': 2}[report['status']]
    assert 'PRIVATE-SENTINEL' not in result.stdout
    if code:
        assert any(f['code'] == code for f in report['findings']), report
    print(('configuration-clear' if expected == 'no-findings' else expected) + ': ' + '; '.join(f['summary'] for f in report['findings']))
    return report

try:
    kubectl('create', 'namespace', namespace)
    # Pin to a nonexistent node so Pod status is stable during observation.
    apply({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'web'},
           'spec': {'nodeName': 'diagnostic-fixture', 'containers': [
               {'name': 'api', 'image': 'busybox:1.36', 'env': [
                   {'name': 'PASSWORD', 'valueFrom': {'secretKeyRef':
                       {'name': 'db', 'key': 'password'}}}]}]}})
    diagnose('findings', 'missing-resource')
    apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'db'},
           'stringData': {'other': 'PRIVATE-SENTINEL'}})
    diagnose('findings', 'missing-key')
    kubectl('patch', 'secret', 'db', '--type=merge', '-p',
            json.dumps({'data': {'password': 'UFJJVkFURS1TRU5USU5FTA=='}}))
    diagnose('no-findings')
    apply({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'config'},
           'spec': {'nodeName': 'diagnostic-fixture', 'containers': [
               {'name': 'api', 'image': 'busybox:1.36'}], 'volumes': [
               {'name': 'settings', 'configMap': {'name': 'settings',
                    'items': [{'key': 'settings.bin', 'path': 'settings.bin'}]}},
               {'name': 'optional', 'secret': {'secretName': 'optional', 'optional': True}}]}})
    diagnose('findings', 'missing-resource', pod='config')
    apply({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'settings'}})
    diagnose('findings', 'missing-key', pod='config')
    kubectl('patch', 'configmap', 'settings', '--type=merge', '-p',
            json.dumps({'binaryData': {'settings.bin': 'eA=='}}))
    diagnose('no-findings', pod='config')
    if '--skip-rbac' not in sys.argv[2:]:
        # A real authenticated reader can read the Pod but cannot read Secrets.
        kubectl('create', 'serviceaccount', 'reader')
        kubectl('create', 'role', 'pod-reader', '--verb=get', '--resource=pods')
        kubectl('create', 'rolebinding', 'pod-reader', '--role=pod-reader',
                '--serviceaccount=' + namespace + ':reader')
        token = kubectl('create', 'token', 'reader').strip()
        view = json.loads(kubectl('config', 'view', '--raw', '-o', 'json'))
        view['users'] = [{'name': 'reader', 'user': {'token': token}}]
        for context in view['contexts']:
            context['context']['user'] = 'reader'
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as restricted:
            json.dump(view, restricted)
            restricted.flush()
            report = diagnose('incomplete', kubeconfig=restricted.name)
            assert not report['findings']
    else:
        print('SKIPPED: restricted-reader acceptance')
    print('Live VM acceptance passed.')
finally:
    kubectl('delete', 'namespace', namespace, '--wait=false')
