#!/usr/bin/env python3
"""Exercise doctor CLI, kubectl transport, dependency traversal, and grouping offline."""
import json
import os
from pathlib import Path
import subprocess
import argparse
import tempfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
entry = parser.add_mutually_exclusive_group()
entry.add_argument('--server', action='store_true', help='Exercise the full gr8s source entry point')
entry.add_argument('--binary', type=Path, help='Exercise a dumped gr8s executable')
options = parser.parse_args()
if options.binary:
    command = [str(options.binary.resolve()), 'doctor']
elif options.server:
    command = [str(root / 'scripts/gr8s'), 'doctor']
else:
    command = [str(root / 'scripts/gr8s-doctor')]
with tempfile.TemporaryDirectory() as directory:
    executable = Path(directory) / 'kubectl'
    log = Path(directory) / 'requests.jsonl'
    executable.write_text('''#!/usr/bin/env python3
import json, os, sys, time
if os.environ.get('SLOW_GET'):
 open(os.environ['SLOW_PID'], 'w').write(str(os.getpid()))
 time.sleep(30)
args = sys.argv[1:]
with open(os.environ['REQUEST_LOG'], 'a') as out: out.write(json.dumps(args) + '\\n')
i = args.index('get')
kind = args[i+1]
name = args[i+2] if i+2 < len(args) and not args[i+2].startswith('-') else None
ns = args[args.index('--namespace')+1] if '--namespace' in args else 'test'
def pod(name):
 if name == 'p2' and os.environ.get('MALFORMED_POD'):
  return {'kind':'Pod','metadata':{'name':name,'namespace':ns,'uid':name,'resourceVersion':'1'},'status':{'conditions':42}}
 return {'kind':'Pod','metadata':{'name':name,'namespace':ns,'uid':name,'resourceVersion':'1','labels':{'app':'web'}},
         'spec':{'nodeName':'n1','containers':[{'name':'api','envFrom':[{'secretRef':{'name':'db'}}]}]}}
node = {'kind':'Node','metadata':{'name':'n1','uid':'n1','resourceVersion':'1'},
        'status':{'conditions':[{'type':'Ready','status':'False'}]}}
if name is None:
 if kind == 'pod': items = [pod('p1'),pod('p2')]
 elif kind == 'node': items = [node]
 else: items = []
 print(json.dumps({'kind':'List','items':items}))
elif kind == 'service':
 print(json.dumps({'kind':'Service','metadata':{'name':name,'namespace':ns,'uid':name,'resourceVersion':'1'},
                   'spec':{'selector':{'app':'web'},'ports':[{'port':80,'targetPort':'http'}]}}))
elif kind == 'poddisruptionbudget':
 print(json.dumps({'apiVersion':'policy/v1','kind':'PodDisruptionBudget',
                   'metadata':{'name':name,'namespace':ns,'uid':name,'resourceVersion':'1','generation':1},
                   'spec':{'selector':{}},'status':{'observedGeneration':1,'disruptionsAllowed':0}}))
elif kind == 'pod': print(json.dumps(pod(name)))
elif kind == 'node': print(json.dumps(node))
elif kind == 'secret':
 if os.environ.get('FORBID_SECRET'): sys.exit(1)
 # Successful empty response is kubectl --ignore-not-found.
else: sys.exit(1)
''')
    executable.chmod(0o755)
    env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'], REQUEST_LOG=str(log))

    def run(args, expected, forbidden=False, malformed=False, slow=False):
        result = subprocess.run([*command, *args],
                                env=dict(env, **({'FORBID_SECRET': '1'} if forbidden else {}),
                                         **({'MALFORMED_POD': '1'} if malformed else {}),
                                         **({'SLOW_GET': '1', 'SLOW_PID': str(Path(directory) / 'slow.pid')} if slow else {})),
                                capture_output=True, text=True, timeout=45)
        assert result.returncode == expected, (result.stdout, result.stderr)
        return result.stdout

    run([], 0)
    run(['checkup', '--fix'], 2)
    assert not log.exists(), 'Help and rejected arguments must not query the cluster'
    # Without --kubeconfig, kubectl is left to its own default configuration.
    run(['diagnose', 'pod/p1', '-n', 'test'], 1)
    assert not any('--kubeconfig' in json.loads(line) for line in log.read_text().splitlines())
    common = ['--kubeconfig', '/unused-test-config', '-n', 'test', '--json']
    report = json.loads(run(['checkup', *common], 1))
    assert len(report['groups']) == 2, report
    for group in report['groups']:
        assert len(group['affectedTargets']) == 2, group
        assert len(group['evidence']) > 0
    requests = [json.loads(line) for line in log.read_text().splitlines()]
    assert all('get' in argv for argv in requests)
    assert not any(argv[argv.index('get')+1] == 'node' and '--ignore-not-found' not in argv for argv in requests)
    partial = json.loads(run(['checkup', *common], 2, malformed=True))
    assert partial['status'] == 'incomplete' and len(partial['groups']) == 2, partial
    assert any(e['result'] == 'diagnosis-error' for r in partial['reports'] for e in r['evidence']), partial
    single = json.loads(run(['diagnose', 'pod/p1', *common], 1))
    assert len(single['groups']) == 2
    unknown = json.loads(run(['diagnose', 'pod/p1', *common], 2, forbidden=True))
    assert unknown['status'] == 'incomplete'
    assert [g['rule'] for g in unknown['groups']] == ['node-Ready-False'], unknown
    cluster = json.loads(run(['checkup', '--kubeconfig', '/unused-test-config', '--json'], 1))
    assert cluster['target'] == 'cluster'
    assert any('--all-namespaces' in json.loads(line) for line in log.read_text().splitlines())
    service = json.loads(run(['diagnose', 'service/web', *common], 1))
    assert {'service-named-port-missing', 'service-no-ready-backends'} <= {g['rule'] for g in service['groups']}, service
    impact = json.loads(run(['impact', 'node/n1', '--kubeconfig', '/unused-test-config', '--json'], 0))
    assert impact['target'] == 'Node/n1', impact
    assert {e['resource'] for e in impact['effects']} == {'Pod/test/p1', 'Pod/test/p2'}, impact
    assert 'Losing Node n1 would affect 2 resources.' in run(['impact', 'node/n1', '--kubeconfig', '/unused-test-config'], 0)
    run(['impact'], 2)
    pdb = json.loads(run(['diagnose', 'pdb/web', *common], 0))
    assert pdb['target'] == 'PodDisruptionBudget/test/web'
    timed_out = json.loads(run(['diagnose', 'pod/p1', *common], 2, slow=True))
    assert timed_out['status'] == 'incomplete' and not timed_out['groups'], timed_out
    pid = int((Path(directory) / 'slow.pid').read_text())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError(f'Timed-out kubectl child {pid} remains alive or unreaped')
    print('Doctor CLI help, scope, grouping, dependency and forbidden-read checks passed.')
