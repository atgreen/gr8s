#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Exercise native doctor fault/recovery diagnoses inside a disposable Linux VM.

Requires root, kubectl, and a native gr8s binary. Starts real containers and loads
BPF programs. Owns a fresh cluster, preserves evidence, and deletes test workloads
before shutting the server down. Never uses an existing kubeconfig or context.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('build/gr8s'))
    parser.add_argument('--evidence-parent', type=Path, default=Path('/var/tmp'))
    options = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root inside a disposable Linux VM')
    binary = str(options.binary.resolve(strict=True))
    spec = importlib.util.spec_from_file_location('storage', Path(__file__).with_name('test-storage-native.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    base = Path(tempfile.mkdtemp(prefix='gr8s-doctor-native-', dir=options.evidence_parent))
    print('EVIDENCE', base, flush=True)
    cluster = module.NativeStorageSmoke(binary, base)
    sequence = 0

    def create(obj):
        cluster.kubectl('create', '-f', '-', input_object=obj)

    def diagnose(target, namespace='default', allow_incomplete=False):
        nonlocal sequence
        sequence += 1
        result = subprocess.run([binary, 'doctor', 'diagnose', target, '-n', namespace, '--kubeconfig', str(cluster.config), '--json'], capture_output=True, text=True, timeout=60)
        assert result.returncode in (0, 1, 2), (result.returncode, result.stderr)
        report = json.loads(result.stdout)
        (base / f'{sequence}-{target.replace("/", "-")}.json').write_text(result.stdout)
        rules = {g['rule'] for g in report['groups']}
        print(target, report['status'], sorted(rules), flush=True)
        if report['status'] == 'incomplete':
            assert allow_incomplete, report
            return None
        return rules

    def wait_rule(target, rule, present=True, namespace='default'):
        def observed():
            rules = diagnose(target, namespace, allow_incomplete=True)
            return rules is not None and ((rule in rules) == present)
        module.wait_for(observed, f'{target} {rule} present={present}', 90)

    try:
        cluster.start()
        create({'apiVersion':'v1','kind':'Service','metadata':{'name':'doctor-web'},'spec':{'selector':{'app':'doctor-web'},'ports':[{'port':80,'targetPort':'http'}]}})
        assert 'service-selector-empty' in diagnose('service/doctor-web')
        create({'apiVersion':'v1','kind':'Pod','metadata':{'name':'doctor-web','labels':{'app':'doctor-web'}},'spec':{'terminationGracePeriodSeconds':1,'containers':[{'name':'web','image':'docker.io/library/busybox:1.37.0','command':['sh','-c','sleep 3600'],'ports':[{'name':'web','containerPort':8080}],'envFrom':[{'secretRef':{'name':'doctor-config'}}]}]}})
        rules = diagnose('service/doctor-web')
        assert 'service-selector-empty' not in rules and 'service-named-port-missing' in rules
        assert 'missing-resource' in diagnose('pod/doctor-web')
        wait_rule('service/doctor-web', 'service-no-ready-backends')
        create({'apiVersion':'v1','kind':'Secret','metadata':{'name':'doctor-config'},'stringData':{'DOCTOR_SETTING':'fixture'}})
        cluster.kubectl('patch','service','doctor-web','--type=merge','-p',json.dumps({'spec':{'ports':[{'port':80,'targetPort':'web'}]}}))
        module.wait_for(lambda: cluster.phase('pod','doctor-web') == 'Running', 'real container Running', 240)
        result = cluster.kubectl('exec','doctor-web','--','sh','-c','printf "%s" "$DOCTOR_SETTING"')
        assert result.stdout == 'fixture', result.stdout
        print('Real container exec and Secret environment passed.', flush=True)
        assert 'service-named-port-missing' not in diagnose('service/doctor-web')
        assert 'missing-resource' not in diagnose('pod/doctor-web')
        wait_rule('service/doctor-web', 'service-no-ready-backends', present=False)
        stats = os.statvfs(str(base))
        assert stats.f_bavail * stats.f_frsize > 1024**3, stats
        assert stats.f_files == 0 or stats.f_ffree >= 10000, stats
        # Observe longer than the default 15-second node lease, covering fresh heartbeats.
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            node = cluster.object('node', 'gr8s-storage')
            conditions = {c['type']: c['status'] for c in node['status']['conditions']}
            assert conditions.get('Ready') == 'True', conditions
            assert conditions.get('DiskPressure') == 'False', conditions
            time.sleep(1)
        (base / 'node-after-heartbeats.json').write_text(json.dumps(node, indent=2))
        assert 'node-DiskPressure-True' not in diagnose('pod/doctor-web')
        print(f'DiskPressure remained False across fresh heartbeats (total inodes={stats.f_files}).', flush=True)
        # A real policy controller must publish current status before this rule fires.
        create({'apiVersion':'policy/v1','kind':'PodDisruptionBudget','metadata':{'name':'doctor-budget'},'spec':{'minAvailable':1,'selector':{'matchLabels':{'app':'doctor-web'}}}})
        wait_rule('pdb/doctor-budget', 'pdb-blocks-healthy-eviction')
        cluster.kubectl('patch','pdb','doctor-budget','--type=merge','-p','{"spec":{"minAvailable":0}}')
        wait_rule('pdb/doctor-budget', 'pdb-blocks-healthy-eviction', present=False)

        create({'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'doctor-target'},'spec':{'replicas':0,'selector':{'matchLabels':{'app':'doctor-web'}},'template':{'metadata':{'labels':{'app':'doctor-web'}},'spec':{'containers':[{'name':'web','image':'docker.io/library/busybox:1.37.0','command':['sleep','3600']}]}}}})
        create({'apiVersion':'autoscaling/v2','kind':'HorizontalPodAutoscaler','metadata':{'name':'doctor-hpa'},'spec':{'scaleTargetRef':{'apiVersion':'apps/v1','kind':'Deployment','name':'doctor-target'},'minReplicas':1,'maxReplicas':2,'metrics':[{'type':'Resource','resource':{'name':'cpu','target':{'type':'Utilization','averageUtilization':50}}}]}})
        wait_rule('hpa/doctor-hpa', 'hpa-missing-resource-request')
        cluster.kubectl('patch','hpa','doctor-hpa','--type=merge','-p',json.dumps({'spec':{'metrics':[{'type':'Resource','resource':{'name':'cpu','target':{'type':'AverageValue','averageValue':'100m'}}}]}}))
        wait_rule('hpa/doctor-hpa', 'hpa-missing-resource-request', present=False)

        create({'apiVersion':'storage.k8s.io/v1','kind':'StorageClass','metadata':{'name':'doctor-wffc'},'provisioner':'kubernetes.io/no-provisioner','volumeBindingMode':'WaitForFirstConsumer'})
        create({'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':'doctor-pvc'},'spec':{'storageClassName':'doctor-wffc','accessModes':['ReadWriteOnce'],'resources':{'requests':{'storage':'1Gi'}}}})
        create({'apiVersion':'v1','kind':'Pod','metadata':{'name':'doctor-bypass'},'spec':{'nodeName':'gr8s-storage','terminationGracePeriodSeconds':1,'volumes':[{'name':'data','persistentVolumeClaim':{'claimName':'doctor-pvc'}}],'containers':[{'name':'main','image':'docker.io/library/busybox:1.37.0','command':['sleep','3600'],'volumeMounts':[{'name':'data','mountPath':'/data'}]}]}})
        wait_rule('pvc/doctor-pvc', 'pvc-consumer-bypasses-binding')
        cluster.kubectl('delete','pod','doctor-bypass','--wait=true','--timeout=30s')
        wait_rule('pvc/doctor-pvc', 'pvc-consumer-bypasses-binding', present=False)

        create({'apiVersion':'v1','kind':'Namespace','metadata':{'name':'doctor-quota'}})
        create({'apiVersion':'v1','kind':'ResourceQuota','metadata':{'name':'doctor-limit','namespace':'doctor-quota'},'spec':{'hard':{'pods':'0'}}})
        create({'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':'doctor-rollout','namespace':'doctor-quota'},'spec':{'replicas':1,'selector':{'matchLabels':{'app':'quota-test'}},'template':{'metadata':{'labels':{'app':'quota-test'}},'spec':{'containers':[{'name':'main','image':'docker.io/library/busybox:1.37.0','command':['sleep','3600']}]}}}})
        wait_rule('deployment/doctor-rollout', 'rollout-quota-rejection', namespace='doctor-quota')
        cluster.kubectl('patch','quota','doctor-limit','-n','doctor-quota','--type=merge','-p','{"spec":{"hard":{"pods":"10"}}}')
        cluster.kubectl('rollout','status','deployment/doctor-rollout','-n','doctor-quota','--timeout=120s', timeout=130)
        wait_rule('deployment/doctor-rollout', 'rollout-quota-rejection', present=False, namespace='doctor-quota')
        print('All seven causal rules passed live fault/recovery trials.', flush=True)
        print('Native VM doctor transitions passed.', flush=True)
    finally:
        try:
            if cluster.process is not None and cluster.process.poll() is None and cluster.config.exists():
                cluster.kubectl('delete', 'deployments,hpa', '--all', '--all-namespaces', '--wait=true', '--timeout=30s', timeout=40)
                cluster.kubectl('delete', 'pods', '--all', '--all-namespaces', '--grace-period=0', '--wait=true', '--timeout=30s', timeout=40)
                print('Owned test workloads deleted.', flush=True)
        finally:
            cluster.stop()
            cluster.log.close()


if __name__ == '__main__':
    main()
