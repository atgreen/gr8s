#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Boot a KVM guest through upstream KubeVirt on an explicitly selected cluster.

The cluster must already have KubeVirt installed. Creates and removes only its
own VirtualMachine, or validates an existing smoke VM without changing it.
Preserves API state, domain XML, guest console, and component logs as evidence.
"""
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True, type=Path)
    parser.add_argument('--namespace', default='default')
    parser.add_argument('--vm-name', default='gr8s-kubevirt-' + uuid.uuid4().hex[:8])
    parser.add_argument('--existing', action='store_true', help='Validate this VM without creating or deleting it')
    parser.add_argument('--keep', action='store_true', help='Leave the newly created VM running')
    parser.add_argument('--image', default='quay.io/kubevirt/cirros-container-disk-demo:latest')
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--report-directory', type=Path)
    args = parser.parse_args()
    root = args.report_directory or Path(tempfile.mkdtemp(prefix='gr8s-kubevirt-proof.'))
    root.mkdir(parents=True, exist_ok=True)
    base = ['kubectl', '--kubeconfig', str(args.kubeconfig), '--request-timeout=30s', '-n', args.namespace]
    report = {'passed': False, 'vm': args.vm_name, 'namespace': args.namespace,
              'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'existingVM': args.existing, 'reportDirectory': str(root.resolve())}
    created = False
    marker = 'GR8S_KUBEVIRT_BOOT_OK'
    deadline = time.monotonic() + args.timeout

    def kubectl(*cmd, obj=None, check=True):
        result = subprocess.run(base + list(cmd), input=None if obj is None else json.dumps(obj),
                                text=True, capture_output=True, timeout=60)
        if check and result.returncode:
            raise RuntimeError(result.stderr.strip())
        return result

    def get(resource, name):
        result = kubectl('get', resource, name, '-o', 'json', check=False)
        if result.returncode:
            if 'NotFound' in result.stderr:
                return None
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout)

    def wait(predicate, description):
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(3)
        raise TimeoutError('Timed out waiting for ' + description)

    try:
        version = kubectl('get', '--raw', '/version').stdout
        (root / 'version.json').write_text(version)
        kv = kubectl('get', 'kubevirt', '-A', '-o', 'json')
        (root / 'kubevirt.json').write_text(kv.stdout)
        installations = json.loads(kv.stdout)['items']
        assert any(any(c.get('type') == 'Available' and c.get('status') == 'True'
                       for c in item.get('status', {}).get('conditions', [])) for item in installations), 'KubeVirt is not Available'
        report['kubevirtVersions'] = [item.get('status', {}).get('observedKubeVirtVersion') for item in installations]
        if not args.existing:
            manifest = {'apiVersion': 'kubevirt.io/v1', 'kind': 'VirtualMachine',
                        'metadata': {'name': args.vm_name, 'namespace': args.namespace},
                        'spec': {'runStrategy': 'Always', 'template': {'spec': {
                            'terminationGracePeriodSeconds': 10,
                            'domain': {'resources': {'requests': {'memory': '128Mi'}},
                                       'devices': {'disks': [{'name': name, 'disk': {'bus': 'virtio'}}
                                                             for name in ('containerdisk', 'cloudinit')],
                                                   'interfaces': [{'name': 'default', 'masquerade': {}}]}},
                            'networks': [{'name': 'default', 'pod': {}}],
                            'volumes': [{'name': 'containerdisk', 'containerDisk': {'image': args.image, 'imagePullPolicy': 'IfNotPresent'}},
                                        {'name': 'cloudinit', 'cloudInitNoCloud': {'userData': '#!/bin/sh\necho ' + marker + ' >/dev/ttyS0\n'}}]}}}}
            kubectl('create', '-f', '-', obj=manifest)
            created = True

        def running():
            vm = get('vm', args.vm_name)
            vmi = get('vmi', args.vm_name)
            if vm:
                (root / 'vm.json').write_text(json.dumps(vm, indent=2) + '\n')
            if not vmi:
                return None
            (root / 'vmi.json').write_text(json.dumps(vmi, indent=2) + '\n')
            return vmi if vmi.get('status', {}).get('phase') == 'Running' and any(
                c.get('type') == 'Ready' and c.get('status') == 'True' for c in vmi.get('status', {}).get('conditions', [])) else None

        vmi = wait(running, 'a Running and Ready VMI')
        active = vmi['status']['activePods']
        pods = json.loads(kubectl('get', 'pods', '-o', 'json').stdout)['items']
        pod = next(p for p in pods if p['metadata']['uid'] in active and not p['metadata'].get('deletionTimestamp'))
        (root / 'launcher-pod.json').write_text(json.dumps(pod, indent=2) + '\n')
        pod_name = pod['metadata']['name']
        report['launcherPod'] = pod_name
        report['node'] = vmi['status']['nodeName']
        report['vmiUID'] = vmi['metadata']['uid']
        node = get('node', report['node'])
        (root / 'node.json').write_text(json.dumps(node, indent=2) + '\n')
        domain = kubectl('exec', pod_name, '-c', 'compute', '--', 'virsh', '-c',
                         'qemu+unix:///session?socket=/var/run/libvirt/virtqemud-sock', 'dumpxml',
                         args.namespace + '_' + args.vm_name).stdout
        (root / 'domain.xml').write_text(domain)
        report['domainType'] = ET.fromstring(domain).get('type')
        assert report['domainType'] == 'kvm', 'The guest is not using KVM'
        print('VMI Running and Ready with KVM; waiting for guest boot marker', flush=True)

        def booted():
            console = kubectl('exec', pod_name, '-c', 'compute', '--', 'cat',
                              '/var/run/kubevirt-private/' + vmi['metadata']['uid'] + '/virt-serial0-log').stdout
            (root / 'guest-console.txt').write_text(console)
            return marker in console

        wait(booted, 'the guest console boot marker')
        report['guestBootMarker'] = marker
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
    finally:
        for resource in ('pods', 'events'):
            result = kubectl('get', resource, '-o', 'json', check=False)
            (root / (resource + '.json')).write_text(result.stdout or result.stderr)
        if created and not args.keep:
            result = kubectl('delete', 'vm', args.vm_name, '--wait=true', '--timeout=45s', check=False)
            report['cleanupSucceeded'] = result.returncode == 0
            if result.returncode:
                report['passed'] = False
                report['cleanupError'] = result.stderr
        report['keptRunning'] = args.existing or (created and args.keep)
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
