#!/usr/bin/env python3
"""Three-VM WireGuard HA acceptance: traffic, capture, restart and rekey."""

import argparse
import json
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time


def run(*args, check=True, input=None, timeout=30):
    return subprocess.run([str(arg) for arg in args], check=check, input=input,
                          universal_newlines=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout)


def wait_for(description, predicate, timeout=120):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            last_error = error
        time.sleep(.5)
    raise RuntimeError(f'timed out waiting for {description}: {last_error}')


class Acceptance:
    def __init__(self, arguments):
        self.kubeconfig = Path(arguments.kubeconfig)
        self.key = Path(arguments.ssh_key)
        self.ips = Path(arguments.vm_ips).read_text().split()
        self.nodes = arguments.nodes.split()
        assert len(self.ips) == len(self.nodes) == 3
        self.ssh_options = ['-i', self.key, '-o', 'IdentitiesOnly=yes',
                            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                            '-o', f'UserKnownHostsFile={arguments.known_hosts}']
        self.work = Path(tempfile.mkdtemp(prefix='gr8s-wireguard-ha.'))

    def kubectl(self, *args, **kwargs):
        return run('kubectl', '--kubeconfig', self.kubeconfig,
                   '--request-timeout=20s', *args, **kwargs)

    def ssh(self, index, command, **kwargs):
        return run('ssh', *self.ssh_options, f'root@{self.ips[index]}', command, **kwargs)

    def pod(self, index):
        return json.loads(self.kubectl('get', 'pod', f'wireguard-ha-{index}',
                                      '-o', 'json').stdout)

    def identities(self):
        pods = [self.pod(index) for index in range(3)]
        if any(pod.get('status', {}).get('phase') != 'Running' or
               not pod.get('status', {}).get('podIP') for pod in pods):
            return False
        return [(pod['metadata']['uid'], pod['spec']['nodeName'], pod['status']['podIP'])
                for pod in pods]

    def create_pods(self):
        for index, node in enumerate(self.nodes):
            pod = {
                'apiVersion': 'v1', 'kind': 'Pod',
                'metadata': {'name': f'wireguard-ha-{index}'},
                'spec': {
                    'nodeName': node, 'terminationGracePeriodSeconds': 1,
                    'containers': [{
                        'name': 'main', 'image': 'docker.io/library/busybox:1.37.0',
                        'command': ['sh', '-c', f'echo wireguard-ha-{index}; sleep 900'],
                    }],
                },
            }
            self.kubectl('create', '-f', '-', input=json.dumps(pod))
        return wait_for('three real Running Pods', self.identities, timeout=240)

    def traffic(self, identities):
        for source in range(3):
            for destination in range(3):
                if source == destination:
                    continue
                self.kubectl('exec', f'wireguard-ha-{source}', '--',
                             'ping', '-c', '2', '-W', '2', '-s', '1200',
                             identities[destination][2])
            self.kubectl('exec', f'wireguard-ha-{source}', '--',
                         'nslookup', 'kubernetes.default.svc.cluster.local')

    def peer_reachable(self, source, destination, identities):
        return self.kubectl(
            'exec', f'wireguard-ha-{source}', '--', 'ping', '-c', '2', '-W', '2',
            '-s', '1200', identities[destination][2], check=False).returncode == 0

    def all_peers_reachable(self, identities):
        for source in range(3):
            for destination in range(3):
                if source != destination and not self.peer_reachable(
                        source, destination, identities):
                    return False
        return True

    def capture_proof(self, identities):
        interface = self.ssh(
            0, "ip route show default | awk '{print $5; exit}'").stdout.strip()
        remote_capture = '/tmp/gr8s-wireguard-ha.pcap'
        capture = subprocess.Popen(
            ['ssh', *map(str, self.ssh_options), f'root@{self.ips[0]}',
             f'rm -f {remote_capture}; tcpdump -U -i {interface} -c 4 '
             f'-w {remote_capture} "(udp port 51820) or (icmp and net 10.80.0.0/12)"'],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            universal_newlines=True)
        time.sleep(1)
        marker_byte = '47'
        marker = bytes.fromhex(marker_byte) * 64
        self.kubectl('exec', 'wireguard-ha-0', '--', 'ping', '-c', '3', '-W', '2',
                     '-s', '1200', '-p', marker_byte, identities[1][2])
        _, error = capture.communicate(timeout=15)
        assert capture.returncode == 0, error
        local_capture = self.work / 'underlay.pcap'
        run('scp', *self.ssh_options, f'root@{self.ips[0]}:{remote_capture}', local_capture)
        assert marker not in local_capture.read_bytes(), 'known plaintext appeared on underlay'
        encrypted = self.ssh(0, f'tcpdump -nn -r {remote_capture} "udp port 51820"').stdout
        plaintext = self.ssh(
            0, f'tcpdump -nn -r {remote_capture} "icmp and net 10.80.0.0/12"').stdout
        assert encrypted.strip(), 'capture contained no WireGuard UDP packets'
        assert not plaintext.strip(), f'capture exposed Pod packets: {plaintext}'
        print('Three-VM underlay capture contains ciphertext and no known Pod plaintext', flush=True)

    def rotate_and_restart(self, identities):
        target = 2
        result = self.ssh(
            target,
            '/usr/local/bin/gr8s wireguard rotate-key --state-directory /var/lib/gr8s/agent')
        assert result.stdout.startswith('WireGuard public key: '), result.stdout
        self.ssh(target, 'systemctl restart gr8s', timeout=60)

        def recovered():
            node = json.loads(self.kubectl('get', 'node', self.nodes[target], '-o', 'json').stdout)
            return any(condition.get('type') == 'Ready' and condition.get('status') == 'True'
                       for condition in node.get('status', {}).get('conditions', []))

        wait_for(f'{self.nodes[target]} Ready after rotation', recovered, timeout=180)
        wait_for('stable Pods after rotation', lambda: self.identities() == identities, timeout=180)
        # Node Ready may still be the pre-restart condition while the replacement
        # agent session and peer key converge. Prove the rotated peer is usable
        # before running the complete all-to-all matrix.
        wait_for('all encrypted peer traffic after rotation',
                 lambda: self.all_peers_reachable(identities), timeout=180)
        self.traffic(identities)
        print(f'{self.nodes[target]} restarted with a new key and encrypted traffic recovered',
              flush=True)

    def telemetry(self):
        for node in self.nodes:
            text = self.kubectl('get', '--raw', f'/api/v1/nodes/{node}/proxy/metrics').stdout
            assert f'gr8s_wireguard_telemetry_available{{node="{node}"}} 1' in text
            for family in ('latest_handshake_seconds', 'received_bytes_total',
                           'transmitted_bytes_total'):
                values = [float(match.group(1)) for match in re.finditer(
                    rf'^gr8s_wireguard_peer_{family}\{{node="{re.escape(node)}".*\}} (\S+)$',
                    text, re.MULTILINE)]
                assert values and any(value > 0 for value in values), (
                    f'{node} has no live WireGuard {family} telemetry: {values}')
        print('Every HA node exposes WireGuard peer handshake/RX/TX telemetry', flush=True)

    def cleanup(self):
        for index in range(3):
            self.kubectl('delete', 'pod', f'wireguard-ha-{index}', '--ignore-not-found',
                         '--grace-period=0', '--force', '--wait=false', check=False)

    def run(self):
        try:
            identities = self.create_pods()
            self.traffic(identities)
            self.capture_proof(identities)
            self.rotate_and_restart(identities)
            self.telemetry()
        finally:
            self.cleanup()
        print(f'WireGuard HA acceptance evidence: {self.work}', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--vm-ips', required=True)
    parser.add_argument('--ssh-key', required=True)
    parser.add_argument('--known-hosts', required=True)
    parser.add_argument('--nodes', default='gr8s-wg-ha-1 gr8s-wg-ha-2 gr8s-wg-ha-3')
    acceptance = Acceptance(parser.parse_args())
    acceptance.run()


if __name__ == '__main__':
    main()
