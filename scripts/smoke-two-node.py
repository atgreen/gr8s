#!/usr/bin/env python3
"""Privileged native two-node overlay smoke; uses routed underlay veths, no bridge.

Run after make native. Requires ip, nsenter, nft, kubectl, and root. Temporary
NAT applies only to the test underlay's external image/DNS downloads. Each
node keeps its own mount/network namespaces across agent restarts. Set
GR8S_OVERLAY_BACKEND=wireguard to exercise encryption, capture proof and key
rotation; the default remains vxlan.
"""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request


def run(*args, check=True, timeout=30, input=None):
    return subprocess.run([str(a) for a in args], input=input, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=check, timeout=timeout)


def wait_for(description, predicate, timeout=90):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            last_error = error
        time.sleep(.2)
    raise RuntimeError(f'timed out waiting for {description}: {last_error}')


class Smoke:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix='gr8s-two-node.'))
        self.binary = Path(__file__).resolve().parents[1] / 'build/gr8s'
        self.prefix = f'g8t{os.getpid():x}'
        self.table = self.prefix
        self.api_port = int(os.environ.get('GR8S_TWO_NODE_PORT', '18084'))
        self.node_port = int(os.environ.get('GR8S_TWO_NODE_AGENT_PORT', '17443'))
        self.overlay = os.environ.get('GR8S_OVERLAY_BACKEND', 'vxlan')
        self.self_tuning = os.environ.get('GR8S_SELF_TUNING_NETWORK') == '1'
        self.alternate_addresses = ['198.19.0.1', '198.19.0.2']
        assert self.overlay in ('vxlan', 'wireguard'), self.overlay
        self.overlay_interface = 'gr8s-wg' if self.overlay == 'wireguard' else 'gr8s-vxlan'
        self.encryption_proved = False
        self.pool = ipaddress.ip_network(os.environ.get('GR8S_SMOKE_UNDERLAY', '198.18.253.0/29'))
        assert self.pool.version == 4 and self.pool.prefixlen == 29
        self.hosts = [str(self.pool.network_address + 1), str(self.pool.network_address + 5)]
        self.addresses = [str(self.pool.network_address + 2), str(self.pool.network_address + 6)]
        self.namespaces = [f'{self.prefix}-{i}' for i in range(2)]
        self.keepers = [None, None]
        self.agents = [None, None]
        self.server = None
        self.logs = []
        self.forwarding = Path('/proc/sys/net/ipv4/ip_forward').read_text()
        self.nat_created = False
        self.success = False
        self.kubeconfig = self.root / 'kubeconfig'

    def start(self, args, name):
        log = open(self.root / f'{name}.log', 'a')
        self.logs.append(log)
        return subprocess.Popen([str(a) for a in args], stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)

    def in_node(self, index, *args, **kwargs):
        keeper = self.keepers[index]
        return run('nsenter', f'--mount=/proc/{keeper.pid}/ns/mnt',
                   f'--net=/run/netns/{self.namespaces[index]}', '--', *args, **kwargs)

    def kubectl(self, *args, **kwargs):
        return run('kubectl', '--kubeconfig', self.kubeconfig, '--request-timeout=10s',
                   *args, **kwargs)

    def pod(self, index):
        return json.loads(self.kubectl('get', 'pod', f'two-node-{index}', '-o', 'json').stdout)

    def metrics(self):
        with urllib.request.urlopen(f'http://127.0.0.1:{self.api_port}/metrics', timeout=3) as response:
            return response.read().decode()

    def setup(self):
        assert os.geteuid() == 0, 'root is required'
        assert self.binary.is_file(), 'run make native first'
        commands = ['ip', 'nsenter', 'nft', 'kubectl', 'mount']
        if self.overlay == 'wireguard':
            commands.append('tcpdump')
        for command in commands:
            assert shutil.which(command), f'missing {command}'
        # Refuse to replace an existing connected route to the test underlay.
        routes = json.loads(run('ip', '-j', '-4', 'route', 'show').stdout)
        for route in routes:
            destination = route.get('dst', 'default')
            if destination != 'default' and ipaddress.ip_network(destination).overlaps(self.pool):
                raise RuntimeError(f'test underlay overlaps host route {destination}')
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
        nameservers = []
        for path in (Path('/run/systemd/resolve/resolv.conf'), Path('/etc/resolv.conf')):
            if path.exists():
                for line in path.read_text().splitlines():
                    words = line.split()
                    if len(words) == 2 and words[0] == 'nameserver':
                        address = ipaddress.ip_address(words[1])
                        if address.version == 4 and not address.is_loopback:
                            nameservers.append(str(address))
            if nameservers:
                break
        assert nameservers, 'a non-loopback upstream DNS resolver is required'
        run('nft', '-f', '-', input=f'''table ip {self.table} {{
 chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
  ip saddr {self.pool} ip daddr != {self.pool} masquerade
 }}
}}
''')
        self.nat_created = True
        for index, namespace in enumerate(self.namespaces):
            run('ip', 'netns', 'add', namespace)
            resolver = Path('/etc/netns') / namespace / 'resolv.conf'
            resolver.parent.mkdir(parents=True)
            resolver.write_text(''.join(f'nameserver {address}\n' for address in nameservers))
            host_link = f'{self.prefix}h{index}'
            run('ip', 'link', 'add', host_link, 'type', 'veth', 'peer', 'name', 'underlay',
                'netns', namespace)
            run('ip', 'addr', 'add', f'{self.hosts[index]}/30', 'dev', host_link)
            run('ip', 'link', 'set', host_link, 'up')
            run('ip', '-n', namespace, 'addr', 'add', f'{self.addresses[index]}/30', 'dev', 'underlay')
            run('ip', '-n', namespace, 'link', 'set', 'underlay', 'up')
            run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
            run('ip', '-n', namespace, 'route', 'add', 'default', 'via', self.hosts[index])
            keeper = self.start(['ip', 'netns', 'exec', namespace, 'sleep', '86400'], f'keeper-{index}')
            self.keepers[index] = keeper
            wait_for('node mount namespace', lambda: os.readlink(f'/proc/{keeper.pid}/ns/mnt') !=
                     os.readlink('/proc/self/ns/mnt'), timeout=5)
            # ip netns exec remounts sysfs for the node and hides cgroup mounts.
            if self.in_node(index, 'stat', '-f', '-c', '%T', '/sys/fs/cgroup').stdout.strip() != 'cgroup2fs':
                self.in_node(index, 'mount', '-t', 'cgroup2', 'none', '/sys/fs/cgroup')
        if self.self_tuning:
            assert self.overlay == 'wireguard', 'self-tuning acceptance requires wireguard'
            run('ip', 'link', 'add', f'{self.prefix}a0', 'type', 'veth', 'peer',
                'name', f'{self.prefix}a1')
            for index, namespace in enumerate(self.namespaces):
                link = f'{self.prefix}a{index}'
                run('ip', 'link', 'set', link, 'netns', namespace)
                run('ip', '-n', namespace, 'link', 'set', link, 'name', 'alternate')
                run('ip', '-n', namespace, 'addr', 'add',
                    f'{self.alternate_addresses[index]}/30', 'dev', 'alternate')
                run('ip', '-n', namespace, 'link', 'set', 'alternate', 'up')
        print(f'Launching native control plane and two nodes in {self.root}', flush=True)
        print(f'Test namespace prefix: {self.prefix}', flush=True)
        self.server = self.start([self.binary, 'serve', '--disable-agent', '--runtime', 'fake',
                                 '--state-directory', self.root / 'control', '--port', self.api_port,
                                 '--node-listen', '0.0.0.0', '--node-port', self.node_port,
                                 '--overlay-backend', self.overlay,
                                 '--kubeconfig', self.kubeconfig], 'control')
        wait_for('control plane', lambda: self.kubeconfig.exists() and
                 self.kubectl('get', '--raw', '/readyz').returncode == 0)
        for index in range(2):
            self.start_agent(index, enroll=True)

    def start_agent(self, index, enroll=False):
        args = [self.binary, 'agent', '--server', f'{self.hosts[0]}:{self.node_port}',
                '--node-name', f'worker-{index}', '--node-address', self.addresses[index],
                '--state-directory', self.root / f'agent-{index}', '--runtime', 'containerd',
                '--containerd-log-root', self.root / f'logs-{index}']
        if enroll:
            token = json.loads(run(self.binary, 'join-token', '--state-directory', self.root / 'control',
                                   '--node-name', f'worker-{index}').stdout)
            args += ['--token', token['token'], '--ca-pin', token['caPin']]
        if self.self_tuning:
            args += ['--wireguard-endpoint',
                     f'alternate={self.alternate_addresses[index]}:51820',
                     '--wireguard-endpoint',
                     f'blackhole=203.0.113.{index + 1}:51820']
        keeper = self.keepers[index]
        self.agents[index] = self.start(['nsenter', f'--mount=/proc/{keeper.pid}/ns/mnt',
                                        f'--net=/run/netns/{self.namespaces[index]}', '--', *args],
                                       f'agent-{index}')
        wait_for(f'worker-{index} connection', lambda:
                 f'gr8s_dataplane_node_ready{{node="worker-{index}"}} 1' in self.metrics())

    def check_pods(self, expected=None):
        pods = [self.pod(index) for index in range(2)]
        if any(pod.get('status', {}).get('phase') != 'Running' or
               not pod.get('status', {}).get('podIP') for pod in pods):
            return False
        identities = [(pod['metadata']['uid'], pod['spec']['nodeName'], pod['status']['podIP'])
                      for pod in pods]
        if expected is not None:
            assert identities == expected, f'Pod identity/assignment changed: {identities} != {expected}'
        return identities

    def selected_path(self, index, name):
        peer = f'worker-{1 - index}'
        result = run(self.binary, 'network', 'explain', f'worker-{index}', peer,
                     '--server', f'http://127.0.0.1:{self.api_port}', check=False)
        return result.returncode == 0 and f'Selected: {name} ' in result.stdout

    def alternate_selected(self, index):
        return self.selected_path(index, 'alternate')

    def blackhole_failed_and_rolled_back(self, index):
        peer = f'worker-{1 - index}'
        result = run(self.binary, 'network', 'explain', f'worker-{index}', peer,
                     '--server', f'http://127.0.0.1:{self.api_port}', check=False)
        failed = any(line.lstrip().startswith('blackhole ') and 'failures=0' not in line
                     for line in result.stdout.splitlines())
        return result.returncode == 0 and 'Selected: alternate ' in result.stdout and failed

    def wait_for_verified_alternate_paths(self):
        for index in range(2):
            wait_for(f'worker-{index} selecting verified alternate path',
                     lambda index=index: self.alternate_selected(index), timeout=240)

    def crash_node_runtime(self, index):
        """Crash one disposable node and its managed runtime, retaining disk/kernel state."""
        agent = self.agents[index]
        if agent and agent.poll() is None:
            agent.kill()
            agent.wait(timeout=5)
        self.agents[index] = None
        keeper = self.keepers[index]
        for pid in run('ip', 'netns', 'pids', self.namespaces[index]).stdout.split():
            pid = int(pid)
            if pid != keeper.pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        wait_for(f'worker-{index} crash cleanup', lambda:
                 all(int(pid) == keeper.pid for pid in
                     run('ip', 'netns', 'pids',
                         self.namespaces[index]).stdout.split()), timeout=10)

    def prove_wireguard_encryption(self, identities):
        if self.overlay != 'wireguard' or self.encryption_proved:
            return
        # BusyBox ping accepts a single payload byte. A long repeated marker is
        # still distinctive enough to prove that known inner payload is absent.
        marker_byte = '47'
        marker = bytes.fromhex(marker_byte) * 64
        capture_interface = 'alternate' if self.self_tuning else 'underlay'
        capture_path = self.root / f'wireguard-{capture_interface}.pcap'
        keeper = self.keepers[0]
        capture = subprocess.Popen(
            ['nsenter', f'--mount=/proc/{keeper.pid}/ns/mnt',
             f'--net=/run/netns/{self.namespaces[0]}', '--',
             'tcpdump', '-U', '-i', capture_interface, '-w', str(capture_path),
             'udp', 'port', '51820', 'or', 'icmp'],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(1)
            self.kubectl('exec', 'two-node-0', '--', 'ping', '-c', '3', '-W', '2',
                         '-s', '1200', '-p', marker_byte, identities[1][2])
        finally:
            capture.send_signal(signal.SIGINT)
            _, error = capture.communicate(timeout=10)
        assert capture.returncode == 0, error
        packets = capture_path.read_bytes()
        assert marker not in packets, 'known Pod payload appeared in plaintext on the underlay'
        encrypted = run('tcpdump', '-nn', '-r', capture_path,
                        'udp', 'port', '51820').stdout.splitlines()
        assert encrypted, 'capture contained no WireGuard UDP packets'
        plaintext = run('tcpdump', '-nn', '-r', capture_path, 'icmp', 'and',
                        '(', 'host', identities[0][2], 'or', 'host', identities[1][2],
                        ')').stdout.splitlines()
        assert not plaintext, f'capture exposed unencapsulated Pod packets: {plaintext}'
        self.encryption_proved = True
        print(f'{capture_interface.capitalize()} capture contains WireGuard UDP, '
              'no Pod ICMP and no known plaintext', flush=True)

    def traffic(self, identities):
        for index in range(2):
            peer = identities[1 - index][2]
            self.kubectl('exec', f'two-node-{index}', '--', 'ping', '-c', '2', '-W', '2', '-s', '1200', peer)
            self.kubectl('exec', f'two-node-{index}', '--', 'nslookup', 'kubernetes.default.svc.cluster.local')
            self.kubectl('exec', f'two-node-{index}', '--', 'nslookup', 'example.com')
            assert f'two-node-{index}' in self.kubectl('logs', f'two-node-{index}').stdout
            addresses = json.loads(self.in_node(index, 'ip', '-j', '-4', 'addr', 'show').stdout)
            gateways = [link['ifname'] for link in addresses for address in link.get('addr_info', [])
                        if address.get('local') == '169.254.1.1']
            assert gateways == ['gr8s-gateway'], gateways
            assert self.kubectl('exec', f'two-node-{index}', '--', 'ip', 'neigh', 'show',
                                '169.254.1.1').stdout.strip().endswith('PERMANENT')
            route = json.loads(self.in_node(index, 'ip', '-j', 'route', 'get', peer).stdout)
            assert route[0]['dev'] == self.overlay_interface, route
            counters = json.loads(self.in_node(
                index, 'ip', '-s', '-j', 'link', 'show', self.overlay_interface).stdout)
            stats = counters[0].get('stats64', counters[0].get('stats'))
            assert stats['tx']['packets'] > 0 and stats['rx']['packets'] > 0, counters
        self.prove_wireguard_encryption(identities)
        # Pause reconciliation while demonstrating that the Pod cannot bypass
        # a down tunnel. Inject directly into the Pod namespace during the pause.
        namespace_root = self.root / 'agent-0/containerd/run/io.containerd.grpc.v1.cri/netns'
        pod_namespaces = self.in_node(0, 'find', namespace_root, '-mindepth', '1',
                                      '-maxdepth', '1').stdout.splitlines()
        assert len(pod_namespaces) == 1, pod_namespaces
        self.agents[0].send_signal(signal.SIGSTOP)
        try:
            self.in_node(0, 'ip', 'link', 'set', self.overlay_interface, 'down')
            assert self.in_node(0, 'nsenter', f'--net={pod_namespaces[0]}', '--',
                                'ping', '-c', '1', '-W', '1', identities[1][2],
                                check=False).returncode != 0
        finally:
            self.in_node(0, 'ip', 'link', 'set', self.overlay_interface, 'up')
            self.agents[0].send_signal(signal.SIGCONT)
        wait_for(f'{self.overlay} state restored without a new snapshot', lambda:
                 self.kubectl('exec', 'two-node-0', '--', 'ping', '-c', '1', '-W', '1',
                              identities[1][2], check=False).returncode == 0, timeout=15)

    def exercise(self):
        if self.self_tuning:
            # Prove selection and restart recovery before image/container activity;
            # the latter has a separately tracked slow-shutdown failure (podster-ojtd)
            # that must not obscure this network acceptance gate.
            self.wait_for_verified_alternate_paths()
            self.crash_node_runtime(0)
            self.start_agent(0)
            wait_for('worker-0 restoring its verified alternate path after restart',
                     lambda: self.alternate_selected(0), timeout=30)
            for index in range(2):
                wait_for(f'worker-{index} rolling back an unreachable candidate',
                         lambda index=index: self.blackhole_failed_and_rolled_back(index),
                         timeout=45)
            print('Self-tuner selected fresh-handshake-verified alternate endpoints '
                  'and restored the durable choice after restart; unreachable '
                  'candidate trials rolled back', flush=True)
        for index in range(2):
            pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': f'two-node-{index}'},
                   'spec': {'nodeName': f'worker-{index}', 'terminationGracePeriodSeconds': 1,
                            'containers': [
                       {'name': 'main', 'image': 'docker.io/library/busybox:1.37.0',
                        'command': ['sh', '-c', f'echo two-node-{index}; sleep 600']}]}}
            self.kubectl('create', '-f', '-', input=json.dumps(pod))
        print('Waiting for two real containerd Pods', flush=True)
        identities = wait_for('two real Running Pods', self.check_pods, timeout=180)
        if os.environ.get('GR8S_TWO_NODE_FAIL_AFTER_CREATE') == '1':
            raise RuntimeError('forced two-node failure after creating Pods')
        self.traffic(identities)
        if self.self_tuning:
            self.wait_for_verified_alternate_paths()
            self.traffic(identities)
            for index in range(2):
                self.in_node(index, 'ip', 'link', 'set', 'alternate', 'down')
            for index in range(2):
                wait_for(f'worker-{index} failing over to its previous underlay',
                         lambda index=index: self.selected_path(index, 'underlay'), timeout=30)
            self.traffic(identities)
            for index in range(2):
                self.in_node(index, 'ip', 'link', 'set', 'alternate', 'up')
            print('Self-tuning network acceptance passed with live Pod traffic', flush=True)
        print(f'Two-node native {self.overlay} connectivity, DNS, logs, exec and '
              'tunnel-dependency checks passed', flush=True)
        if self.self_tuning:
            for index in range(2):
                self.kubectl('delete', 'pod', f'two-node-{index}',
                             '--ignore-not-found', '--wait=false')
            for index in range(2):
                state = self.root / f'agent-{index}/containerd'
                wait_for(f'worker-{index} Pod namespace cleanup', lambda index=index, state=state:
                         not self.in_node(index, 'find',
                                          state / 'run/io.containerd.grpc.v1.cri/netns',
                                          '-mindepth', '1', '-maxdepth', '1').stdout.splitlines(),
                         timeout=30)
                self.crash_node_runtime(index)
            self.success = True
            return
        restart_started = int(time.time())
        self.agents[0].terminate()
        self.agents[0].wait(timeout=20)
        # The stopped agent's existing Pod and pinned dataplane stay alive.
        self.kubectl('exec', 'two-node-1', '--', 'ping', '-c', '2', '-W', '2', identities[0][2])
        if self.overlay == 'wireguard':
            result = run(self.binary, 'wireguard', 'rotate-key', '--state-directory',
                         self.root / 'agent-0')
            assert result.stdout.startswith('WireGuard public key: '), result.stdout
            print(result.stdout.strip(), flush=True)
        print('Restarting enrolled worker-0 without a bootstrap token', flush=True)
        self.start_agent(0)
        wait_for('unchanged Pods after restart', lambda: self.check_pods(identities))
        self.traffic(identities)
        if self.overlay == 'wireguard':
            print('Post-rotation encrypted cross-node traffic confirms peer-key convergence',
                  flush=True)
        for index in range(2):
            def recovered(index=index):
                lines = self.metrics().splitlines()
                fresh = any(line.startswith('gr8s_dataplane_observed_timestamp_seconds{') and
                            f'node="worker-{index}"' in line and
                            int(line.rsplit(' ', 1)[1]) > restart_started for line in lines)
                return fresh and any(line.startswith('gr8s_endpoint_telemetry_available{') and
                                     f'node="worker-{index}"' in line and line.endswith(' 1')
                                     for line in lines)
            wait_for(f'worker-{index} recovered policy telemetry', recovered)
            # CHECK validates the actual TCX link, interface, identity and map schema.
            state = self.root / f'agent-{index}/containerd'
            config = json.loads((state / 'cni/net.d/10-gr8s.conflist').read_text())
            plugin = config['plugins'][0]
            plugin.update(cniVersion=config['cniVersion'], name=config['name'])
            sandboxes = self.in_node(index, 'find', state / 'bpf', '-mindepth', '1',
                                     '-maxdepth', '1', '-type', 'd',
                                     '!', '-name', 'service-lb').stdout.splitlines()
            namespaces = self.in_node(index, 'find', state / 'run/io.containerd.grpc.v1.cri/netns',
                                      '-mindepth', '1', '-maxdepth', '1').stdout.splitlines()
            assert len(sandboxes) == len(namespaces) == 1, (sandboxes, namespaces)
            self.in_node(index, 'env', 'CNI_COMMAND=CHECK', f'CNI_CONTAINERID={Path(sandboxes[0]).name}',
                         f'CNI_NETNS={namespaces[0]}', 'CNI_IFNAME=eth0', self.binary,
                         input=json.dumps(plugin))
        print('Agent restart preserves assignments, addresses, policy and cross-node connectivity', flush=True)
        self.success = True

    def cleanup(self):
        # Delete through the API while agents and their CNI services are alive.
        if self.kubeconfig.exists() and self.server and self.server.poll() is None:
            for index in range(2):
                try:
                    self.kubectl('delete', 'pod', f'two-node-{index}',
                                 '--ignore-not-found', '--wait=false', check=False)
                except subprocess.TimeoutExpired as error:
                    print(f'Pod deletion timed out for worker-{index}: {error}', flush=True)
                    self.success = False
            for index, keeper in enumerate(self.keepers):
                if keeper and keeper.poll() is None:
                    def absent(index=index):
                        result = self.in_node(index, 'sh', '-c',
                            f'for n in {self.root}/agent-{index}/containerd/run/io.containerd.grpc.v1.cri/netns/*; '
                            'do [ ! -e "$n" ] || exit 1; done')
                        processes = run('ps', '-eo', 'comm=,args=').stdout.splitlines()
                        shims = any(line.split(None, 1)[0].startswith('containerd-shim') and
                                    str(self.root / f'agent-{index}') in line for line in processes)
                        return result.returncode == 0 and not shims
                    try:
                        wait_for('Pod namespace cleanup', absent, timeout=30)
                    except (RuntimeError, subprocess.SubprocessError) as error:
                        print(f'Cleanup did not converge for worker-{index}: {error}', flush=True)
                        self.success = False
        for process in [*self.agents, self.server]:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    print(f'Cleanup forcibly stopping process {process.pid}', flush=True)
                    process.kill()
                    process.wait()
                    self.success = False
        # Every process in our owned node namespaces belongs to this test.
        for namespace in self.namespaces:
            result = run('ip', 'netns', 'pids', namespace, check=False)
            roots = {int(pid) for pid in result.stdout.split()
                     if not any(keeper and keeper.pid == int(pid) for keeper in self.keepers)}
            # Pod init processes have their own network namespaces. Include
            # descendants of the owned shims before killing those shims.
            parents = {}
            for process in Path('/proc').glob('[0-9]*/stat'):
                try:
                    fields = process.read_text().rsplit(')', 1)[1].split()
                    parents[int(process.parent.name)] = int(fields[1])
                except (OSError, ValueError, IndexError):
                    pass
            owned = set(roots)
            while True:
                children = {pid for pid, parent in parents.items() if parent in owned}
                if children <= owned:
                    break
                owned.update(children)
            if owned:
                descriptions = []
                for pid in sorted(owned):
                    try:
                        descriptions.append((pid, Path(f'/proc/{pid}/comm').read_text().strip(), parents.get(pid)))
                    except OSError:
                        pass
                print(f'Cleanup found remaining node processes: {descriptions}', flush=True)
            for pid in owned:
                try:
                    os.kill(pid, signal.SIGKILL)
                    self.success = False
                except ProcessLookupError:
                    pass
            run('ip', 'netns', 'del', namespace, check=False)
            shutil.rmtree(Path('/etc/netns') / namespace, ignore_errors=True)
        for keeper in self.keepers:
            if keeper:
                if keeper.poll() is None:
                    keeper.terminate()
                keeper.wait(timeout=5)
        for index in range(2):
            run('ip', 'link', 'del', f'{self.prefix}h{index}', check=False)
        if self.nat_created:
            run('nft', 'delete', 'table', 'ip', self.table)
        Path('/proc/sys/net/ipv4/ip_forward').write_text(self.forwarding)
        for log in self.logs:
            log.close()
        print(f'Two-node smoke diagnostics: {self.root}', flush=True)
        if self.success and os.environ.get('GR8S_SMOKE_KEEP_WORKDIR') != '1':
            shutil.rmtree(self.root)


def main():
    smoke = Smoke()
    try:
        smoke.setup()
        smoke.exercise()
    finally:
        smoke.cleanup()
    assert smoke.success, 'two-node smoke or cleanup failed'
    print('gr8s native two-node smoke passed')


if __name__ == '__main__':
    main()
