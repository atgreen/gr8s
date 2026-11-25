#!/usr/bin/env python3
"""Exercise the Whistler endpoint guards with an interpreter or Linux BPF test-run.

The programs are JIT-compiled in-process by scripts/compile-endpoint-policy-fixture.lisp
and read here from that JSON fixture (raw bytecode for each program, the map
descriptors they share, map-fd relocation sites) -- no ELF object is produced. The
egress guard runs on Pod egress (host veth ingress), the ingress guard on Pod ingress
(host veth egress); both read the NetworkPolicy tries the agent writes and share one
connection table. Use --kernel with BPF privileges to load and execute the same
bytecode in Linux. The default interpreter also checks short buffers, non-linear skb
lengths and uninitialized stack reads.
"""
import ctypes
import ipaddress
import json
import mmap
import os
import platform
import struct
import sys

MASK = (1 << 64) - 1
ARRAY, HASH, LRU_HASH, LPM_TRIE, RINGBUF = 2, 1, 9, 11, 27
FLOW_EVENT_SIZE = 40
EEXIST = 17
EXPECTED_MAPS = {'rejected_spoofs': (ARRAY, 4, 8, 1, 0),
                 'endpoint_identity': (ARRAY, 4, 32, 1, 128),
                 'traffic_stats': (ARRAY, 4, 8, 7, 0),
                 'netpol_mode': (ARRAY, 4, 4, 2, 0),
                 'netpol_egress_cidr': (LPM_TRIE, 8, 4, 16384, 1),
                 'netpol_egress_ports': (LPM_TRIE, 12, 1, 4096, 1),
                 'netpol_ingress_cidr': (LPM_TRIE, 8, 4, 16384, 1),
                 'netpol_ingress_ports': (LPM_TRIE, 12, 1, 4096, 1),
                 'netpol_egress_cidr_v6': (LPM_TRIE, 20, 4, 16384, 1),
                 'netpol_egress_ports_v6': (LPM_TRIE, 12, 1, 4096, 1),
                 'netpol_ingress_cidr_v6': (LPM_TRIE, 20, 4, 16384, 1),
                 'netpol_ingress_ports_v6': (LPM_TRIE, 12, 1, 4096, 1),
                 'netpol_flows': (LRU_HASH, 12, 8, 4096, 0),
                 'netpol_flows_v6': (LRU_HASH, 24, 8, 4096, 0),
                 'local_pod_v4': (LPM_TRIE, 8, 16, 4096, 1),
                 'host_redirect_v4': (HASH, 4, 1, 64, 1),
                 'flow_events': (RINGBUF, 0, 0, 262144, 0),
                 'flow_config': (ARRAY, 4, 4, 1, 0)}
TC_ACT_OK, TC_ACT_SHOT = 0, 2


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def read_programs(path):
    """Return ({program name: code}, map ids, descriptors) with map relocations patched."""
    document = json.load(open(path))
    specs = document['maps']
    descriptors = {spec['name']: (spec['type'], spec['key_size'], spec['value_size'],
                                  spec['max_entries'], spec['flags'])
                   for spec in specs}
    assert descriptors == EXPECTED_MAPS, descriptors
    ids = {spec['name']: index + 100 for index, spec in enumerate(specs)}
    programs = {}
    for program in document['programs']:
        code = bytearray(program['code'])
        for offset, map_index in program['relocations']:
            assert code[offset] == 0x18
            struct.pack_into('<i', code, offset + 4, ids[specs[map_index]['name']])
        assert len(program['relocations']) >= 3
        programs[program['name']] = bytes(code)
    assert set(programs) == {'gr8s_egress_guard', 'gr8s_ingress_guard'}, set(programs)
    return programs, ids, descriptors


def lpm_match(entry_key, lookup_key):
    """Does the trie entry ENTRY_KEY cover LOOKUP_KEY? Both are {u32 prefixlen, data}."""
    length = struct.unpack_from('<I', entry_key)[0]
    if length > struct.unpack_from('<I', lookup_key)[0]:
        return False
    data, wanted = entry_key[4:], lookup_key[4:]
    whole, rest = divmod(length, 8)
    if data[:whole] != wanted[:whole]:
        return False
    if rest:
        mask = (0xff << (8 - rest)) & 0xff
        return data[whole] & mask == wanted[whole] & mask
    return True


class Maps:
    """Map state shared by both programs, as the agent's pinned maps are."""
    def __init__(self, ids, descriptors, memory):
        self.ids, self.descriptors, self.memory = ids, descriptors, memory
        self.names = {fd: name for name, fd in ids.items()}
        self.entries = {name: {} for name in ids}
        self.ring = []
        self.reserved = {}
        self.next_address = 0x400000
        for name, (kind, key_size, value_size, count, _) in descriptors.items():
            if kind == ARRAY:
                for index in range(count):
                    self.entries[name][struct.pack('<I', index)] = self.allocate(value_size)

    def allocate(self, size):
        address = self.next_address
        self.memory[address] = bytearray(size)
        self.next_address += 0x100 if size <= 0x100 else (size + 0xff) & ~0xff
        return address

    def lookup(self, name, key):
        kind = self.descriptors[name][0]
        if kind == LPM_TRIE:
            matches = [(struct.unpack_from('<I', entry)[0], address)
                       for entry, address in self.entries[name].items() if lpm_match(entry, key)]
            return max(matches)[1] if matches else 0
        return self.entries[name].get(bytes(key), 0)

    def update(self, name, key, value, flags=0):
        """Store VALUE at KEY; with BPF_NOEXIST (1), refuse an existing KEY with -EEXIST."""
        kind, key_size, value_size, count, _ = self.descriptors[name]
        assert len(key) == key_size and len(value) == value_size
        key = bytes(key)
        if kind == ARRAY:
            assert key in self.entries[name]
        if flags == 1 and key in self.entries[name]:
            return -EEXIST & MASK
        assert flags in (0, 1), flags
        if key not in self.entries[name]:
            assert len(self.entries[name]) < count
            self.entries[name][key] = self.allocate(value_size)
        self.memory[self.entries[name][key]][:] = value
        return 0

    def value(self, name, key):
        address = self.entries[name].get(bytes(key))
        return None if address is None else bytes(self.memory[address])


class Machine:
    """Interpret one program run over PACKET against MAPS."""
    def __init__(self, code, maps, packet, clock, logical_length=None, pkt_type=0):
        self.code, self.maps, self.clock = code, maps, clock
        self.memory = maps.memory
        self.stack_initialized = set()
        self.registers = [0] * 11
        self.registers[1] = 0x200000
        self.registers[10] = 0x300200
        self.memory[0x100000] = bytearray(packet)
        self.memory[0x200000] = bytearray(84)
        self.memory[0x300000] = bytearray(512)
        context = self.memory[0x200000]
        struct.pack_into('<I', context, 0, len(packet) if logical_length is None else logical_length)
        struct.pack_into('<I', context, 4, pkt_type)
        struct.pack_into('<I', context, 40, 7)  # ifindex
        struct.pack_into('<II', context, 76, 0x100000, 0x100000 + len(packet))

    def region(self, address, size):
        for base, value in self.memory.items():
            if base <= address and address + size <= base + len(value):
                return value, address - base
        raise AssertionError(f'out-of-bounds memory access: {address:x}, size={size}')

    def read_bytes(self, address, size):
        if 0x300000 <= address < 0x300200:
            assert all(byte in self.stack_initialized for byte in range(address, address + size)), \
                f'uninitialized stack read at {address:x}'
        value, offset = self.region(address, size)
        return bytes(value[offset:offset + size])

    def read(self, address, size):
        return int.from_bytes(self.read_bytes(address, size), 'little')

    def write(self, address, size, value):
        if 0x300000 <= address < 0x300200:
            self.stack_initialized.update(range(address, address + size))
        memory, offset = self.region(address, size)
        memory[offset:offset + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, 'little')

    def call(self, helper):
        r = self.registers
        if helper in (1, 2):
            name = self.maps.names[r[1]]
            _, key_size, value_size, _, _ = self.maps.descriptors[name]
            try:
                key = self.read_bytes(r[2], key_size)
            except AssertionError as error:
                raise AssertionError(f'{name}: {error}') from error
            if helper == 1:
                r[0] = self.maps.lookup(name, key)
            else:
                r[0] = self.maps.update(name, key, self.read_bytes(r[3], value_size), r[4])
        elif helper == 5:
            r[0] = self.clock[0]
        elif helper == 23:
            r[0] = 7
        elif helper == 131:
            # bpf_ringbuf_reserve: a record nothing else may touch until it's submitted.
            assert self.maps.descriptors[self.maps.names[r[1]]][0] == RINGBUF and r[3] == 0
            address = self.maps.allocate(r[2])
            self.maps.reserved[address] = r[2]
            r[0] = address
        elif helper in (132, 133):
            size = self.maps.reserved.pop(r[1])
            if helper == 132:
                self.maps.ring.append(bytes(self.memory[r[1]][:size]))
            r[0] = 0
        else:
            raise AssertionError(f'unexpected helper {helper}')
        r[1:6] = [0xdeadbeef] * 5

    def run(self):
        r, pc = self.registers, 0
        for _ in range(20000):
            code, registers, offset, immediate = struct.unpack_from('<BBhi', self.code, pc * 8)
            dst, src = registers & 15, registers >> 4
            cls, op = code & 7, code & 0xf0
            pc += 1
            if code == 0x18:
                high = struct.unpack_from('<I', self.code, pc * 8 + 4)[0]
                r[dst] = (immediate & 0xffffffff) | (high << 32)
                pc += 1
            elif cls in (1, 2, 3):
                size = {0: 4, 8: 2, 16: 1, 24: 8}[code & 24]
                address = r[src] + offset if cls == 1 else r[dst] + offset
                if cls == 1:
                    assert code & 0xe0 == 0x60
                    r[dst] = self.read(address, size)
                elif cls == 2:
                    assert code & 0xe0 == 0x60
                    self.write(address, size, immediate)
                elif code & 0xe0 == 0x60:
                    self.write(address, size, r[src])
                else:
                    assert code & 0xe0 == 0xc0 and immediate in (0, 1)
                    old = self.read(address, size)
                    self.write(address, size, old + r[src])
                    if immediate == 1:
                        r[src] = old
            elif cls in (4, 7):
                bits = 32 if cls == 4 else 64
                mask = (1 << bits) - 1
                a = r[dst] & mask
                b = (r[src] if code & 8 else immediate) & mask
                if op == 0xd0:
                    assert immediate in (16, 32, 64)
                    value = r[dst] & ((1 << immediate) - 1)
                    r[dst] = int.from_bytes(value.to_bytes(immediate // 8, 'little'), 'big') if code & 8 else value
                    continue
                operations = {0: lambda: a + b, 0x10: lambda: a - b,
                              0x20: lambda: a * b, 0x30: lambda: a // b,
                              0x40: lambda: a | b, 0x50: lambda: a & b,
                              0x60: lambda: a << b, 0x70: lambda: a >> b,
                              0x80: lambda: -a, 0x90: lambda: a % b,
                              0xa0: lambda: a ^ b, 0xb0: lambda: b,
                              0xc0: lambda: signed(a, bits) >> b}
                r[dst] = operations[op]() & mask
            elif cls in (5, 6):
                if op == 0x90:
                    return r[0]
                if op == 0x80:
                    self.call(immediate)
                    continue
                bits = 32 if cls == 6 else 64
                mask = (1 << bits) - 1
                a, b = r[dst] & mask, (r[src] if code & 8 else immediate) & mask
                predicates = {0: lambda: True, 0x10: lambda: a == b,
                              0x20: lambda: a > b, 0x30: lambda: a >= b,
                              0x40: lambda: bool(a & b), 0x50: lambda: a != b,
                              0x60: lambda: signed(a, bits) > signed(b, bits),
                              0x70: lambda: signed(a, bits) >= signed(b, bits),
                              0xa0: lambda: a < b, 0xb0: lambda: a <= b,
                              0xc0: lambda: signed(a, bits) < signed(b, bits),
                              0xd0: lambda: signed(a, bits) <= signed(b, bits)}
                if predicates[op]():
                    pc += offset
            else:
                raise AssertionError(f'unsupported instruction {code:x}')
        raise AssertionError('instruction budget exhausted')


class Interpreter:
    """Both programs over shared interpreted maps, with a settable clock."""
    def __init__(self, programs, ids, descriptors):
        self.programs = programs
        self.memory = {}
        self.maps = Maps(ids, descriptors, self.memory)
        self.clock = [1_000_000_000]

    def update(self, name, key, value):
        self.maps.update(name, key, value)

    def lookup(self, name, key):
        return self.maps.value(name, key)

    def run(self, program, packet, logical_length=None, pkt_type=0):
        return Machine(self.programs[program], self.maps, packet, self.clock, logical_length, pkt_type).run()

    def advance(self, seconds):
        self.clock[0] += int(seconds * 1e9)

    def events(self):
        """Take the flow events written since the last call."""
        assert not self.maps.reserved, 'a reserved flow event was never submitted'
        taken, self.maps.ring = self.maps.ring, []
        return taken

    def close(self):
        pass


class Kernel:
    """Load both programs into Linux and run them with BPF_PROG_TEST_RUN."""
    def __init__(self, programs, ids, descriptors, program_types=None):
        self.fds = []
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.syscall_number = {'x86_64': 321, 'aarch64': 280}[platform.machine()]
        self.descriptors = descriptors
        self.map_fds = {}
        self.program_fds = {}
        try:
            for name, descriptor in descriptors.items():
                fd = self.bpf(0, struct.pack('<IIIII', *descriptor))
                self.fds.append(fd)
                self.map_fds[name] = fd
            for program, code in programs.items():
                code = bytearray(code)
                for offset in range(0, len(code), 8):
                    if code[offset] == 0x18 and code[offset + 1] >> 4 == 1:
                        old = struct.unpack_from('<I', code, offset + 4)[0]
                        name = next(name for name, fd in ids.items() if fd == old)
                        struct.pack_into('<I', code, offset + 4, self.map_fds[name])
                instructions = ctypes.create_string_buffer(bytes(code))
                license = ctypes.create_string_buffer(b'GPL')
                log = ctypes.create_string_buffer(1024 * 1024)
                program_type, attach_type = (program_types or {}).get(program, (3, None))
                attr = struct.pack('<IIQQIIQ', program_type, len(code) // 8,
                                   ctypes.addressof(instructions), ctypes.addressof(license),
                                   1, len(log), ctypes.addressof(log))
                if attach_type is not None:
                    attr += bytes(28) + struct.pack('<I', attach_type)
                try:
                    fd = self.bpf(5, attr)
                except OSError as error:
                    raise RuntimeError(f'kernel rejected {program}: {error}\n{log.value.decode()}') from error
                self.fds.append(fd)
                self.program_fds[program] = fd
            ring = self.map_fds['flow_events']
            page = mmap.PAGESIZE
            self.ring_size = descriptors['flow_events'][3]
            self.consumer = mmap.mmap(ring, page, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
            self.producer = mmap.mmap(ring, page + 2 * self.ring_size, mmap.MAP_SHARED,
                                      mmap.PROT_READ, offset=page)
        except BaseException:
            self.close()
            raise

    def events(self):
        """Take the flow events the kernel has committed since the last call."""
        page = mmap.PAGESIZE
        produced = struct.unpack_from('<Q', self.producer, 0)[0]
        consumed = struct.unpack_from('<Q', self.consumer, 0)[0]
        taken = []
        while consumed < produced:
            header = struct.unpack_from('<I', self.producer, page + consumed % self.ring_size)[0]
            assert not header & (1 << 31), 'an uncommitted flow event'
            length = header & 0x3fffffff
            if not header & (1 << 30):
                start = page + (consumed + 8) % self.ring_size
                taken.append(bytes(self.producer[start:start + length]))
            consumed += (length + 8 + 7) & ~7
        struct.pack_into('<Q', self.consumer, 0, consumed)
        return taken

    def bpf(self, command, attr):
        buffer = ctypes.create_string_buffer(attr)
        result = self.libc.syscall(self.syscall_number, command, ctypes.byref(buffer), len(attr))
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return result

    def update(self, name, key, value):
        key_buffer = ctypes.create_string_buffer(bytes(key), len(key))
        value_buffer = ctypes.create_string_buffer(bytes(value), len(value))
        self.bpf(2, struct.pack('<IIQQQ', self.map_fds[name], 0, ctypes.addressof(key_buffer),
                                ctypes.addressof(value_buffer), 0))

    def lookup(self, name, key):
        size = self.descriptors[name][2]
        key_buffer = ctypes.create_string_buffer(bytes(key), len(key))
        value_buffer = ctypes.create_string_buffer(size)
        try:
            self.bpf(1, struct.pack('<IIQQQ', self.map_fds[name], 0, ctypes.addressof(key_buffer),
                                    ctypes.addressof(value_buffer), 0))
        except OSError:
            return None
        return value_buffer.raw

    def run(self, program, packet, logical_length=None, pkt_type=0):
        # A test run's skb takes its type from its destination MAC; it can't be PACKET_LOOPBACK.
        assert logical_length is None and pkt_type == 0
        data = ctypes.create_string_buffer(bytes(packet))
        attr = ctypes.create_string_buffer(struct.pack('<IIIIQQII', self.program_fds[program],
                                                       0, len(packet), 0, ctypes.addressof(data), 0, 1, 0))
        result = self.libc.syscall(self.syscall_number, 10, ctypes.byref(attr), 40)
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return struct.unpack_from('<I', attr.raw, 4)[0]

    def advance(self, seconds):
        # The kernel's clock cannot be moved; age the connection table instead.
        for name in ('netpol_flows', 'netpol_flows_v6'):
            flows = self.map_fds[name]
            size = self.descriptors[name][1]
            key = ctypes.create_string_buffer(size)
            next_key = ctypes.create_string_buffer(size)
            keys = []
            first = True
            while True:
                try:
                    self.bpf(4, struct.pack('<IIQQ', flows, 0,
                                            0 if first else ctypes.addressof(key),
                                            ctypes.addressof(next_key)))
                except OSError:
                    break
                keys.append(next_key.raw)
                ctypes.memmove(key, next_key, size)
                first = False
            for entry in keys:
                stamp = struct.unpack('<Q', self.lookup(name, entry))[0]
                self.update(name, entry,
                            struct.pack('<Q', max(0, stamp - int(seconds * 1e9))))

    def close(self):
        for view in ('producer', 'consumer'):
            if getattr(self, view, None) is not None:
                getattr(self, view).close()
                setattr(self, view, None)
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


MAC = bytes.fromhex('021122334455')
IP = bytes([10, 88, 1, 2])
GATEWAY = bytes([169, 254, 1, 1])
IP6 = ipaddress.IPv6Address('fd42::2').packed
GATEWAY6 = ipaddress.IPv6Address('fe80::1').packed
TCP, UDP, ICMP = 6, 17, 1


REASONS = {'spoof': 1, 'malformed': 2, 'unsupported': 3, 'policy': 4}


def flow_event(raw):
    """Decode one ring record as the guards lay out FLOW-EVENT."""
    assert len(raw) == FLOW_EVENT_SIZE, len(raw)
    ifindex, endpoint, kind, reason, direction, family, protocol = struct.unpack_from('<IIBBBBB', raw)
    length = struct.unpack_from('<I', raw, 20)[0]
    peer = raw[24:28] if family == 4 else raw[24:40]
    return {'ifindex': ifindex, 'endpoint': endpoint, 'kind': kind, 'reason': reason,
            'direction': direction, 'family': family, 'protocol': protocol,
            'pod_port': int.from_bytes(raw[14:16], 'big'), 'peer_port': int.from_bytes(raw[16:18], 'big'),
            'length': length, 'peer': bytes(peer)}


def ethernet(protocol, payload, mac=MAC):
    return bytes.fromhex('02aabbccddee') + mac + struct.pack('>H', protocol) + payload


def ipv4(source=IP, mac=MAC):
    return ethernet(0x0800, bytes([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0]) + source + bytes([10, 88, 2, 2]), mac)


def datagram(source, destination, protocol, sport=0, dport=0, mac=MAC, flags=0x02):
    """An IPv4 packet carrying a minimal L4 header with ports (or an ICMP echo)."""
    if protocol == TCP:
        l4 = struct.pack('>HHIIBBHHH', sport, dport, 1, 0, 0x50, flags, 1024, 0, 0)
    elif protocol == UDP:
        l4 = struct.pack('>HHHH', sport, dport, 8, 0)
    else:
        l4 = struct.pack('>BBHHH', 8, 0, 0, sport, 1)
    header = bytes([0x45, 0]) + struct.pack('>H', 20 + len(l4)) + bytes([0, 0, 0, 0, 64, protocol, 0, 0])
    return ethernet(0x0800, header + bytes(source) + bytes(destination) + l4, mac)


def datagram6(source, destination, protocol, sport=0, dport=0, mac=MAC, flags=0x02):
    """An IPv6 packet carrying a minimal TCP, UDP, or ICMPv6 header."""
    if protocol == TCP:
        l4 = struct.pack('>HHIIBBHHH', sport, dport, 1, 0, 0x50, flags, 1024, 0, 0)
    elif protocol == UDP:
        l4 = struct.pack('>HHHH', sport, dport, 8, 0)
    else:
        l4 = struct.pack('>BBHI', 128, 0, 0, 1)
    header = bytes([0x60, 0, 0, 0]) + struct.pack('>HBB', len(l4), protocol, 64)
    return ethernet(0x86dd, header + bytes(source) + bytes(destination) + l4, mac)


def arp(source=IP, sender_mac=MAC, opcode=1):
    return ethernet(0x0806, struct.pack('>HHBBH', 1, 0x0800, 6, 4, opcode) + sender_mac + source + bytes(6) + bytes([169, 254, 1, 1]))


def cidr_key(cidr):
    address, length = cidr.split('/')
    return struct.pack('<I', int(length)) + bytes(int(octet) for octet in address.split('.'))


def cidr_key6(cidr):
    network = ipaddress.IPv6Network(cidr, strict=False)
    return struct.pack('<I', network.prefixlen) + network.network_address.packed


def port_key(group, protocol=None, port=None, bits=16):
    length = 32 if protocol is None else 40 if port is None else 48 + bits
    return struct.pack('<II', length, group) + bytes([protocol or 0, 0]) + struct.pack('>H', port or 0)


def main(path, kernel=False):
    programs, ids, descriptors = read_programs(path)
    backend = (Kernel if kernel else Interpreter)(programs, ids, descriptors)
    count = 0

    def stat(index):
        return struct.unpack('<Q', backend.lookup('traffic_stats', struct.pack('<I', index)))[0]

    def reset():
        for index in range(7):
            backend.update('traffic_stats', struct.pack('<I', index), bytes(8))
        backend.update('rejected_spoofs', struct.pack('<I', 0), bytes(8))

    def configure(configured=True):
        backend.update('endpoint_identity', struct.pack('<I', 0),
                       (struct.pack('<IIII', 0x0a580102, 0x02112233, 0x4455, 1) + IP6)
                       if configured else bytes(32))

    def mode(egress, ingress):
        backend.update('netpol_mode', struct.pack('<I', 0), struct.pack('<I', egress))
        backend.update('netpol_mode', struct.pack('<I', 1), struct.pack('<I', ingress))

    def check(packet, allowed, reason=None, configured=True, logical_length=None):
        """The egress guard's verdict and counters for one Pod packet."""
        nonlocal count
        # Linux's test-run skb constructor requires an Ethernet header and
        # cannot represent a separately specified non-linear packet length.
        if kernel and (len(packet) < 14 or logical_length is not None):
            return []
        reset()
        configure(configured)
        backend.events()
        result = backend.run('gr8s_egress_guard', packet, logical_length)
        assert result == (TC_ACT_OK if allowed else TC_ACT_SHOT), (count, packet.hex(), result)
        size = len(packet) if logical_length is None else logical_length
        # Every drop is reported once, with its reason; nothing allowed is reported as a drop.
        events = [flow_event(raw) for raw in backend.events()]
        drops = [event for event in events if event['kind'] == 1]
        if allowed:
            assert not drops, (count, drops)
        else:
            assert len(drops) == 1, (count, events)
            assert drops[0]['reason'] == REASONS[reason], (count, drops)
            assert drops[0]['direction'] == 1 and drops[0]['length'] == size, (count, drops)
            assert drops[0]['endpoint'] == (0x0a580102 if configured else 0), (count, drops)
        assert stat(0) == int(allowed)
        assert stat(1) == (size if allowed else 0)
        assert stat(2) == int(not allowed)
        assert stat(3) == (0 if allowed else size)
        assert struct.unpack('<Q', backend.lookup('rejected_spoofs', struct.pack('<I', 0)))[0] == int(reason == 'spoof')
        assert stat(4) == int(reason == 'malformed')
        assert stat(5) == int(reason == 'unsupported')
        assert stat(6) == int(reason == 'policy')
        count += 1
        return events

    def inbound(packet, allowed):
        """The ingress guard's verdict for one packet to the Pod."""
        nonlocal count
        reset()
        backend.events()
        result = backend.run('gr8s_ingress_guard', packet)
        assert result == (TC_ACT_OK if allowed else TC_ACT_SHOT), (count, packet.hex(), result)
        assert stat(6) == int(not allowed)
        events = [flow_event(raw) for raw in backend.events()]
        drops = [event for event in events if event['kind'] == 1]
        assert len(drops) == int(not allowed), (count, events)
        if drops:
            assert drops[0]['reason'] == REASONS['policy'] and drops[0]['direction'] == 2, (count, drops)
        count += 1
        return events

    def single(events, kind):
        """The one event of KIND among EVENTS."""
        found = [event for event in events if event['kind'] == kind]
        assert len(found) == 1, events
        return found[0]

    mode(0, 0)
    # The endpoint identity and anti-spoofing guard.
    check(ipv4(), True)
    check(arp(), True)
    check(arp(opcode=2), True)
    check(ipv4(bytes([10, 88, 1, 3])), False, 'spoof')
    check(ipv4(bytes([192, 0, 2, 10])), False, 'spoof')
    check(ipv4(mac=bytes.fromhex('021122334456')), False, 'spoof')
    check(arp(source=bytes(4)), False, 'spoof')
    check(arp(source=bytes([10, 88, 1, 3])), False, 'spoof')
    check(arp(sender_mac=bytes.fromhex('021122334456')), False, 'spoof')
    check(ipv4(), False, 'spoof', configured=False)
    check(datagram6(IP6, ipaddress.IPv6Address('fd42::3').packed, UDP, 40000, 53), True)
    check(datagram6(ipaddress.IPv6Address('fd42::4').packed,
                    ipaddress.IPv6Address('fd42::3').packed, UDP, 40000, 53),
          False, 'spoof')
    for protocol in (0x8100, 0x88cc):
        check(ethernet(protocol, bytes(64)), False, 'unsupported')
    for packet in (ipv4(), arp()):
        for size in range(len(packet)):
            check(packet[:size], False, 'malformed')
    for offset, value in ((14, 0x65), (14, 0x44), (17, 19), (17, 100)):
        packet = bytearray(ipv4()); packet[offset] = value
        check(packet, False, 'malformed')
    for offset, value in ((15, 2), (17, 1), (18, 5), (19, 16), (21, 3)):
        packet = bytearray(arp()); packet[offset] = value
        check(packet, False, 'malformed')
    # TC may expose only the header in its linear data area.
    packet = bytearray(ipv4()); packet[17] = 100
    check(packet, True, logical_length=114)

    # A node reporting every connection reports a Pod no policy isolates, once per
    # connection and in either direction; without it, such a Pod reports none.
    seen, seen6 = bytes([10, 88, 9, 9]), ipaddress.IPv6Address('fd49::9').packed
    assert not [e for e in check(datagram(IP, seen, TCP, 41000, 443), True) if e['kind'] == 2]
    backend.update('flow_config', struct.pack('<I', 0), struct.pack('<I', 1))
    new = single(check(datagram(IP, seen, TCP, 41001, 443), True), 2)
    assert (new['direction'], new['endpoint'], new['pod_port'], new['peer_port'], new['peer']) \
        == (1, 0x0a580102, 41001, 443, seen), new
    assert not check(datagram(IP, seen, TCP, 41001, 443), True)
    new = single(inbound(datagram(seen, IP, TCP, 5555, 8080), True), 2)
    assert (new['direction'], new['pod_port'], new['peer_port'], new['peer']) == (2, 8080, 5555, seen), new
    assert not [e for e in inbound(datagram(seen, IP, TCP, 5555, 8080), True) if e['kind'] == 2]
    new = single(check(datagram6(IP6, seen6, UDP, 41002, 53), True), 2)
    assert (new['family'], new['peer']) == (6, seen6), new
    # A reply seen first, to a connection opened by a peer whose packets aren't recorded
    # (the node gateway's probes), is no new connection; its opening packet is.
    probe = bytes([169, 254, 1, 1])
    assert not [e for e in check(datagram(IP, probe, TCP, 8080, 56400, flags=0x12), True) if e['kind'] == 2]
    assert not [e for e in check(datagram(IP, seen, TCP, 41004, 443, flags=0x10), True) if e['kind'] == 2]
    assert not [e for e in inbound(datagram(seen, IP, TCP, 5556, 8080, flags=0x12), True) if e['kind'] == 2]
    assert not [e for e in check(datagram6(IP6, seen6, TCP, 41005, 443, flags=0x12), True) if e['kind'] == 2]
    assert not [e for e in inbound(datagram6(seen6, IP6, TCP, 5557, 8080, flags=0x10), True) if e['kind'] == 2]
    single(check(datagram6(IP6, seen6, TCP, 41006, 443), True), 2)
    # podster-4yh: the host's own multicast out the veth (avahi's mDNS from its link-local
    # address to ff02::fb) comes back as a PACKET_LOOPBACK copy received on the veth. It
    # isn't the Pod's, so it passes unjudged and uncounted; the same bytes as a Pod's
    # packet are still a spoof.
    if not kernel:
        host_mac = bytes.fromhex('02ff3fcecfe3')
        mdns = datagram6(ipaddress.IPv6Address('fe80::c558:ffff:fe84:9af9').packed,
                         ipaddress.IPv6Address('ff02::fb').packed, UDP, 5353, 5353, mac=host_mac)
        reset(); configure(True); backend.events()
        assert backend.run('gr8s_egress_guard', mdns, None, 5) == TC_ACT_OK
        assert not backend.events(), 'a loopback copy is no flow event'
        assert all(stat(i) == 0 for i in range(7))
        assert struct.unpack('<Q', backend.lookup('rejected_spoofs', struct.pack('<I', 0)))[0] == 0
        check(mdns, False, 'spoof')
    # Link-local neighbors' housekeeping isn't a connection.
    local6 = ipaddress.IPv6Address('fe80::da:1').packed
    assert not [e for e in inbound(datagram6(local6, IP6, UDP, 5353, 5353), True) if e['kind'] == 2]
    assert not [e for e in inbound(datagram6(bytes(16), IP6, UDP, 5353, 5353), True) if e['kind'] == 2]
    assert not [e for e in check(datagram6(IP6, local6, UDP, 41003, 5353), True) if e['kind'] == 2]
    backend.update('flow_config', struct.pack('<I', 0), struct.pack('<I', 0))

    peer, other, outside = bytes([10, 88, 2, 2]), bytes([10, 88, 3, 3]), bytes([192, 0, 2, 7])
    # Egress isolation: 10.88.2.0/24 on UDP 53 and TCP 8000-8080; 10.0.0.0/8 on everything
    # except 10.88.3.0/24; UDP on every port to 192.0.2.0/24.
    mode(1, 0)
    for key, group in (('10.88.2.0/24', 1), ('10.0.0.0/8', 2), ('10.88.3.0/24', 0), ('192.0.2.0/24', 3)):
        backend.update('netpol_egress_cidr', cidr_key(key), struct.pack('<I', group))
    for key in (port_key(1, UDP, 53), port_key(1, TCP, 8000, 10), port_key(1, TCP, 8064, 12),
                port_key(1, TCP, 8080), port_key(2), port_key(3, UDP)):
        backend.update('netpol_egress_ports', key, b'\x01')
    check(datagram(IP, peer, UDP, 40000, 53), True)
    check(datagram(IP, peer, UDP, 40000, 54), False, 'policy')
    check(datagram(IP, peer, TCP, 40000, 8000), True)
    check(datagram(IP, peer, TCP, 40000, 8079), True)
    check(datagram(IP, peer, TCP, 40000, 8080), True)
    check(datagram(IP, peer, TCP, 40000, 8081), False, 'policy')
    check(datagram(IP, peer, TCP, 40000, 7999), False, 'policy')
    check(datagram(IP, peer, ICMP), False, 'policy')
    check(datagram(IP, bytes([10, 1, 2, 3]), TCP, 40000, 22), True)
    check(datagram(IP, bytes([10, 1, 2, 3]), ICMP), True)
    check(datagram(IP, other, TCP, 40000, 22), False, 'policy')
    check(datagram(IP, outside, UDP, 40000, 9999), True)
    check(datagram(IP, outside, TCP, 40000, 9999), False, 'policy')
    check(datagram(IP, bytes([172, 16, 0, 1]), UDP, 40000, 53), False, 'policy')
    check(arp(), True)
    # A policy drop names the flow it refused, from the Pod's side.
    drop = single(check(datagram(IP, peer, UDP, 40001, 54), False, 'policy'), 1)
    assert (drop['family'], drop['protocol'], drop['pod_port'], drop['peer_port'], drop['peer']) \
        == (4, UDP, 40001, 54, peer), drop
    # An isolated Pod's new connection is reported once, when it's first allowed.
    allowed = single(check(datagram(IP, peer, TCP, 40002, 8000), True), 2)
    assert (allowed['reason'], allowed['direction'], allowed['endpoint'], allowed['pod_port'],
            allowed['peer_port'], allowed['peer']) == (0, 1, 0x0a580102, 40002, 8000, peer), allowed
    assert not check(datagram(IP, peer, TCP, 40002, 8000), True)

    peer6 = ipaddress.IPv6Address('fd43::2').packed
    other6 = ipaddress.IPv6Address('fd44::3').packed
    outside6 = ipaddress.IPv6Address('2001:db8::7').packed
    # IPv6 egress isolation: UDP 53 to fd43::/64, plus every TCP port to
    # 2001:db8::/32. The same LPM and port semantics apply to 128-bit peers.
    mode(1, 0)
    backend.update('netpol_egress_cidr_v6', cidr_key6('fd43::/64'), struct.pack('<I', 1))
    backend.update('netpol_egress_cidr_v6', cidr_key6('2001:db8::/32'), struct.pack('<I', 2))
    backend.update('netpol_egress_ports_v6', port_key(1, UDP, 53), b'\x01')
    backend.update('netpol_egress_ports_v6', port_key(2, TCP), b'\x01')
    check(datagram6(IP6, peer6, UDP, 40000, 53), True)
    drop = single(check(datagram6(IP6, peer6, UDP, 40000, 54), False, 'policy'), 1)
    assert (drop['family'], drop['protocol'], drop['pod_port'], drop['peer_port'], drop['peer']) \
        == (6, UDP, 40000, 54, peer6), drop
    check(datagram6(IP6, outside6, TCP, 40000, 443), True)
    check(datagram6(IP6, other6, TCP, 40000, 443), False, 'policy')
    # Neighbor discovery and MLD to link-scope peers keep the interface working, so
    # egress isolation lets them out (podster-6cy); other link-scope traffic stays policy's.
    solicited = ipaddress.IPv6Address('ff02::1:ff00:1').packed
    check(datagram6(IP6, solicited, 58), True)
    check(datagram6(IP6, ipaddress.IPv6Address('ff02::2').packed, 58), True)
    check(datagram6(IP6, ipaddress.IPv6Address('ff02::16').packed, 0), True)
    check(datagram6(IP6, ipaddress.IPv6Address('fe80::da:1').packed, 58), True)
    check(datagram6(IP6, ipaddress.IPv6Address('ff02::fb').packed, UDP, 5353, 5353), False, 'policy')
    check(datagram6(IP6, other6, 58), False, 'policy')

    # IPv6 ingress isolation and the fixed link-local node gateway exemption.
    mode(0, 1)
    backend.update('netpol_ingress_cidr_v6', cidr_key6('fd43::/64'), struct.pack('<I', 1))
    backend.update('netpol_ingress_ports_v6', port_key(1, TCP, 80), b'\x01')
    inbound(datagram6(peer6, IP6, TCP, 5555, 80), True)
    inbound(datagram6(peer6, IP6, TCP, 5555, 81), False)
    inbound(datagram6(other6, IP6, TCP, 5555, 80), False)
    inbound(datagram6(GATEWAY6, IP6, TCP, 5555, 8080), True)
    # Neighbor discovery and MLD from a link-local or unspecified source pass ingress
    # isolation; a link-local neighbor's UDP is still policy's (podster-6cy).
    inbound(datagram6(ipaddress.IPv6Address('fe80::da:1').packed, IP6, 58), True)
    inbound(datagram6(bytes(16), IP6, 0), True)
    inbound(datagram6(ipaddress.IPv6Address('fe80::da:1').packed, IP6, UDP, 5353, 5353), False)
    inbound(datagram6(other6, IP6, 58), False)
    # Replies to an IPv6 connection opened by the Pod pass ingress isolation.
    check(datagram6(IP6, outside6, TCP, 41000, 443), True)
    inbound(datagram6(outside6, IP6, TCP, 443, 41000), True)
    inbound(datagram6(outside6, IP6, TCP, 444, 41000), False)

    # Conversely, replies to IPv6 traffic accepted by an ingress policy pass
    # egress isolation even when no egress CIDR is allowed.
    mode(1, 0)
    inbound(datagram6(other6, IP6, UDP, 6000, 7000), True)
    check(datagram6(IP6, other6, UDP, 7000, 6000), True)
    check(datagram6(IP6, other6, UDP, 7001, 6000), False, 'policy')

    # Ingress isolation: only TCP 80 from 10.88.2.0/24; the node gateway always reaches the Pod.
    mode(0, 1)
    backend.update('netpol_ingress_cidr', cidr_key('10.88.2.0/24'), struct.pack('<I', 1))
    backend.update('netpol_ingress_ports', port_key(1, TCP, 80), b'\x01')
    inbound(datagram(peer, IP, TCP, 5555, 80), True)
    # An inbound refusal names the Pod by its address and the peer that tried.
    drop = single(inbound(datagram(peer, IP, TCP, 5555, 81), False), 1)
    assert (drop['endpoint'], drop['family'], drop['pod_port'], drop['peer_port'], drop['peer']) \
        == (0x0a580102, 4, 81, 5555, peer), drop
    inbound(datagram(other, IP, TCP, 5555, 80), False)
    inbound(datagram(GATEWAY, IP, TCP, 5555, 8080), True)
    inbound(arp(), True)
    inbound(ethernet(0x86dd, bytes(64)), True)
    # Replies to the Pod's own connections pass ingress isolation.
    check(datagram(IP, outside, TCP, 41000, 443), True)
    inbound(datagram(outside, IP, TCP, 443, 41000), True)
    inbound(datagram(outside, IP, TCP, 444, 41000), False)
    inbound(datagram(outside, IP, TCP, 443, 41001), False)

    # Egress isolation allowing nothing: replies to connections the Pod accepted still pass.
    mode(1, 0)
    for key in ('10.88.2.0/24', '10.0.0.0/8', '10.88.3.0/24', '192.0.2.0/24'):
        backend.update('netpol_egress_cidr', cidr_key(key), struct.pack('<I', 0))
    inbound(datagram(other, IP, UDP, 6000, 7000), True)
    check(datagram(IP, other, UDP, 7000, 6000), True)
    check(datagram(IP, other, UDP, 7001, 6000), False, 'policy')
    # A connection's replies stop passing once it has been idle past its lifetime.
    backend.advance(181)
    check(datagram(IP, other, UDP, 7000, 6000), False, 'policy')
    # A TCP connection idle past tcp_keepalive_time (2h) still gets its peer's keepalives
    # in: TCP replies stay admitted for days, as conntrack keeps ESTABLISHED (podster-af3).
    mode(0, 1)
    check(datagram(IP, outside, TCP, 42000, 443), True)
    check(datagram6(IP6, outside6, TCP, 42000, 443), True)
    backend.advance(7200 + 75)
    inbound(datagram(outside, IP, TCP, 443, 42000), True)
    inbound(datagram6(outside6, IP6, TCP, 443, 42000), True)
    backend.advance(5 * 86400 + 1)
    inbound(datagram(outside, IP, TCP, 443, 42000), False)
    inbound(datagram6(outside6, IP6, TCP, 443, 42000), False)
    backend.close()
    name = 'Linux kernel' if kernel else 'emitted bytecode'
    sizes = ', '.join(f'{len(code) // 8} {program}' for program, code in sorted(programs.items()))
    print(f'Whistler endpoint guards ({name}): {count} packet/counter cases passed ({sizes} instructions)')


if __name__ == '__main__':
    main(sys.argv[1], kernel='--kernel' in sys.argv[2:])
