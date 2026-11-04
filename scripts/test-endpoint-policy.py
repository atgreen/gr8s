#!/usr/bin/env python3
"""Exercise Whistler TC bytecode with an interpreter or Linux BPF test-run.

The program is JIT-compiled in-process by scripts/compile-endpoint-policy-fixture.lisp
and read here from that JSON fixture (raw bytecode, map descriptors, map-fd
relocation sites) -- no ELF object is produced. Use --kernel with BPF privileges
to load and execute the same bytecode in Linux. The default interpreter also
checks short buffers and non-linear skb lengths.
"""
import ctypes
import json
import os
import platform
import struct
import sys

MASK = (1 << 64) - 1


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def read_program(path):
    document = json.load(open(path))
    code = bytearray(document['code'])
    specs = document['maps']
    descriptors = {spec['name']: (spec['type'], spec['key_size'], spec['value_size'],
                                  spec['max_entries'], spec['flags'])
                   for spec in specs}
    maps = {spec['name']: index + 100 for index, spec in enumerate(specs)}
    assert descriptors == {'rejected_spoofs': (2, 4, 8, 1, 0),
                           'endpoint_identity': (2, 4, 16, 1, 128),
                           'traffic_stats': (2, 4, 8, 6, 0)}, descriptors
    relocations = 0
    for offset, map_index in document['relocations']:
        name = specs[map_index]['name']
        assert name in maps and code[offset] == 0x18
        struct.pack_into('<i', code, offset + 4, maps[name])
        relocations += 1
    assert relocations >= 3
    return bytes(code), maps, descriptors


class Machine:
    def __init__(self, program, packet, configured=True, logical_length=None):
        self.code, self.ids, descriptors = program
        self.lookups = []
        self.memory = {}
        self.maps = {}
        self.stack_initialized = set()
        self.registers = [0] * 11
        self.registers[1] = 0x200000
        self.registers[10] = 0x300200
        self.memory[0x100000] = bytearray(packet)
        self.memory[0x200000] = bytearray(84)
        self.memory[0x300000] = bytearray(512)
        context = self.memory[0x200000]
        struct.pack_into('<I', context, 0, len(packet) if logical_length is None else logical_length)
        struct.pack_into('<II', context, 76, 0x100000, 0x100000 + len(packet))
        for name, fd in self.ids.items():
            _, _, size, count, _ = descriptors[name]
            self.maps[fd] = {}
            for key in range(count):
                address = 0x400000 + (fd - 100) * 0x10000 + key * 0x100
                self.memory[address] = bytearray(size)
                self.maps[fd][key] = address
        if configured:
            address = self.maps[self.ids['endpoint_identity']][0]
            self.memory[address][:] = struct.pack('<IIII', 0x0a580102, 0x02112233, 0x4455, 1)

    def region(self, address, size):
        for base, value in self.memory.items():
            if base <= address and address + size <= base + len(value):
                return value, address - base
        raise AssertionError(f'out-of-bounds memory access: {address:x}, size={size}')

    def read(self, address, size):
        if 0x300000 <= address < 0x300200:
            assert all(byte in self.stack_initialized for byte in range(address, address + size)), \
                f'uninitialized stack read at {address:x}'
        value, offset = self.region(address, size)
        return int.from_bytes(value[offset:offset + size], 'little')

    def write(self, address, size, value):
        if 0x300000 <= address < 0x300200:
            self.stack_initialized.update(range(address, address + size))
        memory, offset = self.region(address, size)
        memory[offset:offset + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, 'little')

    def count(self, name, key):
        return self.read(self.maps[self.ids[name]][key], 8)

    def run(self):
        r, pc = self.registers, 0
        for _ in range(10000):
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
                    assert immediate == 1, f'unexpected helper {immediate}'
                    fd, key = r[1], self.read(r[2], 4)
                    self.lookups.append((pc - 1, fd, key))
                    r[0] = self.maps[fd].get(key, 0)
                    r[1:6] = [0xdeadbeef] * 5
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


class KernelProgram:
    """Load the same ELF into Linux and exercise it with BPF_PROG_TEST_RUN."""
    def __init__(self, program):
        self.fds = []
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.syscall_number = {'x86_64': 321, 'aarch64': 280}[platform.machine()]
        code, ids, descriptors = program
        self.ids = {}
        try:
            for name, descriptor in descriptors.items():
                fd = self.bpf(0, struct.pack('<IIIII', *descriptor))
                self.fds.append(fd)
                self.ids[name] = fd
            code = bytearray(code)
            for offset in range(0, len(code), 8):
                if code[offset] == 0x18 and code[offset + 1] >> 4 == 1:
                    old = struct.unpack_from('<I', code, offset + 4)[0]
                    name = next(name for name, fd in ids.items() if fd == old)
                    struct.pack_into('<I', code, offset + 4, self.ids[name])
            instructions = ctypes.create_string_buffer(bytes(code))
            license = ctypes.create_string_buffer(b'GPL')
            log = ctypes.create_string_buffer(1024 * 1024)
            attr = struct.pack('<IIQQIIQ', 3, len(code) // 8,
                               ctypes.addressof(instructions), ctypes.addressof(license),
                               1, len(log), ctypes.addressof(log))
            try:
                self.fd = self.bpf(5, attr)
            except OSError as error:
                raise RuntimeError(f'kernel rejected endpoint guard: {error}\n{log.value.decode()}') from error
            self.fds.append(self.fd)
        except BaseException:
            self.close()
            raise

    def bpf(self, command, attr):
        buffer = ctypes.create_string_buffer(attr)
        result = self.libc.syscall(self.syscall_number, command,
                                   ctypes.byref(buffer), len(attr))
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return result

    def entry(self, name, key, value=None):
        key_buffer = ctypes.create_string_buffer(struct.pack('<I', key))
        size = 16 if name == 'endpoint_identity' else 8
        value_buffer = ctypes.create_string_buffer(value if value is not None else bytes(size), size)
        self.bpf(2 if value is not None else 1,
                 struct.pack('<IIQQQ', self.ids[name], 0, ctypes.addressof(key_buffer),
                             ctypes.addressof(value_buffer), 0))
        return value_buffer.raw

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


class KernelMachine:
    def __init__(self, program, packet, configured=True, logical_length=None):
        assert logical_length is None
        self.program = program
        self.packet = bytes(packet)
        for key in range(6):
            program.entry('traffic_stats', key, bytes(8))
        program.entry('rejected_spoofs', 0, bytes(8))
        program.entry('endpoint_identity', 0,
                      struct.pack('<IIII', 0x0a580102, 0x02112233, 0x4455, 1)
                      if configured else bytes(16))

    def run(self):
        packet = ctypes.create_string_buffer(self.packet)
        attr = ctypes.create_string_buffer(struct.pack('<IIIIQQII', self.program.fd,
                    0, len(self.packet), 0, ctypes.addressof(packet), 0, 1, 0))
        # Use a direct syscall here to retain the output fields.
        result = self.program.libc.syscall(self.program.syscall_number, 10,
                                          ctypes.byref(attr), 40)
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return struct.unpack_from('<I', attr.raw, 4)[0]

    def count(self, name, key):
        return struct.unpack('<Q', self.program.entry(name, key))[0]


MAC = bytes.fromhex('021122334455')
IP = bytes([10, 88, 1, 2])


def ethernet(protocol, payload, mac=MAC):
    return bytes.fromhex('02aabbccddee') + mac + struct.pack('>H', protocol) + payload


def ipv4(source=IP, mac=MAC):
    return ethernet(0x0800, bytes([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0]) + source + bytes([10, 88, 2, 2]), mac)


def arp(source=IP, sender_mac=MAC, opcode=1):
    return ethernet(0x0806, struct.pack('>HHBBH', 1, 0x0800, 6, 4, opcode) + sender_mac + source + bytes(6) + bytes([169, 254, 1, 1]))


def main(path, kernel=False):
    program = read_program(path)
    instructions = len(program[0]) // 8
    native = KernelProgram(program) if kernel else None
    count = 0
    def check(packet, allowed, reason=None, configured=True, logical_length=None):
        nonlocal count
        # Linux's test-run skb constructor requires an Ethernet header and
        # cannot represent a separately specified non-linear packet length.
        if kernel and (len(packet) < 14 or logical_length is not None):
            return
        machine = (KernelMachine(native, packet, configured, logical_length) if kernel
                   else Machine(program, packet, configured, logical_length))
        assert machine.run() == (0 if allowed else 2), (count, packet.hex())
        size = len(packet) if logical_length is None else logical_length
        assert machine.count('traffic_stats', 0) == int(allowed)
        assert machine.count('traffic_stats', 1) == (size if allowed else 0)
        assert machine.count('traffic_stats', 2) == int(not allowed)
        assert machine.count('traffic_stats', 3) == (0 if allowed else size)
        assert machine.count('rejected_spoofs', 0) == int(reason == 'spoof')
        assert machine.count('traffic_stats', 4) == int(reason == 'malformed')
        assert machine.count('traffic_stats', 5) == int(reason == 'unsupported')
        count += 1
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
    for protocol in (0x86dd, 0x8100, 0x88cc):
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
    if native:
        native.close()
    backend = 'Linux kernel' if kernel else 'emitted bytecode'
    print(f'Whistler endpoint guard ({backend}): {count} packet/counter cases passed ({instructions} instructions)')


if __name__ == '__main__':
    main(sys.argv[1], kernel='--kernel' in sys.argv[2:])
