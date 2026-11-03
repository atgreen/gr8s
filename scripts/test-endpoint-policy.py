#!/usr/bin/env python3
"""Exercise Whistler's emitted TC bytecode without kernel BPF privileges.

This is an instruction interpreter, not a Linux verifier. The separate kernel
BPF_PROG_TEST_RUN gate remains necessary before claiming kernel enforcement.
"""
import struct
import sys

MASK = (1 << 64) - 1


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def read_program(path):
    elf = open(path, 'rb').read()
    assert elf[:6] == b'\x7fELF\x02\x01'
    assert struct.unpack_from('<H', elf, 18)[0] == 247
    start = struct.unpack_from('<Q', elf, 40)[0]
    width, count, names_index = struct.unpack_from('<HHH', elf, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', elf, start + i * width) for i in range(count)]
    def data(section):
        return elf[section[4]:section[4] + section[5]]
    def string(table, offset):
        return table[offset:table.index(0, offset)].decode()
    names = data(sections[names_index])
    named = {string(names, s[0]): (i, s) for i, s in enumerate(sections)}
    program_index, program = named['classifier']
    code = bytearray(data(program))
    symbols_index = next(i for i, s in enumerate(sections) if s[1] == 2)
    symbol_section = sections[symbols_index]
    strings = data(sections[symbol_section[6]])
    symbols = [struct.unpack_from('<IBBHQQ', data(symbol_section), i)
               for i in range(0, symbol_section[5], 24)]
    maps = {}
    descriptors = {}
    for name_offset, _, _, section_index, value, _ in symbols:
        name = string(strings, name_offset)
        if name in ('rejected_spoofs', 'endpoint_identity', 'traffic_stats'):
            descriptor = struct.unpack_from('<IIIII', data(sections[section_index]), value)
            descriptors[name] = descriptor
            maps[name] = len(maps) + 100
    assert descriptors == {'rejected_spoofs': (2, 4, 8, 1, 0),
                           'endpoint_identity': (2, 4, 16, 1, 128),
                           'traffic_stats': (2, 4, 8, 6, 0)}, descriptors
    relocations = 0
    for section in sections:
        if section[1] != 9 or section[7] != program_index:
            continue
        for offset in range(0, section[5], 16):
            instruction, info = struct.unpack_from('<QQ', data(section), offset)
            symbol = symbols[info >> 32]
            name = string(strings, symbol[0])
            assert name in maps and code[instruction] == 0x18
            struct.pack_into('<i', code, instruction + 4, maps[name])
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


MAC = bytes.fromhex('021122334455')
IP = bytes([10, 88, 1, 2])


def ethernet(protocol, payload, mac=MAC):
    return bytes.fromhex('02aabbccddee') + mac + struct.pack('>H', protocol) + payload


def ipv4(source=IP, mac=MAC):
    return ethernet(0x0800, bytes([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0]) + source + bytes([10, 88, 2, 2]), mac)


def arp(source=IP, sender_mac=MAC, opcode=1):
    return ethernet(0x0806, struct.pack('>HHBBH', 1, 0x0800, 6, 4, opcode) + sender_mac + source + bytes(6) + bytes([169, 254, 1, 1]))


def main(path):
    program = read_program(path)
    count = 0
    def check(packet, allowed, reason=None, configured=True, logical_length=None):
        nonlocal count
        machine = Machine(program, packet, configured, logical_length)
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
    print(f'Whistler emitted endpoint guard: {count} packet/counter cases passed ({len(program[0]) // 8} instructions)')


if __name__ == '__main__':
    main(sys.argv[1])
