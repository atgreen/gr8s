#!/usr/bin/env python3
"""Independently verify the public-key-42 backup-stream test fixture, not production bundles."""
import argparse
import ctypes as C
import ctypes.util
import hashlib
import hmac
import json
from pathlib import Path

lib = C.CDLL(ctypes.util.find_library('crypto'))
def fn(name, result, *arguments):
    f = getattr(lib, name)
    f.restype, f.argtypes = result, list(arguments)
    return f
new = fn('EVP_CIPHER_CTX_new', C.c_void_p)
free = fn('EVP_CIPHER_CTX_free', None, C.c_void_p)
aes = fn('EVP_aes_256_gcm', C.c_void_p)
init = fn('EVP_DecryptInit_ex', C.c_int, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p)
ctrl = fn('EVP_CIPHER_CTX_ctrl', C.c_int, C.c_void_p, C.c_int, C.c_int, C.c_void_p)
update = fn('EVP_DecryptUpdate', C.c_int, C.c_void_p, C.c_void_p, C.POINTER(C.c_int), C.c_void_p, C.c_int)
final = fn('EVP_DecryptFinal_ex', C.c_int, C.c_void_p, C.c_void_p, C.POINTER(C.c_int))

def decrypt(key, nonce, aad, ciphertext, tag):
    ctx, n = new(), C.c_int()
    out = C.create_string_buffer(len(ciphertext) + 16)
    buffers = [C.create_string_buffer(x) for x in (key, nonce, aad, ciphertext, tag)]
    try:
        assert init(ctx, aes(), None, None, None) == 1
        assert ctrl(ctx, 0x9, 12, None) == 1
        assert init(ctx, None, None, buffers[0], buffers[1]) == 1
        assert update(ctx, None, C.byref(n), buffers[2], len(aad)) == 1
        assert update(ctx, out, C.byref(n), buffers[3], len(ciphertext)) == 1
        length = n.value
        assert ctrl(ctx, 0x11, 16, buffers[4]) == 1
        assert final(ctx, C.byref(out, length), C.byref(n)) == 1
        return out.raw[:length + n.value]
    finally:
        free(ctx)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("bundle", type=Path, help="Fixture containing the two known plaintext records")
path = parser.parse_args().bundle
data = path.read_bytes()
header, offset = data[:40], 40
assert header[:8] == b'GR8SBK01'
# RFC 5869, SHA-256, one expand block. This is a public test key.
prk = hmac.new(header[8:], bytes([42]) * 32, hashlib.sha256).digest()
key = hmac.new(prk, b'gr8s backup chunk key v1\x01', hashlib.sha256).digest()
records, sequence = [], 0
while True:
    prefix = data[offset:offset+5]
    assert len(prefix) == 5
    size, kind = int.from_bytes(prefix[:4], 'big'), prefix[4]
    offset += 5
    assert 1 <= size <= 65536 and kind in (0, 1)
    ciphertext, tag = data[offset:offset+size], data[offset+size:offset+size+16]
    offset += size + 16
    counter = sequence.to_bytes(8, 'big')
    plaintext = decrypt(key, bytes(4) + counter, header + counter + prefix, ciphertext, tag)
    sequence += 1
    if kind == 1:
        assert plaintext == b'\0' and offset == len(data)
        break
    records.append(plaintext)
assert records == [b'independent backup crypto check', bytes([99]) * 65536]
print(json.dumps({'passed': True, 'independent': 'system OpenSSL AES-256-GCM plus Python stdlib RFC5869 HKDF', 'opensslVersion': fn('OpenSSL_version', C.c_char_p, C.c_int)(0).decode(), 'dataRecords': len(records), 'plaintextBytes': sum(map(len, records)), 'authenticatedFinalMarker': True, 'bundleSha256': hashlib.sha256(data).hexdigest()}))
