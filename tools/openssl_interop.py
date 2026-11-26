"""Independent AES-GCM / ChaCha20-Poly1305 and STREAM decoder using OpenSSL.
Test data only. No third-party Python dependencies; requires libcrypto.
"""
import ctypes as c
import ctypes.util
import hashlib
import hmac
import sys

lib = c.CDLL(ctypes.util.find_library('crypto'))
lib.EVP_CIPHER_CTX_new.restype = c.c_void_p
lib.EVP_CIPHER_CTX_free.argtypes = [c.c_void_p]
for name in ('EVP_aes_256_gcm', 'EVP_chacha20_poly1305'):
    getattr(lib, name).restype = c.c_void_p
lib.EVP_DecryptInit_ex.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p]
lib.EVP_DecryptUpdate.argtypes = [c.c_void_p, c.c_void_p, c.POINTER(c.c_int), c.c_void_p, c.c_int]
lib.EVP_DecryptFinal_ex.argtypes = [c.c_void_p, c.c_void_p, c.POINTER(c.c_int)]
lib.EVP_CIPHER_CTX_ctrl.argtypes = [c.c_void_p, c.c_int, c.c_int, c.c_void_p]

def decrypt(algorithm, key, nonce, ciphertext, aad):
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError('OpenSSL allocation failed')
    try:
        cipher = lib.EVP_aes_256_gcm() if algorithm == 0 else lib.EVP_chacha20_poly1305()
        assert lib.EVP_DecryptInit_ex(ctx, cipher, None, None, None) == 1
        assert lib.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(nonce), None) == 1
        assert lib.EVP_DecryptInit_ex(ctx, None, None, key, nonce) == 1
        n = c.c_int()
        assert lib.EVP_DecryptUpdate(ctx, None, c.byref(n), aad, len(aad)) == 1
        body, tag = ciphertext[:-16], ciphertext[-16:]
        out = c.create_string_buffer(len(body) + 16)
        assert lib.EVP_DecryptUpdate(ctx, out, c.byref(n), body, len(body)) == 1
        count = n.value
        assert lib.EVP_CIPHER_CTX_ctrl(ctx, 0x11, 16, tag) == 1
        assert lib.EVP_DecryptFinal_ex(ctx, c.byref(out, count), c.byref(n)) == 1
        return out.raw[:count + n.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)

def stream(key, wire):
    assert wire[0] == 2 and wire[1] in (0, 1)
    algorithm = wire[1]
    chunk = int.from_bytes(wire[2:6], 'big')
    length = int.from_bytes(wire[6:10], 'big')
    salt, prefix, header = wire[10:42], wire[42:49], wire[:49]
    info = b'Quantum-Crypto/STREAM-BE32/v2/' + bytes([algorithm])
    prk = hmac.digest(salt, key, 'sha256')
    derived = hmac.digest(prk, info + b'\x01', 'sha256')
    count = max(1, (length + chunk - 1) // chunk)
    pos, blocks = len(header), []
    for index in range(count):
        last = index == count - 1
        size = (length - index * chunk if last else chunk) + 16
        nonce = prefix + index.to_bytes(4, 'big') + bytes([last])
        blocks.append(decrypt(algorithm, derived, nonce, wire[pos:pos + size], header))
        pos += size
    assert pos == len(wire)
    return b''.join(blocks)

if __name__ == '__main__':
    mode, algo, key, wire, aad, expected = sys.argv[1:]
    key, wire, aad, expected = map(bytes.fromhex, (key, wire, aad, expected))
    actual = stream(key, wire) if mode == 'stream' else decrypt(int(algo), key, wire[:12], wire[12:], aad)
    assert actual == expected, 'Independent implementation disagrees'
