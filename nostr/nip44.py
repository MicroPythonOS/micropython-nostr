import base64
import hashlib
import logging
import sys

import secrets

logger = logging.getLogger(__name__)


def _hmac_sha256(key, data):
    """RFC 2104 HMAC-SHA256 for byte strings."""
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    pad_key = key + b"\x00" * (block_size - len(key))
    ipad = bytes(b ^ 0x36 for b in pad_key)
    opad = bytes(b ^ 0x5c for b in pad_key)
    inner = hashlib.sha256(ipad + data).digest()
    return hashlib.sha256(opad + inner).digest()


def _hkdf_extract(ikm, salt):
    if salt is None:
        salt = b"\x00" * 32
    return _hmac_sha256(salt, ikm)


def _hkdf_expand(prk, info, length):
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = _hmac_sha256(prk, t + info + bytes([counter]))
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def _u32(x):
    return x & 0xFFFFFFFF


def _rol32(x, n):
    x &= 0xFFFFFFFF
    n &= 31
    return _u32((x << n) | (x >> (32 - n)))


def _quarter_round(a, b, c, d):
    a = _u32(a + b)
    d = _u32(_rol32(d ^ a, 16))
    c = _u32(c + d)
    b = _u32(_rol32(b ^ c, 12))
    a = _u32(a + b)
    d = _u32(_rol32(d ^ a, 8))
    c = _u32(c + d)
    b = _u32(_rol32(b ^ c, 7))
    return a, b, c, d


def _int_le(data):
    return (
        data[0]
        | (data[1] << 8)
        | (data[2] << 16)
        | (data[3] << 24)
    )


def _bytes_le(value):
    return bytes([
        value & 0xFF,
        (value >> 8) & 0xFF,
        (value >> 16) & 0xFF,
        (value >> 24) & 0xFF,
    ])


def _chacha20_block(key, nonce, counter):
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    key_words = [_int_le(key[i : i + 4]) for i in range(0, 32, 4)]
    counter_word = _int_le(counter)
    nonce_words = [_int_le(nonce[i : i + 4]) for i in range(0, 12, 4)]

    state = (
        constants
        + key_words
        + [counter_word]
        + nonce_words
    )
    working = list(state)

    for _ in range(10):
        working[0], working[4], working[8], working[12] = _quarter_round(
            working[0], working[4], working[8], working[12]
        )
        working[1], working[5], working[9], working[13] = _quarter_round(
            working[1], working[5], working[9], working[13]
        )
        working[2], working[6], working[10], working[14] = _quarter_round(
            working[2], working[6], working[10], working[14]
        )
        working[3], working[7], working[11], working[15] = _quarter_round(
            working[3], working[7], working[11], working[15]
        )
        working[0], working[5], working[10], working[15] = _quarter_round(
            working[0], working[5], working[10], working[15]
        )
        working[1], working[6], working[11], working[12] = _quarter_round(
            working[1], working[6], working[11], working[12]
        )
        working[2], working[7], working[8], working[13] = _quarter_round(
            working[2], working[7], working[8], working[13]
        )
        working[3], working[4], working[9], working[14] = _quarter_round(
            working[3], working[4], working[9], working[14]
        )

    out = bytearray(64)
    for i in range(16):
        value = _u32(state[i] + working[i])
        out[i * 4 : i * 4 + 4] = _bytes_le(value)
    return out


def _chacha20_py(key, nonce, data):
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")

    out = bytearray()
    counter = 0
    for i in range(0, len(data), 64):
        counter_bytes = _bytes_le(counter)
        block = _chacha20_block(key, nonce, counter_bytes)
        chunk = data[i : i + 64]
        out.extend(b ^ block[j] for j, b in enumerate(chunk))
        counter += 1
    return bytes(out)


# On little-endian MicroPython ports use a Viper ChaCha20 core: it works on
# machine words, so no 32-bit value ever becomes a heap-allocated big int.
# Measured on an ESP32-S3, an 11 KB payload takes about 32 ms this way against
# 3.6 s for the earlier @micropython.native version. CPython, big-endian
# ports and builds where the Viper core fails its self-test below use the
# pure-Python implementation above.
if sys.implementation.name == "micropython" and sys.byteorder == "little":
    # Indices of the 8 quarter rounds of one double round: 4 column rounds,
    # then 4 diagonal rounds (RFC 8439 section 2.3).
    _QUARTER_ROUNDS = bytes([
        0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
        0, 5, 10, 15, 1, 6, 11, 12, 2, 7, 8, 13, 3, 4, 9, 14,
    ])

    @micropython.viper
    def _chacha20_block_viper(state: ptr32, out: ptr32, rounds: ptr8, counter: int):
        # One 64-byte keystream block into `out`. `state` holds the constants,
        # key and nonce as little-endian words; word 12 takes the counter.
        state[12] = counter
        i = 0
        while i < 16:
            out[i] = state[i]
            i += 1
        r = 0
        while r < 80:
            j = (r & 7) << 2
            ia = rounds[j]
            ib = rounds[j + 1]
            ic = rounds[j + 2]
            i_d = rounds[j + 3]
            a = uint(out[ia])
            b = uint(out[ib])
            c = uint(out[ic])
            d = uint(out[i_d])
            a += b
            d ^= a
            d = (d << 16) | (d >> 16)
            c += d
            b ^= c
            b = (b << 12) | (b >> 20)
            a += b
            d ^= a
            d = (d << 8) | (d >> 24)
            c += d
            b ^= c
            b = (b << 7) | (b >> 25)
            out[ia] = a
            out[ib] = b
            out[ic] = c
            out[i_d] = d
            r += 1
        i = 0
        while i < 16:
            out[i] = uint(out[i]) + uint(state[i])
            i += 1

    @micropython.viper
    def _xor_viper(dst: ptr8, src: ptr8, keystream: ptr8, pos: int, n: int):
        i = 0
        while i < n:
            dst[pos + i] = src[pos + i] ^ keystream[i]
            i += 1

    def _chacha20_native(out, src, key, nonce):
        state = bytearray(64)
        state[0:16] = b"expand 32-byte k"
        state[16:48] = key
        state[52:64] = nonce
        keystream = bytearray(64)
        length = len(src)
        pos = 0
        counter = 0
        while pos < length:
            _chacha20_block_viper(state, keystream, _QUARTER_ROUNDS, counter)
            n = length - pos
            if n > 64:
                n = 64
            _xor_viper(out, src, keystream, pos, n)
            pos += n
            counter += 1

    def _chacha20_viper(key, nonce, data):
        if len(key) != 32:
            raise ValueError("ChaCha20 key must be 32 bytes")
        if len(nonce) != 12:
            raise ValueError("ChaCha20 nonce must be 12 bytes")
        out = bytearray(len(data))
        _chacha20_native(out, data, key, nonce)
        return bytes(out)

    def _viper_chacha20_works():
        # Builds without a native emitter (the unix, macOS and web builds of
        # MicroPythonOS) run Viper functions as plain bytecode, where `uint`
        # is undefined, and a 64-bit emitter does not wrap the additions at
        # 32 bits. Check one known answer (three blocks, the last one partial)
        # and use the pure-Python core when it does not match. The input is
        # not all zeros, so an XOR step that ignores it fails the check too.
        try:
            out = _chacha20_viper(bytes(range(32)), bytes(range(12)), bytes(range(130)))
            return hashlib.sha256(out).digest() == _CHACHA20_CHECK
        except Exception:
            return False

    _CHACHA20_CHECK = bytes.fromhex(
        "606f72c1a0aba53e460d2d3e249efe6135979a48710b8ed8e29bc656611d25a4"
    )
    _chacha20 = _chacha20_viper if _viper_chacha20_works() else _chacha20_py
    FAST_CHACHA20 = _chacha20 is _chacha20_viper

else:
    _chacha20 = _chacha20_py
    FAST_CHACHA20 = sys.implementation.name != "micropython"

# FAST_CHACHA20 tells callers whether large payloads are cheap to encrypt and
# decrypt here. It is False on MicroPython builds that run the pure-Python
# core, where an 11 KB payload takes seconds on a microcontroller.


def _calc_padded_len(unpadded_len):
    if unpadded_len < 1 or unpadded_len > 65535:
        raise ValueError("invalid plaintext length")
    if unpadded_len <= 32:
        return 32
    n = unpadded_len - 1
    n |= n >> 1
    n |= n >> 2
    n |= n >> 4
    n |= n >> 8
    n |= n >> 16
    next_power = n + 1
    if next_power <= 256:
        chunk = 32
    else:
        chunk = next_power // 8
    return chunk * ((unpadded_len - 1) // chunk + 1)


def _pad(plaintext):
    unpadded = plaintext.encode("utf-8")
    unpadded_len = len(unpadded)
    prefix = unpadded_len.to_bytes(2, "big")
    suffix = b"\x00" * (_calc_padded_len(unpadded_len) - unpadded_len)
    return prefix + unpadded + suffix


def _unpad(padded):
    if len(padded) < 2:
        raise ValueError("invalid padding")
    unpadded_len = int.from_bytes(padded[:2], "big")
    if unpadded_len == 0 or unpadded_len > 65535:
        raise ValueError("invalid padding length")
    expected_len = 2 + _calc_padded_len(unpadded_len)
    if len(padded) != expected_len:
        raise ValueError("invalid padding size")
    unpadded = padded[2 : 2 + unpadded_len]
    if len(unpadded) != unpadded_len:
        raise ValueError("invalid padding")
    if padded[2 + unpadded_len:] != b"\x00" * (len(padded) - 2 - unpadded_len):
        raise ValueError("invalid padding bytes")
    return unpadded.decode("utf-8")


def _constant_time_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def get_conversation_key(private_key, public_key_hex):
    """NIP-44 conversation key between two keys.

    `private_key` is a nostr.key.PrivateKey instance.
    `public_key_hex` is the other party's public key as 64 hex characters.
    """
    shared_x = private_key.compute_shared_secret(public_key_hex)
    return _hkdf_extract(shared_x, "nip44-v2".encode("utf-8"))


def get_message_keys(conversation_key, nonce):
    """Derive per-message ChaCha key, nonce, and HMAC key from conversation key
    and message nonce. Returns (chacha_key, chacha_nonce, hmac_key).
    """
    if len(conversation_key) != 32:
        raise ValueError("invalid conversation_key length")
    if len(nonce) != 32:
        raise ValueError("invalid nonce length")
    keys = _hkdf_expand(conversation_key, nonce, 76)
    return keys[:32], keys[32:44], keys[44:76]


def _decode_payload(payload):
    plen = len(payload)
    if plen == 0 or payload[0] == ord("#"):
        raise ValueError("unknown version")
    if plen < 132 or plen > 87472:
        raise ValueError("invalid payload size")
    data = base64.b64decode(payload)
    dlen = len(data)
    if dlen < 99 or dlen > 65603:
        raise ValueError("invalid data size")
    version = data[0]
    if version != 2:
        raise ValueError("unknown version {}".format(version))
    nonce = data[1:33]
    ciphertext = data[33 : dlen - 32]
    mac = data[dlen - 32 : dlen]
    return nonce, ciphertext, mac


def _hmac_aad(key, message, aad):
    if len(aad) != 32:
        raise ValueError("AAD must be 32 bytes")
    return _hmac_sha256(key, aad + message)


def encrypt(plaintext, conversation_key, nonce=None):
    """Encrypt a plaintext string with NIP-44 v2. Returns a base64 payload."""
    if nonce is None:
        nonce = secrets.token_bytes(32)
    if len(conversation_key) != 32:
        raise ValueError("invalid conversation_key length")
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    padded = _pad(plaintext)
    ciphertext = _chacha20(chacha_key, chacha_nonce, padded)
    mac = _hmac_aad(hmac_key, ciphertext, nonce)
    raw = bytes([2]) + nonce + ciphertext + mac
    return base64.b64encode(raw).decode("ascii")


def decrypt(payload, conversation_key):
    """Decrypt a NIP-44 v2 base64 payload. Returns the plaintext string."""
    nonce, ciphertext, mac = _decode_payload(payload)
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    calculated_mac = _hmac_aad(hmac_key, ciphertext, nonce)
    if not _constant_time_compare(calculated_mac, mac):
        raise ValueError("invalid MAC")
    padded = _chacha20(chacha_key, chacha_nonce, ciphertext)
    return _unpad(padded)
