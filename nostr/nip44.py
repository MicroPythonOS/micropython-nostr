import base64
import hashlib
import logging

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


def _chacha20(key, nonce, data):
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
