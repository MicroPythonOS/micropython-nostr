"""ChaCha20 core of nostr.nip44.

Plain unittest.TestCase classes, run under MicroPython's unittest (e.g. through
MicroPythonOS' scripts/test_runner.py), where the Viper core is chosen when it
passes its import-time self-test. They also run on CPython, where only the
pure-Python core exists.
"""

import unittest


class TestNip44ChaCha20(unittest.TestCase):
    """The ChaCha20 core NIP-44 uses (Viper-accelerated on MicroPython)."""

    def test_rfc8439_encryption_vector(self):
        # RFC 8439 section 2.4.2. The RFC starts at block counter 1, so prefix
        # one block of zeros and drop its output.
        from nostr.nip44 import _chacha20

        key = bytes(range(32))
        nonce = bytes([0, 0, 0, 0, 0, 0, 0, 0x4A, 0, 0, 0, 0])
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you "
            b"only one tip for the future, sunscreen would be it."
        )
        expected = bytes.fromhex(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
            "5af90bbf74a35be6b40b8eedf2785e42874d"
        )
        ciphertext = _chacha20(key, nonce, bytes(64) + plaintext)[64:]
        self.assertEqual(ciphertext, expected)

    def test_matches_reference_at_block_boundaries(self):
        from nostr.nip44 import _chacha20, _chacha20_py

        key = bytes((7 * i + 3) & 0xFF for i in range(32))
        nonce = bytes((11 * i + 5) & 0xFF for i in range(12))
        for length in (0, 1, 63, 64, 65, 127, 128, 129, 1000):
            data = bytes((i * 31 + length) & 0xFF for i in range(length))
            self.assertEqual(_chacha20(key, nonce, data), _chacha20_py(key, nonce, data), length)

    def test_viper_core_is_used_only_when_it_passes_its_self_test(self):
        from nostr import nip44

        if not hasattr(nip44, "_viper_chacha20_works"):
            return  # CPython or a big-endian port: pure Python only
        if nip44._viper_chacha20_works():
            self.assertTrue(nip44._chacha20 is nip44._chacha20_viper)
        else:
            # e.g. the desktop builds, where Viper runs as plain bytecode
            self.assertTrue(nip44._chacha20 is nip44._chacha20_py)

    def test_is_its_own_inverse(self):
        from nostr.nip44 import _chacha20

        key = bytes(32)
        nonce = bytes(12)
        data = b"pocket money" * 50
        self.assertEqual(_chacha20(key, nonce, _chacha20(key, nonce, data)), data)


if __name__ == "__main__":
    unittest.main()
