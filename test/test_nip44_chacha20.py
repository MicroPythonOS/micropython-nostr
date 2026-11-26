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

    def test_viper_core_is_selected_on_a_device(self):
        # The self-test falls back to the pure-Python core without a word, so
        # a broken Viper core would only show up as NIP-44 being slow. On an
        # ESP32 the Viper core has to pass, which makes an on-device run fail
        # when it doesn't.
        import sys

        from nostr import nip44

        if sys.platform != "esp32":
            return
        self.assertTrue(nip44.FAST_CHACHA20)
        self.assertTrue(nip44._chacha20 is nip44._chacha20_viper)

    def test_is_its_own_inverse(self):
        from nostr.nip44 import _chacha20

        key = bytes(32)
        nonce = bytes(12)
        data = b"pocket money" * 50
        self.assertEqual(_chacha20(key, nonce, _chacha20(key, nonce, data)), data)


def _reference_block(state, out, rounds, counter):
    # What _chacha20_block_viper does, with the pure-Python block function.
    from nostr.nip44 import _chacha20_block

    out[:] = _chacha20_block(bytes(state[16:48]), bytes(state[52:64]), counter.to_bytes(4, "little"))


def _reference_xor(dst, src, keystream, pos, n):
    for i in range(n):
        dst[pos + i] = src[pos + i] ^ keystream[i]


class TestNip44ChaCha20SelfTest(unittest.TestCase):
    """The import-time check that decides whether the Viper core is used.

    Plain-Python stand-ins take the place of the two Viper functions, so the
    check itself is tested on builds without a native emitter too.
    """

    def setUp(self):
        from nostr import nip44

        self.nip44 = nip44
        # CPython and big-endian ports have no Viper core and no check.
        self.has_check = hasattr(nip44, "_viper_chacha20_works")
        if self.has_check:
            self.saved = nip44._chacha20_block_viper, nip44._xor_viper

    def tearDown(self):
        if self.has_check:
            self.nip44._chacha20_block_viper, self.nip44._xor_viper = self.saved

    def _check_with(self, block, xor):
        self.nip44._chacha20_block_viper, self.nip44._xor_viper = block, xor
        return self.nip44._viper_chacha20_works()

    def test_a_correct_core_passes(self):
        if not self.has_check:
            return
        self.assertTrue(self._check_with(_reference_block, _reference_xor))

    def test_an_xor_step_that_ignores_the_input_fails(self):
        if not self.has_check:
            return

        def keystream_only(dst, src, keystream, pos, n):
            for i in range(n):
                dst[pos + i] = keystream[i]

        self.assertFalse(self._check_with(_reference_block, keystream_only))

    def test_a_block_function_that_ignores_the_counter_fails(self):
        if not self.has_check:
            return

        def first_block_only(state, out, rounds, counter):
            _reference_block(state, out, rounds, 0)

        self.assertFalse(self._check_with(first_block_only, _reference_xor))

    def test_a_core_that_raises_fails(self):
        if not self.has_check:
            return

        def no_uint(state, out, rounds, counter):
            raise NameError("name 'uint' isn't defined")

        self.assertFalse(self._check_with(no_uint, _reference_xor))


if __name__ == "__main__":
    unittest.main()
