"""NIP-17 / NIP-59 behaviour of nostr.nip17.

These tests are plain unittest.TestCase classes so they run both under
pytest on CPython (`pytest test/test_nip17.py`) and under MicroPython's
unittest (e.g. through MicroPythonOS' scripts/test_runner.py).
"""

import unittest

from nostr.event import Event
from nostr.key import PrivateKey
from nostr.nip17 import (
    KIND_NIP17_CHAT,
    decrypt_gift_wrap_to_rumor,
    make_nip17_messages,
    make_rumor,
)

_SENDER_SECRET = bytes.fromhex(
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
)


class TestRumorId(unittest.TestCase):
    """NIP-17: 'Fields `id` and `created_at` are required.'"""

    def setUp(self):
        self.sender = PrivateKey(_SENDER_SECRET)
        self.recipients = [PrivateKey().public_key.hex() for _ in range(2)]

    def test_make_rumor_sets_nip01_id(self):
        rumor = make_rumor(
            self.sender, "hello", self.recipients, subject="room", created_at=1700000000
        )
        expected = Event.compute_id(
            rumor["pubkey"], rumor["created_at"], rumor["kind"], rumor["tags"], rumor["content"]
        )
        self.assertEqual(rumor.get("id"), expected)
        self.assertEqual(len(rumor["id"]), 64)
        self.assertEqual(rumor["kind"], KIND_NIP17_CHAT)

    def test_rumor_id_depends_on_content(self):
        a = make_rumor(self.sender, "one", self.recipients, created_at=1700000000)
        b = make_rumor(self.sender, "two", self.recipients, created_at=1700000000)
        self.assertTrue(a["id"] != b["id"])

    def test_decrypted_rumor_keeps_id(self):
        receiver = PrivateKey()
        gifts = make_nip17_messages(
            self.sender, "hi there", [receiver.public_key.hex()], created_at=1700000000
        )
        rumor = decrypt_gift_wrap_to_rumor(gifts[0], receiver)
        self.assertEqual(
            rumor.get("id"),
            Event.compute_id(
                rumor["pubkey"], rumor["created_at"], rumor["kind"], rumor["tags"], rumor["content"]
            ),
        )


if __name__ == "__main__":
    unittest.main()
