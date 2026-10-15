"""NIP-17 / NIP-59 behaviour of nostr.nip17.

These tests are plain unittest.TestCase classes so they run both under
pytest on CPython (`pytest test/test_nip17.py`) and under MicroPython's
unittest (e.g. through MicroPythonOS' scripts/test_runner.py).
"""

import json
import time
import unittest

from nostr.event import Event
from nostr.key import PrivateKey
from nostr.nip17 import (
    KIND_NIP17_CHAT,
    TWO_DAYS,
    decrypt_gift_wrap_to_rumor,
    make_gift_wrap,
    make_nip17_messages,
    make_rumor,
    make_seal,
)
from nostr.nip44 import decrypt as nip44_decrypt
from nostr.nip44 import get_conversation_key

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


class TestTimestampTweaking(unittest.TestCase):
    """NIP-17: 'Clients SHOULD randomize `created_at` in up to two days in
    the past in both the seal and the gift wrap'. NIP-59: 'The canonical
    `created_at` time belongs to the `rumor`.'"""

    def setUp(self):
        self.sender = PrivateKey(_SENDER_SECRET)
        self.receivers = [PrivateKey() for _ in range(8)]
        self.receiver_hex = [r.public_key.hex() for r in self.receivers]
        self.now = 1700000000

    def _seal_of(self, gift, receiver):
        conv_key = get_conversation_key(receiver, gift["pubkey"])
        return json.loads(nip44_decrypt(gift["content"], conv_key))

    def test_rumor_keeps_canonical_timestamp(self):
        gifts = make_nip17_messages(
            self.sender, "when", self.receiver_hex[:1], created_at=self.now
        )
        rumor = decrypt_gift_wrap_to_rumor(gifts[0], self.receivers[0])
        self.assertEqual(rumor["created_at"], self.now)

    def test_seal_and_wrap_are_backdated_up_to_two_days(self):
        gifts = make_nip17_messages(
            self.sender, "when", self.receiver_hex, created_at=self.now
        )
        for gift, receiver in zip(gifts, self.receivers):
            seal = self._seal_of(gift, receiver)
            for ts in (gift["created_at"], seal["created_at"]):
                self.assertTrue(ts <= self.now, "timestamp in the future: %s" % ts)
                self.assertTrue(ts >= self.now - TWO_DAYS, "backdated too far: %s" % ts)

    def test_seal_and_wrap_timestamps_are_independent(self):
        gifts = make_nip17_messages(
            self.sender, "when", self.receiver_hex, created_at=self.now
        )
        wrap_ts = [g["created_at"] for g in gifts]
        seal_ts = [self._seal_of(g, r)["created_at"] for g, r in zip(gifts, self.receivers)]
        # With 8 independent draws from a 2-day window these can't all
        # collapse onto the rumor time or onto each other.
        self.assertTrue(any(ts != self.now for ts in wrap_ts))
        self.assertTrue(any(ts != self.now for ts in seal_ts))
        self.assertTrue(any(w != s for w, s in zip(wrap_ts, seal_ts)))
        self.assertTrue(len(set(wrap_ts)) > 1)

    def test_make_seal_defaults_to_backdated_timestamp(self):
        rumor = make_rumor(self.sender, "x", self.receiver_hex[:1], created_at=self.now)
        before = int(time.time())
        seals = [make_seal(self.sender, dict(rumor), self.receiver_hex[0]) for _ in range(8)]
        after = int(time.time())
        for seal in seals:
            self.assertTrue(seal["created_at"] <= after)
            self.assertTrue(seal["created_at"] >= before - TWO_DAYS)
        self.assertTrue(len(set(s["created_at"] for s in seals)) > 1)

    def test_make_gift_wrap_defaults_to_backdated_timestamp(self):
        rumor = make_rumor(self.sender, "x", self.receiver_hex[:1], created_at=self.now)
        seal = make_seal(self.sender, dict(rumor), self.receiver_hex[0], created_at=self.now)
        before = int(time.time())
        gifts = [make_gift_wrap(self.receiver_hex[0], seal) for _ in range(8)]
        after = int(time.time())
        for gift in gifts:
            self.assertTrue(gift["created_at"] <= after)
            self.assertTrue(gift["created_at"] >= before - TWO_DAYS)
        self.assertTrue(len(set(g["created_at"] for g in gifts)) > 1)

    def test_seal_does_not_backdate_a_rumor_without_timestamp(self):
        rumor = {
            "kind": KIND_NIP17_CHAT,
            "content": "no ts",
            "tags": [["p", self.receiver_hex[0]]],
            "pubkey": self.sender.public_key.hex(),
        }
        before = int(time.time())
        seal = make_seal(self.sender, rumor, self.receiver_hex[0])
        gift = make_gift_wrap(self.receiver_hex[0], seal, created_at=self.now)
        decrypted = decrypt_gift_wrap_to_rumor(gift, self.receivers[0])
        self.assertTrue(decrypted["created_at"] >= before)


def _recipient_of(gift):
    for tag in gift["tags"]:
        if tag and tag[0] == "p":
            return tag[1]
    return None


class TestSenderWrap(unittest.TestCase):
    """NIP-17: messages 'must be sealed (`kind:13`) and then gift-wrapped
    (`kind:1059`) to each receiver and the sender individually.'"""

    def setUp(self):
        self.sender = PrivateKey(_SENDER_SECRET)
        self.own_hex = self.sender.public_key.hex()
        self.receivers = [PrivateKey() for _ in range(3)]
        self.receiver_hex = [r.public_key.hex() for r in self.receivers]

    def test_messages_include_a_wrap_addressed_to_the_sender(self):
        gifts = make_nip17_messages(self.sender, "hi", self.receiver_hex, created_at=1700000000)
        self.assertEqual(len(gifts), len(self.receiver_hex) + 1)
        # Recipients first, in order; the sender's copy last.
        self.assertEqual([_recipient_of(g) for g in gifts], self.receiver_hex + [self.own_hex])

    def test_sender_wrap_decrypts_for_sender_without_a_self_p_tag(self):
        gifts = make_nip17_messages(
            self.sender, "room talk", self.receiver_hex, subject="room", created_at=1700000000
        )
        rumor = decrypt_gift_wrap_to_rumor(gifts[-1], self.sender)
        self.assertEqual(rumor["content"], "room talk")
        self.assertEqual(rumor["pubkey"], self.own_hex)
        p_tags = [t[1] for t in rumor["tags"] if t[0] == "p"]
        self.assertEqual(p_tags, self.receiver_hex)
        self.assertEqual([t[1] for t in rumor["tags"] if t[0] == "subject"], ["room"])

    def test_all_wraps_carry_the_same_rumor(self):
        gifts = make_nip17_messages(self.sender, "same", self.receiver_hex, created_at=1700000000)
        ids = set()
        for gift, key in zip(gifts, self.receivers + [self.sender]):
            ids.add(decrypt_gift_wrap_to_rumor(gift, key)["id"])
        self.assertEqual(len(ids), 1)

    def test_no_extra_wrap_when_sender_is_already_a_recipient(self):
        gifts = make_nip17_messages(
            self.sender, "note to self", [self.own_hex, self.receiver_hex[0]], created_at=1700000000
        )
        self.assertEqual([_recipient_of(g) for g in gifts], [self.own_hex, self.receiver_hex[0]])
        rumor = decrypt_gift_wrap_to_rumor(gifts[0], self.sender)
        self.assertEqual(
            [t[1] for t in rumor["tags"] if t[0] == "p"], [self.own_hex, self.receiver_hex[0]]
        )

    def test_include_sender_can_be_disabled(self):
        gifts = make_nip17_messages(
            self.sender, "hi", self.receiver_hex, created_at=1700000000, include_sender=False
        )
        self.assertEqual([_recipient_of(g) for g in gifts], self.receiver_hex)


if __name__ == "__main__":
    unittest.main()
