"""NIP-17 / NIP-59 behaviour of nostr.nip17.

These tests are plain unittest.TestCase classes so they run both under
pytest on CPython (`pytest test/test_nip17.py`) and under MicroPython's
unittest (e.g. through MicroPythonOS' scripts/test_runner.py).
"""

import json
import unittest

import nostr.nip17 as nip17
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
    tweaked_timestamp,
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
        rumor = decrypt_gift_wrap_to_rumor(gifts[-1], receiver)
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
        # A rumor time well in the past: wraps must still be dated from now.
        self.rumor_time = int(Event.epoch_seconds()) - 5 * TWO_DAYS

    def _seal_of(self, gift, receiver):
        conv_key = get_conversation_key(receiver, gift["pubkey"])
        return json.loads(nip44_decrypt(gift["content"], conv_key))

    def _assert_backdated_from_now(self, ts, before, after):
        self.assertTrue(ts <= after, "timestamp in the future: %s" % ts)
        self.assertTrue(ts >= before - TWO_DAYS, "backdated too far: %s" % ts)

    def test_rumor_keeps_canonical_timestamp(self):
        gifts = make_nip17_messages(
            self.sender, "when", self.receiver_hex[:1], created_at=self.rumor_time
        )
        rumor = decrypt_gift_wrap_to_rumor(gifts[-1], self.receivers[0])
        self.assertEqual(rumor["created_at"], self.rumor_time)

    def test_seal_and_wrap_are_backdated_up_to_two_days_from_now(self):
        before = int(Event.epoch_seconds())
        gifts = make_nip17_messages(
            self.sender, "when", self.receiver_hex, created_at=self.rumor_time,
            include_sender=False,
        )
        after = int(Event.epoch_seconds())
        for gift, receiver in zip(gifts, self.receivers):
            seal = self._seal_of(gift, receiver)
            # Relative to now, not to the (older) rumor time, so a queued
            # message replayed later is not dated out of relay/subscription windows.
            self._assert_backdated_from_now(gift["created_at"], before, after)
            self._assert_backdated_from_now(seal["created_at"], before, after)

    def test_seal_and_wrap_timestamps_are_independent(self):
        gifts = make_nip17_messages(
            self.sender, "when", self.receiver_hex, created_at=self.rumor_time,
            include_sender=False,
        )
        wrap_ts = [g["created_at"] for g in gifts]
        seal_ts = [self._seal_of(g, r)["created_at"] for g, r in zip(gifts, self.receivers)]
        # With 8 independent draws from a 2-day window these can't all
        # collapse onto each other.
        self.assertTrue(any(w != s for w, s in zip(wrap_ts, seal_ts)))
        self.assertTrue(len(set(wrap_ts)) > 1)
        self.assertTrue(len(set(seal_ts)) > 1)

    def test_make_seal_defaults_to_backdated_timestamp(self):
        rumor = make_rumor(self.sender, "x", self.receiver_hex[:1], created_at=self.rumor_time)
        before = int(Event.epoch_seconds())
        seals = [make_seal(self.sender, dict(rumor), self.receiver_hex[0]) for _ in range(8)]
        after = int(Event.epoch_seconds())
        for seal in seals:
            self._assert_backdated_from_now(seal["created_at"], before, after)
        self.assertTrue(len(set(s["created_at"] for s in seals)) > 1)

    def test_make_gift_wrap_defaults_to_backdated_timestamp(self):
        rumor = make_rumor(self.sender, "x", self.receiver_hex[:1], created_at=self.rumor_time)
        seal = make_seal(self.sender, dict(rumor), self.receiver_hex[0], created_at=self.rumor_time)
        before = int(Event.epoch_seconds())
        gifts = [make_gift_wrap(self.receiver_hex[0], seal) for _ in range(8)]
        after = int(Event.epoch_seconds())
        for gift in gifts:
            self._assert_backdated_from_now(gift["created_at"], before, after)
        self.assertTrue(len(set(g["created_at"] for g in gifts)) > 1)

    def test_seal_does_not_backdate_a_rumor_without_timestamp(self):
        rumor = {
            "kind": KIND_NIP17_CHAT,
            "content": "no ts",
            "tags": [["p", self.receiver_hex[0]]],
            "pubkey": self.sender.public_key.hex(),
        }
        before = int(Event.epoch_seconds())
        seal = make_seal(self.sender, rumor, self.receiver_hex[0])
        gift = make_gift_wrap(self.receiver_hex[0], seal, created_at=self.rumor_time)
        decrypted = decrypt_gift_wrap_to_rumor(gift, self.receivers[0])
        self.assertTrue(decrypted["created_at"] >= before)


class TestNostrClock(unittest.TestCase):
    """Every default timestamp must come from Event.epoch_seconds(), the Unix
    clock Nostr needs. On the ESP32 port time.time() counts from 2000-01-01,
    which is why Event.epoch_seconds() exists; a default read from time.time()
    would date seals and gift wraps around 1996 and no relay subscription
    would ever deliver them. Simulated by pinning the Nostr clock."""

    PINNED = 1700000000

    def setUp(self):
        self.sender = PrivateKey(_SENDER_SECRET)
        self.recipient = PrivateKey().public_key.hex()
        self._orig_epoch_seconds = Event.epoch_seconds
        Event.epoch_seconds = staticmethod(lambda: self.PINNED)

    def tearDown(self):
        Event.epoch_seconds = self._orig_epoch_seconds

    def _assert_on_pinned_clock(self, ts):
        self.assertTrue(
            self.PINNED - TWO_DAYS <= ts <= self.PINNED,
            "%s is not within two days before the Nostr clock %s" % (ts, self.PINNED),
        )

    def test_tweaked_timestamp_counts_from_the_nostr_clock(self):
        for _ in range(8):
            self._assert_on_pinned_clock(tweaked_timestamp())

    def test_rumor_default_timestamp_is_the_nostr_clock(self):
        rumor = make_rumor(self.sender, "x", [self.recipient])
        self.assertEqual(rumor["created_at"], self.PINNED)

    def test_seal_and_wrap_defaults_are_on_the_nostr_clock(self):
        rumor = make_rumor(self.sender, "x", [self.recipient], created_at=self.PINNED)
        seal = make_seal(self.sender, dict(rumor), self.recipient)
        gift = make_gift_wrap(self.recipient, seal)
        self._assert_on_pinned_clock(seal["created_at"])
        self._assert_on_pinned_clock(gift["created_at"])

    def test_make_nip17_messages_defaults_are_on_the_nostr_clock(self):
        receiver = PrivateKey()
        gifts = make_nip17_messages(self.sender, "x", [receiver.public_key.hex()])
        for gift in gifts:
            self._assert_on_pinned_clock(gift["created_at"])
        rumor = decrypt_gift_wrap_to_rumor(gifts[-1], receiver)
        self.assertEqual(rumor["created_at"], self.PINNED)

    def test_nip17_module_does_not_read_the_raw_clock(self):
        # Regression guard for the ESP32 epoch: the module must not import time.
        self.assertFalse(hasattr(nip17, "time"))


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

    def test_messages_start_with_a_wrap_addressed_to_the_sender(self):
        gifts = make_nip17_messages(self.sender, "hi", self.receiver_hex, created_at=1700000000)
        self.assertEqual(len(gifts), len(self.receiver_hex) + 1)
        # The sender's copy first (callers key their local copy on gifts[0]),
        # then the recipients in order.
        self.assertEqual([_recipient_of(g) for g in gifts], [self.own_hex] + self.receiver_hex)

    def test_sender_wrap_decrypts_for_sender_without_a_self_p_tag(self):
        gifts = make_nip17_messages(
            self.sender, "room talk", self.receiver_hex, subject="room", created_at=1700000000
        )
        rumor = decrypt_gift_wrap_to_rumor(gifts[0], self.sender)
        self.assertEqual(rumor["content"], "room talk")
        self.assertEqual(rumor["pubkey"], self.own_hex)
        p_tags = [t[1] for t in rumor["tags"] if t[0] == "p"]
        self.assertEqual(p_tags, self.receiver_hex)
        self.assertEqual([t[1] for t in rumor["tags"] if t[0] == "subject"], ["room"])

    def test_all_wraps_carry_the_same_rumor(self):
        gifts = make_nip17_messages(self.sender, "same", self.receiver_hex, created_at=1700000000)
        ids = set()
        for gift, key in zip(gifts, [self.sender] + self.receivers):
            ids.add(decrypt_gift_wrap_to_rumor(gift, key)["id"])
        self.assertEqual(len(ids), 1)

    def test_no_extra_wrap_when_sender_is_already_a_recipient(self):
        gifts = make_nip17_messages(
            self.sender, "note to self", [self.receiver_hex[0], self.own_hex], created_at=1700000000
        )
        self.assertEqual([_recipient_of(g) for g in gifts], [self.receiver_hex[0], self.own_hex])
        rumor = decrypt_gift_wrap_to_rumor(gifts[1], self.sender)
        self.assertEqual(
            [t[1] for t in rumor["tags"] if t[0] == "p"], [self.receiver_hex[0], self.own_hex]
        )

    def test_include_sender_can_be_disabled(self):
        gifts = make_nip17_messages(
            self.sender, "hi", self.receiver_hex, created_at=1700000000, include_sender=False
        )
        self.assertEqual([_recipient_of(g) for g in gifts], self.receiver_hex)


if __name__ == "__main__":
    unittest.main()
