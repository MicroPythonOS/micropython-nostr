"""NIP-17 / NIP-59 behaviour of nostr.nip17.

These tests are plain unittest.TestCase classes, run under MicroPython's
unittest (e.g. through MicroPythonOS' scripts/test_runner.py). nostr.key
imports secp256k1_compat, so they don't run under pytest on CPython yet.
"""

import json
import unittest
from hashlib import sha256

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
from nostr.nip44 import encrypt as nip44_encrypt
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


def _seal_inside(gift, receiver):
    """Return the kind 13 seal inside `gift` as a dict, without checking it."""
    conv_key = get_conversation_key(receiver, gift["pubkey"])
    return json.loads(nip44_decrypt(gift["content"], conv_key))


def _rumor_inside(seal, receiver):
    """Return the rumor inside `seal` as a dict, without checking the seal."""
    conv_key = get_conversation_key(receiver, seal["pubkey"])
    return json.loads(nip44_decrypt(seal["content"], conv_key))


def _seal_content(key, rumor, other_hex):
    """NIP-44 encrypt `rumor` under conv_key(key, other), as a seal's content."""
    conv_key = get_conversation_key(key, other_hex)
    return nip44_encrypt(json.dumps(rumor, separators=(",", ":")), conv_key)


class TestSealAuthor(unittest.TestCase):
    """NIP-17: 'Clients MUST verify if pubkey of the `kind:13` is the same
    pubkey as that of the `unsignedMessageRumor`, otherwise any sender can
    impersonate any other by simply changing the pubkey on the rumor.'"""

    def setUp(self):
        self.sender = PrivateKey(_SENDER_SECRET)
        self.own_hex = self.sender.public_key.hex()
        self.receivers = [PrivateKey() for _ in range(2)]
        self.receiver_hex = [r.public_key.hex() for r in self.receivers]

    def test_seal_signed_by_a_with_rumor_claiming_b_is_rejected(self):
        a, b, receiver = PrivateKey(), PrivateKey(), self.receivers[0]
        rumor = make_rumor(b, "it was b, honest", [self.receiver_hex[0]], created_at=1700000000)
        # A seals and signs it with A's own key: a perfectly valid seal...
        seal = make_seal(a, dict(rumor), self.receiver_hex[0], created_at=1700000000)
        gift = make_gift_wrap(self.receiver_hex[0], seal)
        # ...whose rumor claims B.
        self.assertEqual(_rumor_inside(_seal_inside(gift, receiver), receiver)["pubkey"],
                         b.public_key.hex())
        with self.assertRaises(ValueError):
            decrypt_gift_wrap_to_rumor(gift, receiver)

    def test_every_wrap_from_make_nip17_messages_decrypts(self):
        gifts = make_nip17_messages(self.sender, "all of us", self.receiver_hex, subject="room")
        keys = [self.sender] + self.receivers  # the sender's self-wrap comes first
        self.assertEqual(len(gifts), len(keys))
        for gift, key in zip(gifts, keys):
            rumor = decrypt_gift_wrap_to_rumor(gift, key)
            self.assertEqual(rumor["pubkey"], self.own_hex)
            self.assertEqual(rumor["content"], "all of us")


def _signed_seal(author, content, tags=None, created_at=1700000000):
    """A kind 13 seal dict over `content`, signed by `author`, with `tags`."""
    event = Event(content=content, public_key=author.public_key.hex(), created_at=created_at,
                  kind=13, tags=tags if tags is not None else [])
    author.sign_event(event)
    return {"id": event.id, "pubkey": event.public_key, "created_at": event.created_at,
            "kind": event.kind, "tags": event.tags, "content": event.content,
            "sig": event.signature}


class TestSealSignature(unittest.TestCase):
    """NIP-59: the seal is 'signed by the author of the note'. Its id and
    Schnorr signature are what bind the rumor to that author."""

    def setUp(self):
        self.sender = PrivateKey(_SENDER_SECRET)
        self.receiver = PrivateKey()
        self.receiver_hex = self.receiver.public_key.hex()
        self.rumor = make_rumor(self.sender, "signed?", [self.receiver_hex], created_at=1700000000)
        self.seal = make_seal(self.sender, dict(self.rumor), self.receiver_hex,
                              created_at=1699990000)
        other_rumor = make_rumor(self.sender, "another message", [self.receiver_hex],
                                 created_at=1700000001)
        self.other_seal = make_seal(self.sender, other_rumor, self.receiver_hex,
                                    created_at=1699990001)

    def _decrypt(self, seal):
        return decrypt_gift_wrap_to_rumor(make_gift_wrap(self.receiver_hex, seal), self.receiver)

    def _assert_rejected(self, seal):
        with self.assertRaises(ValueError):
            self._decrypt(seal)

    def test_valid_seal_decrypts(self):
        self.assertEqual(self._decrypt(self.seal)["content"], "signed?")

    def test_garbage_signature_is_rejected(self):
        self.seal["sig"] = "00" * 64
        self._assert_rejected(self.seal)

    def test_signature_over_another_event_is_rejected(self):
        # A real signature by the same key, over a different seal.
        self.seal["sig"] = self.other_seal["sig"]
        self._assert_rejected(self.seal)

    def test_malformed_signature_is_rejected_with_value_error(self):
        for sig in ("", "00" * 63, "zz" * 64, "00" * 65, None, 12):
            seal = dict(self.seal)
            seal["sig"] = sig
            self._assert_rejected(seal)

    def test_unsigned_seal_is_rejected(self):
        for field in ("sig", "id"):
            seal = dict(self.seal)
            del seal[field]
            self._assert_rejected(seal)

    def test_id_not_matching_content_is_rejected(self):
        # The signature still verifies over the seal's real hash; only the
        # id field lies.
        self.seal["id"] = "00" * 32
        self._assert_rejected(self.seal)

    def test_id_and_signature_of_another_seal_are_rejected(self):
        # A consistent id/sig pair, but over another seal's content.
        self.seal["id"] = self.other_seal["id"]
        self.seal["sig"] = self.other_seal["sig"]
        self._assert_rejected(self.seal)

    def test_content_swapped_after_signing_is_rejected(self):
        self.seal["content"] = self.other_seal["content"]
        self._assert_rejected(self.seal)

    def test_signed_seal_with_tags_is_accepted(self):
        # Documented decision, not an oversight: NIP-59 says seal tags MUST be
        # empty, but neither nostr-tools, go-nostr nor rust-nostr rejects a
        # seal with tags, and Anagram (NIP-171) carries a ticket's
        # invitation_proof in its seal tags. The tags are covered by the id
        # and signature, so only the author can have put them there.
        content = _seal_content(self.sender, self.rumor, self.receiver_hex)
        seal = _signed_seal(self.sender, content, tags=[["invitation_proof", "ab" * 64]])
        self.assertEqual(self._decrypt(seal)["content"], "signed?")

    def test_seal_signed_over_nip01_bytes_with_form_feed_tag_decrypts(self):
        # Another client hashes the NIP-01 bytes, where 0x0C is written \f
        # (MicroPython's json.dumps writes \u000c). Built by hand so the
        # expected id does not depend on Event.serialize.
        content = _seal_content(self.sender, self.rumor, self.receiver_hex)
        tags = [["note", "page\fbreak"]]
        author = self.sender.public_key.hex()
        canonical = f'[0,"{author}",1699990000,13,[["note","page\\fbreak"]],"{content}"]'
        digest = sha256(canonical.encode("utf-8")).digest()
        seal = {"id": digest.hex(), "pubkey": author, "created_at": 1699990000, "kind": 13,
                "tags": tags, "content": content, "sig": self.sender.sign_message_hash(digest)}
        self.assertEqual(self._decrypt(seal)["content"], "signed?")

    def test_tags_added_after_signing_are_rejected(self):
        self.seal["tags"] = [["invitation_proof", "ab" * 64]]
        # Even with the id recomputed to match, the signature does not.
        self.seal["id"] = Event.compute_id(
            self.seal["pubkey"], self.seal["created_at"], self.seal["kind"], self.seal["tags"],
            self.seal["content"],
        )
        self._assert_rejected(self.seal)

    def test_seal_with_invalid_author_key_is_rejected_with_value_error(self):
        # Off the curve, not hex, too short. The id is recomputed so each
        # case reaches the signature check, where secp256k1 raises a bare
        # Exception for the first and last.
        for pubkey in ("00" * 32, "zz" * 32, "ab"):
            seal = dict(self.seal)
            seal["pubkey"] = pubkey
            seal["id"] = Event.compute_id(pubkey, seal["created_at"], seal["kind"],
                                          seal["tags"], seal["content"])
            self._assert_rejected(seal)


# A NIP-17 message from an independent implementation, nak 0.21.2, with
# throwaway keys made for this vector by `nak key generate`:
#   nak event -k 14 --sec <sender> -c 'hello from nak <U+2713>' -p <recipient> \
#       -t subject=interop --ts 1760000000 \
#     | nak gift wrap --sec <sender> -p <recipient> \
#       --use-our-identity-key --use-their-identity-key
# The recipient's secret is committed so the test can open it; the sender's
# secret was discarded.
_NAK_RECIPIENT_SECRET = "92921cf415e91c0c8db21d72408d735c2847d7c21ef79359ac7e2e67371a5583"
_NAK_SENDER_PUBKEY = "c45c99f8ab092601e08f3c19966b674c8e54efe4138d6e754577de001fa78817"
_NAK_RUMOR_ID = "c6fd8fbc8ba57dcac1873e0c5558522b2fd6f95bdbb46acd86aab853db4646d2"
_NAK_GIFT_WRAP_JSON = (
    '{"kind":1059,"id":"6ea6b1b3a20301bf615db45bdcde3ea722cbe060178d96e7d91894e21a9ea'
    '28b","pubkey":"7a5ad5dae33a7f5778913c398ce35d250dc36139df98b6cd41f69f7c74e9e019"'
    ',"created_at":1792014214,"tags":[["p","7ae7b3068aa1bd4ab1d410a33214526fed29ca401'
    'b9a59e05b832f914f21f116"]],"content":"ApgNqAEtRyFvBH4Yr+op1xoE0jxPRTv+rfNunseqmc'
    'bMp3ozcO0EshpU6oBtUG+o6RWV9PMTxBdR3W2IDv77elZ9aDveTgGAt5IyBsL0haW1z5WIaXqWOqZ2hD'
    'YL8fFu+SrmbdHUG2oHW78/+m5fohyJ2FG+e0mpUxN2n/dhyOdlxCjNpp+VY67RoVhrSvhYqxFqKi9MBq'
    'Gv/3DH8F7ML1mfoADk604tnSlNPXtfCVB4/GXJ431/1WjHt+GI4XfknmDgdA084L7BmB1iw0Bt6IsSw7'
    '/Ur6+5Ua6M3Itds+1uZWZoDOFOWZTexHoA1GrHE8YQLxAFJzd2vOX9Y7EL+h7+JYgzk0Tr/+dUzsop2I'
    'rPuu7gbp8nQFPQvNmts1RLTCFS7CMx77xYQmsxYx+dujIjgu5Yx6C7dzGV/kNkf7BNZuGH+n5iOlLrAt'
    'KJ888GkXTjbsAliDXKnW7p3rf4zWAWf1CTkt/HEXKHjbOsIYVLyLAIn9SQVK2QxM/IqcyDc68i/9dLFG'
    'D0X+zl7gJ20JZ7YpUloNQAMoYFTdg3qdOlGeTRoCoYhMgfe2+8vEKSLv2r3kwl867piGVCYZNJqPOWQ2'
    'iDlyETPCRGxOC4CVWkOp1Qbl60VT/vh3Yok1vNq1Bk2DUAquAwa16G05H8W44WFjpj62zVbbVlkXYcv1'
    'IXvYQGaY9XjxIpZBL0PDUtYmPqnnPLd/3/Ps39o/MtSUuCCq24y6DkvwP12IDeXrq0RTwOXAYpf2/hlV'
    'wRcddXhRVU7EaQ+tndKdZd9gVcoZTBv4eDCbwJgBCoaTs+QNK/XOyMqZYbgvZeVnmhsbtfHi2f7BkdMu'
    '09Vg6TUyDuw0d1K5CDj0PiKADPlaHk5GzCmO2XRwfY79ckK7VUIL7nBD+v2l2vBT4phRtkYATX3RE3bi'
    '20UUphnI0Dravje6PFGJJW7vJxwmkY2SDhI5oz1w7+qDc8BQP8Dyo2M9Gcx0I5Rb6pV3cd5ir/JXoH2T'
    '2GljlrcvIukV0fwTyoIBYX4/Z0z2bgleDBUKLGxAj5SOJmyK8yrQ9gwjpuVL6x1iS2nWHnFhuI3pyUrl'
    'VsB7WfUF93VvMihXDY5ljI0dZrC+ufp2JG3czWDqZ0QQ6h5TS3PFPsOE3xed6TcyLU52t4wx64KXtveK'
    'nvmwmszA9JOgJrv3s18HhZ74IZQuTa62SRDeiPtaBQQNbRl7gWjTs31CGuhVGCtg+PsccZkHl7UVL9tw'
    'o6ELI15ZVBNIZ5sh6woWoQ/s6quTvCaRckDEvNMHEW","sig":"250aba15fe4558c8f0161d9fc6cdd'
    '041f654e448abb1c2a7dc7ddb5f5b6811df1970f7279c83c78f555dacc9cd2735f5b4648cdf7036f'
    '35688fa4f67972a3659"}'
)


class TestNakInteropVector(unittest.TestCase):
    """A gift wrap made by nak (go-nostr) decrypts here."""

    def setUp(self):
        self.gift = json.loads(_NAK_GIFT_WRAP_JSON)
        self.recipient = PrivateKey(bytes.fromhex(_NAK_RECIPIENT_SECRET))

    def test_nak_gift_wrap_decrypts(self):
        rumor = decrypt_gift_wrap_to_rumor(self.gift, self.recipient)
        self.assertEqual(rumor["kind"], KIND_NIP17_CHAT)
        self.assertEqual(rumor["pubkey"], _NAK_SENDER_PUBKEY)
        self.assertEqual(rumor["created_at"], 1760000000)
        self.assertEqual(rumor["content"], "hello from nak " + chr(0x2713))
        self.assertEqual(rumor["tags"], [
            ["subject", "interop"],
            ["p", self.recipient.public_key.hex()],
        ])
        self.assertEqual(rumor["id"], _NAK_RUMOR_ID)
        # Both implementations hash the same NIP-01 bytes, non-ASCII included.
        self.assertEqual(
            Event.compute_id(
                rumor["pubkey"], rumor["created_at"], rumor["kind"], rumor["tags"], rumor["content"]
            ),
            _NAK_RUMOR_ID,
        )

    def test_nak_seal_is_a_signed_event_with_empty_tags(self):
        seal = _seal_inside(self.gift, self.recipient)
        self.assertEqual(seal["kind"], 13)
        self.assertEqual(seal["pubkey"], _NAK_SENDER_PUBKEY)
        self.assertEqual(seal["tags"], [])
        event = Event(seal["content"], seal["pubkey"], seal["created_at"], seal["kind"],
                      seal["tags"], seal["sig"])
        self.assertEqual(event.id, seal["id"])
        self.assertTrue(event.verify())

    def test_nak_seal_with_a_flipped_signature_bit_is_rejected(self):
        seal = _seal_inside(self.gift, self.recipient)
        last = int(seal["sig"][-1], 16) ^ 1
        seal["sig"] = seal["sig"][:-1] + "0123456789abcdef"[last]
        gift = make_gift_wrap(self.recipient.public_key.hex(), seal)
        with self.assertRaises(ValueError):
            decrypt_gift_wrap_to_rumor(gift, self.recipient)


class TestSharedReceiverKey(unittest.TestCase):
    """Schemes that gift-wrap to a key several members hold (NIP-171 epoch
    keys, Concord streams) give every member conv_key(shared, author) ==
    conv_key(author, shared), so any member can encrypt a seal "from" any
    author. Only the seal's signature tells the real author apart.
    Bob and Mallory both hold `shared`; Alice posts to it."""

    def setUp(self):
        self.shared = PrivateKey()
        self.shared_hex = self.shared.public_key.hex()
        self.alice = PrivateKey()
        self.alice_hex = self.alice.public_key.hex()

    def test_member_reads_a_real_message(self):
        gifts = make_nip17_messages(self.alice, "hi from alice", [self.shared_hex],
                                    include_sender=False)
        rumor = decrypt_gift_wrap_to_rumor(gifts[0], self.shared)
        self.assertEqual(rumor["pubkey"], self.alice_hex)
        self.assertEqual(rumor["content"], "hi from alice")

    def _forged_seal(self, content="send me your sats -- alice"):
        """Mallory's seal "from" Alice, built with nothing but the shared key."""
        now = int(Event.epoch_seconds())
        tags = [["p", self.shared_hex]]
        rumor = {"id": Event.compute_id(self.alice_hex, now, KIND_NIP17_CHAT, tags, content),
                 "pubkey": self.alice_hex, "created_at": now, "kind": KIND_NIP17_CHAT,
                 "tags": tags, "content": content}
        # conv_key(shared, alice) == conv_key(alice, shared): no Alice secret needed.
        seal = {"kind": 13, "content": _seal_content(self.shared, rumor, self.alice_hex),
                "tags": [], "pubkey": self.alice_hex, "created_at": now - 3600}
        # The forgery is well formed: it opens like a real one and claims Alice.
        self.assertEqual(_rumor_inside(seal, self.shared)["pubkey"], self.alice_hex)
        return seal

    def _assert_bob_rejects(self, seal):
        forged = make_gift_wrap(self.shared_hex, seal)  # validly signed wrap
        with self.assertRaises(ValueError):
            decrypt_gift_wrap_to_rumor(forged, self.shared)  # Bob's copy of the key

    def test_forged_seal_with_garbage_id_and_signature_is_rejected(self):
        # The proof of concept: zero id, zero signature.
        seal = self._forged_seal()
        seal["id"] = "00" * 32
        seal["sig"] = "00" * 64
        self._assert_bob_rejects(seal)

    def test_forged_seal_with_correct_id_is_rejected(self):
        seal = self._forged_seal()
        seal["id"] = Event.compute_id(seal["pubkey"], seal["created_at"], seal["kind"],
                                      seal["tags"], seal["content"])
        seal["sig"] = "00" * 64
        self._assert_bob_rejects(seal)

    def test_forged_seal_signed_by_the_forger_is_rejected(self):
        mallory = PrivateKey()
        seal = self._forged_seal()
        event = Event(content=seal["content"], public_key=self.alice_hex,
                      created_at=seal["created_at"], kind=13, tags=[])
        mallory.sign_event(event)  # signs the Alice-claiming hash with Mallory's key
        seal["id"] = event.id
        seal["sig"] = event.signature
        self._assert_bob_rejects(seal)

    def test_forged_seal_reusing_alices_signature_is_rejected(self):
        real = make_nip17_messages(self.alice, "hi from alice", [self.shared_hex],
                                   include_sender=False)[0]
        alices_seal = _seal_inside(real, self.shared)
        seal = self._forged_seal()
        seal["id"] = alices_seal["id"]
        seal["sig"] = alices_seal["sig"]
        self._assert_bob_rejects(seal)


if __name__ == "__main__":
    unittest.main()
