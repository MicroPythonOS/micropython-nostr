"""Event.compute_id must hash the NIP-01 canonical bytes.

Plain unittest.TestCase, run under MicroPython's unittest (for example
through MicroPythonOS' scripts/test_runner.py); nostr.key imports
secp256k1_compat, so these tests don't run on CPython yet. Known answers come from the NIP-59 example and from
canonical bytes built by hand, so they do not depend on json.dumps.
"""

import unittest
from hashlib import sha256

from nostr.event import Event
from nostr.key import PrivateKey


class TestEventId(unittest.TestCase):
    def test_id_matches_the_nip59_example(self):
        # The unsigned kind 1 event from NIP-59 "Create an event", whose id is
        # given in the spec.
        self.assertEqual(
            Event.compute_id(
                "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9",
                1691518405,
                1,
                [],
                "Are you going to the party tonight?",
            ),
            "9dd003c6d3b73b74a85a9ab099469ce251653a7af76f523671ab828acd2a0ef9",
        )

    def test_id_hashes_raw_utf8_content(self):
        # NIP-01 serialises without escaping non-ASCII (CPython's json.dumps
        # does unless told not to; MicroPython's never does).
        pubkey = PrivateKey().public_key.hex()
        content = "h\u00e9llo \U0001F600"
        canonical = '[0,"%s",1700000000,14,[["p","%s"]],"%s"]' % (pubkey, pubkey, content)
        self.assertEqual(
            Event.compute_id(pubkey, 1700000000, 14, [["p", pubkey]], content),
            sha256(canonical.encode("utf-8")).digest().hex(),
        )

    def test_serialize_is_compact_utf8(self):
        data = Event.serialize("ab", 1, 1, [["t", "\u00fc"]], "x")
        self.assertEqual(data, '[0,"ab",1,1,[["t","\u00fc"]],"x"]'.encode("utf-8"))

    def test_serialize_escapes_backspace_and_form_feed_as_nip01(self):
        # NIP-01 escapes 0x08 as \b and 0x0C as \f, as JSON.stringify and
        # CPython do. MicroPython's json.dumps writes \u0008 and \u000c.
        data = Event.serialize("ab", 1, 1, [["t", "x\by"]], "page\fbreak")
        self.assertEqual(data, b'[0,"ab",1,1,[["t","x\\by"]],"page\\fbreak"]')

    def test_serialize_keeps_other_escapes(self):
        # Line break, carriage return, tab, quote and backslash have their
        # short forms everywhere; other control characters stay \u00XX.
        data = Event.serialize("ab", 1, 1, [], "\n\r\t\"\\\x01\x1f")
        self.assertEqual(data, b'[0,"ab",1,1,[],"\\n\\r\\t\\"\\\\\\u0001\\u001f"]')

    def test_serialize_leaves_escaped_backslash_before_u0008_text(self):
        # A literal backslash followed by the text "u0008" is not a control
        # character: its JSON is \\u0008 and must stay that way. Next to a
        # real backspace, only the backspace changes.
        data = Event.serialize("ab", 1, 1, [], "\\u0008 \\\b \\u000c")
        self.assertEqual(data, b'[0,"ab",1,1,[],"\\\\u0008 \\\\\\b \\\\u000c"]')

    def test_id_of_content_with_form_feed_is_the_nip01_hash(self):
        pubkey = PrivateKey().public_key.hex()
        canonical = f'[0,"{pubkey}",1700000000,14,[],"a\\fb\\bc"]'
        self.assertEqual(
            Event.compute_id(pubkey, 1700000000, 14, [], "a\fb\bc"),
            # MicroPython's sha256 has no hexdigest().
            sha256(canonical.encode("utf-8")).digest().hex(),  # noqa: FURB181
        )


if __name__ == "__main__":
    unittest.main()
