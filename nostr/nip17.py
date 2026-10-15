import base64
import json
import logging
import secrets
import time

from nostr.event import Event
from nostr.key import PrivateKey
from nostr.nip44 import decrypt as nip44_decrypt
from nostr.nip44 import encrypt as nip44_encrypt
from nostr.nip44 import get_conversation_key

logger = logging.getLogger(__name__)

KIND_NIP17_CHAT = 14
KIND_NIP17_GIFT_WRAP = 1059
KIND_NIP17_SEAL = 13

# NIP-17: "Clients SHOULD randomize `created_at` in up to two days in the
# past in both the seal and the gift wrap".
TWO_DAYS = 2 * 24 * 60 * 60


def tweaked_timestamp(now=None):
    """Return a timestamp up to TWO_DAYS before `now` (default: current time).

    NIP-59: "All other timestamps SHOULD be tweaked to thwart time-analysis
    attacks" and "all timestamps SHOULD be in the past". Each call draws an
    independent offset, so the seal and the gift wrap of one message carry
    different timestamps.
    """
    if now is None:
        now = int(time.time())
    # token_bytes rather than secrets.randbelow: the MicroPython secrets
    # shim's randbelow needs int.bit_length, which MicroPython lacks.
    offset = int.from_bytes(secrets.token_bytes(4), "big") % (TWO_DAYS + 1)
    return now - offset


def _get_tag(event, name):
    """Return the first tag matching `name`, or None."""
    tags = getattr(event, "tags", None)
    if tags is None and isinstance(event, dict):
        tags = event.get("tags", [])
    for tag in tags or []:
        if tag and tag[0] == name:
            return tag
    return None


def _event_dict_from_source(source):
    """Return a dict representing a Nostr event from several input forms."""
    if isinstance(source, dict):
        return source
    if isinstance(source, Event):
        return {
            "id": source.id,
            "pubkey": source.public_key,
            "created_at": source.created_at,
            "kind": source.kind,
            "tags": source.tags,
            "content": source.content,
            "sig": source.signature,
        }
    raise ValueError("source must be Event or dict")


def _verify_seal(seal, receiver_private_key):
    """Decrypt and verify a kind 13 seal event. Returns decoded rumor dict."""
    seal = _event_dict_from_source(seal)
    if seal.get("kind") != KIND_NIP17_SEAL:
        raise ValueError("invalid seal kind")
    author = seal.get("pubkey")
    if not author:
        raise ValueError("missing author")
    conv_key = get_conversation_key(receiver_private_key, author)
    payload = nip44_decrypt(seal["content"], conv_key)
    rumor = json.loads(payload)
    if rumor.get("pubkey") != author:
        raise ValueError("seal pubkey mismatch")
    return rumor


def decrypt_gift_wrap_to_rumor(gift_wrap, receiver_private_key):
    """Decrypt a kind 1059/21059 gift-wrap event into the underlying rumor.

    Returns the rumor as a dict, or None if decryption fails.
    """
    gift_wrap = _event_dict_from_source(gift_wrap)
    if gift_wrap.get("kind") not in (KIND_NIP17_GIFT_WRAP, 21059):
        raise ValueError("invalid gift-wrap kind")
    p_tag = _get_tag(gift_wrap, "p")
    if not p_tag or p_tag[1] != receiver_private_key.public_key.hex():
        raise ValueError("gift-wrap is not addressed to us")

    wrap_public_key_hex = gift_wrap["pubkey"]
    conv_key = get_conversation_key(
        receiver_private_key,
        wrap_public_key_hex,
    )
    seal_payload = nip44_decrypt(gift_wrap["content"], conv_key)
    seal = json.loads(seal_payload)
    return _verify_seal(seal, receiver_private_key)


def make_rumor(
    private_key,
    content,
    recipients,
    subject=None,
    reply_to=None,
    created_at=None,
):
    """Create a kind 14 rumor dict.

    `recipients` is a list of public-key hex strings. Each becomes a 'p' tag.
    Optionally includes a 'subject' tag and an 'e' reply tag.
    """
    tags = [["p", recipient] for recipient in recipients]
    if subject is not None and subject:
        tags.append(["subject", subject])
    if reply_to:
        tags.append(["e", reply_to])
    pubkey = private_key.public_key.hex()
    if created_at is None:
        created_at = int(time.time())
    # NIP-17: "Fields `id` and `created_at` are required." The id is the
    # NIP-01 hash of the unsigned event; clients key their storage on it.
    return {
        "id": Event.compute_id(pubkey, created_at, KIND_NIP17_CHAT, tags, content),
        "kind": KIND_NIP17_CHAT,
        "content": content,
        "tags": tags,
        "pubkey": pubkey,
        "created_at": created_at,
    }


def make_seal(private_key, rumor, recipient_public_key_hex, created_at=None):
    """Return a signed kind 13 seal event dict addressed to `recipient`.

    `created_at` defaults to a randomly backdated timestamp (NIP-59); the
    rumor keeps its own canonical timestamp.
    """
    if created_at is None:
        created_at = tweaked_timestamp()
    rumor.setdefault("created_at", int(time.time()))
    clear_text = json.dumps(rumor, separators=(",", ":"))
    conv_key = get_conversation_key(private_key, recipient_public_key_hex)
    ciphertext = nip44_encrypt(clear_text, conv_key)
    seal = {
        "kind": KIND_NIP17_SEAL,
        "content": ciphertext,
        "tags": [],
        "pubkey": private_key.public_key.hex(),
        "created_at": created_at,
    }
    sealed_event = Event(
        content=seal["content"],
        public_key=seal["pubkey"],
        created_at=seal["created_at"],
        kind=seal["kind"],
        tags=seal["tags"],
    )
    private_key.sign_event(sealed_event)
    seal["id"] = sealed_event.id
    seal["sig"] = sealed_event.signature
    return seal


def make_gift_wrap(recipient_public_key_hex, seal, created_at=None):
    """Return a kind 1059 gift-wrap event dict addressed to the recipient.

    `created_at` defaults to a randomly backdated timestamp (NIP-59).
    """
    if created_at is None:
        created_at = tweaked_timestamp()
    wrapper = PrivateKey()
    clear_text = json.dumps(seal, separators=(",", ":"))
    conv_key = get_conversation_key(wrapper, recipient_public_key_hex)
    ciphertext = nip44_encrypt(clear_text, conv_key)
    tags = [["p", recipient_public_key_hex]]
    gift = {
        "kind": KIND_NIP17_GIFT_WRAP,
        "content": ciphertext,
        "tags": tags,
        "pubkey": wrapper.public_key.hex(),
        "created_at": created_at,
    }
    wrapped_event = Event(
        content=gift["content"],
        public_key=gift["pubkey"],
        created_at=gift["created_at"],
        kind=gift["kind"],
        tags=gift["tags"],
    )
    wrapper.sign_event(wrapped_event)
    gift["id"] = wrapped_event.id
    gift["sig"] = wrapped_event.signature
    return gift


def make_nip17_messages(
    private_key,
    content,
    recipients,
    subject=None,
    reply_to=None,
    created_at=None,
    include_sender=True,
):
    """Create a gift-wrap event for the sender and one for each recipient.

    NIP-17: the rumor "must be sealed (`kind:13`) and then gift-wrapped
    (`kind:1059`) to each receiver and the sender individually". The
    sender's copy comes FIRST, so a client that keys its local copy of the
    message on `messages[0]["id"]` deduplicates the relay echo of that wrap.
    It is addressed to the sender's own pubkey without adding a `p` tag for
    it to the rumor, so the sender's other clients see the message too and
    the chat room (pubkey + `p` tags) is unchanged. Pass include_sender=False
    to skip it (the result then starts with the first recipient's wrap).

    Returns a list of normalized Event-compatible dicts that can be published
    directly to relays.
    """
    if not recipients:
        raise ValueError("recipients must not be empty")

    seen = set()
    deduped = []
    for r in recipients:
        if r not in seen:
            seen.add(r)
            deduped.append(r)
    recipients = deduped

    if created_at is None:
        created_at = int(time.time())

    rumor = make_rumor(
        private_key,
        content,
        recipients,
        subject=subject,
        reply_to=reply_to,
        created_at=created_at,
    )
    own_hex = private_key.public_key.hex()
    targets = []
    if include_sender and own_hex not in seen:
        targets.append(own_hex)
    targets.extend(recipients)
    messages = []
    for target in targets:
        # The rumor keeps the real `created_at`; the seal and the gift wrap
        # each get an independent backdated timestamp so the N wraps of one
        # message are not linkable by time.
        seal = make_seal(
            private_key, dict(rumor), target, created_at=tweaked_timestamp(created_at)
        )
        gift = make_gift_wrap(target, seal, created_at=tweaked_timestamp(created_at))
        messages.append(gift)
    return messages
