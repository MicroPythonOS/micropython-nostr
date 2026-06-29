import base64
import json
import logging
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
    return {
        "kind": KIND_NIP17_CHAT,
        "content": content,
        "tags": tags,
        "pubkey": private_key.public_key.hex(),
        "created_at": created_at if created_at is not None else int(time.time()),
    }


def make_seal(private_key, rumor, recipient_public_key_hex, created_at=None):
    """Return a signed kind 13 seal event dict addressed to `recipient`."""
    if created_at is None:
        created_at = int(time.time())
    rumor.setdefault("created_at", created_at)
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
    """Return a kind 1059 gift-wrap event dict addressed to the recipient."""
    if created_at is None:
        created_at = int(time.time())
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
    private_key, content, recipients, subject=None, reply_to=None, created_at=None
):
    """Create a gift-wrap event for each recipient.

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
    messages = []
    for recipient in recipients:
        seal = make_seal(private_key, dict(rumor), recipient, created_at=created_at)
        gift = make_gift_wrap(recipient, seal, created_at=created_at)
        messages.append(gift)
    return messages
