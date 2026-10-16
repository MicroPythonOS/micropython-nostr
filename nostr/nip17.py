import base64
import json
import logging
import secrets

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

    `now` defaults to Event.epoch_seconds(), the Unix time every Nostr
    timestamp needs; a raw time.time() counts from 2000 on the ESP32 port.
    """
    if now is None:
        now = int(Event.epoch_seconds())
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


def _check_seal_signature(seal):
    """Raise ValueError unless `seal` carries its own NIP-01 id and a valid
    Schnorr signature by its `pubkey`.

    NIP-59: the seal is "signed by the author's real key". That signature is
    the only thing tying a rumor to its author: the NIP-44 key that opens a
    seal is conv_key(author, receiver), which the receiver can compute as
    well, and under a shared receiver key (NIP-171 epoch keys, Concord) so
    can every other member, who could then seal a rumor "from" anyone.

    The check is Event.verify(), as relay.py applies to every incoming event.
    """
    seal_id = seal.get("id")
    signature = seal.get("sig")
    # A BIP-340 signature is 64 bytes; anything else would only make the
    # secp256k1 shim print a warning before failing.
    if not isinstance(seal_id, str) or not isinstance(signature, str) or len(signature) != 128:
        raise ValueError("unsigned or malformed seal")
    event = Event(
        content=seal.get("content"),
        public_key=seal["pubkey"],
        created_at=seal.get("created_at"),
        kind=seal["kind"],
        tags=seal.get("tags"),
        signature=signature,
    )
    computed_id = event.id
    if computed_id != seal_id:
        raise ValueError("seal id does not match its content")
    event.id = computed_id  # verify() would hash the event again otherwise
    try:
        valid = event.verify()
    except Exception:  # noqa: BLE001 - secp256k1 raises bare Exception for a bad point
        valid = False
    if not valid:
        raise ValueError("invalid seal signature")


def _verify_seal(seal, receiver_private_key):
    """Verify and decrypt a kind 13 seal event. Returns decoded rumor dict.

    Raises ValueError unless the seal is signed by its `pubkey` (see
    _check_seal_signature) and the rumor inside claims that same author.

    The seal's tags are NOT required to be empty, although NIP-59 says they
    MUST be: nostr-tools, go-nostr and rust-nostr accept seals with tags,
    and Anagram (NIP-171) carries a ticket's invitation_proof in them. The
    id and signature cover the tags, so only the author can have set them.
    """
    seal = _event_dict_from_source(seal)
    if seal.get("kind") != KIND_NIP17_SEAL:
        raise ValueError("invalid seal kind")
    author = seal.get("pubkey")
    if not author:
        raise ValueError("missing author")
    # Before decrypting: a forged seal costs one signature check, not an
    # ECDH plus a NIP-44 decryption.
    _check_seal_signature(seal)
    conv_key = get_conversation_key(receiver_private_key, author)
    payload = nip44_decrypt(seal["content"], conv_key)
    rumor = json.loads(payload)
    if rumor.get("pubkey") != author:
        raise ValueError("seal pubkey mismatch")
    return rumor


def decrypt_gift_wrap_to_rumor(gift_wrap, receiver_private_key):
    """Decrypt a kind 1059/21059 gift-wrap event into the underlying rumor.

    Returns the rumor as a dict; never None. Raises ValueError when the
    wrap is not addressed to `receiver_private_key` or its seal is not
    validly signed by the rumor's author; a wrap that does not decrypt
    raises from the NIP-44 / secp256k1 layer. The wrap's own signature (an
    ephemeral key's) is left to the relay layer: it says nothing about who
    wrote the rumor.
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
        created_at = int(Event.epoch_seconds())
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
    rumor.setdefault("created_at", int(Event.epoch_seconds()))
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

    The rumor keeps the real `created_at`; every seal and gift wrap gets its
    own timestamp backdated from now by up to two days, so the N wraps of one
    message are not linkable by time and a message replayed from a queue is
    not dated before the window relays and subscriptions keep.

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
        created_at = int(Event.epoch_seconds())

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
        seal = make_seal(private_key, dict(rumor), target, created_at=tweaked_timestamp())
        gift = make_gift_wrap(target, seal, created_at=tweaked_timestamp())
        messages.append(gift)
    return messages
