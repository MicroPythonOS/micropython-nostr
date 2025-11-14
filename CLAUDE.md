# CLAUDE.md - micropython-nostr

This file provides guidance for working with the micropython-nostr library.

## Project Overview

**micropython-nostr** is a MicroPython port of [python-nostr](https://github.com/jeffthibault/python-nostr), a Python library for building [Nostr](https://github.com/nostr-protocol/nostr) clients. Nostr (Notes and Other Stuff Transmitted by Relays) is a decentralized social media protocol.

This port enables Nostr functionality on embedded devices running MicroPython, particularly ESP32 microcontrollers. It's used by MicroPythonOS for Bitcoin Lightning wallet communication (NWC - Nostr Wallet Connect) and potentially social media features.

### What is Nostr?

Nostr is a simple, open protocol that enables global, decentralized, and censorship-resistant social media. Key concepts:
- **Events**: Signed JSON messages (posts, DMs, reactions, etc.)
- **Relays**: WebSocket servers that store and forward events
- **Keys**: Public/private key pairs identify users (no usernames, no central authority)
- **NIPs**: Nostr Implementation Possibilities (protocol standards)

## Repository Structure

### Top-Level Files

- **`nostr/`**: Main library package (all the protocol implementation)
- **`main.py`**: Interactive CLI demo (posts and DMs)
- **`test/`**: Test suite
- **`README.md`**: Usage examples and API documentation
- **`pyproject.toml`**: Python packaging configuration (shows desktop dependencies)
- **`setup.py`**, **`poetry.lock`**: Desktop Python packaging (not used on MicroPython)

### Core Modules (`nostr/`)

**Key Management**:
- **`key.py`**: `PrivateKey` and `PublicKey` classes
  - Key generation (random or from nsec/npub)
  - Schnorr signing and verification (using secp256k1)
  - ECDH key agreement
  - NIP-04 encrypted DMs (AES-256-CBC)
  - Bech32 encoding (nsec/npub format)

**Event System**:
- **`event.py`**: `Event` and `EncryptedDirectMessage` classes
  - Event creation and serialization (NIP-01)
  - Event ID computation (SHA-256 of serialized data)
  - Signature verification
  - Tag management (e, p, d tags)
  - ESP32 epoch time correction (different Unix epoch)

**Relay Communication**:
- **`relay.py`**: `Relay` class - WebSocket connection to a single relay
  - Connection management (async, reconnect logic)
  - Message validation and filtering
  - Event publishing and subscription
  - Ping/pong keepalive
  - Error handling and reconnection

- **`relay_manager.py`**: `RelayManager` class - Multi-relay orchestration
  - Manages multiple relay connections
  - Broadcasts events to all writable relays
  - Aggregates subscriptions across relays
  - Unified connection lifecycle

**Message Handling**:
- **`message_pool.py`**: `MessagePool` class - Message queue and deduplication
  - Queues for events, notices, EOSE (End Of Stored Events)
  - Deduplicates events by ID across relays
  - Thread-safe access with locks

- **`message_type.py`**: Message type constants
  - `ClientMessageType`: EVENT, REQ, CLOSE
  - `RelayMessageType`: EVENT, NOTICE, EOSE, OK, AUTH

**Filtering**:
- **`filter.py`**: `Filter` and `Filters` classes
  - NIP-01 subscription filters (ids, kinds, authors, since, until)
  - NIP-12 arbitrary tag filters (#e, #p, etc.)
  - Event matching logic

**Utilities**:
- **`bech32.py`**: Bech32 encoding/decoding (NIP-19)
  - Encode/decode npub (public keys), nsec (private keys)
  - Encode/decode note IDs, relay URLs

- **`delegation.py`**: NIP-26 delegation tokens
  - Authorize temporary keys to post on behalf of identity key
  - Delegation signature creation and verification

- **`pow.py`**: NIP-13 proof-of-work
  - Generate events with difficulty target (anti-spam)

**Client**:
- **`client/client.py`**: `NostrClient` class - High-level API
  - Simple post(), get_post(), dm(), get_dm() methods
  - Default relay list (hardcoded for testing)
  - Automatic key generation
  - Threaded subscription handling

- **`client/cbc.py`**: AES-CBC encryption for DMs
  - PKCS7 padding
  - Used by encrypted direct messages (NIP-04)

## Dependencies

### MicroPython-Specific

1. **`secp256k1-embedded-ecdh`** (sibling directory in MicroPythonOS)
   - Elliptic curve cryptography (Schnorr signatures, ECDH)
   - See `MicroPythonOS/secp256k1-embedded-ecdh/CLAUDE.md`
   - Import: `import secp256k1` (C module)

2. **`secp256k1_compat.py`** (in `MicroPythonOS/internal_filesystem/lib/`)
   - Compatibility shim for desktop vs embedded secp256k1
   - Provides FFI interface for both environments

3. **`websocket.py`** (in `MicroPythonOS/internal_filesystem/lib/`)
   - WebSocket client implementation using uasyncio
   - Port of websocket-client's WebSocketApp to MicroPython
   - Uses `aiohttp` for actual WebSocket communication
   - Async callback queue for event handling

4. **`queue.py`** (in `MicroPythonOS/internal_filesystem/lib/`)
   - Thread-safe Queue implementation (like Python's queue.Queue)
   - Used by MessagePool for event queuing

5. **`userlist.py`** (in `MicroPythonOS/internal_filesystem/lib/`)
   - UserList implementation (MicroPython doesn't have collections.UserList)
   - Used by Filters class

6. **MicroPython standard libraries**:
   - `uasyncio`: Async/await support
   - `aiohttp`: HTTP client with WebSocket support
   - `ujson`: JSON encoding/decoding (aliased as `json`)
   - `hashlib`: SHA-256 hashing
   - `binascii`: hexlify for bytes↔hex conversion
   - `secrets`: Random token generation

### Desktop Dependencies (Not Used on MicroPython)

From `pyproject.toml`:
- `cffi`: Foreign function interface (desktop only)
- `cryptography`: AES encryption (desktop only - MicroPython uses custom CBC)
- `websocket-client`: WebSocket (desktop only - MicroPython uses custom implementation)
- Desktop `secp256k1` Python package (different from embedded C module)

## How It Works

### 1. Key Generation and Management

```python
from nostr.key import PrivateKey, PublicKey

# Generate random key
private_key = PrivateKey()
public_key = private_key.public_key

# Bech32 format (human-readable)
nsec = private_key.bech32()  # "nsec1..."
npub = public_key.bech32()   # "npub1..."

# Hex format (32 bytes)
private_hex = private_key.hex()  # 64 hex chars
public_hex = public_key.hex()    # 64 hex chars

# Load from existing key
private_key = PrivateKey.from_nsec("nsec1...")
public_key = PublicKey.from_npub("npub1...")
```

**Key storage format**:
- **Private key**: 32 random bytes (never share!)
- **Public key**: 32 bytes (x-coordinate of secp256k1 point)
- **Bech32 encoding**: Base32 encoding with checksum and prefix (nsec/npub)

### 2. Event Creation and Signing

```python
from nostr.event import Event, EventKind

# Create text note
event = Event(
    content="Hello Nostr!",
    kind=EventKind.TEXT_NOTE
)

# Sign event (adds public_key and signature)
private_key.sign_event(event)

# Event ID is computed from serialized data
print(event.id)  # SHA-256 hash of [0, pubkey, created_at, kind, tags, content]
```

**Event structure** (NIP-01):
```json
{
  "id": "<32-byte hex event ID>",
  "pubkey": "<32-byte hex public key>",
  "created_at": <unix timestamp>,
  "kind": <integer>,
  "tags": [["e", "event_id"], ["p", "pubkey"], ...],
  "content": "<string>",
  "sig": "<64-byte hex Schnorr signature>"
}
```

**Event kinds** (common):
- 0: Metadata (profile info)
- 1: Text note (Twitter-like post)
- 2: Recommend relay
- 3: Contact list
- 4: Encrypted direct message (NIP-04)
- 5: Delete event
- 23194: Nostr Wallet Connect (NWC) request/response

### 3. Publishing Events

```python
from nostr.relay_manager import RelayManager

# Create relay manager
relay_manager = RelayManager()

# Add relays
relay_manager.add_relay("wss://relay.damus.io")
relay_manager.add_relay("wss://nos.lol")

# Connect (async)
await relay_manager.open_connections()

# Wait for connections
await asyncio.sleep(1)

# Publish event (broadcasts to all writable relays)
relay_manager.publish_event(event)
```

### 4. Subscribing to Events

```python
from nostr.filter import Filter, Filters
from nostr.message_type import ClientMessageType
import json

# Create filter (get text notes from a specific author)
filters = Filters([
    Filter(
        authors=["<pubkey_hex>"],
        kinds=[EventKind.TEXT_NOTE],
        since=<unix_timestamp>,
        limit=50
    )
])

# Add subscription
subscription_id = "my_subscription"
relay_manager.add_subscription(subscription_id, filters)

# Send REQ message
request = [ClientMessageType.REQUEST, subscription_id]
request.extend(filters.to_json_array())
relay_manager.publish_message(json.dumps(request))

# Receive events
while relay_manager.message_pool.has_events():
    event_msg = relay_manager.message_pool.get_event()
    print(event_msg.event.content)
```

**Filter fields**:
- `ids`: List of event IDs
- `kinds`: List of event kinds
- `authors`: List of pubkeys
- `since`: Unix timestamp (events newer than)
- `until`: Unix timestamp (events older than)
- `limit`: Max number of events
- `#e`: Event references
- `#p`: Pubkey references

### 5. Encrypted Direct Messages (NIP-04)

```python
from nostr.event import EncryptedDirectMessage

# Create encrypted DM
dm = EncryptedDirectMessage(
    recipient_pubkey="<recipient_pubkey_hex>",
    cleartext_content="Secret message!"
)

# Sign (automatically encrypts content)
private_key.sign_event(dm)

# Publish
relay_manager.publish_event(dm)

# Decrypt received DM
encrypted_content = event.content  # "base64_ciphertext?iv=base64_iv"
decrypted = private_key.decrypt_message(encrypted_content, event.public_key)
```

**Encryption scheme** (NIP-04):
1. Compute shared secret: ECDH(my_private_key, their_public_key)
2. Generate random 16-byte IV
3. Encrypt message: AES-256-CBC(shared_secret, IV, PKCS7_padded_message)
4. Encode: base64(ciphertext) + "?iv=" + base64(IV)

⚠️ **NIP-04 is deprecated** - Prefer NIP-44 (better security) but not implemented yet

## MicroPython Adaptations

### 1. Dataclass Removal

Desktop python-nostr uses `@dataclass` decorators. MicroPython doesn't support dataclasses.

**Solution**: Manual `__init__()` methods
```python
# Desktop version:
@dataclass
class Event:
    content: str = None
    kind: int = EventKind.TEXT_NOTE

# MicroPython version:
class Event:
    def __init__(self, content=None, kind=EventKind.TEXT_NOTE):
        self.content = content
        self.kind = kind
```

### 2. ESP32 Epoch Correction

ESP32's `time.time()` uses a different epoch (year 2000) than Unix epoch (1970).

**Solution**: `Event.epoch_seconds()` method
```python
@staticmethod
def epoch_seconds():
    import sys
    if sys.platform == "esp32":
        return time.time() + 946684800  # Add 30 years in seconds
    else:
        return round(time.time())
```

### 3. Async WebSocket Implementation

Desktop uses `websocket-client` (synchronous). MicroPython needs async for efficiency.

**Solution**: Custom `websocket.py` using `uasyncio` and `aiohttp`
- `WebSocketApp` class mimics websocket-client API
- Uses `aiohttp.ClientSession().ws_connect()`
- Callback queue for thread-safe event handling
- Automatic reconnection on errors

### 4. secp256k1 Compatibility

Desktop uses `secp256k1` Python package (with cffi). MicroPython uses C module.

**Solution**: `secp256k1_compat.py` shim
- Imports embedded C module on MicroPython
- Imports desktop package on regular Python
- Provides unified API for both

### 5. Cryptography Replacement

Desktop uses `cryptography` library for AES. MicroPython doesn't have it.

**Solution**: Custom AES-CBC implementation in `client/cbc.py`
- Pure Python PKCS7 padding
- Uses underlying crypto primitives

### 6. JSON Compatibility

Desktop uses `json.dumps(ensure_ascii=False)`. MicroPython's ujson doesn't support this.

**Solution**: Remove `ensure_ascii=False` parameter
```python
# Desktop:
json.dumps(data, separators=(",", ":"), ensure_ascii=False)

# MicroPython:
json.dumps(data, separators=(",", ":"))
```

## Architecture

### Message Flow

```
User Code
    ↓
NostrClient / Event
    ↓
RelayManager.publish_event()
    ↓
Relay.publish() (for each relay)
    ↓
WebSocketApp.send()
    ↓
aiohttp WebSocket
    ↓
Nostr Relay Server
```

### Subscription Flow

```
Nostr Relay Server
    ↓
aiohttp WebSocket
    ↓
WebSocketApp._on_message()
    ↓
Relay._on_message()
    ↓
MessagePool.add_message()
    ↓
User Code (message_pool.get_event())
```

### Threading Model

- **Main thread**: UI, user code
- **AsyncIO loop**: WebSocket connections, callbacks
- **Callback processing**: `_process_callbacks_async()` task

All WebSocket operations are async. Callbacks are queued and executed asynchronously to avoid blocking.

## Common Patterns

### Basic Post and Subscribe

```python
import asyncio
from nostr.relay_manager import RelayManager
from nostr.event import Event
from nostr.key import PrivateKey
from nostr.filter import Filter, Filters
from nostr.message_type import ClientMessageType
import json

async def main():
    # Setup
    private_key = PrivateKey()
    relay_manager = RelayManager()
    relay_manager.add_relay("wss://relay.damus.io")

    # Connect
    await relay_manager.open_connections()
    await asyncio.sleep(1)

    # Post
    event = Event("Hello Nostr!")
    private_key.sign_event(event)
    relay_manager.publish_event(event)

    # Subscribe
    filters = Filters([Filter(authors=[private_key.public_key.hex()])])
    subscription_id = "sub1"
    relay_manager.add_subscription(subscription_id, filters)

    request = [ClientMessageType.REQUEST, subscription_id]
    request.extend(filters.to_json_array())
    relay_manager.publish_message(json.dumps(request))

    # Receive
    while True:
        if relay_manager.message_pool.has_events():
            event_msg = relay_manager.message_pool.get_event()
            print(event_msg.event.content)
        await asyncio.sleep(0.1)

asyncio.run(main())
```

### Encrypted DMs

```python
from nostr.event import EncryptedDirectMessage

# Send
dm = EncryptedDirectMessage(
    recipient_pubkey=recipient_public_key.hex(),
    cleartext_content="Secret!"
)
sender_private_key.sign_event(dm)
relay_manager.publish_event(dm)

# Receive and decrypt
event_msg = relay_manager.message_pool.get_event()
if event_msg.event.kind == EventKind.ENCRYPTED_DIRECT_MESSAGE:
    decrypted = receiver_private_key.decrypt_message(
        event_msg.event.content,
        event_msg.event.public_key
    )
    print(decrypted)
```

### NWC (Nostr Wallet Connect) - Complete Implementation

Nostr Wallet Connect (NIP-47) allows apps to communicate with Lightning wallets over Nostr relays. The LightningPiggyApp demonstrates a complete implementation.

#### NWC URL Format

```
nostr+walletconnect://<wallet_pubkey>?relay=<relay_url>&secret=<client_secret>&lud16=<lightning_address>
```

**Example**:
```
nostr+walletconnect://69effe7b49a6dd5cf525bd0905917a5005ffe480b58eeb8e861bb4168e5e6a56
  ?relay=wss://relay.getalby.com/v1
  &secret=a1b2c3d4e5f6...
  &lud16=user@getalby.com
```

**Components**:
- **wallet_pubkey**: Wallet service's public key (64 hex chars)
- **relay**: Nostr relay for communication (can have multiple `relay=` params)
- **secret**: Client's private key (64 hex chars) - keep secret!
- **lud16**: Lightning address (optional, for receiving payments)

#### Parsing NWC URL

```python
import mpos.util

def parse_nwc_url(nwc_url):
    """Parse NWC URL into components"""
    # Remove prefix
    if nwc_url.startswith('nostr+walletconnect://'):
        nwc_url = nwc_url[22:]
    elif nwc_url.startswith('nwc:'):
        nwc_url = nwc_url[4:]

    # URL decode (relay URLs may be encoded)
    nwc_url = mpos.util.urldecode(nwc_url)

    # Split pubkey and params
    parts = nwc_url.split('?')
    wallet_pubkey = parts[0]

    # Validate pubkey (64 hex chars)
    if len(wallet_pubkey) != 64:
        raise ValueError("Invalid wallet pubkey")

    # Parse query parameters
    relays = []
    secret = None
    lud16 = None

    if len(parts) > 1:
        params = parts[1].split('&')
        for param in params:
            if param.startswith('relay='):
                relays.append(param[6:])
            elif param.startswith('secret='):
                secret = param[7:]
            elif param.startswith('lud16='):
                lud16 = param[6:]

    # Validate
    if not relays or not secret:
        raise ValueError("Missing relay or secret")
    if len(secret) != 64:
        raise ValueError("Invalid secret")

    return relays, wallet_pubkey, secret, lud16
```

#### Complete NWC Client Implementation

```python
import asyncio
import json
import ssl
import time
from nostr.relay_manager import RelayManager
from nostr.message_type import ClientMessageType
from nostr.filter import Filter, Filters
from nostr.event import EncryptedDirectMessage
from nostr.key import PrivateKey

class NWCWallet:
    """Nostr Wallet Connect client implementation"""

    def __init__(self, nwc_url):
        # Parse connection string
        self.relays, self.wallet_pubkey, secret, self.lud16 = self.parse_nwc_url(nwc_url)

        # Create client keypair from secret
        self.private_key = PrivateKey(bytes.fromhex(secret))

        # Initialize relay manager
        self.relay_manager = RelayManager()
        for relay in self.relays:
            self.relay_manager.add_relay(relay)

    async def connect(self):
        """Connect to NWC relays and set up subscription"""
        # Open relay connections
        await self.relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})

        # Wait for connections (with timeout)
        for _ in range(100):
            await asyncio.sleep(0.1)
            if self.relay_manager.connected_relays() > 0:
                break

        if self.relay_manager.connected_relays() == 0:
            raise RuntimeError("Failed to connect to any relay")

        # Subscribe to wallet responses and notifications
        subscription_id = f"nwc_{int(time.time())}"
        filters = Filters([Filter(
            kinds=[23195, 23196],  # Response and notification kinds
            authors=[self.wallet_pubkey],  # From wallet service
            pubkey_refs=[self.private_key.public_key.hex()]  # To us
        )])

        self.relay_manager.add_subscription(subscription_id, filters)

        # Send REQ message
        request = [ClientMessageType.REQUEST, subscription_id]
        request.extend(filters.to_json_array())
        self.relay_manager.publish_message(json.dumps(request))

    async def get_balance(self):
        """Request wallet balance (returns balance in msats via callback)"""
        request = {
            "method": "get_balance",
            "params": {}
        }

        dm = EncryptedDirectMessage(
            recipient_pubkey=self.wallet_pubkey,
            cleartext_content=json.dumps(request),
            kind=23194  # NWC request kind
        )
        self.private_key.sign_event(dm)
        self.relay_manager.publish_event(dm)

    async def list_transactions(self, limit=10):
        """Request transaction list"""
        request = {
            "method": "list_transactions",
            "params": {"limit": limit}
        }

        dm = EncryptedDirectMessage(
            recipient_pubkey=self.wallet_pubkey,
            cleartext_content=json.dumps(request),
            kind=23194
        )
        self.private_key.sign_event(dm)
        self.relay_manager.publish_event(dm)

    async def pay_invoice(self, invoice, amount_msats=None):
        """Pay a Lightning invoice"""
        request = {
            "method": "pay_invoice",
            "params": {"invoice": invoice}
        }
        if amount_msats:
            request["params"]["amount"] = amount_msats

        dm = EncryptedDirectMessage(
            recipient_pubkey=self.wallet_pubkey,
            cleartext_content=json.dumps(request),
            kind=23194
        )
        self.private_key.sign_event(dm)
        self.relay_manager.publish_event(dm)

    async def process_responses(self):
        """Process incoming wallet responses and notifications"""
        while True:
            await asyncio.sleep(0.1)

            if self.relay_manager.message_pool.has_events():
                event_msg = self.relay_manager.message_pool.get_event()

                # Decrypt the response
                decrypted_content = self.private_key.decrypt_message(
                    event_msg.event.content,
                    event_msg.event.public_key
                )

                response = json.loads(decrypted_content)

                # Check if it's a response or notification
                if response.get("result"):
                    # Response to a request
                    result = response["result"]

                    if result.get("balance") is not None:
                        balance_msats = int(result["balance"])
                        print(f"Balance: {balance_msats / 1000} sats")

                    elif result.get("transactions") is not None:
                        for tx in result["transactions"]:
                            amount = tx["amount"] / 1000  # msats to sats
                            created_at = tx["created_at"]
                            description = tx.get("description", "")
                            print(f"{amount} sats at {created_at}: {description}")

                    elif result.get("preimage"):
                        # Payment succeeded
                        print(f"Payment successful: {result['preimage']}")

                elif response.get("notification"):
                    # Real-time payment notification
                    notif = response["notification"]
                    amount = notif["amount"] / 1000
                    notif_type = notif["type"]  # "incoming" or "outgoing"

                    if notif_type == "incoming":
                        print(f"Received {amount} sats!")
                    elif notif_type == "outgoing":
                        print(f"Sent {amount} sats")

                elif response.get("error"):
                    # Error response
                    error = response["error"]
                    print(f"Error: {error.get('message')}")

# Usage example
async def main():
    nwc_url = "nostr+walletconnect://..."
    wallet = NWCWallet(nwc_url)

    await wallet.connect()

    # Request balance
    await wallet.get_balance()

    # Start processing responses
    await wallet.process_responses()

asyncio.run(main())
```

#### NWC Event Kinds

- **23194**: Client request (from app to wallet)
- **23195**: Wallet response (from wallet to app)
- **23196**: Wallet notification (real-time updates)

#### NWC Methods (NIP-47)

Supported methods vary by wallet implementation:

**Balance/Info**:
- `get_balance`: Returns `{"balance": <msats>}`
- `get_info`: Returns wallet capabilities and metadata

**Transactions**:
- `list_transactions`: Returns array of transaction objects
  - Params: `limit` (optional)
  - Each transaction has: `type`, `amount`, `created_at`, `description`, `preimage`

**Payments**:
- `pay_invoice`: Pay a BOLT11 invoice
  - Params: `invoice` (required), `amount` (optional for zero-amount invoices)
  - Returns: `{"preimage": "<hex>"}` on success

- `make_invoice`: Create a new invoice
  - Params: `amount` (msats), `description` (optional), `expiry` (seconds, optional)
  - Returns: `{"invoice": "lnbc...", "payment_hash": "<hex>"}`

**Advanced** (not all wallets support):
- `lookup_invoice`: Get invoice details by payment_hash
- `multi_pay_invoice`: Pay multiple invoices atomically
- `multi_pay_keysend`: Send keysend payments

#### Response Structure

**Success response**:
```json
{
  "result_type": "get_balance",
  "result": {
    "balance": 50000
  }
}
```

**Error response**:
```json
{
  "result_type": "pay_invoice",
  "error": {
    "code": "PAYMENT_FAILED",
    "message": "Insufficient balance"
  }
}
```

**Notification** (kind 23196):
```json
{
  "notification_type": "payment_received",
  "notification": {
    "type": "incoming",
    "amount": 10000,
    "created_at": 1234567890,
    "description": "Thanks for the coffee!"
  }
}
```

#### LightningPiggyApp Pattern

The LightningPiggyApp demonstrates best practices:

**1. Background Thread Pattern**:
```python
class NWCWallet:
    def start(self, balance_updated_cb, payments_updated_cb, error_cb):
        """Start wallet manager in background thread"""
        self.keep_running = True
        self.balance_updated_cb = balance_updated_cb
        self.payments_updated_cb = payments_updated_cb
        self.error_cb = error_cb

        _thread.stack_size(mpos.apps.good_stack_size())
        _thread.start_new_thread(self.wallet_manager_thread, ())

    def wallet_manager_thread(self):
        """Thread entry point"""
        try:
            asyncio.run(self.async_wallet_manager_task())
        except Exception as e:
            print(f"Wallet manager crashed: {e}")
            self.error_cb(e)
```

**2. Connection Waiting**:
```python
# Wait for relay connections with timeout
nrconnected = 0
for _ in range(100):  # 10 seconds max
    await asyncio.sleep(0.1)
    nrconnected = self.relay_manager.connected_relays()
    if nrconnected == len(self.relays):
        break

if nrconnected == 0:
    self.error_cb("Could not connect to any relay")
    return
```

**3. Periodic Balance Fetching**:
```python
PERIODIC_FETCH_BALANCE_SECONDS = 60

last_fetch_balance = time.time() - PERIODIC_FETCH_BALANCE_SECONDS

while self.keep_running:
    await asyncio.sleep(0.1)

    # Periodic balance refresh
    if time.time() - last_fetch_balance >= PERIODIC_FETCH_BALANCE_SECONDS:
        last_fetch_balance = time.time()
        await self.fetch_balance()

    # Process incoming events
    if self.relay_manager.message_pool.has_events():
        # ... handle event ...
```

**4. Notification vs Response Handling**:
```python
response = json.loads(decrypted_content)

if response.get("result"):
    # Response to our request
    if result.get("balance") is not None:
        self.handle_balance_update(result["balance"])
    elif result.get("transactions") is not None:
        self.handle_transaction_list(result["transactions"])

elif response.get("notification"):
    # Real-time notification (unsolicited)
    notif = response["notification"]
    if notif["type"] == "incoming":
        # Payment received! Update balance without full fetch
        new_balance = self.last_balance + (notif["amount"] / 1000)
        self.handle_balance_update(new_balance, fetch_payments=False)
        self.handle_single_payment(notif)
```

**5. Transaction Comment Parsing**:
```python
def getCommentFromTransaction(self, transaction):
    """Extract human-readable comment from transaction description"""
    comment = transaction.get("description", "")

    # Some wallets put JSON in description field
    try:
        json_comment = json.loads(comment)
        # Look for text/plain field
        for field in json_comment:
            if field[0] == "text/plain":
                return field[1]
    except:
        # Not JSON, use as-is
        pass

    return comment
```

**6. Graceful Shutdown**:
```python
def stop(self):
    """Stop wallet manager"""
    self.keep_running = False
    # The background thread will notice and clean up

async def async_wallet_manager_task(self):
    # ... main loop ...
    while self.keep_running:
        # ... work ...

    # Cleanup on exit
    print("Closing connections...")
    await self.relay_manager.close_connections()
```

#### Performance Considerations

**Decryption is slow** (~100-200ms on ESP32):
- Only decrypt when needed
- Cache decrypted responses if possible
- Don't block UI thread during decryption

**Balance polling**:
- Poll every 60 seconds (configurable)
- Use notifications for real-time updates
- Don't fetch balance on every notification (use notification amount instead)

**Connection reliability**:
- Multiple relays improve reliability
- Some wallets only listen on specific relays
- Handle reconnection automatically (RelayManager does this)

#### Security Notes

⚠️ **Protect the secret**:
- The `secret` in NWC URL is your wallet's private key
- Store securely (use SharedPreferences, never hardcode)
- Never share or expose in logs
- Anyone with the secret can spend your funds!

⚠️ **Validate responses**:
- Always verify signature (done automatically by relay.py)
- Check `public_key` matches `wallet_pubkey`
- Validate amounts before displaying

⚠️ **Network privacy**:
- Relays see your IP address
- Relays see timing of requests
- Consider using Tor for privacy (not implemented yet)

## Nostr NIPs (Standards)

Implemented/supported NIPs:

- **NIP-01**: Basic protocol (events, relays, subscriptions) ✅
- **NIP-02**: Contact lists (not specifically implemented, but supported)
- **NIP-04**: Encrypted DMs (AES-256-CBC + ECDH) ✅
- **NIP-12**: Generic tag queries ✅
- **NIP-13**: Proof of work ✅ (pow.py)
- **NIP-19**: bech32 encoding (npub, nsec, note) ✅
- **NIP-26**: Delegated event signing ✅
- **NIP-47**: Nostr Wallet Connect (used by Lightning apps) ✅

Not yet implemented:
- **NIP-44**: Better encrypted DMs (secp256k1 ECDH with ChaCha20)
- **NIP-46**: Nostr Connect (remote signing)
- **NIP-65**: Relay list metadata

## Use Cases in MicroPythonOS

### 1. Nostr Wallet Connect (NWC)

MicroPythonOS apps use NWC to communicate with Lightning wallets:

**Example**: `LightningPiggyApp` displays wallet balance
- App connects to user's NWC relay
- Subscribes to kind 23194 events addressed to app's pubkey
- Sends encrypted requests (get_balance, pay_invoice)
- Receives encrypted responses with balance/payment status

**Benefits**:
- No custody: wallet stays on user's server
- Standard protocol: works with Alby, LNbits, etc.
- Nostr relays provide reliable message delivery

### 2. Social Media (Future)

Potential Nostr social app for MicroPythonOS:
- Post notes (kind 1)
- Follow users (kind 3 contact lists)
- View feed (subscribe to followed users)
- React to posts (kind 7)
- Reply to posts (kind 1 with 'e' and 'p' tags)

### 3. Authentication

Use Nostr keys for device authentication:
- Device generates keypair
- User adds device pubkey to allowed list
- Device signs challenges to prove ownership
- Decentralized, no central auth server

## Known Issues and Limitations

### 1. NIP-04 Encryption Weakness

⚠️ **NIP-04 is cryptographically weak**:
- Metadata leakage (message length)
- No authentication (only encryption)
- CBC mode padding oracle attacks

**Future**: Implement NIP-44 (ChaCha20-Poly1305 with better key derivation)

### 2. Memory Usage

Each relay connection uses:
- WebSocket overhead: ~2-4KB
- Message queues: variable (bounded by queue size)
- Event storage: ~1KB per cached event

**Recommendations**:
- Limit concurrent relay connections (2-3 on ESP32)
- Use event filtering aggressively
- Clear message pool regularly

### 3. Reconnection Logic

Current reconnection is basic:
- Reconnects on error
- No exponential backoff
- No connection state persistence

**Improvements needed**:
- Exponential backoff (avoid hammering dead relays)
- Subscription re-establishment after reconnect
- Better error differentiation (network vs relay errors)

### 4. Time Synchronization

ESP32 needs NTP for accurate timestamps:
- Events with wrong timestamps may be rejected
- DM decryption may fail if time is way off

**Solution**: Ensure NTP is enabled in MicroPythonOS WiFi setup

### 5. Threading vs AsyncIO

Current code mixes threading and asyncio:
- WebSocket runs in asyncio
- Some user code uses threading (client.py)
- Potential race conditions

**Improvements needed**:
- Fully async API (no threading in client code)
- Better task lifecycle management

## Testing

### Manual Testing

```bash
# Desktop
python3 main.py

# MicroPython (on device)
mpremote run main.py
```

### Unit Tests

```bash
cd test
python3 -m pytest
```

Tests cover:
- Event creation and serialization
- Signature verification
- Filter matching
- Bech32 encoding/decoding

## Performance Considerations

### ESP32 Benchmarks (240MHz)

- **Event creation**: ~1ms
- **Event signing** (Schnorr): ~15ms
- **Event verification**: ~25ms
- **ECDH** (DM encryption setup): ~20ms
- **AES-256-CBC encrypt** (1KB message): ~5ms
- **WebSocket send**: ~10-50ms (depends on network)
- **WebSocket receive**: ~5-20ms (depends on message size)

### Optimization Tips

1. **Pre-generate keys**: Don't generate new keys for each event
2. **Batch subscriptions**: Use one subscription with multiple filters instead of many subscriptions
3. **Limit event history**: Use `since` filter to avoid downloading old events
4. **Close unused subscriptions**: Send CLOSE messages when done
5. **Reuse relay connections**: Don't reconnect unnecessarily

## Security Best Practices

### 1. Key Storage

⚠️ **Never hardcode private keys in source code**

```python
# BAD
private_key = PrivateKey.from_nsec("nsec1...")

# GOOD - load from secure storage
from mpos.config import SharedPreferences
prefs = SharedPreferences("com.myapp.nostr")
nsec = prefs.get_string("private_key")
if nsec:
    private_key = PrivateKey.from_nsec(nsec)
else:
    private_key = PrivateKey()
    prefs.edit().put_string("private_key", private_key.bech32()).commit()
```

### 2. Event Validation

Always verify events before processing:

```python
if not event.verify():
    print("Invalid signature - discarding event")
    return
```

### 3. Relay Trust

- Don't trust relay-provided data without verification
- Relays can censor, inject, or modify events
- Always verify signatures (relay can't forge signatures)
- Use multiple relays for censorship resistance

### 4. DM Privacy

- NIP-04 DMs are only encrypted, not anonymous
- Relays see sender/recipient pubkeys
- Message length is visible
- Use NIP-44 when available (better metadata protection)

## Future Improvements

### High Priority

1. **NIP-44 Encrypted DMs**: Replace NIP-04 with better encryption
2. **Async-only API**: Remove threading, full asyncio
3. **Better reconnection**: Exponential backoff, subscription recovery
4. **Event caching**: LRU cache for frequently accessed events
5. **NIP-46 Nostr Connect**: Remote signing for improved security

### Medium Priority

6. **NIP-65 Relay lists**: Read/write relay preferences from kind 10002 events
7. **NIP-57 Zaps**: Lightning tips on Nostr events
8. **NIP-42 Relay AUTH**: Authenticate to relays for private access
9. **Pagination**: Better handling of large event sets
10. **Outbox model** (NIP-65): Smart relay selection based on user preferences

### Low Priority

11. **NIP-23 Long-form content**: Blog posts, articles
12. **NIP-58 Badges**: User achievements, verifications
13. **NIP-89 App handlers**: Register app as handler for certain event kinds
14. **NIP-94 File metadata**: Attach files to events

## Debugging Tips

### Enable Debug Logging

```python
# In websocket.py
def _log_debug(msg):
    print(f"[DEBUG {time.ticks_ms()}] {msg}")  # Already enabled

# In relay.py
print(f"relay.py _on_message received message: {message}")
```

### Check Connection Status

```python
for relay in relay_manager.relays.values():
    print(f"Relay {relay.url}: connected={relay.connected}, "
          f"sent={relay.num_sent_events}, received={relay.num_received_events}, "
          f"errors={relay.error_counter}")
```

### Monitor Message Pool

```python
print(f"Events: {relay_manager.message_pool.events.qsize()}")
print(f"Notices: {relay_manager.message_pool.notices.qsize()}")
print(f"EOSE: {relay_manager.message_pool.eose_notices.qsize()}")
```

### Verify Event Serialization

```python
event = Event("Test")
private_key.sign_event(event)
print(f"Event ID: {event.id}")
print(f"Signature: {event.signature}")
print(f"Serialized: {event.to_message()}")
print(f"Valid: {event.verify()}")
```

## References

- **Nostr Protocol**: https://github.com/nostr-protocol/nostr
- **NIPs**: https://github.com/nostr-protocol/nips
- **python-nostr (upstream)**: https://github.com/jeffthibault/python-nostr
- **MicroPythonOS websocket.py**: `internal_filesystem/lib/websocket.py`
- **MicroPythonOS secp256k1**: `secp256k1-embedded-ecdh/CLAUDE.md`
- **Nostr clients**: Damus (iOS), Amethyst (Android), Snort (web)

## Getting Help

- **Nostr Discord**: https://discord.gg/nostr
- **GitHub Issues**: https://github.com/jeffthibault/python-nostr/issues
- **MicroPythonOS Issues**: https://github.com/MicroPythonOS/MicroPythonOS/issues
- **NIP Specifications**: https://github.com/nostr-protocol/nips (authoritative protocol docs)
