import uasyncio as asyncio
import json
import logging
import time

from .event import Event
from .filter import Filters
from .message_pool import MessagePool
from .message_type import ClientMessageType
from .relay import Relay, RelayPolicy

logger = logging.getLogger(__name__)


class RelayException(Exception):
    pass


class RelayManager:
    def __init__(self) -> None:
        self.relays: dict[str, Relay] = {}
        self.message_pool = MessagePool()

    def add_relay(
        self, url: str, read: bool = True, write: bool = True, subscriptions={}
    ):
        policy = RelayPolicy(read, write)
        relay = Relay(url, policy, self.message_pool, subscriptions)
        self.relays[url] = relay

    def remove_relay(self, url: str):
        self.relays.pop(url)

    def add_subscription(self, id: str, filters: Filters):
        for relay in self.relays.values():
            relay.add_subscription(id, filters)

    def close_subscription(self, id: str):
        for relay in self.relays.values():
            relay.close_subscription(id)

    async def open_connections(self, ssl_options: dict = None, proxy: dict = None):
        for relay in self.relays.values():
            logger.info("relay connecting task %s", relay.url)
            self.connected = False
            relay.task = asyncio.create_task(relay.connect(ssl_options, proxy))

    async def close_connections(self):
        for relay in self.relays.values():
            logger.info("closing relay %s", relay.url)
            try:
                await relay.close()
            except Exception as e:
                logger.error("relay close %s exception: %s", relay.url, e)
            logger.info("closed relay %s, cancelling task", relay.url)
            relay.task.cancel()

    def publish_message(self, message: str):
        if __debug__:
            logger.debug("publishing message to %s relay(s)", len(self.relays))
        for relay in self.relays.values():
            if relay.policy.should_write and relay.connected:
                relay.publish(message)

    def publish_event(self, event: Event):
        """Verifies that the Event is publishable before submitting it to relays"""
        if event.signature is None:
            raise RelayException(f"Could not publish {event.id}: must be signed")

        if not event.verify():
            raise RelayException(
                f"Could not publish {event.id}: failed to verify signature {event.signature}"
            )
        self.publish_message(event.to_message())

    def connected_relays(self):
        nrconnected = 0
        for relay in self.relays.values():
            if relay.connected is True:
                nrconnected += 1
        return nrconnected

    def connected_or_errored_relays(self):
        nrconnected = 0
        for relay in self.relays.values():
            if relay.connected is True:
                nrconnected += 1
            elif relay.error_counter > 0:
                nrconnected += 1
        return nrconnected

    def connection_summary(self):
        """Return (connected_urls, disconnected_urls) for diagnostics."""
        connected = []
        disconnected = []
        for url, relay in self.relays.items():
            if relay.connected:
                connected.append(url)
            else:
                disconnected.append(url)
        return connected, disconnected
