import json
import threading
import time

from .event import Event
from .filter import Filters
from .message_pool import MessagePool
from .message_type import ClientMessageType
from .relay import Relay, RelayPolicy


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

    def open_connections(self, ssl_options: dict = None, proxy: dict = None):
        for relay in self.relays.values():
            print("starting relay.connect thread...")
            threading.Thread(
                target=relay.connect,
                args=(ssl_options, proxy),
                name=f"{relay.url}-thread",
                daemon=True,
            ).start()
            #time.sleep(3)
            #print("starting relay send.queue_worker thread...")
            #threading.Thread(
            #    target=relay.queue_worker, name=f"{relay.url}-queue", daemon=True
            #).start()
            #time.sleep(1)

    def close_connections(self):
        for relay in self.relays.values():
            relay.close()
            relay.stop_send_queue()
            # maybe also do stop_connect() thread?

    def publish_message(self, message: str):
        for relay in self.relays.values():
            if relay.policy.should_write:
                relay.publish(message)
                time.sleep(1)

    def publish_event(self, event: Event):
        """Verifies that the Event is publishable before submitting it to relays"""
        if event.signature is None:
            raise RelayException(f"Could not publish {event.id}: must be signed")

        if not event.verify():
            raise RelayException(
                f"Could not publish {event.id}: failed to verify signature {event.signature}"
            )
        self.publish_message(event.to_message())
