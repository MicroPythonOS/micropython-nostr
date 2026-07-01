import json
import logging
import time
from threading import Lock

from uaiowebsocket import WebSocketApp
from .event import Event
from .filter import Filters
from .message_pool import MessagePool
from .message_type import RelayMessageType
from .subscription import Subscription

logger = logging.getLogger(__name__)


class RelayPolicy:
    def __init__(self, should_read: bool = True, should_write: bool = True) -> None:
        self.should_read = should_read
        self.should_write = should_write

    def to_json_object(self) -> dict[str, bool]:
        return {"read": self.should_read, "write": self.should_write}


class Relay:
    def __init__(
        self,
        url: str,
        policy: RelayPolicy,
        message_pool: MessagePool,
        subscriptions: dict[str, Subscription] = {},
    ) -> None:
        self.url = url
        self.policy = policy
        self.message_pool = message_pool
        self.subscriptions = subscriptions
        self.connected: bool = False
        self.reconnect: bool = True
        self.error_counter: int = 0
        self.error_threshold: int = 0
        self.num_received_events: int = 0
        self.num_sent_events: int = 0
        self.num_subscriptions: int = 0
        self.ssl_options: dict = {}
        self.proxy: dict = {}
        self.lock = Lock()
        self.ws = WebSocketApp(
            url,
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
            on_ping=self._on_ping,
            on_pong=self._on_pong,
        )

    async def connect(self, ssl_options: dict = None, proxy: dict = None):
        self.ssl_options = ssl_options
        self.proxy = proxy
        if not self.connected:
            logger.info("relay connecting to %s", self.url)
            try:
                await self.ws.run_forever(
                    sslopt=ssl_options,
                    http_proxy_host=None if proxy is None else proxy.get("host"),
                    http_proxy_port=None if proxy is None else proxy.get("port"),
                    proxy_type=None if proxy is None else proxy.get("type"),
                    ping_interval=15,
                    reconnect=30,
                    )
            except Exception as e:
                logger.error("relay connect %s run_forever exception: %s", self.url, e)

    async def close(self):
        logger.info("relay closing %s", self.url)
        try:
            await self.ws.close()
            logger.info("relay closed %s", self.url)
        except Exception as e:
            logger.error("relay close %s exception: %s", self.url, e)

    def check_reconnect(self):
        try:
            self.close()
        except:
            pass
        self.connected = False
        if self.reconnect:
            self.connect(self.ssl_options, self.proxy)

    @property
    def ping(self):
        ping_ms = int((self.ws.last_pong_tm - self.ws.last_ping_tm) * 1000)
        return ping_ms if self.connected and ping_ms > 0 else 0

    def publish(self, message: str):
        self.ws.send(message)

    def add_subscription(self, id, filters: Filters):
        with self.lock:
            self.subscriptions[id] = Subscription(id, filters)

    def close_subscription(self, id: str) -> None:
        with self.lock:
            self.subscriptions.pop(id, None)

    def update_subscription(self, id: str, filters: Filters) -> None:
        with self.lock:
            subscription = self.subscriptions[id]
            subscription.filters = filters

    def to_json_object(self) -> dict:
        return {
            "url": self.url,
            "policy": self.policy.to_json_object(),
            "subscriptions": [
                subscription.to_json_object()
                for subscription in self.subscriptions.values()
            ],
        }

    def _on_open(self, class_obj):
        logger.info("relay open %s", self.url)
        self.connected = True

    def _on_close(self, class_obj, status_code, message):
        logger.info("relay close %s status=%s message=%s", self.url, status_code, message)
        self.connected = False
        pass

    def _on_message(self, class_obj, message: str):
        if __debug__:
            logger.debug(
                "relay message %s length=%s data=%s...",
                self.url,
                len(message),
                message[:180],
            )
        if self._is_valid_message(message):
            self.num_received_events += 1
            self.message_pool.add_message(message, self.url)

    def _on_error(self, class_obj, error):
        # Include the error detail + relay URL so a failure is actionable
        # from logs alone — without this, downstream debugging had to
        # resort to patching the library to surface the exception type.
        logger.error("relay error %s: %s", self.url, error)
        self.connected = False
        self.error_counter += 1
        # Reconnection is handled by the WebSocketApp itself (reconnect=30),
        # so Relay no longer needs to spawn a second reconnect loop here.

    def _on_ping(self, class_obj, message):
        if __debug__:
            logger.debug("relay ping %s", self.url)
        return

    def _on_pong(self, class_obj, message):
        if __debug__:
            logger.debug("relay pong %s", self.url)
        return

    def _is_valid_message(self, message: str) -> bool:
        message = message.strip("\n")
        if not message or message[0] != "[" or message[-1] != "]":
            logger.warning("relay invalid message %s: malformed frame", self.url)
            return False

        try:
            message_json = json.loads(message)
        except Exception as e:
            logger.warning("relay invalid message %s: JSON parse error: %s", self.url, e)
            return False

        message_type = message_json[0]
        if not RelayMessageType.is_valid(message_type):
            logger.warning("relay invalid message %s: unknown message type %s", self.url, message_type)
            return False
        if message_type == RelayMessageType.EVENT:
            if not len(message_json) == 3:
                logger.warning("relay invalid message %s: EVENT length %s", self.url, len(message_json))
                return False

            subscription_id = message_json[1]
            with self.lock:
                if subscription_id not in self.subscriptions:
                    logger.warning(
                        "relay invalid message %s: unknown subscription %s",
                        self.url,
                        subscription_id,
                    )
                    return False

            e = message_json[2]
            event = Event(
                e["content"],
                e["pubkey"],
                e["created_at"],
                e["kind"],
                e["tags"],
                e["sig"],
            )
            if not event.verify():
                logger.warning(
                    "relay invalid message %s: signature verification failed for event %s",
                    self.url,
                    event.id,
                )
                return False

            with self.lock:
                subscription = self.subscriptions[subscription_id]

            if subscription.filters and not subscription.filters.match(event):
                logger.warning(
                    "relay invalid message %s: event %s does not match subscription %s filters",
                    self.url,
                    event.id,
                    subscription_id,
                )
                return False

        elif message_type == RelayMessageType.OK:
            if not len(message_json) == 4:
                logger.warning("relay invalid message %s: OK length %s", self.url, len(message_json))
                return False

            event_id = message_json[1]
            if not isinstance(event_id, str):
                logger.warning("relay invalid message %s: OK event_id is not a string", self.url)
                return False

            if message_json[2] is False:
                logger.warning(
                    "relay %s rejected event %s: %s",
                    self.url,
                    event_id,
                    message_json[3],
                )

        return True
