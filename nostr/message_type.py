class ClientMessageType:
    EVENT = "EVENT"
    REQUEST = "REQ"
    CLOSE = "CLOSE"

class RelayMessageType:
    EVENT = "EVENT"
    NOTICE = "NOTICE"
    END_OF_STORED_EVENTS = "EOSE"
    OK = "OK"

    @staticmethod
    def is_valid(type: str) -> bool:
        return type in (
            RelayMessageType.EVENT,
            RelayMessageType.NOTICE,
            RelayMessageType.END_OF_STORED_EVENTS,
            RelayMessageType.OK,
        )