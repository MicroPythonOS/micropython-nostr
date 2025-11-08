from nostr.filter import Filter, Filters
from nostr.event import Event, EventKind

# Create a filter
f = Filter(authors=["pubkey1"], kinds=[EventKind.TEXT_NOTE])
filters = Filters([f])

# Create an event
e = Event(public_key="pubkey1", kind=EventKind.TEXT_NOTE, content="Hello")

# Test matching
print(filters.match(e))  # Should print: True

# Test JSON output
print(filters.to_json_array())  # Should print: [{'authors': ['pubkey1'], 'kinds': [1]}]
