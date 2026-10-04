# Local Snapshotter Context

`LocalSnapshotterContext` captures a context-local dict of key-value pairs and returns an opaque token string that can be shipped across a process boundary (environment variable, command-line argument, pipe) and reloaded in another process.

## Usage

```python
import os
from local_snapshotter_context import LocalSnapshotterContext

parent = LocalSnapshotterContext(key=os.urandom(32))
parent.set("user_id", 42)
parent.set("roles", ["reader", "writer"])

token = parent.snapshot()          # str, e.g. "<b64>.<sig>"

# Ship `token` and `parent.get_key()` to the child process somehow.

child = LocalSnapshotterContext()
child.set_key(parent.get_key())
restored = child.restore(token)    # {"user_id": 42, "roles": ["reader", "writer"]}
```

For one-way flows where the child has no access to the parent's key, use `restore_untrusted`, which parses and version-checks the payload but skips the MAC comparison:

```python
child = LocalSnapshotterContext()
restored = child.restore_untrusted(token)
```

## Why this exists

Cross-process context propagation usually reaches for a distributed-tracing library. That is overkill when the requirement is: take these few values, turn them into a string, and get them back on the other side. This library does only that, with a JSON payload wrapped in URL-safe base64 and a keyed SHA-256 HMAC.

The trade-off is the key. The default key is process-local random bytes, so a token minted under it cannot be verified by a freshly-forked child. Cross-process callers must either pass an explicit `key` (or use `get_key` / `set_key` to share it), or call `restore_untrusted`, which skips the MAC entirely. Pick one and apply it consistently. The library will not silently fall back between them.

## Edge you will hit

`float("nan")` is rejected by `set`, because Python's `json` module emits `NaN` by default, which is not valid JSON, and a round-trip would not be sound. Use `None` or a string sentinel instead if you need a not-a-number marker.
