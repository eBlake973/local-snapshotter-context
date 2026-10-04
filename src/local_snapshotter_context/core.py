import base64
import binascii
import json
import os
import threading
from typing import Optional


class LocalSnapshotterContext:
    """Context-local key-value store producing an opaque, serializable token.

    The token is a URL-safe base64 string encoding a JSON object with three keys:
    ``m`` (the captured mapping), ``i`` (a random identifier), and ``v``
    (a version integer, currently ``1``).

    The token is safe to propagate across process boundaries (including into
    child processes via environment variables). The intended propagation path
    is: capture a token in one process, pass it as a string to another
    process, and ``restore`` it there. This is a one-way flow; there is no
    live synchronization back to the parent.

    Integrity is verified with a keyed SHA-256 HMAC. The key is generated
    per instance, and the class uses a module-level lock so that the first
    instance to run seeds a process-wide key which survives in the module
    until interpreter exit. Child processes always start without a parent's
    key, so on the child side the token is verified by opting into a context
    whose key was set (via :meth:`set_key`) to the parent's key, or by
    accepting the token as untrusted data (see :meth:`restore_untrusted`).

    The default-key design is a deliberate trade-off. The alternative is to
    enforce that every caller manage their own key. The cost of making key
    handling automatic is that the default key does not propagate across a
    fork or exec, so cross-process tokens minted under the default key
    cannot be HMAC-verified by another default-key instance. This is
    documented because it is the edge most callers will hit. For
    cross-process flows, set an explicit key on both sides, or use
    :meth:`restore_untrusted` which parses the payload without verifying
    the MAC.
    """

    _module_lock = threading.Lock()
    _module_key: Optional[bytes] = None
    _VERSION = 1

    def __init__(self, key: Optional[bytes] = None):
        """Construct a context.

        If ``key`` is omitted, a random 32-byte key is lazily created and
        cached at module scope; all instances in the same process that omit
        ``key`` share that one module key. Passing ``key`` explicitly does
        not touch the module key, so explicit keys are instance-local.
        """
        self._data: dict = {}
        if key is not None:
            if not isinstance(key, (bytes, bytearray)):
                raise TypeError("key must be bytes")
            if len(key) < 32:
                raise ValueError("key must be at least 32 bytes")
            self._key = bytes(key)
        else:
            self._key = self._get_or_init_module_key()

    @classmethod
    def _get_or_init_module_key(cls) -> bytes:
        with cls._module_lock:
            if cls._module_key is None:
                cls._module_key = os.urandom(32)
            return cls._module_key

    def set(self, key: str, value) -> None:
        """Set ``key`` to ``value``. ``value`` must be JSON-serializable."""
        if not isinstance(key, str):
            raise TypeError("key must be a str")
        try:
            json.dumps({key: value}, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                "value for key {!r} is not JSON-serializable".format(key)
            ) from exc
        self._data[key] = value

    def get(self, key: str, default=None):
        """Get the value for ``key``, or ``default`` if not set."""
        return self._data.get(key, default)

    def as_dict(self) -> dict:
        """Return a shallow copy of the current mapping."""
        return dict(self._data)

    def _build_payload(self) -> dict:
        return {
            "v": self._VERSION,
            "i": binascii.hexlify(os.urandom(8)).decode("ascii"),
            "m": dict(self._data),
        }

    def _sign(self, raw: bytes) -> str:
        import hmac
        import hashlib
        mac = hmac.new(self._key, raw, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")

    def snapshot(self) -> str:
        """Serialize the current context state into a single token string.

        Returns a string of the form ``"<payload>.<sig>"`` where ``payload``
        is a URL-safe base64 encoding of the JSON object and ``sig`` is the
        keyed MAC. The token carries no leading scheme or delimiter beyond
        the single dot, so it is safe to store in an environment variable or
        pass as a command-line argument.
        """
        payload = self._build_payload()
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        enc = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        sig = self._sign(raw)
        return "{}.{}".format(enc, sig)

    def _verify(self, token: str) -> dict:
        import hmac
        import hashlib
        if not isinstance(token, str):
            raise TypeError("token must be a str")
        if "." not in token:
            raise ValueError("malformed token: missing signature")
        enc, _, sig = token.rpartition(".")
        if not enc or not sig:
            raise ValueError("malformed token: empty segment")
        raw = _b64decode(enc)
        expected = self._sign(raw)
        if not hmac.compare_digest(expected, sig):
            raise ValueError("token signature mismatch")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("malformed token: invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("malformed token: payload not an object")
        if payload.get("v") != self._VERSION:
            raise ValueError("unsupported token version")
        m = payload.get("m")
        if not isinstance(m, dict):
            raise ValueError("malformed token: missing mapping")
        return payload

    def restore(self, token: str) -> dict:
        """Verify ``token`` against this context's key and load its mapping.

        On success, replaces the context's in-memory mapping with the one
        from the token and returns it. Raises ``ValueError`` for any
        signature, format, or version problem, and ``TypeError`` if the
        token is not a str. The original mapping is only replaced after all
        validation succeeds.
        """
        payload = self._verify(token)
        new_data = dict(payload["m"])
        self._data = new_data
        return dict(new_data)

    def restore_untrusted(self, token: str) -> dict:
        """Parse ``token``'s payload without verifying the MAC.

        For cross-process flows where the receiver does not have the
        sender's key, this is the entry point. It performs the same version
        and shape checks as :meth:`restore`, but skips the MAC comparison.
        The name makes the trust assumption explicit at the call site.
        """
        if not isinstance(token, str):
            raise TypeError("token must be a str")
        if "." not in token:
            raise ValueError("malformed token: missing signature")
        enc, _, _sig = token.rpartition(".")
        if not enc:
            raise ValueError("malformed token: empty payload")
        raw = _b64decode(enc)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("malformed token: invalid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("malformed token: payload not an object")
        if payload.get("v") != self._VERSION:
            raise ValueError("unsupported token version")
        m = payload.get("m")
        if not isinstance(m, dict):
            raise ValueError("malformed token: missing mapping")
        new_data = dict(m)
        self._data = new_data
        return dict(new_data)

    def set_key(self, key: bytes) -> None:
        """Replace this context's signing key.

        Useful for cross-process flows: the parent mints a key, passes it to
        the child out-of-band (e.g. via a pipe or a side environment
        variable), and the child calls this before :meth:`restore`.
        """
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if len(key) < 32:
            raise ValueError("key must be at least 32 bytes")
        self._key = bytes(key)

    def get_key(self) -> bytes:
        """Return a copy of this context's signing key.

        Provided so the parent can ship the key to a child process for
        :meth:`restore` to succeed there.
        """
        return bytes(self._key)


def _b64decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("malformed token: invalid base64") from exc
