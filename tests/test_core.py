import base64
import json
import os
import unittest

from local_snapshotter_context import LocalSnapshotterContext


class TestSnapshotRestore(unittest.TestCase):

    def test_roundtrip_preserves_values(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        ctx.set("user_id", 42)
        ctx.set("roles", ["a", "b"])
        ctx.set("active", True)
        token = ctx.snapshot()
        other = LocalSnapshotterContext(key=ctx.get_key())
        out = other.restore(token)
        self.assertEqual(out, {"user_id": 42, "roles": ["a", "b"], "active": True})
        self.assertEqual(other.get("user_id"), 42)

    def test_token_structure(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        ctx.set("k", "v")
        token = ctx.snapshot()
        self.assertIsInstance(token, str)
        enc, _, sig = token.rpartition(".")
        self.assertTrue(enc)
        self.assertTrue(sig)
        raw = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4))
        payload = json.loads(raw)
        self.assertEqual(payload["v"], 1)
        self.assertIn("i", payload)
        self.assertEqual(payload["m"], {"k": "v"})

    def test_restore_replaces_existing_mapping(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        ctx.set("a", 1)
        ctx.set("b", 2)
        token = ctx.snapshot()
        other = LocalSnapshotterContext(key=ctx.get_key())
        other.set("x", 99)
        other.restore(token)
        self.assertIsNone(other.get("x"))
        self.assertEqual(other.get("a"), 1)

    def test_two_tokens_have_distinct_ids(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        ctx.set("k", "v")
        t1 = ctx.snapshot()
        t2 = ctx.snapshot()
        e1 = base64.urlsafe_b64decode(t1.split(".")[0] + "==")
        e2 = base64.urlsafe_b64decode(t2.split(".")[0] + "==")
        self.assertNotEqual(json.loads(e1)["i"], json.loads(e2)["i"])


class TestIntegrity(unittest.TestCase):

    def test_restore_rejects_wrong_key(self):
        a = LocalSnapshotterContext(key=os.urandom(32))
        a.set("k", "v")
        token = a.snapshot()
        b = LocalSnapshotterContext(key=os.urandom(32))
        with self.assertRaises(ValueError):
            b.restore(token)

    def test_restore_rejects_tampered_payload(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        ctx.set("role", "user")
        token = ctx.snapshot()
        enc, _, sig = token.rpartition(".")
        raw = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4))
        payload = json.loads(raw)
        payload["m"]["role"] = "admin"
        raw2 = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        enc2 = base64.urlsafe_b64encode(raw2).decode().rstrip("=")
        tampered = "{}.{}".format(enc2, sig)
        with self.assertRaises(ValueError):
            ctx.restore(tampered)

    def test_restore_rejects_missing_dot(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        with self.assertRaises(ValueError):
            ctx.restore("nodothere")

    def test_restore_rejects_empty_segments(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        with self.assertRaises(ValueError):
            ctx.restore(".")

    def test_restore_rejects_non_string(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        with self.assertRaises(TypeError):
            ctx.restore(b"not.a.string")

    def test_restore_rejects_invalid_base64(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        with self.assertRaises(ValueError):
            ctx.restore("!!!!.sig")

    def test_restore_rejects_bad_json(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        raw = b"not json"
        enc = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        import hmac, hashlib
        sig = base64.urlsafe_b64encode(
            hmac.new(ctx.get_key(), raw, hashlib.sha256).digest()
        ).decode().rstrip("=")
        with self.assertRaises(ValueError):
            ctx.restore("{}.{}".format(enc, sig))

    def test_restore_rejects_wrong_version(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        payload = {"v": 99, "i": "abc", "m": {}}
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        enc = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        import hmac, hashlib
        sig = base64.urlsafe_b64encode(
            hmac.new(ctx.get_key(), raw, hashlib.sha256).digest()
        ).decode().rstrip("=")
        with self.assertRaises(ValueError):
            ctx.restore("{}.{}".format(enc, sig))

    def test_restore_rejects_non_object_payload(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        raw = json.dumps([1, 2, 3]).encode()
        enc = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        import hmac, hashlib
        sig = base64.urlsafe_b64encode(
            hmac.new(ctx.get_key(), raw, hashlib.sha256).digest()
        ).decode().rstrip("=")
        with self.assertRaises(ValueError):
            ctx.restore("{}.{}".format(enc, sig))

    def test_restore_rejects_payload_without_mapping(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        payload = {"v": 1, "i": "abc"}
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        enc = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        import hmac, hashlib
        sig = base64.urlsafe_b64encode(
            hmac.new(ctx.get_key(), raw, hashlib.sha256).digest()
        ).decode().rstrip("=")
        with self.assertRaises(ValueError):
            ctx.restore("{}.{}".format(enc, sig))


class TestUntrusted(unittest.TestCase):

    def test_restore_untrusted_skips_mac(self):
        a = LocalSnapshotterContext(key=os.urandom(32))
        a.set("k", "v")
        token = a.snapshot()
        b = LocalSnapshotterContext(key=os.urandom(32))
        out = b.restore_untrusted(token)
        self.assertEqual(out, {"k": "v"})

    def test_restore_untrusted_rejects_missing_dot(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        with self.assertRaises(ValueError):
            ctx.restore_untrusted("nodothere")

    def test_restore_untrusted_rejects_bad_version(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        payload = {"v": 2, "i": "x", "m": {}}
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        enc = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        with self.assertRaises(ValueError):
            ctx.restore_untrusted("{}.sig".format(enc))


class TestSetKey(unittest.TestCase):

    def test_explicit_key_cross_process_flow(self):
        parent = LocalSnapshotterContext(key=os.urandom(32))
        parent.set("trace", "abc")
        token = parent.snapshot()
        shared_key = parent.get_key()
        child = LocalSnapshotterContext()
        child.set_key(shared_key)
        self.assertEqual(child.restore(token), {"trace": "abc"})

    def test_set_key_rejects_short(self):
        ctx = LocalSnapshotterContext()
        with self.assertRaises(ValueError):
            ctx.set_key(b"short")

    def test_set_key_rejects_non_bytes(self):
        ctx = LocalSnapshotterContext()
        with self.assertRaises(TypeError):
            ctx.set_key("not bytes")


class TestSetValidation(unittest.TestCase):

    def test_set_rejects_non_string_key(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        with self.assertRaises(TypeError):
            ctx.set(123, "v")

    def test_set_rejects_non_serializable_value(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        with self.assertRaises(TypeError):
            ctx.set("bad", object())

    def test_set_rejects_nan(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        with self.assertRaises(TypeError):
            ctx.set("bad", float("nan"))


class TestDefaults(unittest.TestCase):

    def test_get_missing_returns_default(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        self.assertEqual(ctx.get("nope", "fallback"), "fallback")

    def test_as_dict_returns_copy(self):
        ctx = LocalSnapshotterContext(key=os.urandom(32))
        ctx.set("k", 1)
        d = ctx.as_dict()
        d["k"] = 99
        self.assertEqual(ctx.get("k"), 1)

    def test_default_key_shared_across_instances(self):
        a = LocalSnapshotterContext()
        b = LocalSnapshotterContext()
        self.assertEqual(a.get_key(), b.get_key())

    def test_default_key_sufficient_length(self):
        ctx = LocalSnapshotterContext()
        self.assertGreaterEqual(len(ctx.get_key()), 32)

    def test_constructor_rejects_short_key(self):
        with self.assertRaises(ValueError):
            LocalSnapshotterContext(key=b"short")

    def test_constructor_rejects_non_bytes_key(self):
        with self.assertRaises(TypeError):
            LocalSnapshotterContext(key="a string not bytes")


if __name__ == "__main__":
    unittest.main()
