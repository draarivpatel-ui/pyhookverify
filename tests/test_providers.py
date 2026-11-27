"""All six built-in providers, canonical signing formats, and registry tests."""

import base64
import hashlib
import hmac
import unittest

from pyhookverify import (
    BUILTIN_ALIASES,
    BUILTIN_PROVIDERS,
    HookVerifyError,
    Provider,
    WebhookVerifier,
    get_provider,
    provider_aliases,
    register_alias,
    register_provider,
    registered_providers,
)

NOW = 1700000000.0
SECRET = "s3cr3t"


def hex_sig(secret, payload):
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def b64_sig(secret, payload):
    return base64.b64encode(hmac.new(secret.encode(), payload, hashlib.sha256).digest()).decode()


class BaseProviderTest(unittest.TestCase):
    provider = ""
    secret = SECRET

    def verifier(self, **kwargs):
        kwargs.setdefault("clock", lambda: NOW)
        return WebhookVerifier([self.secret], self.provider, **kwargs)


class GitHubTests(BaseProviderTest):
    provider = "github"

    def test_valid(self):
        body = b'{"action":"push"}'
        result = self.verifier().verify(
            {"X-Hub-Signature-256": "sha256=" + hex_sig(self.secret, body)}, body
        )
        self.assertEqual(result.provider, "github")
        self.assertEqual(result.secret_index, 0)

    def test_case_insensitive_header(self):
        body = b"abc"
        result = self.verifier().verify(
            {"x-hub-signature-256": "sha256=" + hex_sig(self.secret, body)}, body
        )
        self.assertTrue(result.signature)

    def test_wrong_body_fails(self):
        body = b"abc"
        header = {"X-Hub-Signature-256": "sha256=" + hex_sig(self.secret, body)}
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify(header, b"abd")
        self.assertEqual(cm.exception.code, "invalid_signature")

    def test_bad_prefix_fails(self):
        body = b"abc"
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify(
                {"X-Hub-Signature-256": "md5=" + hex_sig(self.secret, body)}, body
            )
        self.assertEqual(cm.exception.code, "invalid_signature")

    def test_missing_header_fails(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({}, b"abc")
        self.assertEqual(cm.exception.code, "missing_header")

    def test_duplicate_header_fails(self):
        body = b"abc"
        sig = "sha256=" + hex_sig(self.secret, body)
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify(
                {"X-Hub-Signature-256": sig, "x-hub-signature-256": sig}, body
            )
        self.assertEqual(cm.exception.code, "duplicate_header")

    def test_duplicate_case_variant_fails(self):
        body = b"abc"
        sig = "sha256=" + hex_sig(self.secret, body)
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify(
                {"X-Hub-Signature-256": [sig, sig]}, body
            )
        self.assertEqual(cm.exception.code, "duplicate_header")

    def test_odd_hex_fails(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({"X-Hub-Signature-256": "sha256=abc"}, b"abc")
        self.assertEqual(cm.exception.code, "invalid_encoding")

    def test_uppercase_prefix_accepted(self):
        body = b"abc"
        result = self.verifier().verify(
            {"X-Hub-Signature-256": "SHA256=" + hex_sig(self.secret, body)}, body
        )
        self.assertEqual(result.secret_index, 0)


class StripeTests(BaseProviderTest):
    provider = "stripe"

    def header(self, payload, timestamp=1700000000, extra_sigs=()):
        sig = hex_sig(self.secret, str(timestamp).encode() + b"." + payload)
        values = ["t=%d" % timestamp, "v1=" + sig]
        values.extend("v1=" + s for s in extra_sigs)
        return ",".join(values)

    def test_valid(self):
        body = b'{"id":"evt_1"}'
        result = self.verifier().verify({"Stripe-Signature": self.header(body)}, body)
        self.assertEqual(result.timestamp, 1700000000)

    def test_multi_v1_all_match(self):
        body = b"abc"
        sig = hex_sig(self.secret, b"1700000000.abc")
        other = hex_sig("other", b"1700000000.abc")
        header = "t=1700000000,v1=" + sig + ",v1=" + other
        result = self.verifier().verify({"Stripe-Signature": header}, body)
        self.assertEqual(result.signature, sig)

    def test_stale_rejected(self):
        body = b"abc"
        header = self.header(body, timestamp=NOW - 301)
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({"Stripe-Signature": header}, body)
        self.assertEqual(cm.exception.code, "stale_timestamp")

    def test_future_skew_rejected(self):
        body = b"abc"
        header = self.header(body, timestamp=int(NOW) + 301)
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({"Stripe-Signature": header}, body)
        self.assertEqual(cm.exception.code, "future_timestamp")

    def test_boundary_stale_accepted(self):
        body = b"abc"
        header = self.header(body, timestamp=int(NOW) - 300)
        result = self.verifier().verify({"Stripe-Signature": header}, body)
        self.assertEqual(result.timestamp, int(NOW) - 300)

    def test_missing_v1_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({"Stripe-Signature": "t=1700000000"}, b"abc")
        self.assertEqual(cm.exception.code, "invalid_signature")

    def test_duplicate_t_rejected(self):
        body = b"abc"
        header = "t=1700000000,t=1700000000,v1=" + hex_sig(self.secret, b"1700000000.abc")
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({"Stripe-Signature": header}, body)
        self.assertEqual(cm.exception.code, "invalid_timestamp")

    def test_malformed_key_value_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({"Stripe-Signature": "t=1700000000,garbage"}, b"abc")
        self.assertEqual(cm.exception.code, "invalid_signature")

    def test_float_timestamp_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({"Stripe-Signature": "t=1700000000.5,v1=aa"}, b"abc")
        self.assertEqual(cm.exception.code, "invalid_timestamp")

    def test_wrong_body_fails(self):
        body = b"abc"
        header = self.header(body)
        with self.assertRaises(HookVerifyError):
            self.verifier().verify({"Stripe-Signature": header}, b"abd")


class SlackTests(BaseProviderTest):
    provider = "slack"

    def header(self, body, timestamp=1700000000):
        payload = b"v0:" + str(timestamp).encode() + b":" + body
        return "v0=" + hex_sig(self.secret, payload)

    def test_valid(self):
        body = b"token=xxx&team_id=T1"
        headers = {
            "X-Slack-Signature": self.header(body),
            "X-Slack-Request-Timestamp": "1700000000",
        }
        result = self.verifier().verify(headers, body)
        self.assertEqual(result.timestamp, 1700000000)

    def test_wrong_body_fails(self):
        body = b"abc"
        headers = {
            "X-Slack-Signature": self.header(body),
            "X-Slack-Request-Timestamp": "1700000000",
        }
        with self.assertRaises(HookVerifyError):
            self.verifier().verify(headers, b"abd")

    def test_wrong_timestamp_fails(self):
        body = b"abc"
        headers = {
            "X-Slack-Signature": self.header(body),
            "X-Slack-Request-Timestamp": "1700000001",
        }
        with self.assertRaises(HookVerifyError):
            self.verifier().verify(headers, body)

    def test_missing_timestamp_header_fails(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({"X-Slack-Signature": "v0=aa"}, b"abc")
        self.assertEqual(cm.exception.code, "missing_header")

    def test_bad_version_fails(self):
        headers = {
            "X-Slack-Signature": "v1=" + "aa" * 32,
            "X-Slack-Request-Timestamp": "1700000000",
        }
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify(headers, b"abc")
        self.assertEqual(cm.exception.code, "invalid_signature")

    def test_stale_rejected(self):
        body = b"abc"
        headers = {
            "X-Slack-Signature": self.header(body, NOW - 400),
            "X-Slack-Request-Timestamp": str(int(NOW) - 400),
        }
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify(headers, body)
        self.assertEqual(cm.exception.code, "stale_timestamp")


class ShopifyTests(BaseProviderTest):
    provider = "shopify"

    def test_valid(self):
        body = b'{"order_id":1}'
        result = self.verifier().verify(
            {"X-Shopify-Hmac-Sha256": b64_sig(self.secret, body)}, body
        )
        self.assertEqual(result.provider, "shopify")

    def test_wrong_body_fails(self):
        body = b"abc"
        header = {"X-Shopify-Hmac-Sha256": b64_sig(self.secret, body)}
        with self.assertRaises(HookVerifyError):
            self.verifier().verify(header, b"abd")

    def test_unpadded_base64_rejected(self):
        body = b"abc"
        raw = b64_sig(self.secret, body).rstrip("=")
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({"X-Shopify-Hmac-Sha256": raw}, body)
        self.assertEqual(cm.exception.code, "invalid_encoding")

    def test_hex_instead_of_base64_rejected(self):
        body = b"abc"
        with self.assertRaises(HookVerifyError):
            self.verifier().verify(
                {"X-Shopify-Hmac-Sha256": hex_sig(self.secret, body)}, body
            )


class LinearTests(BaseProviderTest):
    provider = "linear"

    def test_valid(self):
        body = b'{"type":"Issue"}'
        result = self.verifier().verify(
            {"Linear-Signature": hex_sig(self.secret, body)}, body
        )
        self.assertEqual(result.provider, "linear")

    def test_wrong_secret_fails(self):
        body = b"abc"
        with self.assertRaises(HookVerifyError):
            self.verifier().verify({"Linear-Signature": hex_sig("other", body)}, body)

    def test_odd_hex_rejected(self):
        with self.assertRaises(HookVerifyError):
            self.verifier().verify({"Linear-Signature": "abc"}, b"abc")


class SvixTests(BaseProviderTest):
    provider = "svix"
    secret = "whsec_" + SECRET

    def header(self, body, message_id="msg_1", timestamp=1700000000, extra=()):
        payload = (
            message_id.encode() + b"." + str(timestamp).encode() + b"." + body
        )
        sig = "v1," + b64_sig(SECRET, payload)
        parts = [sig]
        parts.extend("v1," + s for s in extra)
        return " ".join(parts)

    def headers(self, body, timestamp=None, signature=None, **kwargs):
        if timestamp is None:
            timestamp = int(NOW)
        return {
            "webhook-id": "msg_1",
            "webhook-timestamp": str(timestamp),
            "webhook-signature": signature or self.header(body, timestamp=timestamp, **kwargs),
        }

    def test_valid(self):
        body = b'{"event":"user.created"}'
        result = self.verifier().verify(self.headers(body), body)
        self.assertEqual(result.provider, "svix")
        self.assertEqual(result.timestamp, 1700000000)

    def test_whsec_prefix_stripped(self):
        body = b"abc"
        result = self.verifier().verify(self.headers(body), body)
        self.assertEqual(result.secret_index, 0)

    def test_multi_v1(self):
        body = b"abc"
        extra = [b64_sig("other", b"msg_1.1700000000.abc")]
        result = self.verifier().verify(self.headers(body, extra=extra), body)
        self.assertEqual(result.provider, "svix")

    def test_wrong_body_fails(self):
        body = b"abc"
        headers = self.headers(body)
        with self.assertRaises(HookVerifyError):
            self.verifier().verify(headers, b"abd")

    def test_no_v1_fails(self):
        headers = self.headers(b"abc", signature="v2," + b64_sig(SECRET, b"x"))
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify(headers, b"abc")
        self.assertEqual(cm.exception.code, "invalid_signature")

    def test_malformed_signature_field_fails(self):
        headers = self.headers(b"abc", signature="nonsense")
        with self.assertRaises(HookVerifyError):
            self.verifier().verify(headers, b"abc")

    def test_case_insensitive_headers(self):
        body = b"abc"
        headers = self.headers(body)
        lowered = {k.upper(): v for k, v in headers.items()}
        result = self.verifier().verify(lowered, body)
        self.assertEqual(result.provider, "svix")

    def test_stale_rejected(self):
        body = b"abc"
        headers = self.headers(body, timestamp=int(NOW) - 400)
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify(headers, body)
        self.assertEqual(cm.exception.code, "stale_timestamp")

    def test_bad_base64_rejected(self):
        headers = self.headers(b"abc", signature="v1,Zg")
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify(headers, b"abc")
        self.assertEqual(cm.exception.code, "invalid_encoding")


class RegistryTests(unittest.TestCase):
    def test_six_builtins(self):
        self.assertEqual(len(BUILTIN_PROVIDERS), 6)

    def test_all_names_registered(self):
        names = set(registered_providers())
        self.assertTrue({"github", "stripe", "slack", "shopify", "linear", "svix"} <= names)

    def test_case_insensitive_lookup(self):
        self.assertEqual(get_provider("GitHub").name, "github")

    def test_unknown_provider_fails(self):
        with self.assertRaises(HookVerifyError) as cm:
            get_provider("nope")
        self.assertEqual(cm.exception.code, "unknown_provider")

    def test_duplicate_registration_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            register_provider(Provider("github2", lambda h, b: (None, [], b)))
            register_provider(Provider("github2", lambda h, b: (None, [], b)))
        self.assertEqual(cm.exception.code, "duplicate_provider")

    def test_replace_registration(self):
        def parser(headers, body):
            return None, [], body

        register_provider(Provider("custom_replace", parser))
        register_provider(Provider("custom_replace", parser), replace=True)
        self.assertEqual(get_provider("custom_replace").name, "custom_replace")

    def test_invalid_provider_object(self):
        with self.assertRaises(HookVerifyError):
            register_provider("not-a-provider")

    def test_invalid_provider_name(self):
        with self.assertRaises(HookVerifyError):
            register_provider(Provider("bad name!", lambda h, b: (None, [], b)))

    def test_custom_provider_roundtrip(self):
        def parser(headers, body):
            import hashlib
            import hmac

            candidate = hmac.new(b"custom", body, hashlib.sha256).digest()
            return None, [candidate], body

        register_provider(Provider("custom_rt", parser))
        verifier = WebhookVerifier(["custom"], "custom_rt")
        result = verifier.verify({"X-Custom": "1"}, b"abc")
        self.assertEqual(result.provider, "custom_rt")
        self.assertEqual(result.signature, result.signature)

    def test_custom_provider_wrong_secret_fails(self):
        def parser(headers, body):
            import hashlib
            import hmac

            candidate = hmac.new(b"custom", body, hashlib.sha256).digest()
            return None, [candidate], body

        register_provider(Provider("custom_rt2", parser))
        verifier = WebhookVerifier(["wrong"], "custom_rt2")
        with self.assertRaises(HookVerifyError) as cm:
            verifier.verify({}, b"abc")
        self.assertEqual(cm.exception.code, "invalid_signature")


class StandardWebhooksAliasTests(SvixTests):
    """The standard-webhooks alias runs the full svix suite."""

    provider = "standard-webhooks"


class AliasTests(unittest.TestCase):
    def test_builtin_alias_table(self):
        self.assertEqual(BUILTIN_ALIASES, {"standard-webhooks": "svix"})
        self.assertEqual(provider_aliases()["standard-webhooks"], "svix")

    def test_alias_resolves_to_canonical_provider(self):
        self.assertIs(get_provider("standard-webhooks"), get_provider("svix"))
        verifier = WebhookVerifier(["secret"], "standard-webhooks")
        self.assertEqual(verifier.provider, "svix")

    def test_alias_lookup_case_insensitive(self):
        self.assertIs(get_provider("Standard-Webhooks"), get_provider("svix"))
        self.assertIs(get_provider("STANDARD-WEBHOOKS"), get_provider("svix"))

    def test_aliases_not_in_registered_providers(self):
        self.assertNotIn("standard-webhooks", registered_providers())

    def test_provider_aliases_returns_copy(self):
        provider_aliases()["tampered"] = "github"
        self.assertNotIn("tampered", provider_aliases())

    def test_conflicting_alias_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            register_alias("standard-webhooks", "github")
        self.assertEqual(cm.exception.code, "duplicate_provider")
        self.assertEqual(get_provider("standard-webhooks").name, "svix")

    def test_conflicting_alias_case_variant_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            register_alias("Standard-Webhooks", "github")
        self.assertEqual(cm.exception.code, "duplicate_provider")

    def test_alias_replace(self):
        register_alias("alias-replace", "github")
        register_alias("alias-replace", "stripe", replace=True)
        self.assertEqual(get_provider("alias-replace").name, "stripe")

    def test_same_alias_without_replace_rejected(self):
        register_alias("alias-dup", "github")
        with self.assertRaises(HookVerifyError) as cm:
            register_alias("alias-dup", "github")
        self.assertEqual(cm.exception.code, "duplicate_provider")

    def test_alias_cannot_shadow_provider_name(self):
        for replace in (False, True):
            with self.assertRaises(HookVerifyError) as cm:
                register_alias("GitHub", "stripe", replace=replace)
            self.assertEqual(cm.exception.code, "duplicate_provider")
        self.assertEqual(get_provider("github").name, "github")

    def test_provider_cannot_shadow_alias(self):
        for replace in (False, True):
            with self.assertRaises(HookVerifyError) as cm:
                register_provider(
                    Provider("standard-webhooks", lambda h, b: (None, [], b)),
                    replace=replace,
                )
            self.assertEqual(cm.exception.code, "duplicate_provider")
        self.assertEqual(get_provider("standard-webhooks").name, "svix")

    def test_alias_to_unknown_provider_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            register_alias("alias-unknown", "nope")
        self.assertEqual(cm.exception.code, "unknown_provider")

    def test_invalid_alias_name_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            register_alias("bad alias!", "svix")
        self.assertEqual(cm.exception.code, "invalid_config")


if __name__ == "__main__":
    unittest.main()
