"""Pluggable HMAC provider registry, six built-in providers, and aliases.

A provider parses provider-specific headers, computes HMACs over the exact
raw body, and returns the list of candidate decoded signatures. The verifier
never compares strings and never parses JSON.
"""

import hmac
import hashlib
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .encoding import decode_base64, decode_hex, is_safe_header_name, parse_timestamp
from .errors import HookVerifyError, Headers

# Provider parse function signature:
#   (headers, raw_body) -> ParsedMessage
# ParsedMessage: (timestamp, candidates, signing_payload)
ParsedMessage = Tuple[Optional[int], List[bytes], bytes]
Parser = Callable[[Headers, bytes], ParsedMessage]

__all__ = [
    "Provider",
    "register_provider",
    "get_provider",
    "registered_providers",
    "register_alias",
    "provider_aliases",
    "BUILTIN_PROVIDERS",
    "BUILTIN_ALIASES",
]


@dataclass(frozen=True)
class Provider:
    """A named signature scheme."""

    name: str
    parser: Parser
    builtin: bool = False

    def parse(self, headers: Headers, raw_body: bytes) -> ParsedMessage:
        return self.parser(headers, raw_body)


_REGISTRY: Dict[str, Provider] = {}
# Lowercased alias -> canonical registered provider name.
_ALIASES: Dict[str, str] = {}


def register_provider(provider: Provider, *, replace: bool = False) -> None:
    """Register a provider. Duplicate names raise unless ``replace=True``."""
    if not isinstance(provider, Provider):
        raise HookVerifyError("invalid_config", "provider must be a Provider instance")
    name = provider.name
    if not is_safe_header_name(name):
        raise HookVerifyError("invalid_config", "provider name must be an ASCII token")
    if not callable(provider.parser):
        raise HookVerifyError("invalid_config", "provider parser must be callable")
    if name in _REGISTRY and not replace:
        raise HookVerifyError("duplicate_provider", "provider %s already registered" % name)
    if name.lower() in _ALIASES:
        raise HookVerifyError("duplicate_provider", "provider name %s is an alias" % name)
    _REGISTRY[name] = provider


def register_alias(alias: str, provider_name: str, *, replace: bool = False) -> None:
    """Register ``alias`` as another name for a registered provider.

    Aliases are case-insensitive and resolve to the canonical provider, so a
    verifier built from an alias reports and behaves as that provider. An
    alias may not shadow a registered provider name. Rebinding an existing
    alias raises ``duplicate_provider`` unless ``replace=True``.
    """
    if not is_safe_header_name(alias):
        raise HookVerifyError("invalid_config", "alias must be an ASCII token")
    target = get_provider(provider_name).name
    key = alias.lower()
    if key in _REGISTRY:
        raise HookVerifyError("duplicate_provider", "alias %s is a provider name" % alias)
    if key in _ALIASES and not replace:
        raise HookVerifyError("duplicate_provider", "alias %s already registered" % alias)
    _ALIASES[key] = target


def get_provider(name: str) -> Provider:
    """Look up a provider by case-insensitive name or alias."""
    if not isinstance(name, str):
        raise HookVerifyError("unknown_provider", "provider must be a string")
    key = name.lower()
    key = _ALIASES.get(key, key)
    if key not in _REGISTRY:
        raise HookVerifyError("unknown_provider", "unknown provider: %s" % name)
    return _REGISTRY[key]


def registered_providers() -> Tuple[str, ...]:
    """Canonical names of all registered providers, sorted.

    Aliases are not included; see ``provider_aliases()``.
    """
    return tuple(sorted(_REGISTRY))


def provider_aliases() -> Dict[str, str]:
    """A copy of the alias table, mapping lowercased alias to provider name."""
    return dict(sorted(_ALIASES.items()))


def _get_headers(headers: Headers, name: str, *, required: bool = True) -> List[str]:
    """Return all values for a case-insensitive header name, preserving order."""
    target = name.lower()
    found: List[str] = []
    for key, value in headers.items():
        if not isinstance(key, str) or key.lower() != target:
            continue
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, (list, tuple)):
            found.extend(v for v in value if isinstance(v, str))
    if required and not found:
        raise HookVerifyError("missing_header", "missing required header: %s" % name)
    return found


def _one_header(headers: Headers, name: str, *, required: bool = True) -> Optional[str]:
    values = _get_headers(headers, name, required=required)
    if not values:
        return None
    if len(values) != 1:
        raise HookVerifyError("duplicate_header", "ambiguous duplicate header: %s" % name)
    value = values[0]
    if not isinstance(value, str) or not value.strip():
        raise HookVerifyError("missing_header", "empty header: %s" % name)
    return value


def _hmac_sha256(secret: str, payload: bytes) -> bytes:
    key = secret.encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).digest()


def _simple_hex_provider(
    header_name: str, prefix: Optional[str] = None
) -> Parser:
    def parser(headers: Headers, raw_body: bytes) -> ParsedMessage:
        value = _one_header(headers, header_name)
        assert value is not None
        text = value.strip()
        if prefix is not None:
            if not text.lower().startswith(prefix):
                raise HookVerifyError(
                    "invalid_signature", "%s must start with %s" % (header_name, prefix)
                )
            text = text[len(prefix):]
        candidate = decode_hex(text, header_name)
        return None, [candidate], raw_body

    return parser


def _github(headers: Headers, raw_body: bytes) -> ParsedMessage:
    return _simple_hex_provider("X-Hub-Signature-256", "sha256=")(headers, raw_body)


def _linear(headers: Headers, raw_body: bytes) -> ParsedMessage:
    return _simple_hex_provider("Linear-Signature")(headers, raw_body)


def _shopify(headers: Headers, raw_body: bytes) -> ParsedMessage:
    value = _one_header(headers, "X-Shopify-Hmac-Sha256")
    assert value is not None
    candidate = decode_base64(value.strip(), "X-Shopify-Hmac-Sha256")
    return None, [candidate], raw_body


def _slack(headers: Headers, raw_body: bytes) -> ParsedMessage:
    signature = _one_header(headers, "X-Slack-Signature")
    timestamp_text = _one_header(headers, "X-Slack-Request-Timestamp")
    assert signature is not None and timestamp_text is not None
    text = signature.strip()
    if not text.lower().startswith("v0="):
        raise HookVerifyError("invalid_signature", "Slack signature must start with v0=")
    candidate = decode_hex(text[3:], "X-Slack-Signature")
    timestamp = parse_timestamp(timestamp_text.strip(), "X-Slack-Request-Timestamp")
    payload = b"v0:" + str(timestamp).encode("ascii") + b":" + raw_body
    return timestamp, [candidate], payload


def _parse_key_value_header(value: str) -> List[Tuple[str, str]]:
    """Parse a comma-separated ``k=v`` provider header."""
    pairs: List[Tuple[str, str]] = []
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise HookVerifyError("invalid_signature", "malformed signature field: %s" % chunk)
        key, val = chunk.split("=", 1)
        pairs.append((key.strip().lower(), val.strip()))
    if not pairs:
        raise HookVerifyError("invalid_signature", "empty signature header")
    return pairs


def _stripe(headers: Headers, raw_body: bytes) -> ParsedMessage:
    value = _one_header(headers, "Stripe-Signature")
    assert value is not None
    pairs = _parse_key_value_header(value)
    timestamps = [v for k, v in pairs if k == "t"]
    if len(timestamps) != 1:
        raise HookVerifyError("invalid_timestamp", "Stripe header needs exactly one t value")
    timestamp = parse_timestamp(timestamps[0], "Stripe t")
    v1s = [v for k, v in pairs if k == "v1"]
    if not v1s:
        raise HookVerifyError("invalid_signature", "Stripe header needs at least one v1 value")
    candidates = [decode_hex(v, "Stripe v1") for v in v1s]
    payload = str(timestamp).encode("ascii") + b"." + raw_body
    return timestamp, candidates, payload


def _svix(headers: Headers, raw_body: bytes) -> ParsedMessage:
    message_id = _one_header(headers, "webhook-id")
    timestamp_text = _one_header(headers, "webhook-timestamp")
    signature_header = _one_header(headers, "webhook-signature")
    assert message_id is not None and timestamp_text is not None and signature_header is not None
    if not message_id.strip():
        raise HookVerifyError("missing_header", "empty webhook-id")
    timestamp = parse_timestamp(timestamp_text.strip(), "webhook-timestamp")
    candidates: List[bytes] = []
    # Standard Webhooks uses a space-separated list of "v1,<base64>" values.
    for chunk in signature_header.split():
        if "," not in chunk:
            raise HookVerifyError("invalid_signature", "malformed webhook-signature field")
        version, raw_sig = chunk.split(",", 1)
        if version.lower() != "v1":
            continue
        candidates.append(decode_base64(raw_sig, "webhook-signature"))
    if not candidates:
        raise HookVerifyError("invalid_signature", "no v1 webhook-signature found")
    payload = (
        message_id.strip().encode("utf-8")
        + b"."
        + str(timestamp).encode("ascii")
        + b"."
        + raw_body
    )
    return timestamp, candidates, payload


def _prepared_secret(secret: str, provider_name: str) -> str:
    if provider_name == "svix" and secret.startswith("whsec_"):
        return secret[len("whsec_"):]
    return secret


BUILTIN_PROVIDERS: Tuple[Provider, ...] = (
    Provider("github", _github, builtin=True),
    Provider("stripe", _stripe, builtin=True),
    Provider("slack", _slack, builtin=True),
    Provider("shopify", _shopify, builtin=True),
    Provider("linear", _linear, builtin=True),
    Provider("svix", _svix, builtin=True),
)

BUILTIN_ALIASES: Dict[str, str] = {
    "standard-webhooks": "svix",
}


def _install_builtins() -> None:
    for provider in BUILTIN_PROVIDERS:
        register_provider(provider)
    for alias, provider_name in BUILTIN_ALIASES.items():
        register_alias(alias, provider_name)


_install_builtins()
