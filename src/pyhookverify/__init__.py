"""pyhookverify: zero-dependency HMAC webhook verification and replay defense.

Typical use::

    from pyhookverify import WebhookVerifier, HookVerifyError

    verifier = WebhookVerifier(secrets=["current", "previous"], provider="github")
    try:
        result = verifier.verify(dict(request.headers), request.body)
    except HookVerifyError as exc:
        return {"error": exc.code}, 401
"""

from .core import MAX_CANDIDATE_SIGNATURES, WebhookVerifier
from .encoding import ct_equal, decode_base64, decode_hex, parse_timestamp
from .errors import HookVerifyError, Headers, HeaderValue, ReplayStore, VerificationResult
from .providers import (
    BUILTIN_ALIASES,
    BUILTIN_PROVIDERS,
    Provider,
    get_provider,
    provider_aliases,
    register_alias,
    register_provider,
    registered_providers,
)
from .replay import MemoryReplayStore, NullReplayStore

__version__ = "0.1.0"

__all__ = [
    "WebhookVerifier",
    "HookVerifyError",
    "VerificationResult",
    "ReplayStore",
    "MemoryReplayStore",
    "NullReplayStore",
    "Provider",
    "register_provider",
    "get_provider",
    "registered_providers",
    "register_alias",
    "provider_aliases",
    "BUILTIN_PROVIDERS",
    "BUILTIN_ALIASES",
    "decode_hex",
    "decode_base64",
    "parse_timestamp",
    "ct_equal",
    "Headers",
    "HeaderValue",
    "MAX_CANDIDATE_SIGNATURES",
    "__version__",
]
