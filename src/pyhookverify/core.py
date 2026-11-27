"""Core verifier: provider dispatch, constant-time HMAC check, and replay defense."""

import hmac
import hashlib
from typing import Callable, Optional, Sequence

from .encoding import ct_equal, current_time, is_blank
from .errors import HookVerifyError, Headers, ReplayStore, VerificationResult
from .providers import _prepared_secret, get_provider
from .replay import MemoryReplayStore

MAX_CANDIDATE_SIGNATURES = 32

__all__ = ["WebhookVerifier"]


class WebhookVerifier:
    """Verify webhook signatures over an exact raw request body.

    Args:
        secrets: Rotation list of shared secrets. Each is tried in order.
        provider: Registered provider name (github, stripe, slack, shopify,
            linear, svix, or a custom provider) or alias such as
            ``standard-webhooks``. Aliases resolve to the canonical provider.
        replay_store: Store that enforces one-time consumption. Defaults to a
            bounded in-memory store.
        tolerance_seconds: Maximum accepted past/future timestamp skew.
        clock: Zero-argument callable returning POSIX seconds.
        max_candidate_signatures: Hard cap on signature values per request.
    """

    def __init__(
        self,
        secrets: Sequence[str],
        provider: str,
        replay_store: Optional[ReplayStore] = None,
        tolerance_seconds: int = 300,
        clock: Optional[Callable[[], float]] = None,
        max_candidate_signatures: int = MAX_CANDIDATE_SIGNATURES,
    ) -> None:
        if isinstance(secrets, (str, bytes, bytearray)) or not isinstance(secrets, Sequence):
            raise HookVerifyError("invalid_config", "secrets must be a sequence of strings")
        if not secrets:
            raise HookVerifyError("invalid_config", "at least one secret is required")
        prepared = []
        for index, secret in enumerate(secrets):
            if not isinstance(secret, str) or is_blank(secret):
                raise HookVerifyError("invalid_secret", "secret %d is empty or not a string" % index)
            prepared.append(secret)
        self._secrets = tuple(prepared)
        if not isinstance(max_candidate_signatures, int) or isinstance(max_candidate_signatures, bool):
            raise HookVerifyError("invalid_config", "max_candidate_signatures must be an integer")
        if max_candidate_signatures < 1 or max_candidate_signatures > MAX_CANDIDATE_SIGNATURES:
            raise HookVerifyError("invalid_config", "max_candidate_signatures must be 1..32")
        self.max_candidate_signatures = max_candidate_signatures
        if not isinstance(tolerance_seconds, int) or isinstance(tolerance_seconds, bool):
            raise HookVerifyError("invalid_config", "tolerance_seconds must be an integer")
        if tolerance_seconds < 0 or tolerance_seconds > 86400:
            raise HookVerifyError("invalid_config", "tolerance_seconds must be 0..86400")
        self.tolerance_seconds = tolerance_seconds
        self._provider = get_provider(provider)
        self.provider = self._provider.name
        self._clock = clock if clock is not None else current_time
        if not callable(self._clock):
            raise HookVerifyError("invalid_config", "clock must be callable")
        self.replay_store = replay_store if replay_store is not None else MemoryReplayStore(
            clock=self._clock
        )
        if not isinstance(self.replay_store, ReplayStore):
            raise HookVerifyError("invalid_config", "replay_store must implement ReplayStore")

    def _now(self) -> float:
        return float(self._clock())

    def _check_timestamp(self, timestamp: Optional[int], now: float) -> None:
        if timestamp is None:
            return
        if timestamp > 2 ** 63 - 1:
            raise HookVerifyError("invalid_timestamp", "timestamp is out of range")
        skew = abs(now - float(timestamp))
        if skew > float(self.tolerance_seconds):
            if timestamp > now:
                raise HookVerifyError("future_timestamp", "timestamp is too far in the future")
            raise HookVerifyError("stale_timestamp", "timestamp is too old")

    def verify(self, headers: Headers, raw_body: bytes) -> VerificationResult:
        """Verify a request or raise ``HookVerifyError``.

        ``raw_body`` must be ``bytes``, ``bytearray``, or ``memoryview``. Never
        pass a parsed dict, list, or re-serialized JSON: the exact bytes on the
        wire are the only valid HMAC input.
        """
        if not isinstance(headers, dict) and not hasattr(headers, "items"):
            raise HookVerifyError("invalid_headers", "headers must be a mapping")
        if isinstance(raw_body, (bytes, bytearray, memoryview)):
            body = bytes(raw_body)
        else:
            raise HookVerifyError(
                "invalid_body",
                "raw_body must be bytes, bytearray, or memoryview, not %s"
                % type(raw_body).__name__,
            )

        timestamp, candidates, payload = self._provider.parse(headers, body)
        if len(candidates) > self.max_candidate_signatures:
            raise HookVerifyError(
                "too_many_signatures",
                "at most %d candidate signatures are allowed" % self.max_candidate_signatures,
            )
        self._check_timestamp(timestamp, self._now())

        matched_index: Optional[int] = None
        matched_signature: Optional[bytes] = None
        for secret_index, secret in enumerate(self._secrets):
            prepared = _prepared_secret(secret, self.provider)
            digest = hmac.new(prepared.encode("utf-8"), payload, hashlib.sha256).digest()
            for candidate in candidates:
                # Length filtering happens before the constant-time primitive.
                if ct_equal(digest, candidate):
                    matched_index = secret_index
                    matched_signature = candidate
                    break
            if matched_index is not None:
                break

        if matched_index is None or matched_signature is None:
            raise HookVerifyError("invalid_signature", "no signature matched any configured secret")

        # Only post-auth do we touch replay state. Every candidate that matched
        # ANY configured secret is consumed. This stops an attacker from
        # replaying a multi-v1 header with a subset of signatures under key
        # rotation, or swapping which secret a signature belongs to.
        canonical = matched_signature.hex()
        # Include a digest of the signing payload so that the same signature
        # bytes on two different messages never share a replay key.
        payload_tag = hashlib.sha256(payload).hexdigest()
        keys = ["%s:%s:%s:%s" % (self.provider, matched_index, canonical, payload_tag)]
        for secret_index, secret in enumerate(self._secrets):
            prepared = _prepared_secret(secret, self.provider)
            digest = hmac.new(prepared.encode("utf-8"), payload, hashlib.sha256).digest()
            for candidate in candidates:
                if not ct_equal(digest, candidate):
                    continue
                key = "%s:%s:%s:%s" % (
                    self.provider, secret_index, candidate.hex(), payload_tag
                )
                if key not in keys:
                    keys.append(key)
        now = self._now()
        for key in keys:
            self.replay_store.check_and_store(key, now)

        return VerificationResult(
            provider=self.provider,
            secret_index=matched_index,
            timestamp=timestamp,
            signature=canonical,
        )

    # Explicit alias for framework adapters that prefer a verb-first name.
    verify_request = verify
