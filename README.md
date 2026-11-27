# pyhookverify

Zero-dependency HMAC webhook signature verification and replay protection for Python 3.9+.

`pyhookverify` verifies webhook signatures over the exact bytes received on the wire. It uses only the Python standard library, compares signatures in constant time after a length check, and consumes replay keys only after a signature has been cryptographically verified.

## Install

```bash
pip install pyhookverify
```

No runtime dependencies. Python 3.9 through 3.13 are supported.

## Quick start

```python
from pyhookverify import HookVerifyError, WebhookVerifier

verifier = WebhookVerifier(
    secrets=["current-secret", "previous-secret"],
    provider="github",
)

def handle_request(request):
    try:
        result = verifier.verify(dict(request.headers), request.body)
    except HookVerifyError as exc:
        return {"error": exc.code}, 401
    return process(request.body), 200
```

Always pass the raw request body (`bytes`, `bytearray`, or `memoryview`). Passing a parsed `dict`, `list`, `int`, or re-serialized JSON string raises `HookVerifyError` with code `invalid_body`. This prevents verification against bytes that differ from what the provider signed.

## Built-in providers

| Provider name | Header(s) | Signature format |
| --- | --- | --- |
| `github` | `X-Hub-Signature-256` | `sha256=<hex>` |
| `stripe` | `Stripe-Signature` | `t=<unix>,v1=<hex>[,v1=<hex>...]` |
| `slack` | `X-Slack-Signature`, `X-Slack-Request-Timestamp` | `v0=<hex>` over `v0:<ts>:<body>` |
| `shopify` | `X-Shopify-Hmac-Sha256` | base64 HMAC-SHA256 |
| `linear` | `Linear-Signature` | hex HMAC-SHA256 |
| `svix` | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `v1,<base64>` list, `whsec_` secret prefix |

Provider names are case-insensitive. Header names are normalized case-insensitively; a duplicate or ambiguous signature header is rejected with `duplicate_header`.

### Provider aliases

| Alias | Resolves to |
| --- | --- |
| `standard-webhooks` | `svix` |

An alias is another name for a registered provider. Alias lookup is case-insensitive, and a verifier built from an alias behaves exactly like the canonical provider: `WebhookVerifier(["secret"], "standard-webhooks").provider` is `"svix"`, and `VerificationResult.provider` reports `"svix"`.

```python
from pyhookverify import provider_aliases, register_alias, registered_providers

register_alias("acme-hooks", "svix")
print(provider_aliases())      # {'acme-hooks': 'svix', 'standard-webhooks': 'svix'}
print(registered_providers())  # canonical provider names only, aliases excluded
```

Registering an alias that is already bound raises `duplicate_provider` unless `replace=True` is passed. An alias can never share a name with a registered provider, in either direction, and its target must already be registered.

## Framework examples

### FastAPI

```python
from fastapi import FastAPI, Request
from pyhookverify import HookVerifyError, WebhookVerifier

app = FastAPI()
verifier = WebhookVerifier(["secret"], "github")

@app.post("/webhooks/github")
async def github_webhook(request: Request):
    try:
        verifier.verify(dict(request.headers), await request.body())
    except HookVerifyError as exc:
        return {"error": exc.code}, 401
    return {"ok": True}
```

### Django

```python
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from pyhookverify import HookVerifyError, WebhookVerifier

verifier = WebhookVerifier(["secret"], "stripe")

@csrf_exempt
def stripe_webhook(request):
    try:
        verifier.verify(dict(request.headers), request.body)
    except HookVerifyError as exc:
        return HttpResponse(exc.code, status=401)
    return HttpResponse("ok")
```

### Flask

```python
from flask import Flask, request
from pyhookverify import HookVerifyError, WebhookVerifier

app = Flask(__name__)
verifier = WebhookVerifier(["secret"], "shopify")

@app.post("/webhooks/shopify")
def shopify_webhook():
    try:
        verifier.verify(dict(request.headers), request.get_data())
    except HookVerifyError as exc:
        return {"error": exc.code}, 401
    return {"ok": True}
```

### Starlette

```python
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from pyhookverify import HookVerifyError, WebhookVerifier

app = Starlette()
verifier = WebhookVerifier(["secret"], "svix")

async def svix_webhook(request: Request):
    try:
        verifier.verify(dict(request.headers), await request.body())
    except HookVerifyError as exc:
        return JSONResponse({"error": exc.code}, status_code=401)
    return JSONResponse({"ok": True})

app.add_route("/webhooks/svix", svix_webhook, methods=["POST"])
```

## Key rotation and replay defense

Pass a sequence of secrets. Each is tried in order; `VerificationResult.secret_index` tells you which one matched.

Multi-signature headers (Stripe and Standard Webhooks allow several `v1` values) are handled safely. After a signature matches any configured secret, **every** candidate that matches **any** secret is recorded in the replay store. Replaying the same delivery with a subset of signatures cannot bypass replay protection.

Replay keys are written only after cryptographic verification succeeds. Invalid signatures, malformed headers, stale timestamps, and wrong secrets never poison the replay cache.

`MemoryReplayStore` is bounded by `ttl_seconds` and `max_entries`, and purges expired entries on each check. The oldest entry is evicted at capacity. The store serializes check-and-store and purge behind a reentrant lock, so concurrent request threads cannot both consume the same key and a purge cannot race a resize. A strict cap of 32 candidate signatures per request limits parsing and comparison work.

## Strict encoding rules

* Hex must be non-empty, even-length, and contain only `0-9a-fA-F`. No `0x` prefix, whitespace, or Unicode digits.
* Base64 must be canonical RFC 4648 with correct padding and zero padding bits. Re-encoding must reproduce the input exactly. URL-safe characters and whitespace are rejected.
* Timestamps must be strict base-10 positive integers. Floats, signs, exponents, Unicode digits, and runs longer than 19 digits are rejected before integer conversion, so a multi-megabyte digit string cannot trigger the CPython 3.11+ conversion error or quadratic parsing.
* A tolerance window (default 300 seconds) rejects both stale and excessive future skew. The clock is injectable for deterministic tests.

All comparisons use `hmac.compare_digest` on decoded, equal-length `bytes` only.

## Custom providers

```python
from pyhookverify import Provider, WebhookVerifier, register_provider

def parse_acme(headers, raw_body):
    sig = headers["X-Acme-Signature"]
    from pyhookverify import decode_hex
    return None, [decode_hex(sig)], raw_body

register_provider(Provider("acme", parse_acme))
verifier = WebhookVerifier(["secret"], "acme")
```

A parser returns `(timestamp_or_None, [candidate_bytes, ...], signing_payload_bytes)`.

## Error codes

| Code | Meaning |
| --- | --- |
| `invalid_body` | Body was not `bytes`, `bytearray`, or `memoryview` |
| `invalid_headers` | Headers were not a mapping |
| `invalid_signature` | No candidate matched any secret |
| `replay` | Signature already consumed |
| `stale_timestamp` / `future_timestamp` | Timestamp outside tolerance |
| `invalid_timestamp` | Malformed timestamp value |
| `invalid_encoding` | Malformed hex or base64 |
| `duplicate_header` | Ambiguous duplicate signature header |
| `missing_header` | Required header absent or empty |
| `too_many_signatures` | More than 32 candidate signatures |
| `invalid_secret` / `invalid_config` | Misconfigured verifier or store |
| `unknown_provider` / `duplicate_provider` | Registry errors |

## Threat model

`pyhookverify` protects the authenticity and freshness of a webhook delivery. It assumes the configured secrets are stored safely and delivered out of band. It does not validate the semantics of the payload, authorize the sender beyond HMAC possession, encrypt data, or replace TLS. Keep HTTPS enabled, rotate secrets on exposure, and use a persistent replay store if you run multiple processes or need replay defense across restarts.

The in-memory replay store is per-process and bounded. Under a valid-signature flood it evicts the oldest entries; an attacker without a valid HMAC cannot cause eviction or cache writes.

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

188 deterministic tests cover all six providers, provider aliases, strict hex and base64 rejection, timestamp edges, key rotation, multi-signature replay bypass attempts, pre-auth store poisoning, raw-body type enforcement, replay-store caps and concurrency, and header normalization.

## License

MIT. See [LICENSE](LICENSE).
