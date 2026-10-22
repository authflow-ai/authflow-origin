# SPDX-License-Identifier: Apache-2.0
"""Copy this entire file. Python 3.11+; install ``cryptography`` for Ed25519.

Create one OriginVerifier for the life of the process. Configure issuer/resource
from the registration receipt, never from the inbound request. Before dispatching
every MCP request, call ``await verifier.verify(identity_header_values)`` with ALL
raw X-Authflow-Identity field values (case-insensitive name). For ASGI:
``[v.decode('latin-1') for k, v in scope['headers']
   if k.lower() == b'x-authflow-identity']``.

On OriginVerificationError, respond with its status_code, headers, and body at
the HTTP layer; do not dispatch MCP or add WWW-Authenticate. Trust only the
returned identity, for this request. Keep the origin's ingress behind Authflow.

Supply a ReplayStore whose claim is an ATOMIC insert-if-absent, shared by every
replica, retaining the key until retain_until (UTC Unix seconds). Redis SET NX
with an expiry or a database unique insert works; a get followed by put does not.
Store failure must raise an exception. No process-local or fail-open fallback is
provided. For asyncio servers, the store must be asynchronous and non-blocking.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
import ipaddress
import json
import math
import re
import time
from typing import Protocol
import urllib.error
import urllib.request
from urllib.parse import unquote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROTOCOL_VERSION = "v1"
VERIFIER_VERSION = "1.0.1"
MAX_HEADER_BYTES = 16_384
MAX_KEY_DOCUMENT_BYTES = 65_536
_KID = re.compile(r"[A-Za-z0-9._-]{1,64}")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_TIER = re.compile(r"[a-z][a-z0-9_]{0,63}")
_NONCE = re.compile(r"[A-Za-z0-9_-]{16,64}")
_FORBIDDEN = frozenset(("credits", "credit_balance", "balance", "remaining",
                        "remaining_credits", "quota", "units_remaining"))


class ReplayStore(Protocol):
    async def claim(self, key: str, retain_until: int) -> bool:
        """Atomically insert key until retain_until; True=new, False=replay.

        All replicas for the configured resource must use the same namespace.
        Raise on unavailable storage; never report True without durable storage.
        """
        ...


@dataclass(frozen=True)
class VerifiedIdentity:
    sub: str
    resource: str
    tier: str
    nonce: str
    iat: int
    exp: int


class OriginVerificationError(Exception):
    """A complete safe HTTP rejection; never a JSON-RPC result or a 401."""

    status_code = 403

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
        self.headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "X-Authflow-Verifier": f"python/{VERIFIER_VERSION}",
        }
        self.body = {
            "error": "invalid_origin_identity",
            "error_code": code,
            "error_description": "Request does not carry a valid Authflow origin identity.",
        }


def _decode(token: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        raise ValueError("Invalid base64url")
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != token:
        raise ValueError("Noncanonical base64url")
    return raw


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("Non-JSON numeric constant")


def _json_object(raw: bytes) -> dict:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("JSON BOM")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                       parse_constant=_invalid_constant)
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object")
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > 64:
            raise ValueError("JSON nesting limit")
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        stack.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))
    return value


def _valid_url(value: str, *, issuer: bool, canonical: bool) -> bool:
    try:
        if not isinstance(value, str) or not value or any(ord(c) <= 32 for c in value):
            return False
        if any(c in value for c in "\\?#@") or value.endswith("/"):
            return False
        url = urlsplit(value)
        host = url.hostname
        if not host or url.scheme not in ("https", "http") or not url.netloc:
            return False
        if url.scheme == "http":
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = host.lower() == "localhost"
            if not loopback:
                return False
        if issuer and url.path:
            return False
        port = url.port  # Also validates the port range.
        if canonical:
            authority = f"[{host}]" if ":" in host else host
            if port is not None:
                if port == (443 if url.scheme == "https" else 80):
                    return False
                authority += f":{port}"
            if value != f"{url.scheme}://{authority}{url.path}":
                return False
            if any(segment in (".", "..") for segment in unquote(url.path).split("/")):
                return False
            if re.search(r"%(?![0-9A-Fa-f]{2})", url.path):
                return False
        return True
    except (ValueError, UnicodeError):
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_keys(url: str) -> bytes:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    deadline = time.monotonic() + 5
    try:
        response = opener.open(request, timeout=5)
    except urllib.error.HTTPError as error:
        error.close()
        raise ValueError("Key endpoint failed") from None
    with response:
        if response.status != 200:
            raise ValueError("Key endpoint failed")
        raw = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Key endpoint timed out")
            chunk = response.read1(min(4096, MAX_KEY_DOCUMENT_BYTES + 1 - len(raw)))
            if not chunk:
                return bytes(raw)
            raw.extend(chunk)
            if len(raw) > MAX_KEY_DOCUMENT_BYTES:
                raise ValueError("Key document too large")


async def _fetch_keys(url: str) -> bytes:
    return await asyncio.wait_for(asyncio.to_thread(_read_keys, url), timeout=5)


class OriginVerifier:
    def __init__(self, *, issuer: str, resource: str, replay_store: ReplayStore,
                 fetch_keys: Callable[[str], Awaitable[bytes]] = _fetch_keys,
                 clock: Callable[[], float] = time.time):
        """fetch_keys, when supplied, must fetch this URL with TLS verification,
        reject redirects/non-success responses and return at most 64 KiB in 5s.
        Reuse the verifier within one asyncio event loop; warm it at startup.
        """
        if not _valid_url(issuer, issuer=True, canonical=True):
            raise ValueError("Copy the canonical issuer from the registration receipt")
        if not _valid_url(resource, issuer=False, canonical=True):
            raise ValueError("Copy the canonical resource from the registration receipt")
        if not callable(getattr(replay_store, "claim", None)):
            raise ValueError("An atomic replay store is required")
        self.issuer, self.resource = issuer, resource
        self._replay, self._fetch, self._clock = replay_store, fetch_keys, clock
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._fetched_at = -math.inf
        self._last_attempt = -math.inf
        self._attempts = 0
        self._forced: list[tuple[str, float]] = []
        self._lock = asyncio.Lock()

    async def warm(self) -> None:
        """Fetch keys before accepting traffic. Raises if none are usable."""
        await self._refresh()
        if not self._keys:
            raise OriginVerificationError("keys_unavailable")

    async def _refresh(self, kid: str | None = None) -> None:
        attempts = self._attempts
        async with self._lock:
            if attempts != self._attempts:
                return
            now = self._clock()
            if kid is not None:
                self._forced = [(k, at) for k, at in self._forced if now - at < 30]
                if len(self._forced) >= 3 or any(k == kid for k, _ in self._forced):
                    return
            elif now - self._last_attempt < 30:
                return
            try:
                raw = await asyncio.wait_for(
                    self._fetch(self.issuer + "/.well-known/authflow-origin-keys"), timeout=5)
                if not isinstance(raw, bytes) or len(raw) > MAX_KEY_DOCUMENT_BYTES:
                    raise ValueError("Invalid key response")
                document = _json_object(raw)
                keys = document.get("keys")
                if (document.get("issuer") != self.issuer or document.get("protocol_version") != "v1"
                        or not isinstance(keys, list) or not 1 <= len(keys) <= 128):
                    raise ValueError("Invalid key document")
                parsed = {}
                seen = set()
                for jwk in keys:
                    if not isinstance(jwk, dict) or "d" in jwk:
                        raise ValueError("Invalid public key")
                    key_id = jwk.get("kid")
                    if isinstance(key_id, str):
                        if key_id in seen:
                            raise ValueError("Duplicate kid")
                        seen.add(key_id)
                    if (jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519"
                            or jwk.get("use") != "sig" or jwk.get("alg") != "EdDSA"
                            or not isinstance(key_id, str) or not _KID.fullmatch(key_id)
                            or not isinstance(jwk.get("x"), str)):
                        continue
                    try:
                        public_key = _decode(jwk["x"])
                        parsed[key_id] = Ed25519PublicKey.from_public_bytes(public_key)
                    except ValueError:
                        continue
                if not parsed:
                    raise ValueError("No usable v1 key")
                self._keys, self._fetched_at = parsed, self._clock()
            except Exception:
                # A failed refresh never discards a last-good document (§5.3).
                pass
            self._last_attempt = now
            self._attempts += 1
            if kid is not None:
                self._forced.append((kid, now))

    async def _resolve(self, kid: str) -> Ed25519PublicKey:
        if not self._keys or self._clock() - self._fetched_at > 300:
            await self._refresh()
        if not self._keys:
            raise OriginVerificationError("keys_unavailable")
        if kid not in self._keys:
            await self._refresh(kid)
        if kid not in self._keys:
            raise OriginVerificationError("unknown_key")
        return self._keys[kid]

    async def verify(self, header_values: Sequence[str]) -> VerifiedIdentity:
        """Pass all raw identity field values; an absent header is an empty list."""
        if isinstance(header_values, str) or len(header_values) != 1:
            raise OriginVerificationError("missing_identity")
        raw = header_values[0]
        if not isinstance(raw, str) or not raw.strip() or "," in raw:
            raise OriginVerificationError("missing_identity")
        raw = raw.strip()
        if len(raw) > MAX_HEADER_BYTES:
            raise OriginVerificationError("malformed_identity")
        parts = raw.split(";")
        if len(parts) != 3 or not all(parts):
            raise OriginVerificationError("malformed_identity")
        version, claims_token, signature_token = parts
        if version != "v1":
            raise OriginVerificationError("unsupported_version")
        try:
            claims = _json_object(_decode(claims_token))
            signature = _decode(signature_token)
            if len(signature) != 64:
                raise ValueError("Signature length")
            kid = claims.get("kid")
            if not isinstance(kid, str) or not _KID.fullmatch(kid):
                raise ValueError("Invalid kid")
        except (ValueError, UnicodeError, RecursionError):
            raise OriginVerificationError("malformed_identity") from None
        key = await self._resolve(kid)
        try:
            key.verify(signature, ("v1;" + claims_token).encode("ascii"))
        except InvalidSignature:
            raise OriginVerificationError("bad_signature") from None
        stack = [claims]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                if _FORBIDDEN.intersection(item):
                    raise OriginVerificationError("forbidden_claim")
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        if (any(not isinstance(claims.get(name), str)
                for name in ("iss", "sub", "resource", "tier", "nonce"))
                or any(type(claims.get(name)) is not int or not -(2**63) <= claims[name] < 2**63
                       for name in ("iat", "exp"))):
            raise OriginVerificationError("malformed_identity")
        if (not _valid_url(claims["iss"], issuer=True, canonical=False)
                or not _UUID.fullmatch(claims["sub"])
                or claims["sub"] == "00000000-0000-0000-0000-000000000000"
                or not _TIER.fullmatch(claims["tier"])
                or not _NONCE.fullmatch(claims["nonce"]) or not claims["resource"]):
            raise OriginVerificationError("malformed_identity")
        if claims["iss"] != self.issuer:
            raise OriginVerificationError("iss_mismatch")
        if claims["resource"] != self.resource:
            raise OriginVerificationError("resource_mismatch")
        iat, exp = claims["iat"], claims["exp"]
        if exp <= iat or exp - iat > 300:
            raise OriginVerificationError("malformed_identity")
        now = int(self._clock())
        if now > exp + 60:
            raise OriginVerificationError("expired")
        if iat > now + 60:
            raise OriginVerificationError("not_yet_valid")
        nonce_key = json.dumps([self.issuer, self.resource, claims["nonce"]],
                               ensure_ascii=False, separators=(",", ":"))
        try:
            recorded = await asyncio.wait_for(
                self._replay.claim(nonce_key, max(now + 180, exp + 61)), timeout=5)
        except Exception:
            raise OriginVerificationError("replay_cache_unavailable") from None
        if recorded is not True:
            raise OriginVerificationError("replayed_nonce" if recorded is False else "replay_cache_unavailable")
        return VerifiedIdentity(claims["sub"], claims["resource"], claims["tier"], claims["nonce"], iat, exp)
