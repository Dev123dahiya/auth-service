"""JSON Web Tokens signed with HMAC-SHA256, written out so every check is visible."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


class TokenError(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode_jwt(claims: dict, secret: bytes) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signature = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(signature)}"


def decode_jwt(token: str, secret: bytes, *, audience: str | None = None, issuer: str | None = None,
               now: float | None = None, leeway: float = 0.0) -> dict:
    """Verify a token and return its claims. Raises TokenError on any problem.

    Order matters: the algorithm is pinned and the signature is checked before
    any claim is trusted. The token's own header never chooses the algorithm,
    which is what defeats the "alg: none" and algorithm-confusion attacks.
    """
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(_unb64(header_b64))
        signature = _unb64(signature_b64)
    except (ValueError, TypeError):
        raise TokenError("malformed token") from None
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        raise TokenError("unsupported algorithm")
    expected = hmac.new(secret, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise TokenError("bad signature")
    try:
        claims = json.loads(_unb64(payload_b64))
    except (ValueError, TypeError):
        raise TokenError("malformed token") from None
    if not isinstance(claims, dict):
        raise TokenError("malformed token")
    now = time.time() if now is None else now
    if "exp" not in claims:
        raise TokenError("token has no expiry")
    if now >= claims["exp"] + leeway:
        raise TokenError("token expired")
    if "nbf" in claims and now < claims["nbf"] - leeway:
        raise TokenError("token not yet valid")
    if audience is not None and claims.get("aud") != audience:
        raise TokenError("wrong audience")
    if issuer is not None and claims.get("iss") != issuer:
        raise TokenError("wrong issuer")
    return claims
