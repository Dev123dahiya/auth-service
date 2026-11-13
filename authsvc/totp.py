"""Time-based one-time passwords (RFC 6238), the codes authenticator apps show."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time


def new_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    return base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))


def totp(secret: str, at: float | None = None, step: int = 30, digits: int = 6, algorithm: str = "sha1") -> str:
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(_key(secret), struct.pack(">Q", counter), getattr(hashlib, algorithm)).digest()
    offset = mac[-1] & 0x0F                                            # dynamic truncation (RFC 4226)
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** digits
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, at: float | None = None, window: int = 1, step: int = 30, last_used_counter: int | None = None) -> int | None:
    """Return the matching time-step counter, or None.

    ``window`` accepts codes one step either side to tolerate clock drift.
    ``last_used_counter`` makes each code single-use: a code at or before the
    last accepted step is refused, so one shoulder-surfed code cannot be replayed.
    """
    at = time.time() if at is None else at
    if not (isinstance(code, str) and code.isdigit()):
        return None
    current = int(at // step)
    for counter in range(current - window, current + window + 1):
        if last_used_counter is not None and counter <= last_used_counter:
            continue
        if hmac.compare_digest(totp(secret, counter * step, step, len(code)), code):
            return counter
    return None


def provisioning_uri(secret: str, account: str, issuer: str) -> str:
    """The otpauth:// link an authenticator app reads from a QR code."""
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
