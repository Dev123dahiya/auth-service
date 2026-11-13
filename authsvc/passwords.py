"""Password storage with scrypt: slow and memory-hard on purpose, so stolen hashes are expensive to crack."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

N, R, P = 2 ** 14, 8, 1      # work factors; stored with each hash so they can be raised later


def hash_password(password: str, n: int = N) -> str:
    salt = os.urandom(16)    # unique per password: identical passwords get different hashes
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=R, p=P, dklen=32)
    return f"scrypt${n}${R}${P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)     # constant time: no timing hint about how many bytes matched


def needs_rehash(stored: str, n: int = N) -> bool:
    """True when a hash was made with weaker settings than today's; rehash it at the next successful login."""
    try:
        return int(stored.split("$")[1]) < n
    except (IndexError, ValueError):
        return True
