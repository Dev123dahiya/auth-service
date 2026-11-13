from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from typing import Callable

from .passwords import hash_password, needs_rehash, verify_password
from .tokens import TokenError, decode_jwt, encode_jwt
from .totp import new_secret, verify_totp

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer',
    totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, totp_last_counter INTEGER,
    failed_logins INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0, token_version INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, family TEXT NOT NULL, expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (at REAL, user_id INTEGER, event TEXT, detail TEXT);
"""

ROLES = {
    "viewer": {"reports:read"},
    "editor": {"reports:read", "reports:write"},
    "admin": {"reports:read", "reports:write", "users:manage"},
}
# Burned once at import so a login for an unknown email takes as long as one for a real account.
_DUMMY_HASH = hash_password("not-a-real-password")


class AuthError(Exception):
    """Authentication or authorisation failed. ``code`` is safe to show; details stay in the audit log."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class AuthService:
    def __init__(self, db_path: str, secret: bytes, *, clock: Callable[[], float] = time.time, access_ttl: int = 900,
                 refresh_ttl: int = 30 * 86400, max_failed_logins: int = 5, lockout_seconds: int = 900, issuer: str = "authsvc") -> None:
        if len(secret) < 32:
            raise ValueError("signing secret must be at least 32 bytes")
        self.db = sqlite3.connect(db_path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self._secret, self._clock, self.issuer = secret, clock, issuer
        self.access_ttl, self.refresh_ttl = access_ttl, refresh_ttl
        self.max_failed_logins, self.lockout_seconds = max_failed_logins, lockout_seconds

    def _audit(self, user_id, event: str, detail: str = "") -> None:
        self.db.execute("INSERT INTO audit VALUES (?, ?, ?, ?)", (self._clock(), user_id, event, detail))

    # ---- accounts --------------------------------------------------------
    def register(self, email: str, password: str, role: str = "viewer") -> int:
        email = email.strip().lower()
        if "@" not in email or len(email) > 254:
            raise AuthError("invalid_email")
        if len(password) < 12:
            raise AuthError("password_too_short")
        if role not in ROLES:
            raise AuthError("unknown_role")
        try:
            cur = self.db.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", (email, hash_password(password), role))
        except sqlite3.IntegrityError:
            raise AuthError("email_taken") from None
        self._audit(cur.lastrowid, "registered")
        return cur.lastrowid

    def enable_totp(self, user_id: int) -> str:
        """Start two-factor enrolment. Returns the secret to show as a QR code; it is active after confirm_totp."""
        secret = new_secret()
        self.db.execute("UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?", (secret, user_id))
        return secret

    def confirm_totp(self, user_id: int, code: str) -> None:
        row = self.db.execute("SELECT totp_secret FROM users WHERE id = ?", (user_id,)).fetchone()
        counter = verify_totp(row["totp_secret"], code, self._clock()) if row and row["totp_secret"] else None
        if counter is None:
            raise AuthError("invalid_code")
        self.db.execute("UPDATE users SET totp_enabled = 1, totp_last_counter = ? WHERE id = ?", (counter, user_id))
        self._audit(user_id, "totp_enabled")

    # ---- login -----------------------------------------------------------
    def login(self, email: str, password: str, totp_code: str | None = None) -> dict:
        """Check credentials and issue tokens.

        Unknown email and wrong password give the same error and take the same
        time, so the endpoint cannot be used to discover which emails have accounts.
        """
        now = self._clock()
        user = self.db.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
        if user is None:
            verify_password(password, _DUMMY_HASH)
            raise AuthError("invalid_credentials")
        if user["locked_until"] > now:
            self._audit(user["id"], "login_blocked", "account locked")
            raise AuthError("account_locked")
        if not verify_password(password, user["password_hash"]):
            failed = user["failed_logins"] + 1
            locked = now + self.lockout_seconds if failed >= self.max_failed_logins else 0
            self.db.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?", (0 if locked else failed, locked, user["id"]))
            self._audit(user["id"], "login_failed", "locked" if locked else f"attempt {failed}")
            raise AuthError("invalid_credentials")
        if user["totp_enabled"]:
            if totp_code is None:
                raise AuthError("totp_required")
            counter = verify_totp(user["totp_secret"], totp_code, now, last_used_counter=user["totp_last_counter"])
            if counter is None:
                self._audit(user["id"], "login_failed", "bad or reused TOTP code")
                raise AuthError("invalid_code")
            self.db.execute("UPDATE users SET totp_last_counter = ? WHERE id = ?", (counter, user["id"]))
        if needs_rehash(user["password_hash"]):
            self.db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user["id"]))
        self.db.execute("UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?", (user["id"],))
        self._audit(user["id"], "login_succeeded")
        return self._issue(user["id"], secrets.token_hex(8))

    def _issue(self, user_id: int, family: str) -> dict:
        now = self._clock()
        user = self.db.execute("SELECT role, token_version FROM users WHERE id = ?", (user_id,)).fetchone()
        access = encode_jwt({"sub": str(user_id), "role": user["role"], "ver": user["token_version"], "iss": self.issuer,
                             "aud": "api", "iat": int(now), "exp": int(now + self.access_ttl)}, self._secret)
        refresh = secrets.token_urlsafe(32)
        # Only a hash of the refresh token is stored: a leaked database does not hand out working sessions.
        self.db.execute("INSERT INTO refresh_tokens (token_hash, user_id, family, expires_at) VALUES (?, ?, ?, ?)",
                        (hashlib.sha256(refresh.encode()).hexdigest(), user_id, family, now + self.refresh_ttl))
        return {"access_token": access, "refresh_token": refresh, "expires_in": self.access_ttl}

    def refresh(self, refresh_token: str) -> dict:
        """Exchange a refresh token for a new pair. Each refresh token works exactly once.

        If a token that was already used shows up again, either the user or an
        attacker is replaying a stolen copy. The two cannot be told apart, so the
        whole family of tokens descended from that login is revoked and both
        parties have to sign in again.
        """
        now = self._clock()
        row = self.db.execute("SELECT * FROM refresh_tokens WHERE token_hash = ?", (hashlib.sha256(refresh_token.encode()).hexdigest(),)).fetchone()
        if row is None or row["revoked"]:
            raise AuthError("invalid_refresh_token")
        if row["used"]:
            self.db.execute("UPDATE refresh_tokens SET revoked = 1 WHERE family = ?", (row["family"],))
            self._audit(row["user_id"], "refresh_reuse_detected", f"family {row['family']} revoked")
            raise AuthError("refresh_token_reused")
        if row["expires_at"] <= now:
            raise AuthError("invalid_refresh_token")
        self.db.execute("UPDATE refresh_tokens SET used = 1 WHERE token_hash = ?", (row["token_hash"],))
        return self._issue(row["user_id"], row["family"])

    def logout_everywhere(self, user_id: int) -> None:
        """Revoke every session: refresh tokens die now, and access tokens are refused via the version claim."""
        self.db.execute("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
        self.db.execute("UPDATE users SET token_version = token_version + 1 WHERE id = ?", (user_id,))
        self._audit(user_id, "logout_everywhere")

    # ---- authorisation ---------------------------------------------------
    def authenticate(self, access_token: str) -> dict:
        try:
            claims = decode_jwt(access_token, self._secret, audience="api", issuer=self.issuer, now=self._clock())
        except TokenError as exc:
            raise AuthError("invalid_token") from exc
        user = self.db.execute("SELECT role, token_version FROM users WHERE id = ?", (int(claims["sub"]),)).fetchone()
        if user is None or user["token_version"] != claims.get("ver"):
            raise AuthError("invalid_token")
        return {"user_id": int(claims["sub"]), "role": user["role"]}   # role from the database, so a demotion applies at once

    def authorize(self, access_token: str, permission: str) -> dict:
        principal = self.authenticate(access_token)
        if permission not in ROLES.get(principal["role"], set()):
            self._audit(principal["user_id"], "permission_denied", permission)
            raise AuthError("forbidden")
        return principal

    def set_role(self, admin_token: str, user_id: int, role: str) -> None:
        admin = self.authorize(admin_token, "users:manage")
        if role not in ROLES:
            raise AuthError("unknown_role")
        self.db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        self._audit(admin["user_id"], "role_changed", f"user {user_id} -> {role}")

    def audit_log(self, user_id: int | None = None) -> list[tuple]:
        sql = "SELECT user_id, event, detail FROM audit" + (" WHERE user_id = ?" if user_id is not None else "") + " ORDER BY rowid"
        return [tuple(r) for r in self.db.execute(sql, (user_id,) if user_id is not None else ())]
