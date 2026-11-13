"""Demo: python -m authsvc   (walks through a login, token rotation, a stolen token and a role change)"""
from __future__ import annotations

import os

from . import AuthError, AuthService, totp


def attempt(label: str, fn) -> None:
    try:
        fn()
        print(f"   {label}: allowed")
    except AuthError as exc:
        print(f"   {label}: refused ({exc.code})")


def main() -> None:
    now = [1_800_000_000.0]
    auth = AuthService(":memory:", os.urandom(32), clock=lambda: now[0])
    admin_id = auth.register("admin@example.com", "correct horse battery staple", role="admin")
    user_id = auth.register("priya@example.com", "a long passphrase 42")

    print("1. Two-factor login")
    secret = auth.enable_totp(user_id)
    auth.confirm_totp(user_id, totp(secret, now[0]))
    attempt("password only", lambda: auth.login("priya@example.com", "a long passphrase 42"))
    now[0] += 30
    code = totp(secret, now[0])
    session = auth.login("priya@example.com", "a long passphrase 42", code)
    print("   password + code: allowed")
    attempt("same code again", lambda: auth.login("priya@example.com", "a long passphrase 42", code))

    print("\n2. Permissions follow the role")
    attempt("viewer reads reports", lambda: auth.authorize(session["access_token"], "reports:read"))
    attempt("viewer writes reports", lambda: auth.authorize(session["access_token"], "reports:write"))
    admin = auth.login("admin@example.com", "correct horse battery staple")
    auth.set_role(admin["access_token"], user_id, "editor")
    attempt("after promotion to editor, same token", lambda: auth.authorize(session["access_token"], "reports:write"))

    print("\n3. Access tokens expire; refresh tokens rotate")
    now[0] += 901
    attempt("access token after 15 minutes", lambda: auth.authenticate(session["access_token"]))
    stolen = session["refresh_token"]                  # imagine an attacker copied this
    session2 = auth.refresh(session["refresh_token"])
    attempt("new access token", lambda: auth.authenticate(session2["access_token"]))

    print("\n4. A stolen refresh token is replayed")
    attempt("attacker uses the old refresh token", lambda: auth.refresh(stolen))
    attempt("the real user's newer refresh token", lambda: auth.refresh(session2["refresh_token"]))
    print("   (the whole token family was revoked; the user signs in again and the attacker is locked out)")

    print("\n5. Brute force")
    for _ in range(5):
        try:
            auth.login("admin@example.com", "wrong guess")
        except AuthError:
            pass
    attempt("correct password after 5 wrong ones", lambda: auth.login("admin@example.com", "correct horse battery staple"))
    now[0] += 901
    attempt("correct password after the 15-minute lockout", lambda: auth.login("admin@example.com", "correct horse battery staple"))

    print("\nAudit log for the user:")
    for _, event, detail in auth.audit_log(user_id):
        print(f"   {event}" + (f": {detail}" if detail else ""))


if __name__ == "__main__":
    main()
