import base64
import json
import os

import pytest

from authsvc import AuthError, AuthService, TokenError, decode_jwt, encode_jwt, hash_password, totp, verify_password, verify_totp
from authsvc.passwords import needs_rehash
from authsvc.tokens import _b64

SECRET = b"k" * 32
PASSWORD = "a long passphrase 42"


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def env():
    clock = Clock()
    auth = AuthService(":memory:", SECRET, clock=clock)
    return auth, clock, auth.register("Priya@Example.com", PASSWORD)


def code_of(exc_info):
    return exc_info.value.code


# ---- passwords ------------------------------------------------------------
def test_password_hashing():
    a, b = hash_password("hunter2hunter2"), hash_password("hunter2hunter2")
    assert a != b and a.startswith("scrypt$16384$8$1$")          # salted: same password, different hash
    assert verify_password("hunter2hunter2", a) and not verify_password("hunter2hunter3", a)
    assert not verify_password("x", "not-a-hash") and not verify_password("x", "md5$1$2$3$4$5")
    weak = hash_password("hunter2hunter2", n=2 ** 10)
    assert verify_password("hunter2hunter2", weak) and needs_rehash(weak) and not needs_rehash(a)


# ---- JWT ------------------------------------------------------------------
def claims(**extra):
    return {"sub": "1", "exp": 2_000, "aud": "api", "iss": "authsvc", **extra}


def test_jwt_round_trip_and_claim_checks():
    token = encode_jwt(claims(role="admin"), SECRET)
    assert decode_jwt(token, SECRET, audience="api", issuer="authsvc", now=1_000)["role"] == "admin"
    for kwargs, message in [({"now": 2_000}, "expired"), ({"now": 1_000, "audience": "billing"}, "wrong audience"),
                            ({"now": 1_000, "issuer": "someone-else"}, "wrong issuer")]:
        with pytest.raises(TokenError, match=message):
            decode_jwt(token, SECRET, **kwargs)
    with pytest.raises(TokenError, match="not yet valid"):
        decode_jwt(encode_jwt(claims(nbf=1_500), SECRET), SECRET, now=1_000)
    with pytest.raises(TokenError, match="no expiry"):
        decode_jwt(encode_jwt({"sub": "1"}, SECRET), SECRET, now=1_000)
    assert decode_jwt(token, SECRET, now=2_010, leeway=30)["sub"] == "1"


def test_jwt_rejects_tampering_and_algorithm_tricks():
    token = encode_jwt(claims(role="viewer"), SECRET)
    header, payload, signature = token.split(".")
    forged_payload = _b64(json.dumps(claims(role="admin")).encode())
    with pytest.raises(TokenError, match="bad signature"):
        decode_jwt(f"{header}.{forged_payload}.{signature}", SECRET, now=1_000)       # payload edited, old signature
    with pytest.raises(TokenError, match="bad signature"):
        decode_jwt(encode_jwt(claims(role="admin"), b"x" * 32), SECRET, now=1_000)    # signed with another key
    none_header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    with pytest.raises(TokenError, match="unsupported algorithm"):
        decode_jwt(f"{none_header}.{forged_payload}.", SECRET, now=1_000)             # the classic "alg: none" attack
    rs_header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    with pytest.raises(TokenError, match="unsupported algorithm"):
        decode_jwt(f"{rs_header}.{forged_payload}.{signature}", SECRET, now=1_000)
    for garbage in ["", "abc", "a.b", "a.b.c.d", "!!!.###.$$$", f"{header}.{payload}"]:
        with pytest.raises(TokenError):
            decode_jwt(garbage, SECRET, now=1_000)


# ---- TOTP -----------------------------------------------------------------
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.mark.parametrize("at, expected", [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                                          (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")])
def test_totp_matches_the_rfc_6238_test_vectors(at, expected):
    assert totp(RFC_SECRET, at, digits=8) == expected


def test_totp_window_and_single_use():
    at = 1_800_000_015
    code = totp(RFC_SECRET, at)
    counter = verify_totp(RFC_SECRET, code, at)
    assert counter == at // 30
    assert verify_totp(RFC_SECRET, code, at + 30) == counter              # one step of clock drift is tolerated
    assert verify_totp(RFC_SECRET, code, at + 90) is None                 # three steps later it is not
    assert verify_totp(RFC_SECRET, code, at, last_used_counter=counter) is None   # a used code cannot be replayed
    for bad in ["000000" if code != "000000" else "111111", "abcdef", "", "12345 "]:
        assert verify_totp(RFC_SECRET, bad, at) is None


# ---- service: registration and login --------------------------------------
def test_registration_rules(env):
    auth, _, _ = env
    for args, code in [(("priya@example.com", PASSWORD), "email_taken"), (("not-an-email", PASSWORD), "invalid_email"),
                       (("new@example.com", "short"), "password_too_short"), (("new@example.com", PASSWORD, "root"), "unknown_role")]:
        with pytest.raises(AuthError) as exc:
            auth.register(*args)
        assert code_of(exc) == code
    assert "a long passphrase" not in str(auth.db.execute("SELECT * FROM users").fetchall()[0][:])
    with pytest.raises(ValueError):
        AuthService(":memory:", b"too short")


def test_login_gives_identical_errors_for_unknown_email_and_wrong_password(env):
    auth, _, user_id = env
    session = auth.login("priya@example.com", PASSWORD)
    assert auth.authenticate(session["access_token"]) == {"user_id": user_id, "role": "viewer"}
    with pytest.raises(AuthError) as wrong:
        auth.login("priya@example.com", "wrong password 123")
    with pytest.raises(AuthError) as unknown:
        auth.login("nobody@example.com", PASSWORD)
    assert code_of(wrong) == code_of(unknown) == "invalid_credentials"


def test_lockout_after_repeated_failures_then_recovery(env):
    auth, clock, _ = env
    for _ in range(5):
        with pytest.raises(AuthError):
            auth.login("priya@example.com", "wrong password 123")
    with pytest.raises(AuthError) as exc:
        auth.login("priya@example.com", PASSWORD)                    # correct password, but locked
    assert code_of(exc) == "account_locked"
    clock.now += 901
    assert "access_token" in auth.login("priya@example.com", PASSWORD)
    for _ in range(4):                                               # the counter was reset by the successful login
        with pytest.raises(AuthError):
            auth.login("priya@example.com", "wrong password 123")
    assert "access_token" in auth.login("priya@example.com", PASSWORD)


def test_two_factor_login(env):
    auth, clock, user_id = env
    secret = auth.enable_totp(user_id)
    assert "access_token" in auth.login("priya@example.com", PASSWORD)          # not enforced until confirmed
    with pytest.raises(AuthError) as exc:
        auth.confirm_totp(user_id, "000000" if totp(secret, clock.now) != "000000" else "111111")
    assert code_of(exc) == "invalid_code"
    auth.confirm_totp(user_id, totp(secret, clock.now))

    with pytest.raises(AuthError) as exc:
        auth.login("priya@example.com", PASSWORD)
    assert code_of(exc) == "totp_required"
    clock.now += 30
    code = totp(secret, clock.now)
    assert "access_token" in auth.login("priya@example.com", PASSWORD, code)
    with pytest.raises(AuthError) as exc:
        auth.login("priya@example.com", PASSWORD, code)                         # replay of the same code
    assert code_of(exc) == "invalid_code"
    with pytest.raises(AuthError) as exc:
        auth.login("priya@example.com", "wrong password 123", totp(secret, clock.now + 30))
    assert code_of(exc) == "invalid_credentials"                                # password is checked first


# ---- service: tokens -------------------------------------------------------
def test_access_token_expires_and_refresh_rotates(env):
    auth, clock, user_id = env
    first = auth.login("priya@example.com", PASSWORD)
    clock.now += 901
    with pytest.raises(AuthError):
        auth.authenticate(first["access_token"])
    second = auth.refresh(first["refresh_token"])
    assert auth.authenticate(second["access_token"])["user_id"] == user_id
    assert second["refresh_token"] != first["refresh_token"]
    stored = [r[0] for r in auth.db.execute("SELECT token_hash FROM refresh_tokens")]
    assert first["refresh_token"] not in stored and second["refresh_token"] not in stored and all(len(h) == 64 for h in stored)


def test_reusing_a_refresh_token_revokes_the_whole_family_but_not_other_sessions(env):
    auth, _, user_id = env
    laptop = auth.login("priya@example.com", PASSWORD)
    phone = auth.login("priya@example.com", PASSWORD)             # a separate login is a separate family
    stolen = laptop["refresh_token"]
    newer = auth.refresh(laptop["refresh_token"])
    with pytest.raises(AuthError) as exc:
        auth.refresh(stolen)
    assert code_of(exc) == "refresh_token_reused"
    with pytest.raises(AuthError) as exc:
        auth.refresh(newer["refresh_token"])                      # the legitimate descendant is revoked too
    assert code_of(exc) == "invalid_refresh_token"
    assert "access_token" in auth.refresh(phone["refresh_token"])
    assert ("refresh_reuse_detected" in [e for _, e, _ in auth.audit_log(user_id)])


def test_refresh_tokens_expire_and_unknown_ones_fail(env):
    auth, clock, _ = env
    session = auth.login("priya@example.com", PASSWORD)
    clock.now += 31 * 86400
    with pytest.raises(AuthError):
        auth.refresh(session["refresh_token"])
    with pytest.raises(AuthError):
        auth.refresh("made-up-token")


def test_logout_everywhere_kills_access_and_refresh_tokens(env):
    auth, _, user_id = env
    session = auth.login("priya@example.com", PASSWORD)
    auth.logout_everywhere(user_id)
    with pytest.raises(AuthError):
        auth.authenticate(session["access_token"])                # still unexpired and correctly signed, but refused
    with pytest.raises(AuthError):
        auth.refresh(session["refresh_token"])
    assert "access_token" in auth.login("priya@example.com", PASSWORD)


def test_tokens_from_another_issuer_or_key_are_refused(env):
    auth, clock, user_id = env
    good = {"sub": str(user_id), "role": "admin", "ver": 0, "aud": "api", "iss": "authsvc", "exp": int(clock.now + 60)}
    assert auth.authenticate(encode_jwt(good, SECRET))["role"] == "viewer"       # role comes from the database, not the token
    for bad in [encode_jwt(good, os.urandom(32)), encode_jwt({**good, "iss": "other"}, SECRET),
                encode_jwt({**good, "aud": "billing"}, SECRET), encode_jwt({**good, "sub": "9999"}, SECRET), "garbage"]:
        with pytest.raises(AuthError) as exc:
            auth.authenticate(bad)
        assert code_of(exc) == "invalid_token"


# ---- service: roles ---------------------------------------------------------
def test_role_based_access_and_immediate_role_changes(env):
    auth, _, user_id = env
    auth.register("admin@example.com", "correct horse battery staple", role="admin")
    viewer = auth.login("priya@example.com", PASSWORD)["access_token"]
    admin = auth.login("admin@example.com", "correct horse battery staple")["access_token"]

    assert auth.authorize(viewer, "reports:read")["role"] == "viewer"
    for token, permission in [(viewer, "reports:write"), (viewer, "users:manage"), (admin, "made:up")]:
        with pytest.raises(AuthError) as exc:
            auth.authorize(token, permission)
        assert code_of(exc) == "forbidden"
    with pytest.raises(AuthError):
        auth.set_role(viewer, user_id, "admin")                   # no self-promotion
    auth.set_role(admin, user_id, "editor")
    assert auth.authorize(viewer, "reports:write")["role"] == "editor"          # applies to the token already issued
    auth.set_role(admin, user_id, "viewer")
    with pytest.raises(AuthError):
        auth.authorize(viewer, "reports:write")
    assert ("permission_denied", "reports:write") in [(e, d) for _, e, d in auth.audit_log(user_id)]
