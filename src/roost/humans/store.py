# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Password credentials and legacy sessions in D1.

Session tokens are JWT-shaped so clients that read `exp` and `scope` from them
keep working, but roost never trusts their contents: a token is valid only
while its SHA-256 is stored here, which also makes revocation immediate.
"""

import base64
import hmac
import json
import secrets
import time

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .. import directory
from ..encoding import b64url_encode, sha256_b64url

ACCESS_TTL_S = 2 * 60 * 60
REFRESH_TTL_S = 60 * 24 * 60 * 60
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 256
LOGIN_WINDOW_S = 15 * 60
LOGIN_MAX_FAILURES = 10

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS password_credentials (
  did TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  email TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
)""",
    """CREATE TABLE IF NOT EXISTS password_sessions (
  token_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  did TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
  exp INTEGER NOT NULL
)""",
    "CREATE INDEX IF NOT EXISTS idx_password_sessions_session ON password_sessions(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_password_sessions_did ON password_sessions(did)",
    """CREATE TABLE IF NOT EXISTS login_failures (
  identifier TEXT NOT NULL,
  at INTEGER NOT NULL
)""",
    "CREATE INDEX IF NOT EXISTS idx_login_failures ON login_failures(identifier, at)",
    """CREATE TABLE IF NOT EXISTS actor_preferences (
  did TEXT PRIMARY KEY,
  preferences TEXT NOT NULL
)""",
]

_initialized = False


class SessionError(Exception):
    pass


async def init_humans(db) -> None:
    global _initialized
    await directory.init_directory(db)
    if not _initialized:
        await db.batch([(statement, []) for statement in SCHEMA])
        _initialized = True


# Passwords

def _scrypt(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password.encode("utf-8"))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        derived = Scrypt(salt=base64.b64decode(salt), length=32, n=int(n), r=int(r), p=int(p)).derive(
            password.encode("utf-8")
        )
    except Exception:
        return False
    return hmac.compare_digest(derived, base64.b64decode(digest))


def password_problem(password) -> str | None:
    if not isinstance(password, str):
        return "Password is required"
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must be at most {MAX_PASSWORD_LENGTH} characters"
    return None


async def set_password(db, did: str, password: str, email: str | None) -> None:
    await db.run(
        """INSERT INTO password_credentials (did, password_hash, email) VALUES (?, ?, ?)
           ON CONFLICT (did) DO UPDATE SET password_hash = excluded.password_hash""",
        did, hash_password(password), email,
    )


async def email_taken(db, email: str) -> bool:
    return await db.first("SELECT 1 AS x FROM password_credentials WHERE email = ?", email) is not None


async def find_login(db, identifier: str) -> dict | None:
    """{did, handle, do_id, password_hash, email} for a handle, DID or email with a password."""
    if "@" in identifier:
        column = "p.email"
    elif identifier.startswith("did:"):
        column = "a.did"
    else:
        column = "a.handle"
    return await db.first(
        f"""SELECT a.did, a.handle, a.do_id, p.password_hash, p.email FROM accounts a
            JOIN password_credentials p ON p.did = a.did WHERE {column} = ? AND a.active = 1""",
        identifier,
    )


async def note_login_failure(db, identifier: str) -> None:
    now = int(time.time())
    await db.run("DELETE FROM login_failures WHERE at < ?", now - LOGIN_WINDOW_S)
    await db.run("INSERT INTO login_failures (identifier, at) VALUES (?, ?)", identifier, now)


async def too_many_failures(db, identifier: str) -> bool:
    row = await db.first(
        "SELECT COUNT(*) AS n FROM login_failures WHERE identifier = ? AND at >= ?",
        identifier, int(time.time()) - LOGIN_WINDOW_S,
    )
    return bool(row) and row["n"] >= LOGIN_MAX_FAILURES


# Sessions

def _token(did: str, scope: str, aud: str, exp: int) -> str:
    header = {"typ": "at+jwt" if scope == "com.atproto.access" else "refresh+jwt", "alg": "HS256"}
    payload = {"scope": scope, "sub": did, "aud": aud, "iat": int(time.time()), "exp": exp,
               "jti": secrets.token_hex(16)}
    parts = [b64url_encode(json.dumps(part, separators=(",", ":")).encode()) for part in (header, payload)]
    return ".".join(parts + [b64url_encode(secrets.token_bytes(32))])


async def create_session(db, did: str, aud: str, session_id: str | None = None) -> dict:
    now = int(time.time())
    session_id = session_id or secrets.token_hex(16)
    access = _token(did, "com.atproto.access", aud, now + ACCESS_TTL_S)
    refresh = _token(did, "com.atproto.refresh", aud, now + REFRESH_TTL_S)
    await db.batch([
        ("DELETE FROM password_sessions WHERE exp < ?", [now]),
        ("INSERT INTO password_sessions (token_hash, session_id, did, kind, exp) VALUES (?, ?, ?, 'access', ?)",
         [sha256_b64url(access), session_id, did, now + ACCESS_TTL_S]),
        ("INSERT INTO password_sessions (token_hash, session_id, did, kind, exp) VALUES (?, ?, ?, 'refresh', ?)",
         [sha256_b64url(refresh), session_id, did, now + REFRESH_TTL_S]),
    ])
    return {"accessJwt": access, "refreshJwt": refresh}


async def resolve_token(db, token: str, kind: str) -> dict:
    """{did, do_id, handle, session_id} for a live token of `kind`; raises SessionError."""
    await init_humans(db)
    row = await db.first(
        """SELECT s.session_id, s.did, s.exp, a.do_id, a.handle FROM password_sessions s
           JOIN accounts a ON a.did = s.did AND a.active = 1 WHERE s.token_hash = ? AND s.kind = ?""",
        sha256_b64url(token), kind,
    )
    if not row:
        raise SessionError("Token could not be verified")
    if row["exp"] <= time.time():
        raise SessionError("Token has expired")
    return {"did": row["did"], "do_id": row["do_id"], "handle": row["handle"], "session_id": row["session_id"]}


async def rotate_session(db, refresh_token: str, aud: str) -> dict:
    session = await resolve_token(db, refresh_token, "refresh")
    await db.run("DELETE FROM password_sessions WHERE session_id = ?", session["session_id"])
    tokens = await create_session(db, session["did"], aud, session["session_id"])
    return dict(session, **tokens)


async def delete_session(db, refresh_token: str) -> None:
    session = await resolve_token(db, refresh_token, "refresh")
    await db.run("DELETE FROM password_sessions WHERE session_id = ?", session["session_id"])
