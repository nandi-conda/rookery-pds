# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""OAuth state in D1: pushed requests, codes, sessions, access tokens, and
DPoP jti replay guards. Codes and tokens are stored hashed. Rows are dicts
with the column names."""

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS oauth_par_requests (
  request_uri TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL,
  exp INTEGER NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL,
  did TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL,
  exp INTEGER NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS oauth_sessions (
  session_id TEXT PRIMARY KEY,
  refresh_token_hash TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  did TEXT NOT NULL,
  scope TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL,
  exp INTEGER NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS oauth_tokens (
  access_token_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  did TEXT NOT NULL,
  scope TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL,
  exp INTEGER NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS oauth_dpop_jti (
  jti_hash TEXT PRIMARY KEY,
  exp INTEGER NOT NULL
)""",
]

PAR_FIELDS = ("request_uri", "client_id", "params", "code_challenge", "redirect_uri", "scope", "dpop_jkt", "exp")
CODE_FIELDS = ("code_hash", "client_id", "redirect_uri", "code_challenge", "scope", "did", "dpop_jkt", "exp")
SESSION_FIELDS = ("session_id", "refresh_token_hash", "client_id", "did", "scope", "dpop_jkt", "exp")
TOKEN_FIELDS = ("access_token_hash", "session_id", "client_id", "did", "scope", "dpop_jkt", "exp")


async def init_oauth(db) -> None:
    await db.batch([(statement, []) for statement in SCHEMA])


async def _insert(db, table: str, fields: tuple, row: dict, now: int) -> None:
    await db.run(f"DELETE FROM {table} WHERE exp < ?", now)
    await db.run(
        f"INSERT INTO {table} ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
        *(row[field] for field in fields),
    )


async def insert_par_request(db, request: dict, now: int) -> None:
    await _insert(db, "oauth_par_requests", PAR_FIELDS, request, now)


async def get_par_request(db, request_uri: str) -> dict | None:
    return await db.first("SELECT * FROM oauth_par_requests WHERE request_uri = ?", request_uri)


async def consume_par_request(db, request_uri: str) -> bool:
    return await db.run("DELETE FROM oauth_par_requests WHERE request_uri = ?", request_uri) == 1


async def insert_code(db, code: dict, now: int) -> None:
    await _insert(db, "oauth_codes", CODE_FIELDS, code, now)


async def consume_code(db, code_hash: str) -> dict | None:
    return await db.first("DELETE FROM oauth_codes WHERE code_hash = ? RETURNING *", code_hash)


async def insert_session(db, session: dict, now: int) -> None:
    await _insert(db, "oauth_sessions", SESSION_FIELDS, session, now)


async def get_session_by_refresh_hash(db, refresh_hash: str) -> dict | None:
    return await db.first("SELECT * FROM oauth_sessions WHERE refresh_token_hash = ?", refresh_hash)


async def get_session_by_id(db, session_id: str) -> dict | None:
    return await db.first("SELECT * FROM oauth_sessions WHERE session_id = ?", session_id)


async def rotate_session_refresh(db, session_id: str, presented_hash: str, new_hash: str) -> bool:
    return await db.run(
        "UPDATE oauth_sessions SET refresh_token_hash = ? WHERE session_id = ? AND refresh_token_hash = ?",
        new_hash, session_id, presented_hash,
    ) == 1


async def delete_session_by_id(db, session_id: str) -> None:
    await db.run("DELETE FROM oauth_sessions WHERE session_id = ?", session_id)


async def insert_token(db, token: dict, now: int) -> None:
    await _insert(db, "oauth_tokens", TOKEN_FIELDS, token, now)


async def get_token_by_hash(db, access_hash: str) -> dict | None:
    return await db.first("SELECT * FROM oauth_tokens WHERE access_token_hash = ?", access_hash)


async def get_token_with_session(db, access_hash: str) -> dict | None:
    """The token row plus `session_exp`."""
    return await db.first(
        """SELECT t.*, s.exp AS session_exp
           FROM oauth_tokens t
           JOIN oauth_sessions s ON t.session_id = s.session_id
           WHERE t.access_token_hash = ?""",
        access_hash,
    )


async def delete_token_by_hash(db, access_hash: str) -> None:
    await db.run("DELETE FROM oauth_tokens WHERE access_token_hash = ?", access_hash)


async def delete_tokens_by_session(db, session_id: str) -> None:
    await db.run("DELETE FROM oauth_tokens WHERE session_id = ?", session_id)


async def insert_dpop_jti(db, jti_hash: str, exp: int, now: int) -> bool:
    await db.run("DELETE FROM oauth_dpop_jti WHERE exp < ?", now)
    return await db.run(
        "INSERT INTO oauth_dpop_jti (jti_hash, exp) VALUES (?, ?) ON CONFLICT(jti_hash) DO NOTHING", jti_hash, exp
    ) == 1
