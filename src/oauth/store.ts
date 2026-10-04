// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

const PAR_REQUESTS_SCHEMA = `
CREATE TABLE IF NOT EXISTS oauth_par_requests (
  request_uri TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL,
  exp INTEGER NOT NULL
);
`;

const CODES_SCHEMA = `
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL,
  did TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL,
  exp INTEGER NOT NULL
);
`;

const SESSIONS_SCHEMA = `
CREATE TABLE IF NOT EXISTS oauth_sessions (
  session_id TEXT PRIMARY KEY,
  refresh_token_hash TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  did TEXT NOT NULL,
  scope TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL,
  exp INTEGER NOT NULL
);
`;

const TOKENS_SCHEMA = `
CREATE TABLE IF NOT EXISTS oauth_tokens (
  access_token_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  did TEXT NOT NULL,
  scope TEXT NOT NULL,
  dpop_jkt TEXT NOT NULL,
  exp INTEGER NOT NULL
);
`;

const DPOP_JTI_SCHEMA = `
CREATE TABLE IF NOT EXISTS oauth_dpop_jti (
  jti_hash TEXT PRIMARY KEY,
  exp INTEGER NOT NULL
);
`;

export interface OAuthParRequest {
  requestUri: string;
  clientId: string;
  params: string;
  codeChallenge: string;
  redirectUri: string;
  scope: string;
  dpopJkt: string;
  exp: number;
}

export interface OAuthCode {
  codeHash: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  did: string;
  dpopJkt: string;
  exp: number;
}

export interface OAuthSession {
  sessionId: string;
  refreshTokenHash: string;
  clientId: string;
  did: string;
  scope: string;
  dpopJkt: string;
  exp: number;
}

export interface OAuthToken {
  accessTokenHash: string;
  sessionId: string;
  clientId: string;
  did: string;
  scope: string;
  dpopJkt: string;
  exp: number;
}

type OAuthParRequestRow = {
  request_uri: string;
  client_id: string;
  params: string;
  code_challenge: string;
  redirect_uri: string;
  scope: string;
  dpop_jkt: string;
  exp: number;
};

type OAuthCodeRow = {
  code_hash: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scope: string;
  did: string;
  dpop_jkt: string;
  exp: number;
};

type OAuthSessionRow = {
  session_id: string;
  refresh_token_hash: string;
  client_id: string;
  did: string;
  scope: string;
  dpop_jkt: string;
  exp: number;
};

type OAuthTokenRow = {
  access_token_hash: string;
  session_id: string;
  client_id: string;
  did: string;
  scope: string;
  dpop_jkt: string;
  exp: number;
};

type OAuthTokenWithSessionRow = OAuthTokenRow & {
  session_exp: number;
};

export async function initOAuth(db: D1Database): Promise<void> {
  await db.batch([
    db.prepare(PAR_REQUESTS_SCHEMA),
    db.prepare(CODES_SCHEMA),
    db.prepare(SESSIONS_SCHEMA),
    db.prepare(TOKENS_SCHEMA),
    db.prepare(DPOP_JTI_SCHEMA),
  ]);
}

function mapParRequest(row: OAuthParRequestRow): OAuthParRequest {
  return {
    requestUri: row.request_uri,
    clientId: row.client_id,
    params: row.params,
    codeChallenge: row.code_challenge,
    redirectUri: row.redirect_uri,
    scope: row.scope,
    dpopJkt: row.dpop_jkt,
    exp: row.exp,
  };
}

function mapCode(row: OAuthCodeRow): OAuthCode {
  return {
    codeHash: row.code_hash,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    scope: row.scope,
    did: row.did,
    dpopJkt: row.dpop_jkt,
    exp: row.exp,
  };
}

function mapSession(row: OAuthSessionRow): OAuthSession {
  return {
    sessionId: row.session_id,
    refreshTokenHash: row.refresh_token_hash,
    clientId: row.client_id,
    did: row.did,
    scope: row.scope,
    dpopJkt: row.dpop_jkt,
    exp: row.exp,
  };
}

function mapToken(row: OAuthTokenRow): OAuthToken {
  return {
    accessTokenHash: row.access_token_hash,
    sessionId: row.session_id,
    clientId: row.client_id,
    did: row.did,
    scope: row.scope,
    dpopJkt: row.dpop_jkt,
    exp: row.exp,
  };
}

export async function insertOAuthParRequest(
  db: D1Database,
  request: OAuthParRequest,
  now: number,
): Promise<void> {
  await deleteExpiredOAuthParRequests(db, now);
  await db.prepare(
    `INSERT INTO oauth_par_requests
      (request_uri, client_id, params, code_challenge, redirect_uri, scope, dpop_jkt, exp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    request.requestUri,
    request.clientId,
    request.params,
    request.codeChallenge,
    request.redirectUri,
    request.scope,
    request.dpopJkt,
    request.exp,
  ).run();
}

export async function getOAuthParRequest(
  db: D1Database,
  requestUri: string,
): Promise<OAuthParRequest | null> {
  const row = await db.prepare(
    "SELECT * FROM oauth_par_requests WHERE request_uri = ?",
  ).bind(requestUri).first<OAuthParRequestRow>();
  return row ? mapParRequest(row) : null;
}

export async function deleteOAuthParRequest(
  db: D1Database,
  requestUri: string,
): Promise<void> {
  await db.prepare("DELETE FROM oauth_par_requests WHERE request_uri = ?").bind(requestUri).run();
}

export async function consumeOAuthParRequest(
  db: D1Database,
  requestUri: string,
): Promise<boolean> {
  const res = await db.prepare(
    "DELETE FROM oauth_par_requests WHERE request_uri = ?",
  ).bind(requestUri).run();
  return res.meta.changes === 1;
}

export async function deleteExpiredOAuthParRequests(
  db: D1Database,
  now: number,
): Promise<void> {
  await db.prepare("DELETE FROM oauth_par_requests WHERE exp < ?").bind(now).run();
}

export async function insertOAuthCode(
  db: D1Database,
  code: OAuthCode,
  now: number,
): Promise<void> {
  await deleteExpiredOAuthCodes(db, now);
  await db.prepare(
    `INSERT INTO oauth_codes
      (code_hash, client_id, redirect_uri, code_challenge, scope, did, dpop_jkt, exp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    code.codeHash,
    code.clientId,
    code.redirectUri,
    code.codeChallenge,
    code.scope,
    code.did,
    code.dpopJkt,
    code.exp,
  ).run();
}

export async function getOAuthCode(
  db: D1Database,
  codeHash: string,
): Promise<OAuthCode | null> {
  const row = await db.prepare(
    "SELECT * FROM oauth_codes WHERE code_hash = ?",
  ).bind(codeHash).first<OAuthCodeRow>();
  return row ? mapCode(row) : null;
}

export async function consumeOAuthCode(
  db: D1Database,
  codeHash: string,
): Promise<OAuthCode | null> {
  const row = await db.prepare(
    "DELETE FROM oauth_codes WHERE code_hash = ? RETURNING *",
  ).bind(codeHash).first<OAuthCodeRow>();
  return row ? mapCode(row) : null;
}

export async function deleteOAuthCode(
  db: D1Database,
  codeHash: string,
): Promise<void> {
  await db.prepare("DELETE FROM oauth_codes WHERE code_hash = ?").bind(codeHash).run();
}

export async function deleteExpiredOAuthCodes(
  db: D1Database,
  now: number,
): Promise<void> {
  await db.prepare("DELETE FROM oauth_codes WHERE exp < ?").bind(now).run();
}

export async function insertOAuthSession(
  db: D1Database,
  session: OAuthSession,
  now: number,
): Promise<void> {
  await deleteExpiredOAuthSessions(db, now);
  await db.prepare(
    `INSERT INTO oauth_sessions
      (session_id, refresh_token_hash, client_id, did, scope, dpop_jkt, exp)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    session.sessionId,
    session.refreshTokenHash,
    session.clientId,
    session.did,
    session.scope,
    session.dpopJkt,
    session.exp,
  ).run();
}

export async function getOAuthSessionByRefreshTokenHash(
  db: D1Database,
  refreshTokenHash: string,
): Promise<OAuthSession | null> {
  const row = await db.prepare(
    "SELECT * FROM oauth_sessions WHERE refresh_token_hash = ?",
  ).bind(refreshTokenHash).first<OAuthSessionRow>();
  return row ? mapSession(row) : null;
}

export async function getOAuthSessionById(
  db: D1Database,
  sessionId: string,
): Promise<OAuthSession | null> {
  const row = await db.prepare(
    "SELECT * FROM oauth_sessions WHERE session_id = ?",
  ).bind(sessionId).first<OAuthSessionRow>();
  return row ? mapSession(row) : null;
}

export async function rotateOAuthSessionRefresh(
  db: D1Database,
  sessionId: string,
  presentedRefreshHash: string,
  newRefreshHash: string,
): Promise<boolean> {
  const res = await db.prepare(
    "UPDATE oauth_sessions SET refresh_token_hash = ? WHERE session_id = ? AND refresh_token_hash = ?",
  ).bind(newRefreshHash, sessionId, presentedRefreshHash).run();
  return res.meta.changes === 1;
}

export async function deleteOAuthSessionByRefreshTokenHash(
  db: D1Database,
  refreshTokenHash: string,
): Promise<void> {
  await db.prepare(
    "DELETE FROM oauth_sessions WHERE refresh_token_hash = ?",
  ).bind(refreshTokenHash).run();
}

export async function deleteOAuthSessionById(
  db: D1Database,
  sessionId: string,
): Promise<void> {
  await db.prepare("DELETE FROM oauth_sessions WHERE session_id = ?").bind(sessionId).run();
}

export async function deleteExpiredOAuthSessions(
  db: D1Database,
  now: number,
): Promise<void> {
  await db.prepare("DELETE FROM oauth_sessions WHERE exp < ?").bind(now).run();
}

export async function insertOAuthToken(
  db: D1Database,
  token: OAuthToken,
  now: number,
): Promise<void> {
  await deleteExpiredOAuthTokens(db, now);
  await db.prepare(
    `INSERT INTO oauth_tokens
      (access_token_hash, session_id, client_id, did, scope, dpop_jkt, exp)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    token.accessTokenHash,
    token.sessionId,
    token.clientId,
    token.did,
    token.scope,
    token.dpopJkt,
    token.exp,
  ).run();
}

export async function getOAuthTokenByAccessTokenHash(
  db: D1Database,
  accessTokenHash: string,
): Promise<OAuthToken | null> {
  const row = await db.prepare(
    "SELECT * FROM oauth_tokens WHERE access_token_hash = ?",
  ).bind(accessTokenHash).first<OAuthTokenRow>();
  return row ? mapToken(row) : null;
}

export async function getOAuthTokenWithSession(
  db: D1Database,
  accessTokenHash: string,
): Promise<{ token: OAuthToken; sessionExp: number } | null> {
  const row = await db.prepare(
    `SELECT t.*, s.exp AS session_exp
      FROM oauth_tokens t
      JOIN oauth_sessions s ON t.session_id = s.session_id
      WHERE t.access_token_hash = ?`,
  ).bind(accessTokenHash).first<OAuthTokenWithSessionRow>();
  return row ? { token: mapToken(row), sessionExp: row.session_exp } : null;
}

export async function deleteOAuthTokenByAccessTokenHash(
  db: D1Database,
  accessTokenHash: string,
): Promise<void> {
  await db.prepare(
    "DELETE FROM oauth_tokens WHERE access_token_hash = ?",
  ).bind(accessTokenHash).run();
}

export async function deleteOAuthTokensBySessionId(
  db: D1Database,
  sessionId: string,
): Promise<void> {
  await db.prepare("DELETE FROM oauth_tokens WHERE session_id = ?").bind(sessionId).run();
}

export async function deleteExpiredOAuthTokens(
  db: D1Database,
  now: number,
): Promise<void> {
  await db.prepare("DELETE FROM oauth_tokens WHERE exp < ?").bind(now).run();
}

export async function insertOAuthDpopJti(
  db: D1Database,
  jtiHash: string,
  exp: number,
  now: number,
): Promise<boolean> {
  await deleteExpiredOAuthDpopJtis(db, now);
  const res = await db.prepare(
    `INSERT INTO oauth_dpop_jti (jti_hash, exp) VALUES (?, ?)
      ON CONFLICT(jti_hash) DO NOTHING`,
  ).bind(jtiHash, exp).run();
  return res.meta.changes === 1;
}

export async function deleteExpiredOAuthDpopJtis(
  db: D1Database,
  now: number,
): Promise<void> {
  await db.prepare("DELETE FROM oauth_dpop_jti WHERE exp < ?").bind(now).run();
}
