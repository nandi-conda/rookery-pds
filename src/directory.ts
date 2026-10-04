// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import type { Env } from "./types";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS accounts (
  did TEXT PRIMARY KEY,
  handle TEXT NOT NULL UNIQUE,
  do_id TEXT NOT NULL,
  jwk_thumbprint TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

const INDEX = "CREATE INDEX IF NOT EXISTS idx_accounts_handle ON accounts(handle);";
const THUMBPRINT_INDEX = "CREATE INDEX IF NOT EXISTS idx_accounts_thumbprint ON accounts(jwk_thumbprint);";
const INVITE_QUOTAS_SCHEMA = `
CREATE TABLE IF NOT EXISTS invite_quotas (
  did TEXT PRIMARY KEY,
  quota INTEGER NOT NULL CHECK (quota >= 0)
);
`;
const INVITES_SCHEMA = `
CREATE TABLE IF NOT EXISTS invites (
  token TEXT PRIMARY KEY,
  minted_by TEXT,
  minted_at TEXT NOT NULL DEFAULT (datetime('now')),
  spent_by_did TEXT,
  spent_at TEXT,
  idempotency_key TEXT,
  CHECK (
    (spent_by_did IS NULL AND spent_at IS NULL)
    OR (spent_by_did IS NOT NULL AND spent_at IS NOT NULL)
  )
);
`;
const INVITES_MINTED_BY_INDEX = "CREATE INDEX IF NOT EXISTS idx_invites_minted_by ON invites(minted_by);";
const INVITES_MINTED_AT_INDEX = "CREATE INDEX IF NOT EXISTS idx_invites_minted_at ON invites(minted_at, token);";
// Partial unique index: only keyed (idempotent) mints are constrained; legacy
// rows and un-keyed mints keep idempotency_key NULL and are excluded, so this is
// backward-compatible with already-populated invites tables.
const INVITES_IDEMPOTENCY_INDEX =
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_idempotency_key ON invites(idempotency_key) WHERE idempotency_key IS NOT NULL;";
const CONFIG_SCHEMA = `
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;
const CONFIG_SEED = "INSERT OR IGNORE INTO config (key, value) VALUES ('invite_quota_default', '3');";
const TAKEDOWNS_SCHEMA = `
CREATE TABLE IF NOT EXISTS takedowns (
  did TEXT NOT NULL,
  handle TEXT NOT NULL,
  actor TEXT NOT NULL,
  records_deleted INTEGER NOT NULL,
  blobs_deleted INTEGER NOT NULL,
  collections TEXT NOT NULL,
  taken_down_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

const INVITE_TOKEN_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";
const INVITE_TOKEN_LENGTH = 10;

export interface InviteRecord {
  token: string;
  minted_by: string | null;
  minted_at: string;
  spent_by_did: string | null;
  spent_at: string | null;
}

export interface InviteListCursor {
  mintedAt: string;
  token: string;
}

export interface TakedownAccount {
  did: string;
  handle: string;
  doId: string;
}

export interface TakedownAuditInput {
  did: string;
  handle: string;
  actor: string;
  recordsDeleted: number;
  blobsDeleted: number;
  collections: string[];
}

/**
 * Thrown when directory schema initialization cannot be completed even after
 * retries. The Worker's global error handler maps this to a structured,
 * retryable 503 instead of leaking a bare 500 on cold-start init races.
 */
export class DirectoryInitError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = "DirectoryInitError";
    if (options && "cause" in options) {
      this.cause = options.cause;
    }
  }
}

const DIRECTORY_INIT_MAX_ATTEMPTS = 3;
const DIRECTORY_INIT_RETRY_BASE_MS = 25;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// One-time-per-isolate guard for the additive idempotency_key migration. Adding
// a column is a one-way, never-reverted migration, so memoizing avoids a PRAGMA
// on every request while staying correct across the process lifetime.
let inviteIdempotencyEnsured = false;

async function ensureInviteIdempotency(db: D1Database): Promise<void> {
  if (inviteIdempotencyEnsured) {
    return;
  }
  // CREATE TABLE IF NOT EXISTS is a no-op on already-provisioned directories, so
  // an existing invites table won't gain the column from the batch above. Add it
  // idempotently here, then build the partial unique index that backs idempotent
  // mints. New deployments already have the column from INVITES_SCHEMA.
  const columns = await db.prepare("PRAGMA table_info(invites)").all<{ name: string }>();
  const hasColumn = columns.results.some((column) => column.name === "idempotency_key");
  if (!hasColumn) {
    await db.prepare("ALTER TABLE invites ADD COLUMN idempotency_key TEXT").run();
  }
  await db.prepare(INVITES_IDEMPOTENCY_INDEX).run();
  inviteIdempotencyEnsured = true;
}

export async function initDirectory(db: D1Database): Promise<void> {
  // Create the account, invite, quota, config, and takedown schemas and seed
  // the default configuration.
  //
  // Cold-start guard: the first directory op after idle can lose a DO+D1 init
  // race and throw. An immediate retry succeeds once D1 is warm, so bound a few
  // attempts here rather than letting the caller surface a bare 500.
  let lastError: unknown;
  for (let attempt = 1; attempt <= DIRECTORY_INIT_MAX_ATTEMPTS; attempt++) {
    try {
      await db.batch([
        db.prepare(SCHEMA),
        db.prepare(INDEX),
        db.prepare(THUMBPRINT_INDEX),
        db.prepare(INVITE_QUOTAS_SCHEMA),
        db.prepare(INVITES_SCHEMA),
        db.prepare(INVITES_MINTED_BY_INDEX),
        db.prepare(INVITES_MINTED_AT_INDEX),
        db.prepare(CONFIG_SCHEMA),
        db.prepare(CONFIG_SEED),
        db.prepare(TAKEDOWNS_SCHEMA),
      ]);
      await ensureInviteIdempotency(db);
      return;
    } catch (err) {
      lastError = err;
      if (attempt < DIRECTORY_INIT_MAX_ATTEMPTS) {
        await sleep(DIRECTORY_INIT_RETRY_BASE_MS * attempt);
      }
    }
  }
  throw new DirectoryInitError(
    `Directory initialization failed after ${DIRECTORY_INIT_MAX_ATTEMPTS} attempts: ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
    { cause: lastError },
  );
}

export class RepoNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RepoNotFoundError";
  }
}

export async function resolveRepo(
  repo: string,
  env: Env,
): Promise<{ did: string; doId: string }> {
  const row = repo.includes(":")
    ? await env.DIRECTORY.prepare(
      "SELECT did, do_id FROM accounts WHERE did = ? AND active = 1",
    ).bind(repo).first<{ did: string; do_id: string }>()
    : await env.DIRECTORY.prepare(
      "SELECT did, do_id FROM accounts WHERE handle = ? AND active = 1",
    ).bind(repo).first<{ did: string; do_id: string }>();

  if (!row) {
    throw new RepoNotFoundError(`Repository not found: ${repo}`);
  }

  return { did: row.did, doId: row.do_id };
}

export async function insertAccount(
  db: D1Database,
  account: { did: string; handle: string; doId: string; jwkThumbprint?: string },
): Promise<void> {
  await db.prepare(
    "INSERT INTO accounts (did, handle, do_id, jwk_thumbprint) VALUES (?, ?, ?, ?)",
  ).bind(account.did, account.handle, account.doId, account.jwkThumbprint ?? null).run();
}

export async function resolveAccountForTakedown(
  db: D1Database,
  did: string,
): Promise<TakedownAccount | null> {
  const row = await db.prepare(
    "SELECT did, handle, do_id FROM accounts WHERE did = ?",
  ).bind(did).first<{ did: string; handle: string; do_id: string }>();

  return row ? { did: row.did, handle: row.handle, doId: row.do_id } : null;
}

export async function deactivateAccount(db: D1Database, did: string): Promise<void> {
  await db.prepare("UPDATE accounts SET active = 0 WHERE did = ?").bind(did).run();
}

export async function finalizeTakedown(
  db: D1Database,
  input: TakedownAuditInput,
): Promise<void> {
  await db.batch([
    db.prepare("DELETE FROM accounts WHERE did = ?").bind(input.did),
    db.prepare("DELETE FROM oauth_sessions WHERE did = ?").bind(input.did),
    db.prepare("DELETE FROM oauth_tokens WHERE did = ?").bind(input.did),
    db.prepare("DELETE FROM oauth_codes WHERE did = ?").bind(input.did),
    db.prepare("DELETE FROM invite_quotas WHERE did = ?").bind(input.did),
    db.prepare(
      `INSERT INTO takedowns
        (did, handle, actor, records_deleted, blobs_deleted, collections)
        VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(
      input.did,
      input.handle,
      input.actor,
      input.recordsDeleted,
      input.blobsDeleted,
      JSON.stringify(input.collections),
    ),
  ]);
}

export async function handleExists(db: D1Database, handle: string): Promise<boolean> {
  const row = await db.prepare(
    "SELECT 1 FROM accounts WHERE handle = ? LIMIT 1",
  ).bind(handle).first();

  return row !== null;
}

export function generateInviteToken(): string {
  const bytes = new Uint8Array(INVITE_TOKEN_LENGTH);
  crypto.getRandomValues(bytes);
  let token = "";
  for (const byte of bytes) {
    token += INVITE_TOKEN_ALPHABET[byte % INVITE_TOKEN_ALPHABET.length];
  }
  return token;
}

export async function mintRookInvite(
  db: D1Database,
  did: string,
  quota: number,
): Promise<{ token: string; remaining: number } | null> {
  const token = generateInviteToken();
  const res = await db.prepare(
    "INSERT INTO invites (token, minted_by) SELECT ?, ? WHERE (SELECT COUNT(*) FROM invites WHERE minted_by = ?) < ?",
  ).bind(token, did, did, quota).run();

  if (res.meta.changes === 0) {
    return null;
  }

  const row = await db.prepare(
    "SELECT COUNT(*) AS count FROM invites WHERE minted_by = ?",
  ).bind(did).first<{ count: number }>();
  const count = row?.count ?? 0;

  return { token, remaining: quota - count };
}

export async function mintOrgInvite(
  db: D1Database,
  opts: { idempotencyKey?: string } = {},
): Promise<{ token: string; replayed: boolean }> {
  const key = opts.idempotencyKey;

  // Idempotent path: a retry carrying the same key returns the invite minted by
  // the first request instead of stranding another unspent invite.
  if (key) {
    const existing = await db.prepare(
      "SELECT token FROM invites WHERE idempotency_key = ?",
    ).bind(key).first<{ token: string }>();
    if (existing) {
      return { token: existing.token, replayed: true };
    }
  }

  const token = generateInviteToken();
  try {
    await db.prepare(
      "INSERT INTO invites (token, minted_by, idempotency_key) VALUES (?, 'org', ?)",
    ).bind(token, key ?? null).run();
  } catch (err) {
    // Concurrent first-use of the same key: the partial unique index rejects the
    // loser, which then resolves to the winner's token.
    if (key && err instanceof Error && err.message.includes("UNIQUE constraint failed")) {
      const existing = await db.prepare(
        "SELECT token FROM invites WHERE idempotency_key = ?",
      ).bind(key).first<{ token: string }>();
      if (existing) {
        return { token: existing.token, replayed: true };
      }
    }
    throw err;
  }

  return { token, replayed: false };
}

export async function getEffectiveQuota(db: D1Database, did: string): Promise<number> {
  const override = await db.prepare(
    "SELECT quota FROM invite_quotas WHERE did = ?",
  ).bind(did).first<{ quota: number }>();
  if (override) {
    return override.quota;
  }

  const row = await db.prepare(
    "SELECT value FROM config WHERE key = 'invite_quota_default'",
  ).first<{ value: string }>();
  if (!row) {
    throw new Error("invite_quota_default is missing");
  }

  const quota = Number(row.value);
  if (!Number.isInteger(quota) || quota < 0) {
    throw new Error("invite_quota_default must be a non-negative integer");
  }
  return quota;
}

export async function setInviteQuota(
  db: D1Database,
  did: string,
  quota: number,
): Promise<void> {
  await db.prepare(
    "INSERT INTO invite_quotas (did, quota) VALUES (?, ?) ON CONFLICT(did) DO UPDATE SET quota = excluded.quota",
  ).bind(did, quota).run();
}

export async function setInviteQuotaDefault(
  db: D1Database,
  value: number,
): Promise<void> {
  await db.prepare(
    "INSERT INTO config (key, value, updated_at) VALUES ('invite_quota_default', ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')",
  ).bind(String(value)).run();
}

export type InviteListState = "unspent" | "spent";

export async function listInvites(
  db: D1Database,
  opts: { limit: number; cursor?: InviteListCursor; state?: InviteListState },
): Promise<InviteRecord[]> {
  const conditions: string[] = [];
  const binds: unknown[] = [];

  if (opts.cursor) {
    conditions.push("(minted_at, token) < (?, ?)");
    binds.push(opts.cursor.mintedAt, opts.cursor.token);
  }
  // "unspent" excludes both spent and pending (in-flight) invites — a pending
  // invite is spent_by_did = 'pending', which is NOT NULL.
  if (opts.state === "unspent") {
    conditions.push("spent_by_did IS NULL");
  } else if (opts.state === "spent") {
    conditions.push("spent_by_did IS NOT NULL");
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  binds.push(opts.limit);

  const result = await db.prepare(
    `SELECT token, minted_by, minted_at, spent_by_did, spent_at FROM invites ${where} ORDER BY minted_at DESC, token DESC LIMIT ?`,
  ).bind(...binds).all<InviteRecord>();
  return result.results;
}

/**
 * Revoke (hard-delete) a specific unspent invite. Only an unspent invite can be
 * revoked; a spent or in-flight ('pending') invite is preserved and reported as
 * "spent" so the caller can reject clearly. Deleting rather than flagging keeps
 * the spend path (isInviteAvailable / spendInvitePending) untouched.
 */
export async function revokeInvite(
  db: D1Database,
  token: string,
): Promise<"revoked" | "spent" | "not_found"> {
  const res = await db.prepare(
    "DELETE FROM invites WHERE token = ? AND spent_by_did IS NULL",
  ).bind(token).run();
  if (res.meta.changes === 1) {
    return "revoked";
  }

  const row = await db.prepare(
    "SELECT 1 FROM invites WHERE token = ? LIMIT 1",
  ).bind(token).first();
  return row ? "spent" : "not_found";
}

export async function isInviteAvailable(db: D1Database, token: string): Promise<boolean> {
  const row = await db.prepare(
    "SELECT 1 FROM invites WHERE token = ? AND spent_by_did IS NULL LIMIT 1",
  ).bind(token).first();

  return row !== null;
}

export async function spendInvitePending(db: D1Database, token: string): Promise<boolean> {
  const res = await db.prepare(
    "UPDATE invites SET spent_by_did = 'pending', spent_at = datetime('now') WHERE token = ? AND spent_by_did IS NULL",
  ).bind(token).run();

  return res.meta.changes === 1;
}

export async function finalizeInviteSpend(
  db: D1Database,
  token: string,
  did: string,
): Promise<boolean> {
  const res = await db.prepare(
    "UPDATE invites SET spent_by_did = ? WHERE token = ? AND spent_by_did = 'pending'",
  ).bind(did, token).run();

  return res.meta.changes === 1;
}

export async function unspendInvite(
  db: D1Database,
  token: string,
  spentByDid: string,
): Promise<boolean> {
  const res = await db.prepare(
    "UPDATE invites SET spent_by_did = NULL, spent_at = NULL WHERE token = ? AND spent_by_did = ?",
  ).bind(token, spentByDid).run();

  return res.meta.changes === 1;
}

export async function resolveByThumbprint(
  db: D1Database,
  thumbprint: string,
): Promise<{ did: string; doId: string }> {
  const row = await db.prepare(
    "SELECT did, do_id FROM accounts WHERE jwk_thumbprint = ? AND active = 1",
  ).bind(thumbprint).first<{ did: string; do_id: string }>();

  if (!row) {
    throw new RepoNotFoundError("No account found for thumbprint");
  }

  return { did: row.did, doId: row.do_id };
}
