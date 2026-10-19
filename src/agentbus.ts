// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

/**
 * agent-bus registry: `dev.agentbus.agent` records describe agents reachable
 * over agent-bus (a D-Bus mesh bridged between hosts). rookery stays
 * lexicon-agnostic for every other collection, but validates this one on write
 * and indexes it in D1 so brokers can discover agents across the whole PDS
 * with one bounded query (`dev.agentbus.listAgents`).
 *
 * One record per agent, keyed by the agent's bus name element (`rkey == name`).
 * An account may hold one agent (an agent with its own DID) or several (one
 * broker DID speaking for every agent on a desktop).
 */

export const AGENT_COLLECTION = "dev.agentbus.agent";

const AGENTS_SCHEMA = `
CREATE TABLE IF NOT EXISTS agentbus_agents (
  did TEXT NOT NULL,
  rkey TEXT NOT NULL,
  capabilities TEXT NOT NULL,
  task_classes TEXT NOT NULL,
  record TEXT NOT NULL,
  indexed_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (did, rkey)
);
`;

// D-Bus bus name elements: [A-Za-z0-9_-], must not start with a digit. We
// also drop '-' so the name is valid as an object path element too.
const AGENT_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const MAX_LIST_ITEMS = 64;
const MAX_TAG_LENGTH = 256;
const MAX_TEXT_LENGTH = 2048;
const MAX_RECORD_BYTES = 64 * 1024;

export const LIST_AGENTS_DEFAULT_LIMIT = 50;
export const LIST_AGENTS_MAX_LIMIT = 100;

export class InvalidAgentRecordError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidAgentRecordError";
  }
}

export interface AgentRecord {
  $type?: string;
  name: string;
  description?: string;
  capabilities?: string[];
  taskClasses?: string[];
  interfaces?: string[];
  endpoint?: string;
  transportKey?: string;
  freeq?: { server: string; channel?: string; did?: string };
  createdAt: string;
  [key: string]: unknown;
}

function fail(message: string): never {
  throw new InvalidAgentRecordError(`Invalid ${AGENT_COLLECTION} record: ${message}`);
}

function optionalText(record: Record<string, unknown>, field: string, max = MAX_TEXT_LENGTH): void {
  const value = record[field];
  if (value === undefined) return;
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    fail(`${field} must be a non-empty string of at most ${max} characters`);
  }
}

function optionalTagList(record: Record<string, unknown>, field: string): void {
  const value = record[field];
  if (value === undefined) return;
  if (
    !Array.isArray(value) ||
    value.length > MAX_LIST_ITEMS ||
    !value.every((tag) => typeof tag === "string" && tag.length > 0 && tag.length <= MAX_TAG_LENGTH)
  ) {
    fail(`${field} must be an array of at most ${MAX_LIST_ITEMS} non-empty strings`);
  }
}

/** Validate an agent record against its rkey. Throws InvalidAgentRecordError. */
export function validateAgentRecord(rkey: string | undefined, record: unknown): AgentRecord {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    fail("record must be an object");
  }
  const r = record as Record<string, unknown>;
  if (new TextEncoder().encode(JSON.stringify(r)).length > MAX_RECORD_BYTES) {
    fail(`record exceeds ${MAX_RECORD_BYTES} bytes`);
  }
  if (r.$type !== undefined && r.$type !== AGENT_COLLECTION) {
    fail(`$type must be ${AGENT_COLLECTION}`);
  }
  if (typeof r.name !== "string" || !AGENT_NAME_RE.test(r.name)) {
    fail("name must match [A-Za-z_][A-Za-z0-9_]{0,63} (a D-Bus name element)");
  }
  if (rkey !== r.name) {
    fail("rkey must equal name");
  }
  if (typeof r.createdAt !== "string" || Number.isNaN(Date.parse(r.createdAt))) {
    fail("createdAt must be a datetime string");
  }
  optionalText(r, "description");
  optionalText(r, "endpoint", 512);
  optionalTagList(r, "capabilities");
  optionalTagList(r, "taskClasses");
  optionalTagList(r, "interfaces");
  if (r.transportKey !== undefined) {
    optionalText(r, "transportKey", 512);
    if (!(r.transportKey as string).startsWith("did:key:")) {
      fail("transportKey must be a did:key");
    }
  }
  if (r.freeq !== undefined) {
    const freeq = r.freeq as Record<string, unknown>;
    if (!freeq || typeof freeq !== "object" || Array.isArray(freeq)) {
      fail("freeq must be an object");
    }
    if (typeof freeq.server !== "string" || freeq.server.length === 0 || freeq.server.length > 256) {
      fail("freeq.server must be a non-empty string");
    }
    optionalText(freeq, "channel", 256);
    if (freeq.did !== undefined && (typeof freeq.did !== "string" || !freeq.did.startsWith("did:"))) {
      fail("freeq.did must be a DID");
    }
  }
  return r as AgentRecord;
}

/** Write shape shared by applyWrites and the single-record routes. */
export type AgentWrite =
  | { kind: "put"; rkey: string; record: AgentRecord }
  | { kind: "delete"; rkey: string };

/**
 * Validate the agent-collection writes in an applyWrites batch before any of
 * it is committed. Returns the index updates to apply after the commit.
 */
export function collectAgentWrites(
  writes: Array<{ $type: string; collection: string; rkey?: string; record?: unknown }>,
): AgentWrite[] {
  const out: AgentWrite[] = [];
  for (const write of writes) {
    if (write.collection !== AGENT_COLLECTION) continue;
    if (write.$type === "com.atproto.repo.applyWrites#delete") {
      if (!write.rkey) fail("delete requires rkey");
      out.push({ kind: "delete", rkey: write.rkey });
    } else {
      out.push({ kind: "put", rkey: write.rkey!, record: validateAgentRecord(write.rkey, write.record) });
    }
  }
  return out;
}

// Created on use rather than in initDirectory: only agent writes and
// listAgents touch it, and an OAuth-authenticated write never runs
// initDirectory. CREATE TABLE IF NOT EXISTS is cheap and idempotent.
async function ensureAgentsSchema(db: D1Database): Promise<void> {
  await db.prepare(AGENTS_SCHEMA).run();
}

export async function applyAgentIndex(db: D1Database, did: string, writes: AgentWrite[]): Promise<void> {
  if (writes.length === 0) return;
  await ensureAgentsSchema(db);
  await db.batch(writes.map((write) =>
    write.kind === "delete"
      ? db.prepare("DELETE FROM agentbus_agents WHERE did = ? AND rkey = ?").bind(did, write.rkey)
      : db.prepare(
        `INSERT INTO agentbus_agents (did, rkey, capabilities, task_classes, record, indexed_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT (did, rkey) DO UPDATE SET
           capabilities = excluded.capabilities,
           task_classes = excluded.task_classes,
           record = excluded.record,
           indexed_at = excluded.indexed_at`,
      ).bind(
        did,
        write.rkey,
        JSON.stringify(write.record.capabilities ?? []),
        JSON.stringify(write.record.taskClasses ?? []),
        JSON.stringify(write.record),
      )
  ));
}

export async function deleteAgentsForDid(db: D1Database, did: string): Promise<void> {
  await ensureAgentsSchema(db);
  await db.prepare("DELETE FROM agentbus_agents WHERE did = ?").bind(did).run();
}

export interface AgentView {
  uri: string;
  did: string;
  handle: string;
  name: string;
  value: AgentRecord;
  indexedAt: string;
}

export interface ListAgentsQuery {
  did?: string;
  capability?: string;
  taskClass?: string;
  limit: number;
  cursor?: { did: string; rkey: string };
}

export function clampListAgentsLimit(raw: string | undefined): number | null {
  if (raw === undefined) return LIST_AGENTS_DEFAULT_LIMIT;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) return null;
  return Math.min(n, LIST_AGENTS_MAX_LIMIT);
}

export function encodeAgentCursor(agent: { did: string; name: string }): string {
  return `${agent.did}/${agent.name}`;
}

export function decodeAgentCursor(raw: string): { did: string; rkey: string } | null {
  const slash = raw.lastIndexOf("/");
  if (slash <= 0 || slash === raw.length - 1) return null;
  return { did: raw.slice(0, slash), rkey: raw.slice(slash + 1) };
}

/** Agents on active accounts, ordered by (did, rkey), filtered and bounded. */
export async function listAgents(db: D1Database, query: ListAgentsQuery): Promise<AgentView[]> {
  await ensureAgentsSchema(db);
  const where = ["a.active = 1"];
  const binds: unknown[] = [];
  if (query.did) {
    where.push("g.did = ?");
    binds.push(query.did);
  }
  if (query.capability) {
    where.push("EXISTS (SELECT 1 FROM json_each(g.capabilities) WHERE value = ?)");
    binds.push(query.capability);
  }
  if (query.taskClass) {
    where.push("EXISTS (SELECT 1 FROM json_each(g.task_classes) WHERE value = ?)");
    binds.push(query.taskClass);
  }
  if (query.cursor) {
    where.push("(g.did > ? OR (g.did = ? AND g.rkey > ?))");
    binds.push(query.cursor.did, query.cursor.did, query.cursor.rkey);
  }
  binds.push(query.limit);

  const rows = await db.prepare(
    `SELECT g.did, g.rkey, g.record, g.indexed_at, a.handle
     FROM agentbus_agents g JOIN accounts a ON a.did = g.did
     WHERE ${where.join(" AND ")}
     ORDER BY g.did, g.rkey
     LIMIT ?`,
  ).bind(...binds).all<{ did: string; rkey: string; record: string; indexed_at: string; handle: string }>();

  return rows.results.map((row) => ({
    uri: `at://${row.did}/${AGENT_COLLECTION}/${row.rkey}`,
    did: row.did,
    handle: row.handle,
    name: row.rkey,
    value: JSON.parse(row.record) as AgentRecord,
    indexedAt: row.indexed_at,
  }));
}
