// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

/**
 * agent-bus registry: `org.latha.agentbus.agent` records describe agents reachable
 * over agent-bus (a D-Bus mesh bridged between hosts). rookery stays
 * lexicon-agnostic for every other collection, but validates this one on write
 * and indexes it in D1 so brokers can discover agents across the whole PDS
 * with one bounded query (`org.latha.agentbus.listAgents`).
 *
 * One record per agent, keyed by the agent's bus name element (`rkey == name`).
 * An account may hold one agent (an agent with its own DID) or several (one
 * broker DID speaking for every agent on a desktop).
 */

export const AGENT_COLLECTION = "org.latha.agentbus.agent";

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

/*
 * `org.latha.agentbus.proc` records describe networked procs: deterministic bots
 * that host functions and publish topics on agent-bus. Each public proc has
 * its own account holding one record, keyed by the proc's name, that lists
 * what it provides and publishes. Validated and indexed like agents, served by
 * `org.latha.agentbus.listProcs`.
 */

export const PROC_COLLECTION = "org.latha.agentbus.proc";

const PROCS_SCHEMA = `
CREATE TABLE IF NOT EXISTS agentbus_procs (
  did TEXT NOT NULL,
  rkey TEXT NOT NULL,
  functions TEXT NOT NULL,
  topics TEXT NOT NULL,
  record TEXT NOT NULL,
  indexed_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (did, rkey)
);
`;

// Function and topic names: dotted app-domain words, e.g. weather.current.
const BUS_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z][A-Za-z0-9_-]*)*$/;

export interface ProcRecord {
  $type?: string;
  name: string;
  description?: string;
  provides?: Array<{ function: string; regions?: string[] }>;
  publishes?: Array<{ topic: string; subjects?: string }>;
  freeq?: { server: string; channel?: string; did?: string };
  createdAt: string;
  [key: string]: unknown;
}

function failProc(message: string): never {
  throw new InvalidAgentRecordError(`Invalid ${PROC_COLLECTION} record: ${message}`);
}

function entryList(
  record: Record<string, unknown>,
  field: "provides" | "publishes",
  key: "function" | "topic",
): void {
  const value = record[field];
  if (value === undefined) return;
  if (!Array.isArray(value) || value.length > MAX_LIST_ITEMS) {
    failProc(`${field} must be an array of at most ${MAX_LIST_ITEMS} entries`);
  }
  for (const entry of value) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      failProc(`${field} entries must be objects`);
    }
    const e = entry as Record<string, unknown>;
    const name = e[key];
    if (typeof name !== "string" || name.length > MAX_TAG_LENGTH || !BUS_NAME_RE.test(name)) {
      failProc(`${field}[].${key} must be a dotted name such as weather.current`);
    }
    try {
      optionalTagList(e, "regions");
      optionalText(e, "subjects", MAX_TAG_LENGTH);
    } catch {
      failProc(`${field}[] has a malformed regions or subjects field`);
    }
  }
}

/** Validate a proc record against its rkey. Throws InvalidAgentRecordError. */
export function validateProcRecord(rkey: string | undefined, record: unknown): ProcRecord {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    failProc("record must be an object");
  }
  const r = record as Record<string, unknown>;
  if (new TextEncoder().encode(JSON.stringify(r)).length > MAX_RECORD_BYTES) {
    failProc(`record exceeds ${MAX_RECORD_BYTES} bytes`);
  }
  if (r.$type !== undefined && r.$type !== PROC_COLLECTION) {
    failProc(`$type must be ${PROC_COLLECTION}`);
  }
  if (typeof r.name !== "string" || !AGENT_NAME_RE.test(r.name)) {
    failProc("name must match [A-Za-z_][A-Za-z0-9_]{0,63}");
  }
  if (rkey !== r.name) {
    failProc("rkey must equal name");
  }
  if (typeof r.createdAt !== "string" || Number.isNaN(Date.parse(r.createdAt))) {
    failProc("createdAt must be a datetime string");
  }
  try {
    optionalText(r, "description");
  } catch {
    failProc(`description must be a non-empty string of at most ${MAX_TEXT_LENGTH} characters`);
  }
  entryList(r, "provides", "function");
  entryList(r, "publishes", "topic");
  if (r.freeq !== undefined) {
    const freeq = r.freeq as Record<string, unknown>;
    if (
      !freeq || typeof freeq !== "object" || Array.isArray(freeq) ||
      typeof freeq.server !== "string" || freeq.server.length === 0 || freeq.server.length > 256 ||
      (freeq.channel !== undefined && (typeof freeq.channel !== "string" || freeq.channel.length > 256)) ||
      (freeq.did !== undefined && (typeof freeq.did !== "string" || !freeq.did.startsWith("did:")))
    ) {
      failProc("freeq must be {server, channel?, did?}");
    }
  }
  return r as ProcRecord;
}

export type ProcWrite =
  | { kind: "put"; rkey: string; record: ProcRecord }
  | { kind: "delete"; rkey: string };

/** Validate the proc-collection writes in a batch before any of it is committed. */
export function collectProcWrites(
  writes: Array<{ $type: string; collection: string; rkey?: string; record?: unknown }>,
): ProcWrite[] {
  const out: ProcWrite[] = [];
  for (const write of writes) {
    if (write.collection !== PROC_COLLECTION) continue;
    if (write.$type === "com.atproto.repo.applyWrites#delete") {
      if (!write.rkey) failProc("delete requires rkey");
      out.push({ kind: "delete", rkey: write.rkey });
    } else {
      out.push({ kind: "put", rkey: write.rkey!, record: validateProcRecord(write.rkey, write.record) });
    }
  }
  return out;
}

async function ensureProcsSchema(db: D1Database): Promise<void> {
  await db.prepare(PROCS_SCHEMA).run();
}

export async function applyProcIndex(db: D1Database, did: string, writes: ProcWrite[]): Promise<void> {
  if (writes.length === 0) return;
  await ensureProcsSchema(db);
  await db.batch(writes.map((write) =>
    write.kind === "delete"
      ? db.prepare("DELETE FROM agentbus_procs WHERE did = ? AND rkey = ?").bind(did, write.rkey)
      : db.prepare(
        `INSERT INTO agentbus_procs (did, rkey, functions, topics, record, indexed_at)
         VALUES (?, ?, ?, ?, ?, datetime('now'))
         ON CONFLICT (did, rkey) DO UPDATE SET
           functions = excluded.functions,
           topics = excluded.topics,
           record = excluded.record,
           indexed_at = excluded.indexed_at`,
      ).bind(
        did,
        write.rkey,
        JSON.stringify((write.record.provides ?? []).map((p) => p.function)),
        JSON.stringify((write.record.publishes ?? []).map((p) => p.topic)),
        JSON.stringify(write.record),
      )
  ));
}

export async function deleteProcsForDid(db: D1Database, did: string): Promise<void> {
  await ensureProcsSchema(db);
  await db.prepare("DELETE FROM agentbus_procs WHERE did = ?").bind(did).run();
}

export interface ProcView {
  uri: string;
  did: string;
  handle: string;
  name: string;
  value: ProcRecord;
  indexedAt: string;
}

export interface ListProcsQuery {
  did?: string;
  fn?: string;
  topic?: string;
  limit: number;
  cursor?: { did: string; rkey: string };
}

/** Procs on active accounts, ordered by (did, rkey), filtered and bounded. */
export async function listProcs(db: D1Database, query: ListProcsQuery): Promise<ProcView[]> {
  await ensureProcsSchema(db);
  const where = ["a.active = 1"];
  const binds: unknown[] = [];
  if (query.did) {
    where.push("p.did = ?");
    binds.push(query.did);
  }
  if (query.fn) {
    where.push("EXISTS (SELECT 1 FROM json_each(p.functions) WHERE value = ?)");
    binds.push(query.fn);
  }
  if (query.topic) {
    where.push("EXISTS (SELECT 1 FROM json_each(p.topics) WHERE value = ?)");
    binds.push(query.topic);
  }
  if (query.cursor) {
    where.push("(p.did > ? OR (p.did = ? AND p.rkey > ?))");
    binds.push(query.cursor.did, query.cursor.did, query.cursor.rkey);
  }
  binds.push(query.limit);

  const rows = await db.prepare(
    `SELECT p.did, p.rkey, p.record, p.indexed_at, a.handle
     FROM agentbus_procs p JOIN accounts a ON a.did = p.did
     WHERE ${where.join(" AND ")}
     ORDER BY p.did, p.rkey
     LIMIT ?`,
  ).bind(...binds).all<{ did: string; rkey: string; record: string; indexed_at: string; handle: string }>();

  return rows.results.map((row) => ({
    uri: `at://${row.did}/${PROC_COLLECTION}/${row.rkey}`,
    did: row.did,
    handle: row.handle,
    name: row.rkey,
    value: JSON.parse(row.record) as ProcRecord,
    indexedAt: row.indexed_at,
  }));
}

/*
 * Service provider records: a proc serving the XRPC methods of service
 * `org.latha.agentbus.<service>` (e.g. `org.latha.agentbus.weather.current`) over HTTPS
 * holds one record in the collection named for the service itself
 * (`org.latha.agentbus.weather`), rkey `self`, naming its endpoint and the methods
 * it implements. Brokers find providers through a relay's
 * `com.atproto.sync.listReposByCollection`, so rookery validates these on
 * write but does not index them.
 */

const SERVICE_RKEY = "self";
const RESERVED_COLLECTIONS = new Set([AGENT_COLLECTION, PROC_COLLECTION]);
// org.latha.agentbus.<one or more lowercase-led segments>
const SERVICE_NSID_RE = /^org\.latha\.agentbus(\.[a-z][A-Za-z0-9]{0,62})+$/;
const METHOD_NAME_RE = /^[a-z][A-Za-z0-9]{0,62}$/;
const MAX_ENDPOINT_LENGTH = 512;

export interface ServiceRecord {
  $type?: string;
  endpoint: string;
  methods: string[];
  createdAt: string;
  [key: string]: unknown;
}

/** Is `collection` a service provider collection (org.latha.agentbus.* minus agent/proc)? */
export function isServiceCollection(collection: string): boolean {
  return collection.startsWith("org.latha.agentbus.") && !RESERVED_COLLECTIONS.has(collection);
}

/** An https URL without credentials, query or fragment; plain http only on localhost (local dev). */
function isServiceEndpoint(value: unknown): value is string {
  if (typeof value !== "string" || value.length > MAX_ENDPOINT_LENGTH) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.username || url.password || url.search || url.hash) return false;
  return url.protocol === "https:" ||
    (url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1"));
}

/** Validate a provider record for service `collection`. Throws InvalidAgentRecordError. */
export function validateServiceRecord(collection: string, rkey: string | undefined, record: unknown): ServiceRecord {
  const fail = (message: string): never => {
    throw new InvalidAgentRecordError(`Invalid ${collection} record: ${message}`);
  };
  if (!SERVICE_NSID_RE.test(collection) || collection.length > MAX_TAG_LENGTH) {
    fail("collection must be org.latha.agentbus.<service>, e.g. org.latha.agentbus.weather");
  }
  if (rkey !== SERVICE_RKEY) fail(`rkey must be ${SERVICE_RKEY}`);
  if (!record || typeof record !== "object" || Array.isArray(record)) fail("record must be an object");
  const r = record as Record<string, unknown>;
  if (new TextEncoder().encode(JSON.stringify(r)).length > MAX_RECORD_BYTES) {
    fail(`record exceeds ${MAX_RECORD_BYTES} bytes`);
  }
  if (r.$type !== undefined && r.$type !== collection) fail(`$type must be ${collection}`);
  if (!isServiceEndpoint(r.endpoint)) {
    fail(`endpoint must be an https URL of at most ${MAX_ENDPOINT_LENGTH} characters, without query or fragment`);
  }
  const methods = r.methods;
  if (!Array.isArray(methods) || methods.length === 0 || methods.length > MAX_LIST_ITEMS) {
    fail(`methods must be a non-empty array of at most ${MAX_LIST_ITEMS} NSIDs`);
  }
  for (const method of methods as unknown[]) {
    if (
      typeof method !== "string" || !method.startsWith(`${collection}.`) ||
      !METHOD_NAME_RE.test(method.slice(collection.length + 1))
    ) {
      fail(`methods[] must be NSIDs directly under ${collection}, e.g. ${collection}.current`);
    }
  }
  if (typeof r.createdAt !== "string" || Number.isNaN(Date.parse(r.createdAt))) {
    fail("createdAt must be a datetime string");
  }
  return r as ServiceRecord;
}

/** Validate the service provider records in a batch before any of it is committed. */
export function checkServiceWrites(
  writes: Array<{ $type: string; collection: string; rkey?: string; record?: unknown }>,
): void {
  for (const write of writes) {
    if (!isServiceCollection(write.collection) || write.$type === "com.atproto.repo.applyWrites#delete") continue;
    validateServiceRecord(write.collection, write.rkey, write.record);
  }
}
