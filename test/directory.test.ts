import { Secp256k1Keypair } from "@atproto/crypto";
import type { AccountDurableObject } from "../src/account-do";
import {
  generateInviteToken,
  initDirectory,
  insertAccount,
  listInvites,
  mintOrgInvite,
  mintRookInvite,
  resolveRepo,
  revokeInvite,
  spendInvitePending,
  unspendInvite,
} from "../src/directory";
import { env, runInDurableObject, worker } from "./helpers";
import { describe, it, expect, beforeAll } from "vitest";
import { toString } from "uint8arrays/to-string";

async function generateTestKeys() {
  const signing = await Secp256k1Keypair.create({ exportable: true });
  const rotation = await Secp256k1Keypair.create({ exportable: true });
  return {
    signingKeyHex: toString(await signing.export(), "hex"),
    signingKeyPub: signing.did().split(":").pop()!,
    rotationKeyHex: toString(await rotation.export(), "hex"),
    rotationKeyPub: rotation.did().split(":").pop()!,
  };
}

async function setupTestAccount(
  testEnv: typeof env,
  opts: { did: string; handle: string },
) {
  const keys = await generateTestKeys();
  const doId = testEnv.ACCOUNT.newUniqueId();
  const stub = testEnv.ACCOUNT.get(doId);

  await runInDurableObject(stub, async (instance: AccountDurableObject) => {
    await instance.rpcInitAccount({
      did: opts.did,
      handle: opts.handle,
      ...keys,
    });
  });

  await insertAccount(testEnv.DIRECTORY, {
    did: opts.did,
    handle: opts.handle,
    doId: doId.toString(),
  });

  return { did: opts.did, handle: opts.handle, doId: doId.toString() };
}

describe("D1 Directory", () => {
  beforeAll(async () => {
    await initDirectory(env.DIRECTORY);
  });

  describe("com.atproto.identity.resolveHandle", () => {
    it("resolves a known handle to a DID", async () => {
      const account = await setupTestAccount(env, {
        did: "did:plc:resolve-test-1",
        handle: "alice.rookery.test",
      });
      const res = await worker.fetch(
        "http://localhost/xrpc/com.atproto.identity.resolveHandle?handle=alice.rookery.test",
      );
      expect(res.status).toBe(200);
      const body = await res.json() as { did: string };
      expect(body.did).toBe(account.did);
    });

    it("returns 400 when handle param is missing", async () => {
      const res = await worker.fetch(
        "http://localhost/xrpc/com.atproto.identity.resolveHandle",
      );
      expect(res.status).toBe(400);
    });

    it("returns 404 for unknown handle", async () => {
      const res = await worker.fetch(
        "http://localhost/xrpc/com.atproto.identity.resolveHandle?handle=nobody.rookery.test",
      );
      expect(res.status).toBe(404);
    });
  });

  describe("DO ID round-trip", () => {
    it("resolveRepo returns doId that recovers a valid DO stub", async () => {
      const account = await setupTestAccount(env, {
        did: "did:plc:roundtrip-test-1",
        handle: "roundtrip.rookery.test",
      });
      const resolved = await resolveRepo("roundtrip.rookery.test", env);
      expect(resolved.did).toBe(account.did);
      expect(resolved.doId).toBe(account.doId);

      // Round-trip: recover DO stub from stored doId
      const recoveredId = env.ACCOUNT.idFromString(resolved.doId);
      const stub = env.ACCOUNT.get(recoveredId);
      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const state = await instance.rpcGetState();
        expect(state).not.toBeNull();
        expect(state!.did).toBe(account.did);
        expect(state!.handle).toBe(account.handle);
      });
    });
  });

  describe("com.atproto.sync.listRepos", () => {
    it("returns repos ordered by DID", async () => {
      const res = await worker.fetch(
        "http://localhost/xrpc/com.atproto.sync.listRepos",
      );
      expect(res.status).toBe(200);
      const body = await res.json() as {
        repos: Array<{ did: string; head: string; rev: string; active: boolean }>;
      };
      expect(Array.isArray(body.repos)).toBe(true);
      for (let i = 1; i < body.repos.length; i++) {
        expect(body.repos[i].did > body.repos[i - 1].did).toBe(true);
      }
      for (const repo of body.repos) {
        expect(typeof repo.head).toBe("string");
        expect(typeof repo.rev).toBe("string");
      }
    });

    it("paginates with cursor", async () => {
      await setupTestAccount(env, {
        did: "did:plc:page-a",
        handle: "page-a.rookery.test",
      });
      await setupTestAccount(env, {
        did: "did:plc:page-b",
        handle: "page-b.rookery.test",
      });
      await setupTestAccount(env, {
        did: "did:plc:page-c",
        handle: "page-c.rookery.test",
      });

      const res1 = await worker.fetch(
        "http://localhost/xrpc/com.atproto.sync.listRepos?limit=1",
      );
      expect(res1.status).toBe(200);
      const body1 = await res1.json() as {
        repos: Array<{ did: string; head: string; rev: string }>;
        cursor?: string;
      };
      expect(body1.repos.length).toBe(1);
      expect(body1.cursor).toBeTruthy();

      const res2 = await worker.fetch(
        `http://localhost/xrpc/com.atproto.sync.listRepos?limit=1&cursor=${body1.cursor}`,
      );
      expect(res2.status).toBe(200);
      const body2 = await res2.json() as {
        repos: Array<{ did: string; head: string; rev: string }>;
      };
      expect(body2.repos.length).toBe(1);
      expect(body2.repos[0].did).not.toBe(body1.repos[0].did);
      expect(typeof body2.repos[0].head).toBe("string");
      expect(typeof body2.repos[0].rev).toBe("string");
      expect(body2.repos[0].did > body1.repos[0].did).toBe(true);
    });

    it("omits cursor on final page", async () => {
      const res = await worker.fetch(
        "http://localhost/xrpc/com.atproto.sync.listRepos?limit=1000",
      );
      expect(res.status).toBe(200);
      const body = await res.json() as {
        repos: Array<{ did: string; head: string; rev: string }>;
        cursor?: string;
      };
      if (body.repos.length < 1000) {
        expect(body.cursor).toBeUndefined();
      }
    });
  });

  describe("com.atproto.server.describeServer", () => {
    it("returns server description with account count", async () => {
      const res = await worker.fetch(
        "http://localhost/xrpc/com.atproto.server.describeServer",
      );
      expect(res.status).toBe(200);
      const body = await res.json() as {
        availableUserDomains: string[];
        inviteCodeRequired: boolean;
        accounts: number;
      };
      expect(body.availableUserDomains).toContain("rookery.test");
      expect(body.inviteCodeRequired).toBe(false);
      expect(typeof body.accounts).toBe("number");
      expect(body.accounts).toBeGreaterThanOrEqual(0);
    });
  });

  describe("invite helpers", () => {
    it("generates 10-character lowercase Crockford invite tokens", () => {
      const alphabet = /^[0123456789abcdefghjkmnpqrstvwxyz]+$/;
      for (let i = 0; i < 5000; i++) {
        const token = generateInviteToken();
        expect(token).toHaveLength(10);
        expect(token).toMatch(alphabet);
      }
    });

    it("mintRookInvite returns null at the quota boundary", async () => {
      const did = `did:plc:dir-mint-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      const first = await mintRookInvite(env.DIRECTORY, did, 1);
      expect(first).not.toBeNull();
      expect(first?.remaining).toBe(0);

      const second = await mintRookInvite(env.DIRECTORY, did, 1);
      expect(second).toBeNull();
    });

    it("spends an invite only once", async () => {
      const token = `dir-spend-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      await env.DIRECTORY.prepare(
        "INSERT INTO invites (token) VALUES (?)",
      ).bind(token).run();

      expect(await spendInvitePending(env.DIRECTORY, token)).toBe(true);
      expect(await spendInvitePending(env.DIRECTORY, token)).toBe(false);
    });

    it("unspends only with the matching spent_by_did predicate", async () => {
      const token = `dir-unspend-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      await env.DIRECTORY.prepare(
        "INSERT INTO invites (token) VALUES (?)",
      ).bind(token).run();

      expect(await spendInvitePending(env.DIRECTORY, token)).toBe(true);
      expect(await unspendInvite(env.DIRECTORY, token, "did:plc:not-pending")).toBe(false);
      const pending = await env.DIRECTORY.prepare(
        "SELECT spent_by_did, spent_at FROM invites WHERE token = ?",
      ).bind(token).first<{ spent_by_did: string | null; spent_at: string | null }>();
      expect(pending).toMatchObject({ spent_by_did: "pending" });
      expect(pending?.spent_at).not.toBeNull();

      expect(await unspendInvite(env.DIRECTORY, token, "pending")).toBe(true);
      const unspent = await env.DIRECTORY.prepare(
        "SELECT spent_by_did, spent_at FROM invites WHERE token = ?",
      ).bind(token).first<{ spent_by_did: string | null; spent_at: string | null }>();
      expect(unspent).toMatchObject({ spent_by_did: null, spent_at: null });
    });

    it("mintOrgInvite is idempotent for a repeated key and fresh otherwise", async () => {
      const key = `dir-idem-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      const first = await mintOrgInvite(env.DIRECTORY, { idempotencyKey: key });
      expect(first.replayed).toBe(false);
      expect(first.token).toHaveLength(10);

      const replay = await mintOrgInvite(env.DIRECTORY, { idempotencyKey: key });
      expect(replay.replayed).toBe(true);
      expect(replay.token).toBe(first.token);

      const different = await mintOrgInvite(env.DIRECTORY, {
        idempotencyKey: `${key}-other`,
      });
      expect(different.replayed).toBe(false);
      expect(different.token).not.toBe(first.token);

      // Un-keyed mints always create a distinct invite.
      const bareA = await mintOrgInvite(env.DIRECTORY);
      const bareB = await mintOrgInvite(env.DIRECTORY);
      expect(bareA.replayed).toBe(false);
      expect(bareB.token).not.toBe(bareA.token);
    });

    it("collapses concurrent same-key mints to a single invite", async () => {
      // Against a single D1 connection (production shape), the partial unique
      // index backstops the check-then-insert: the losing INSERT hits
      // SQLITE_CONSTRAINT and resolves to the winner's token.
      const key = `dir-idem-race-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      const results = await Promise.all(
        Array.from({ length: 6 }, () => mintOrgInvite(env.DIRECTORY, { idempotencyKey: key })),
      );
      const tokens = new Set(results.map((r) => r.token));
      expect(tokens.size).toBe(1);
      expect(results.filter((r) => !r.replayed)).toHaveLength(1);

      const row = await env.DIRECTORY.prepare(
        "SELECT COUNT(*) AS count FROM invites WHERE idempotency_key = ?",
      ).bind(key).first<{ count: number }>();
      expect(row?.count).toBe(1);
    });

    it("revokeInvite removes an unspent invite and reports spent/not_found", async () => {
      const prefix = `dir-revoke-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

      await env.DIRECTORY.prepare("INSERT INTO invites (token) VALUES (?)").bind(`${prefix}-unspent`).run();
      expect(await revokeInvite(env.DIRECTORY, `${prefix}-unspent`)).toBe("revoked");
      expect(
        await env.DIRECTORY.prepare("SELECT 1 FROM invites WHERE token = ?").bind(`${prefix}-unspent`).first(),
      ).toBeNull();

      expect(await revokeInvite(env.DIRECTORY, `${prefix}-missing`)).toBe("not_found");

      await env.DIRECTORY.prepare(
        "INSERT INTO invites (token, spent_by_did, spent_at) VALUES (?, ?, datetime('now'))",
      ).bind(`${prefix}-spent`, "did:plc:x").run();
      expect(await revokeInvite(env.DIRECTORY, `${prefix}-spent`)).toBe("spent");

      // A pending (in-flight) invite is likewise not revocable.
      await env.DIRECTORY.prepare("INSERT INTO invites (token) VALUES (?)").bind(`${prefix}-pending`).run();
      expect(await spendInvitePending(env.DIRECTORY, `${prefix}-pending`)).toBe(true);
      expect(await revokeInvite(env.DIRECTORY, `${prefix}-pending`)).toBe("spent");
    });

    it("listInvites state filter separates unspent from spent/pending", async () => {
      const prefix = `dir-state-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      await env.DIRECTORY.batch([
        env.DIRECTORY.prepare(
          "INSERT INTO invites (token, minted_at) VALUES (?, ?)",
        ).bind(`${prefix}-u`, "2099-07-01 00:00:00"),
        env.DIRECTORY.prepare(
          "INSERT INTO invites (token, minted_at, spent_by_did, spent_at) VALUES (?, ?, ?, ?)",
        ).bind(`${prefix}-s`, "2099-07-02 00:00:00", "did:plc:s", "2099-07-03 00:00:00"),
        env.DIRECTORY.prepare(
          "INSERT INTO invites (token, minted_at, spent_by_did, spent_at) VALUES (?, ?, 'pending', ?)",
        ).bind(`${prefix}-p`, "2099-07-04 00:00:00", "2099-07-05 00:00:00"),
      ]);

      const unspent = (await listInvites(env.DIRECTORY, { limit: 500, state: "unspent" }))
        .map((r) => r.token);
      expect(unspent).toContain(`${prefix}-u`);
      expect(unspent).not.toContain(`${prefix}-s`);
      expect(unspent).not.toContain(`${prefix}-p`);

      const spent = (await listInvites(env.DIRECTORY, { limit: 500, state: "spent" }))
        .map((r) => r.token);
      expect(spent).toContain(`${prefix}-s`);
      expect(spent).toContain(`${prefix}-p`);
      expect(spent).not.toContain(`${prefix}-u`);
    });

    it("initDirectory tolerates concurrent invocation", async () => {
      await Promise.all(Array.from({ length: 8 }, () => initDirectory(env.DIRECTORY)));
      // A directory op immediately after concurrent init works.
      const minted = await mintOrgInvite(env.DIRECTORY);
      expect(minted.token).toHaveLength(10);
    });
  });

  describe(".well-known/atproto-did", () => {
    it("returns DID for a known handle hostname", async () => {
      await setupTestAccount(env, {
        did: "did:plc:wellknown-test-1",
        handle: "wk-test.rookery.test",
      });
      const res = await worker.fetch(
        new Request("http://localhost/.well-known/atproto-did", {
          headers: { Host: "wk-test.rookery.test" },
        }),
      );
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text).toBe("did:plc:wellknown-test-1");
    });

    it("returns 404 for unknown handle hostname", async () => {
      const res = await worker.fetch(
        new Request("http://localhost/.well-known/atproto-did", {
          headers: { Host: "unknown.rookery.test" },
        }),
      );
      expect(res.status).toBe(404);
    });
  });
});
