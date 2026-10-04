// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import {
  buildAccessToken,
  createDpopJwt,
  env,
  generateAuthKeys,
  runInDurableObject,
  signJwt,
  signTos,
  worker,
} from "./helpers";
import { decodeFirst } from "@atcute/cbor";
import app from "../src/worker";
import { __resetAccessJwksCache } from "../src/access";
import { AccountDurableObject } from "../src/account-do";
import type { Env } from "../src/types";
import {
  deactivateAccount,
  initDirectory,
  insertAccount,
  setInviteQuota,
  spendInvitePending,
} from "../src/directory";
import {
  initOAuth,
  insertOAuthCode,
  insertOAuthSession,
  insertOAuthToken,
} from "../src/oauth/store";
import {
  backfillFirehose,
  getLatestSequencerCursor,
} from "./firehose-helpers";

const SERVICE_ORIGIN = `https://${env.ROOKERY_HOSTNAME}`;

type SignupBody = {
  did?: string;
  handle?: string;
  access_token?: string;
  token_type?: string;
  error?: string;
  message?: string;
};

type SignupResult = {
  status: number;
  body: SignupBody;
  text: string;
  authKeys: CryptoKeyPair;
  publicJwk: JsonWebKey;
  accessToken: string;
};

type TakedownBody = {
  did: string;
  handle: string;
  recordsDeleted: number;
  blobsDeleted: number;
  collections: string[];
};

type AccessFixture = {
  privateKey: CryptoKey;
  publicJwk: {
    kid: string;
    kty: "RSA";
    alg: "RS256";
    use: "sig";
    n: string;
    e: string;
  };
};

function uniqueLabel(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function entryRef(token: string): string {
  return `https://rookery.test/roost#${token}`;
}

function fullHandle(handle: string): string {
  return handle.toLowerCase() + env.ROOKERY_HANDLE_DOMAIN;
}

async function fetchTosText(): Promise<string> {
  const response = await worker.fetch("http://localhost/tos");
  expect(response.status).toBe(200);
  return response.text();
}

function fetchInputUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof Request) return input.url;
  return input.href;
}

function stubPlcDirectory(options: {
  status?: number;
  body?: string;
  onPlc?: (url: string) => void | Promise<void>;
  accessJwk?: AccessFixture["publicJwk"];
  webhook?: {
    url: string;
    handler: (request: Request) => Response | Promise<Response>;
  };
} = {}) {
  const originalFetch = globalThis.fetch.bind(globalThis);
  return vi
    .spyOn(globalThis, "fetch")
    .mockImplementation(async (input, init) => {
      const url = fetchInputUrl(input);
      if (options.webhook && url === options.webhook.url) {
        const request = input instanceof Request && init === undefined
          ? input
          : new Request(input, init);
        return options.webhook.handler(request);
      }
      if (url.startsWith("https://plc.directory/")) {
        await options.onPlc?.(url);
        return new Response(options.body ?? null, { status: options.status ?? 200 });
      }
      if (url.startsWith(`https://${env.CF_ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`)) {
        if (!options.accessJwk) {
          return new Response(null, { status: 404 });
        }
        return Response.json({
          keys: [options.accessJwk],
          public_cert: "",
          public_certs: [],
        });
      }
      return originalFetch(input as RequestInfo | URL, init);
    });
}

function plcCallCount(fetchSpy: ReturnType<typeof stubPlcDirectory>): number {
  return fetchSpy.mock.calls.filter(([input]) =>
    fetchInputUrl(input).startsWith("https://plc.directory/")
  ).length;
}

async function insertInvite(token: string): Promise<void> {
  await initDirectory(env.DIRECTORY);
  await env.DIRECTORY.prepare(
    "INSERT INTO invites (token) VALUES (?)",
  ).bind(token).run();
}

async function getInvite(token: string): Promise<{
  token: string;
  minted_by: string | null;
  minted_at: string;
  spent_by_did: string | null;
  spent_at: string | null;
} | null> {
  return env.DIRECTORY.prepare(
    "SELECT token, minted_by, minted_at, spent_by_did, spent_at FROM invites WHERE token = ?",
  ).bind(token).first<{
    token: string;
    minted_by: string | null;
    minted_at: string;
    spent_by_did: string | null;
    spent_at: string | null;
  }>();
}

async function expectNoAccount(handle: string): Promise<void> {
  const row = await env.DIRECTORY.prepare(
    "SELECT 1 FROM accounts WHERE handle = ? LIMIT 1",
  ).bind(fullHandle(handle)).first();
  expect(row).toBeNull();
}

async function accountExists(did: string): Promise<boolean> {
  const row = await env.DIRECTORY.prepare(
    "SELECT 1 FROM accounts WHERE did = ? LIMIT 1",
  ).bind(did).first();
  return row !== null;
}

async function signupWithFreshKeys(
  handle: string,
  ref?: string,
): Promise<SignupResult> {
  const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
  const tosText = await fetchTosText();
  const accessToken = await buildAccessToken(authKeys, thumbprint, tosText, SERVICE_ORIGIN);
  const requestBody: Record<string, string> = {
    handle,
    tos_signature: await signTos(authKeys.privateKey, tosText),
    access_token: accessToken,
  };
  if (ref !== undefined) {
    requestBody.ref = ref;
  }

  const response = await worker.fetch(
    new Request("http://localhost/api/signup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        dpop: await createDpopJwt(authKeys, publicJwk, "http://localhost/api/signup", null),
      },
      body: JSON.stringify(requestBody),
    }),
  );
  const text = await response.text();
  let body: SignupBody = {};
  if (text.length > 0) {
    try {
      body = JSON.parse(text) as SignupBody;
    } catch {
      body = {};
    }
  }
  return { status: response.status, body, text, authKeys, publicJwk, accessToken };
}

async function enrollRookWithInvite(
  prefix: string,
): Promise<SignupResult & { did: string; inviteToken: string }> {
  const token = uniqueLabel(`${prefix}-invite`);
  await insertInvite(token);
  const result = await signupWithFreshKeys(uniqueLabel(prefix), entryRef(token));
  expect(result.status).toBe(200);
  expect(result.body.did).toBeTruthy();
  return { ...result, did: result.body.did!, inviteToken: token };
}

async function publishRecord(
  account: SignupResult & { did: string },
  collection = "app.bsky.feed.post",
  rkey?: string,
): Promise<{ uri: string; cid: string }> {
  const url = "http://localhost/xrpc/com.atproto.repo.createRecord";
  const response = await worker.fetch(
    new Request(url, {
      method: "POST",
      headers: {
        authorization: `DPoP ${account.accessToken}`,
        dpop: await createDpopJwt(account.authKeys, account.publicJwk, url, account.accessToken),
        "content-type": "application/json",
      },
      body: JSON.stringify({
        repo: account.did,
        collection,
        ...(rkey ? { rkey } : {}),
        record: {
          text: uniqueLabel("post"),
          createdAt: new Date().toISOString(),
        },
      }),
    }),
  );
  expect(response.status).toBe(200);
  return response.json<{ uri: string; cid: string }>();
}

async function uploadBlob(
  account: SignupResult & { did: string },
  bytes: Uint8Array,
): Promise<{ ref: { $link: string } }> {
  const url = "http://localhost/xrpc/com.atproto.repo.uploadBlob";
  const response = await worker.fetch(
    new Request(url, {
      method: "POST",
      headers: {
        authorization: `DPoP ${account.accessToken}`,
        dpop: await createDpopJwt(account.authKeys, account.publicJwk, url, account.accessToken),
        "content-type": "text/plain",
      },
      body: bytes,
    }),
  );
  expect(response.status).toBe(200);
  return (await response.json<{ blob: { ref: { $link: string } } }>()).blob;
}

async function getAccountStub(did: string) {
  const row = await env.DIRECTORY.prepare(
    "SELECT do_id FROM accounts WHERE did = ?",
  ).bind(did).first<{ do_id: string }>();
  if (!row) throw new Error(`Missing test account ${did}`);
  return env.ACCOUNT.get(env.ACCOUNT.idFromString(row.do_id));
}

async function takedownAccount(
  account: SignupResult & { did: string },
  access: AccessFixture,
  overrides: Record<string, unknown> = {},
): Promise<Response> {
  return adminFetch(
    `/admin/accounts/${account.did}`,
    access,
    {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ confirm: account.body.handle }),
    },
    overrides,
  );
}

function decodeFirehoseFrame(frame: ArrayBuffer): {
  header: Record<string, unknown>;
  body: Record<string, unknown>;
} {
  const [header, bodyBytes] = decodeFirst(new Uint8Array(frame));
  const [body, remainder] = decodeFirst(bodyBytes);
  expect(remainder).toHaveLength(0);
  return {
    header: header as Record<string, unknown>,
    body: body as Record<string, unknown>,
  };
}

async function mintAsRook(account: SignupResult & { did: string }): Promise<{
  status: number;
  body: { token?: string; url?: string; remaining?: number; error?: string; message?: string };
}> {
  const url = "http://localhost/api/invites";
  const response = await worker.fetch(
    new Request(url, {
      method: "POST",
      headers: {
        authorization: `DPoP ${account.accessToken}`,
        dpop: await createDpopJwt(account.authKeys, account.publicJwk, url, account.accessToken),
      },
    }),
  );
  return {
    status: response.status,
    body: await response.json(),
  };
}

async function resetDefaultQuotaToSeed(): Promise<void> {
  await initDirectory(env.DIRECTORY);
  await env.DIRECTORY.prepare(
    "DELETE FROM config WHERE key = 'invite_quota_default'",
  ).run();
  await initDirectory(env.DIRECTORY);
}

async function generateAccessFixture(): Promise<AccessFixture> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const exported = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return {
    privateKey: keyPair.privateKey,
    publicJwk: {
      kid: uniqueLabel("access-kid"),
      kty: "RSA",
      alg: "RS256",
      use: "sig",
      n: exported.n!,
      e: exported.e!,
    },
  };
}

async function buildAccessAssertion(
  access: AccessFixture,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    { alg: "RS256", kid: access.publicJwk.kid },
    {
      iss: `https://${env.CF_ACCESS_TEAM_DOMAIN}`,
      aud: [env.CF_ACCESS_AUD],
      exp: now + 300,
      iat: now,
      sub: "access-test-sub",
      email: "operator@example.com",
      identity_nonce: uniqueLabel("nonce"),
      ...overrides,
    },
    access.privateKey,
  );
}

async function adminFetch(
  path: string,
  access: AccessFixture,
  init: RequestInit = {},
  overrides: Record<string, unknown> = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Cf-Access-Jwt-Assertion", await buildAccessAssertion(access, overrides));
  return worker.fetch(new Request(`http://localhost${path}`, { ...init, headers }));
}

async function directTakedownAccount(
  account: SignupResult & { did: string },
  access: AccessFixture,
  testEnv: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const headers = new Headers({ "content-type": "application/json" });
  headers.set("Cf-Access-Jwt-Assertion", await buildAccessAssertion(access));
  const request = new Request(`http://localhost/admin/accounts/${account.did}`, {
    method: "DELETE",
    headers,
    body: JSON.stringify({ confirm: account.body.handle }),
  });
  return app.fetch(request, testEnv, ctx);
}

afterEach(() => {
  __resetAccessJwksCache();
});

// The commons /tos serves the founder-approved agent-first canonical terms
// byte-for-byte: agents SHA-256 these exact bytes into tos_hash and sign them,
// so byte-equality with the CLO-owned canonical source is the acceptance test.
// This hash is the sha256 (hex) of the canonical served-text region of the
// rook.host commons ToS. Any intentional edit re-computes and updates it here.
const CANONICAL_TOS_SHA256_HEX =
  "ae7ddbf25eeaa781e61d0cb0b5a4a2fdbf345f73c4892d5023bf065e30cdd2b4";

describe("commons /tos canonical byte-form", () => {
  it("serves the agent-signed bytes as text/markdown, sha256-locked", async () => {
    const response = await worker.fetch("http://localhost/tos");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/markdown; charset=utf-8");

    const bytes = new Uint8Array(await response.arrayBuffer());
    // No BOM, LF line endings, single trailing newline.
    expect(bytes[0]).not.toBe(0xef);
    const text = new TextDecoder("utf-8").decode(bytes);
    expect(text).not.toContain("\r");
    expect(text.startsWith("**rook.host — the rules**")).toBe(true);
    expect(text.endsWith("your own rookery is always your fallback.\n")).toBe(true);
    // Markdown emphasis markers are part of the signed bytes — not stripped.
    expect(text).toContain("**handle.**");

    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(hex).toBe(CANONICAL_TOS_SHA256_HEX);
  });
});

it("serves the rook CLI OAuth client metadata", async () => {
  const EXPECTED_SCOPE =
    "atproto transition:generic repo:sh.tangled.repo repo:sh.tangled.repo.pull blob:*/* rpc:sh.tangled.repo.create?aud=did:web:knot.rook.host rpc:sh.tangled.git.receivePack?aud=did:web:knot.rook.host";
  const expected = {
    client_id: "https://rook.host/client-metadata.json",
    client_name: "rook cli",
    application_type: "native",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    redirect_uris: ["http://127.0.0.1/callback"],
    scope: EXPECTED_SCOPE,
    token_endpoint_auth_method: "none",
    dpop_bound_access_tokens: true,
    client_uri: "https://rook.host",
  };
  const response = await worker.fetch(
    new Request("http://localhost/client-metadata.json"),
  );

  expect(response.status).toBe(200);
  expect(response.headers.get("content-type")?.startsWith("application/json")).toBe(true);
  const body = await response.json() as typeof expected;
  expect(body).toEqual(expected);
  expect(body.scope).toBe(EXPECTED_SCOPE);
});

describe("commons invite-gated enrollment", () => {
  beforeAll(async () => {
    await initDirectory(env.DIRECTORY);
  });

  it("requires ref before handle policy checks and creates nothing", async () => {
    const handle = uniqueLabel("missing-ref");
    const fetchSpy = stubPlcDirectory();
    try {
      const response = await signupWithFreshKeys(handle);
      expect(response.status).toBe(403);
      expect(response.body).toMatchObject({
        error: "InviteRequired",
        message: "A valid invite ref is required for enrollment.",
      });
      expect(plcCallCount(fetchSpy)).toBe(0);
      await expectNoAccount(handle);

      const ordering = await signupWithFreshKeys("ab");
      expect(ordering.status).toBe(403);
      expect(ordering.body).toMatchObject({ error: "InviteRequired" });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("rejects empty-fragment and unparseable refs", async () => {
    const fetchSpy = stubPlcDirectory();
    try {
      const empty = await signupWithFreshKeys(uniqueLabel("empty-ref"), "https://rookery.test/roost#");
      expect(empty.status).toBe(403);
      expect(empty.body).toMatchObject({ error: "InviteRequired" });

      const unparseable = await signupWithFreshKeys(uniqueLabel("bad-ref"), "not a url");
      expect(unparseable.status).toBe(403);
      expect(unparseable.body).toMatchObject({ error: "InviteRequired" });
      expect(plcCallCount(fetchSpy)).toBe(0);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("rejects unknown and already-spent invite tokens without PLC writes", async () => {
    const unknownHandle = uniqueLabel("unknown-token");
    const spentHandle = uniqueLabel("spent-token");
    const spentToken = uniqueLabel("spent-token");
    await insertInvite(spentToken);
    expect(await spendInvitePending(env.DIRECTORY, spentToken)).toBe(true);

    const fetchSpy = stubPlcDirectory();
    try {
      const unknown = await signupWithFreshKeys(unknownHandle, entryRef(uniqueLabel("missing-token")));
      expect(unknown.status).toBe(403);
      expect(unknown.body).toMatchObject({
        error: "InviteInvalid",
        message: "Invite is invalid or already spent.",
      });
      await expectNoAccount(unknownHandle);

      const spent = await signupWithFreshKeys(spentHandle, entryRef(spentToken));
      expect(spent.status).toBe(403);
      expect(spent.body).toMatchObject({ error: "InviteInvalid" });
      await expectNoAccount(spentHandle);
      expect(plcCallCount(fetchSpy)).toBe(0);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("enrolls with an unspent invite and finalizes the invite to the DID", async () => {
    const handle = uniqueLabel("happy");
    const token = uniqueLabel("happy-token");
    await insertInvite(token);
    const fetchSpy = stubPlcDirectory();
    try {
      const response = await signupWithFreshKeys(handle, entryRef(token));
      expect(response.status).toBe(200);
      expect(response.body.handle).toBe(fullHandle(handle));
      expect(response.body.did?.startsWith("did:plc:")).toBe(true);
      expect(response.body.token_type).toBe("DPoP");

      const invite = await getInvite(token);
      expect(invite?.spent_by_did).toBe(response.body.did);
      expect(invite?.spent_at).not.toBeNull();
      expect(await accountExists(response.body.did!)).toBe(true);
      expect(plcCallCount(fetchSpy)).toBe(1);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("allows only one concurrent signup for the same invite token", async () => {
    const token = uniqueLabel("concurrent-token");
    const handleA = uniqueLabel("concurrent-a");
    const handleB = uniqueLabel("concurrent-b");
    await insertInvite(token);
    const fetchSpy = stubPlcDirectory();
    try {
      const results = await Promise.all([
        signupWithFreshKeys(handleA, entryRef(token)),
        signupWithFreshKeys(handleB, entryRef(token)),
      ]);
      const successes = results.filter((result) => result.status === 200);
      const failures = results.filter((result) => result.status !== 200);

      expect(successes).toHaveLength(1);
      expect(failures).toHaveLength(1);
      expect(failures[0].status).toBe(403);
      expect(failures[0].body).toMatchObject({ error: "InviteInvalid" });
      expect(plcCallCount(fetchSpy)).toBe(1);

      const invite = await getInvite(token);
      expect(invite?.spent_by_did).toBe(successes[0].body.did);
      expect(await accountExists(successes[0].body.did!)).toBe(true);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("unspends the invite when PLC creation fails", async () => {
    const handle = uniqueLabel("plc-fail");
    const token = uniqueLabel("plc-fail-token");
    await insertInvite(token);
    const fetchSpy = stubPlcDirectory({ status: 500, body: "rejected" });
    try {
      const response = await signupWithFreshKeys(handle, entryRef(token));
      expect(response.status).toBeGreaterThanOrEqual(500);
      await expectNoAccount(handle);
      expect(await getInvite(token)).toMatchObject({
        spent_by_did: null,
        spent_at: null,
      });
      expect(plcCallCount(fetchSpy)).toBe(1);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("unspends the invite when insertAccount loses a UNIQUE race", async () => {
    const handle = uniqueLabel("unique-race");
    const token = uniqueLabel("unique-race-token");
    await insertInvite(token);
    let insertedRace = false;
    const fetchSpy = stubPlcDirectory({
      onPlc: async () => {
        if (insertedRace) return;
        insertedRace = true;
        await insertAccount(env.DIRECTORY, {
          did: `did:plc:${uniqueLabel("race")}`,
          handle: fullHandle(handle),
          doId: `race-${Date.now().toString(36)}`,
        });
      },
    });

    try {
      const response = await signupWithFreshKeys(handle, entryRef(token));
      expect(response.status).toBe(409);
      expect(response.body).toMatchObject({
        error: "HandleTaken",
        message: "Handle is already taken. Choose another name.",
      });
      expect(await getInvite(token)).toMatchObject({
        spent_by_did: null,
        spent_at: null,
      });
      expect(plcCallCount(fetchSpy)).toBe(1);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("reports invite-required server metadata and commons welcome text", async () => {
    const describe = await worker.fetch("http://localhost/xrpc/com.atproto.server.describeServer");
    expect(describe.status).toBe(200);
    const describeBody = await describe.json() as { inviteCodeRequired: boolean };
    expect(describeBody.inviteCodeRequired).toBe(true);

    const welcome = await worker.fetch("http://localhost/.well-known/welcome.md");
    expect(welcome.status).toBe(200);
    const text = await welcome.text();
    expect(text).toContain("WelcomeMat v1.1");
    expect(text).toContain("`ref`");
    expect(text).toContain("POST /api/invites");
    expect(text).toContain("DPoP");
    expect(text).toContain("lifetime-quota");
    expect(text).toContain('"url"');
    expect(text).toContain("MintLocked");
    expect(text).toContain("QuotaExceeded");
  });

  it("redirects /roost to the invite landing", async () => {
    const response = await worker.fetch("http://localhost/roost", { redirect: "manual" });
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("/invite");
    expect(await response.text()).toContain("Continue to rookery");
});

  it("uses the default quota seed of three and minted invites can be spent", async () => {
    await resetDefaultQuotaToSeed();
    const fetchSpy = stubPlcDirectory();
    try {
      const account = await enrollRookWithInvite("default-quota");
      await publishRecord(account);

      const first = await mintAsRook(account);
      expect(first.status).toBe(200);
      expect(Object.keys(first.body).sort()).toEqual(["remaining", "token", "url"]);
      expect(first.body.remaining).toBe(2);
      expect(first.body.url).toBe(`https://${env.ROOKERY_HOSTNAME}/roost#${first.body.token}`);

      const signup = await signupWithFreshKeys(uniqueLabel("mint-spend"), first.body.url);
      expect(signup.status).toBe(200);
      expect((await getInvite(first.body.token!))?.spent_by_did).toBe(signup.body.did);

      const second = await mintAsRook(account);
      expect(second.status).toBe(200);
      expect(second.body.remaining).toBe(1);

      const third = await mintAsRook(account);
      expect(third.status).toBe(200);
      expect(third.body.remaining).toBe(0);

      const fourth = await mintAsRook(account);
      expect(fourth.status).toBe(403);
      expect(fourth.body).toMatchObject({ error: "QuotaExceeded" });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("checks proof-of-life before quota", async () => {
    const fetchSpy = stubPlcDirectory();
    try {
      const account = await enrollRookWithInvite("locked");
      await setInviteQuota(env.DIRECTORY, account.did, 0);

      const locked = await mintAsRook(account);
      expect(locked.status).toBe(403);
      expect(locked.body).toMatchObject({ error: "MintLocked" });

      await publishRecord(account);
      const quotaExceeded = await mintAsRook(account);
      expect(quotaExceeded.status).toBe(403);
      expect(quotaExceeded.body).toMatchObject({ error: "QuotaExceeded" });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("honors per-rook quota overrides", async () => {
    const fetchSpy = stubPlcDirectory();
    try {
      const account = await enrollRookWithInvite("override-five");
      await publishRecord(account);
      await setInviteQuota(env.DIRECTORY, account.did, 5);

      for (let i = 4; i >= 0; i--) {
        const minted = await mintAsRook(account);
        expect(minted.status).toBe(200);
        expect(minted.body.remaining).toBe(i);
      }

      const blocked = await mintAsRook(account);
      expect(blocked.status).toBe(403);
      expect(blocked.body).toMatchObject({ error: "QuotaExceeded" });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("allows org operators to mint unlimited invites through Access", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const response = await adminFetch("/admin/invites", access, { method: "POST" });
      expect(response.status).toBe(200);
      const body = await response.json() as { token: string; url: string; remaining?: number };
      expect(Object.keys(body).sort()).toEqual(["token", "url"]);
      expect(body.url).toBe(`https://${env.ROOKERY_HOSTNAME}/roost#${body.token}`);
      expect(body.remaining).toBeUndefined();
      expect((await getInvite(body.token))?.minted_by).toBe("org");

      const signup = await signupWithFreshKeys(uniqueLabel("org-minted"), body.url);
      expect(signup.status).toBe(200);
      expect((await getInvite(body.token))?.spent_by_did).toBe(signup.body.did);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("enforces Access JWTs on admin routes", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const valid = await adminFetch("/admin/invites", access, { method: "POST" });
      expect(valid.status).toBe(200);

      __resetAccessJwksCache();
      const missing = await worker.fetch(new Request("http://localhost/admin/invites", {
        method: "POST",
      }));
      expect(missing.status).toBe(403);
      expect(await missing.json()).toMatchObject({ error: "AccessDenied" });

      __resetAccessJwksCache();
      const wrongAud = await adminFetch(
        "/admin/invites",
        access,
        { method: "POST" },
        { aud: ["wrong-aud"] },
      );
      expect(wrongAud.status).toBe(403);
      expect(await wrongAud.json()).toMatchObject({ error: "AccessDenied" });

      __resetAccessJwksCache();
      const stringAud = await adminFetch(
        "/admin/invites",
        access,
        { method: "POST" },
        { aud: env.CF_ACCESS_AUD },
      );
      expect(stringAud.status).toBe(200);

      __resetAccessJwksCache();
      const stringWrongAud = await adminFetch(
        "/admin/invites",
        access,
        { method: "POST" },
        { aud: "definitely-not-the-aud" },
      );
      expect(stringWrongAud.status).toBe(403);
      expect(await stringWrongAud.json()).toMatchObject({ error: "AccessDenied" });

      __resetAccessJwksCache();
      const numberAud = await adminFetch(
        "/admin/invites",
        access,
        { method: "POST" },
        { aud: 42 },
      );
      expect(numberAud.status).toBe(403);
      expect(await numberAud.json()).toMatchObject({ error: "AccessDenied" });

      __resetAccessJwksCache();
      const numberArrayAud = await adminFetch(
        "/admin/invites",
        access,
        { method: "POST" },
        { aud: [42] },
      );
      expect(numberArrayAud.status).toBe(403);
      expect(await numberArrayAud.json()).toMatchObject({ error: "AccessDenied" });

      __resetAccessJwksCache();
      const now = Math.floor(Date.now() / 1000);
      const expired = await adminFetch(
        "/admin/invites",
        access,
        { method: "POST" },
        { exp: now - 1 },
      );
      expect(expired.status).toBe(403);
      expect(await expired.json()).toMatchObject({ error: "AccessDenied" });

      __resetAccessJwksCache();
      const signed = await buildAccessAssertion(access);
      const parts = signed.split(".");
      const signature = parts[2]!;
      // Corrupt the first char: it maps to 6 significant bits of the signature's
      // leading byte, so the decoded signature always changes. (Flipping the last
      // char is unreliable — it carries only 2 significant bits, the rest padding.)
      parts[2] = (signature.startsWith("A") ? "B" : "A") + signature.slice(1);
      const badSignature = await worker.fetch(new Request("http://localhost/admin/invites", {
        method: "POST",
        headers: { "Cf-Access-Jwt-Assertion": parts.join(".") },
      }));
      expect(badSignature.status).toBe(403);
      expect(await badSignature.json()).toMatchObject({ error: "AccessDenied" });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("validates and applies admin quota/config updates", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      for (const body of [{}, { quota: -1 }, { quota: 1.5 }, { quota: "1" }]) {
        __resetAccessJwksCache();
        const response = await adminFetch("/admin/quotas/did:plc:badquota", access, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
        expect(response.status).toBe(400);
        expect(await response.json()).toMatchObject({ error: "InvalidRequest" });
      }

      __resetAccessJwksCache();
      const quota = await adminFetch("/admin/quotas/did:plc:quota-route", access, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ quota: 4 }),
      });
      expect(quota.status).toBe(200);
      expect(await quota.json()).toMatchObject({ did: "did:plc:quota-route", quota: 4 });

      for (const body of [{}, { value: -1 }, { value: 1.5 }, { value: "1" }]) {
        __resetAccessJwksCache();
        const response = await adminFetch("/admin/config/invite_quota_default", access, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
        expect(response.status).toBe(400);
        expect(await response.json()).toMatchObject({ error: "InvalidRequest" });
      }

      __resetAccessJwksCache();
      const config = await adminFetch("/admin/config/invite_quota_default", access, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ value: 1 }),
      });
      expect(config.status).toBe(200);
      expect(await config.json()).toMatchObject({ value: 1 });

      const account = await enrollRookWithInvite("default-one");
      await publishRecord(account);
      const first = await mintAsRook(account);
      expect(first.status).toBe(200);
      expect(first.body.remaining).toBe(0);
      const second = await mintAsRook(account);
      expect(second.status).toBe(403);
      expect(second.body).toMatchObject({ error: "QuotaExceeded" });
    } finally {
      await resetDefaultQuotaToSeed();
      fetchSpy.mockRestore();
    }
  });

  it("lists invites newest-first with clamp, cursor, and spent state", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const prefix = uniqueLabel("list");
      await env.DIRECTORY.batch([
        env.DIRECTORY.prepare(
          "INSERT INTO invites (token, minted_by, minted_at, spent_by_did, spent_at) VALUES (?, ?, ?, ?, ?)",
        ).bind(`${prefix}-older`, "org", "2099-01-01 00:00:00", null, null),
        env.DIRECTORY.prepare(
          "INSERT INTO invites (token, minted_by, minted_at, spent_by_did, spent_at) VALUES (?, ?, ?, ?, ?)",
        ).bind(`${prefix}-newer`, "did:plc:list", "2099-01-02 00:00:00", "did:plc:spent", "2099-01-03 00:00:00"),
      ]);

      __resetAccessJwksCache();
      const firstPage = await adminFetch("/admin/invites?limit=1", access);
      expect(firstPage.status).toBe(200);
      const firstBody = await firstPage.json() as {
        records: Array<{
          token: string;
          minted_by: string | null;
          minted_at: string;
          spent_by_did: string | null;
          spent_at: string | null;
        }>;
        cursor?: string;
      };
      expect(firstBody.records).toHaveLength(1);
      expect(firstBody.records[0]).toMatchObject({
        token: `${prefix}-newer`,
        minted_by: "did:plc:list",
        spent_by_did: "did:plc:spent",
      });
      expect(firstBody.cursor).toBeTruthy();

      __resetAccessJwksCache();
      const secondPage = await adminFetch(
        `/admin/invites?limit=1&cursor=${encodeURIComponent(firstBody.cursor!)}`,
        access,
      );
      expect(secondPage.status).toBe(200);
      const secondBody = await secondPage.json() as { records: Array<{ token: string }> };
      expect(secondBody.records[0].token).toBe(`${prefix}-older`);

      __resetAccessJwksCache();
      const emptyCursor = btoa("0000-01-01 00:00:00 zzz")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
      const emptyPage = await adminFetch(
        `/admin/invites?cursor=${encodeURIComponent(emptyCursor)}`,
        access,
      );
      expect(emptyPage.status).toBe(200);
      const emptyBody = await emptyPage.json() as { records: unknown[]; cursor?: string };
      expect(emptyBody.records).toEqual([]);
      expect(emptyBody.cursor).toBeUndefined();

      __resetAccessJwksCache();
      const invalidCursor = await adminFetch("/admin/invites?cursor=not-base64url", access);
      expect(invalidCursor.status).toBe(400);
      expect(await invalidCursor.json()).toMatchObject({ error: "InvalidRequest" });

      const batch = [];
      for (let i = 0; i < 501; i++) {
        batch.push(env.DIRECTORY.prepare(
          "INSERT INTO invites (token, minted_by, minted_at) VALUES (?, ?, ?)",
        ).bind(`${prefix}-bulk-${i.toString().padStart(3, "0")}`, "org", "2099-02-01 00:00:00"));
      }
      await env.DIRECTORY.batch(batch);

      __resetAccessJwksCache();
      const clamped = await adminFetch("/admin/invites?limit=9999", access);
      expect(clamped.status).toBe(200);
      const clampedBody = await clamped.json() as { records: unknown[] };
      expect(clampedBody.records).toHaveLength(500);
    } finally {
      fetchSpy.mockRestore();
    }
  });
	});

describe("commons admin invite lifecycle", () => {
  beforeAll(async () => {
    await initDirectory(env.DIRECTORY);
  });

  // Cold-start guard (F3): the first admin mint after idle used to lose a DO+D1
  // init race and return a bare 500. Fire a burst of first-touch mints and assert
  // every one is a structured 200 with a distinct token — never a bare 500.
  it("mints structured invites under concurrent cold-start load", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      __resetAccessJwksCache();
      const responses = await Promise.all(
        Array.from({ length: 6 }, () => adminFetch("/admin/invites", access, { method: "POST" })),
      );

      const tokens = new Set<string>();
      for (const response of responses) {
        expect(response.status).toBe(200);
        expect(response.headers.get("content-type")?.startsWith("application/json")).toBe(true);
        const body = await response.json() as { token: string; url: string };
        expect(body.token).toBeTruthy();
        expect(body.url).toBe(`https://${env.ROOKERY_HOSTNAME}/roost#${body.token}`);
        tokens.add(body.token);
      }
      // Distinct tokens: no init race collapsed two mints onto one row.
      expect(tokens.size).toBe(responses.length);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  // Idempotent re-mint (F7): a retry carrying the same Idempotency-Key returns the
  // first invite instead of stranding another unspent one.
  it("re-mints idempotently per Idempotency-Key", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const key = uniqueLabel("idem");

      __resetAccessJwksCache();
      const first = await adminFetch("/admin/invites", access, {
        method: "POST",
        headers: { "Idempotency-Key": key },
      });
      expect(first.status).toBe(200);
      expect(first.headers.get("Idempotency-Replayed")).toBeNull();
      const firstBody = await first.json() as { token: string; url: string };
      expect(firstBody.token).toBeTruthy();

      __resetAccessJwksCache();
      const replay = await adminFetch("/admin/invites", access, {
        method: "POST",
        headers: { "Idempotency-Key": key },
      });
      expect(replay.status).toBe(200);
      expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
      const replayBody = await replay.json() as { token: string; url: string };
      expect(replayBody.token).toBe(firstBody.token);
      expect(replayBody.url).toBe(firstBody.url);

      // Exactly one row was minted for the key.
      const row = await env.DIRECTORY.prepare(
        "SELECT COUNT(*) AS count FROM invites WHERE idempotency_key = ?",
      ).bind(key).first<{ count: number }>();
      expect(row?.count).toBe(1);

      // A different key mints a distinct invite.
      __resetAccessJwksCache();
      const other = await adminFetch("/admin/invites", access, {
        method: "POST",
        headers: { "Idempotency-Key": uniqueLabel("idem-other") },
      });
      expect((await other.json() as { token: string }).token).not.toBe(firstBody.token);

      // No key at all still mints fresh every time (unchanged behavior).
      __resetAccessJwksCache();
      const noKeyA = await adminFetch("/admin/invites", access, { method: "POST" });
      __resetAccessJwksCache();
      const noKeyB = await adminFetch("/admin/invites", access, { method: "POST" });
      expect((await noKeyA.json() as { token: string }).token)
        .not.toBe((await noKeyB.json() as { token: string }).token);

      // A blank / oversized key is rejected structurally.
      __resetAccessJwksCache();
      const blank = await adminFetch("/admin/invites", access, {
        method: "POST",
        headers: { "Idempotency-Key": "   " },
      });
      expect(blank.status).toBe(400);
      expect(await blank.json()).toMatchObject({ error: "InvalidRequest" });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  // Revoke of an unspent invite (F7 cleanup); a spent or unknown one is rejected.
  it("revokes an unspent invite and rejects spent or unknown ones", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      __resetAccessJwksCache();
      const mint = await adminFetch("/admin/invites", access, { method: "POST" });
      const { token } = await mint.json() as { token: string };
      expect(await getInvite(token)).not.toBeNull();

      __resetAccessJwksCache();
      const revoke = await adminFetch(`/admin/invites/${token}`, access, { method: "DELETE" });
      expect(revoke.status).toBe(200);
      expect(await revoke.json()).toMatchObject({ token, revoked: true });
      // The stray unspent invite is gone — it can never be spent.
      expect(await getInvite(token)).toBeNull();

      // Revoking the now-absent invite is a clear 404.
      __resetAccessJwksCache();
      const revokeAgain = await adminFetch(`/admin/invites/${token}`, access, { method: "DELETE" });
      expect(revokeAgain.status).toBe(404);
      expect(await revokeAgain.json()).toMatchObject({ error: "InviteNotFound" });

      // A spent invite is preserved and rejected clearly.
      const spentToken = uniqueLabel("revoke-spent");
      await env.DIRECTORY.prepare(
        "INSERT INTO invites (token, minted_by, spent_by_did, spent_at) VALUES (?, 'org', ?, datetime('now'))",
      ).bind(spentToken, "did:plc:spender").run();

      __resetAccessJwksCache();
      const revokeSpent = await adminFetch(`/admin/invites/${spentToken}`, access, { method: "DELETE" });
      expect(revokeSpent.status).toBe(409);
      expect(await revokeSpent.json()).toMatchObject({ error: "InviteSpent" });
      expect(await getInvite(spentToken)).not.toBeNull();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  // Unspent listing (F7): state=unspent surfaces only the stray invites an
  // operator would want to clean up; pending (in-flight) invites are excluded.
  it("filters the listing by state", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const prefix = uniqueLabel("state");
      // Future-dated so these sort onto the first page ahead of bulk fixtures.
      await env.DIRECTORY.batch([
        env.DIRECTORY.prepare(
          "INSERT INTO invites (token, minted_by, minted_at, spent_by_did, spent_at) VALUES (?, 'org', ?, NULL, NULL)",
        ).bind(`${prefix}-unspent`, "2099-06-01 00:00:00"),
        env.DIRECTORY.prepare(
          "INSERT INTO invites (token, minted_by, minted_at, spent_by_did, spent_at) VALUES (?, 'org', ?, ?, ?)",
        ).bind(`${prefix}-spent`, "2099-06-02 00:00:00", "did:plc:spent", "2099-06-03 00:00:00"),
        env.DIRECTORY.prepare(
          "INSERT INTO invites (token, minted_by, minted_at, spent_by_did, spent_at) VALUES (?, 'org', ?, 'pending', ?)",
        ).bind(`${prefix}-pending`, "2099-06-04 00:00:00", "2099-06-05 00:00:00"),
      ]);

      __resetAccessJwksCache();
      const unspent = await adminFetch("/admin/invites?state=unspent&limit=500", access);
      expect(unspent.status).toBe(200);
      const unspentBody = await unspent.json() as {
        records: Array<{ token: string; spent_by_did: string | null }>;
      };
      const unspentTokens = unspentBody.records.map((r) => r.token);
      expect(unspentTokens).toContain(`${prefix}-unspent`);
      expect(unspentTokens).not.toContain(`${prefix}-spent`);
      expect(unspentTokens).not.toContain(`${prefix}-pending`);
      for (const record of unspentBody.records) {
        expect(record.spent_by_did).toBeNull();
      }

      __resetAccessJwksCache();
      const spent = await adminFetch("/admin/invites?state=spent&limit=500", access);
      expect(spent.status).toBe(200);
      const spentTokens = (await spent.json() as { records: Array<{ token: string }> })
        .records.map((r) => r.token);
      expect(spentTokens).toContain(`${prefix}-spent`);
      expect(spentTokens).toContain(`${prefix}-pending`);
      expect(spentTokens).not.toContain(`${prefix}-unspent`);

      __resetAccessJwksCache();
      const invalid = await adminFetch("/admin/invites?state=bogus", access);
      expect(invalid.status).toBe(400);
      expect(await invalid.json()).toMatchObject({ error: "InvalidRequest" });
    } finally {
      fetchSpy.mockRestore();
    }
  });
});

describe("commons operator account takedown", () => {
  it("removes the account, records, blob, and writes an operator audit", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const account = await enrollRookWithInvite("takedown-full");
      const post = await publishRecord(account, "app.bsky.feed.post", "primary-post");
      await publishRecord(account, "com.example.note", "primary-note");
      const blob = await uploadBlob(account, new TextEncoder().encode("remove me"));

      const response = await takedownAccount(account, access);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        did: account.did,
        handle: account.body.handle,
        recordsDeleted: 2,
        blobsDeleted: 1,
        collections: ["app.bsky.feed.post", "com.example.note"],
      });

      const resolveHandle = await worker.fetch(
        `http://localhost/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(account.body.handle!)}`,
      );
      expect(resolveHandle.status).toBe(404);

      const wellKnown = await worker.fetch(
        new Request("http://localhost/.well-known/atproto-did", {
          headers: { host: account.body.handle! },
        }),
      );
      expect(wellKnown.status).toBe(404);

      const record = await worker.fetch(
        `http://localhost/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(account.did)}&collection=app.bsky.feed.post&rkey=${post.uri.split("/").pop()}`,
      );
      expect(record.status).toBe(404);
      expect(await record.json()).toMatchObject({ error: "RepoNotFound" });

      const repo = await worker.fetch(
        `http://localhost/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(account.did)}`,
      );
      expect(repo.status).toBe(404);
      expect(await repo.json()).toMatchObject({ error: "RepoNotFound" });

      expect(await env.BLOBS.head(`${account.did}/${blob.ref.$link}`)).toBeNull();
      expect(await accountExists(account.did)).toBe(false);

      const audit = await env.DIRECTORY.prepare(
        `SELECT did, handle, actor, records_deleted, blobs_deleted, collections, taken_down_at
          FROM takedowns WHERE did = ?`,
      ).bind(account.did).first<{
        did: string;
        handle: string;
        actor: string;
        records_deleted: number;
        blobs_deleted: number;
        collections: string;
        taken_down_at: string;
      }>();
      expect(audit).toMatchObject({
        did: account.did,
        handle: account.body.handle,
        actor: "operator@example.com",
        records_deleted: 2,
        blobs_deleted: 1,
        collections: JSON.stringify(["app.bsky.feed.post", "com.example.note"]),
      });
      expect(audit?.taken_down_at).toBeTruthy();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("purges more than one R2 page without touching another DID prefix", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    const foreignDid = `did:plc:${uniqueLabel("takedown-foreign")}`;
    const foreignKey = `${foreignDid}/keep`;
    try {
      const account = await enrollRookWithInvite("takedown-r2-pages");
      const prefix = `${account.did}/`;
      const keys = Array.from(
        { length: 1_001 },
        (_, index) => `${prefix}blob-${index.toString().padStart(4, "0")}`,
      );
      for (let offset = 0; offset < keys.length; offset += 100) {
        await Promise.all(
          keys.slice(offset, offset + 100).map((key) => env.BLOBS.put(key, "blob")),
        );
      }
      await env.BLOBS.put(foreignKey, "keep");

      const response = await takedownAccount(account, access);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ blobsDeleted: 1_001 });
      expect((await env.BLOBS.list({ prefix })).objects).toHaveLength(0);
      expect(await env.BLOBS.head(foreignKey)).not.toBeNull();
    } finally {
      await env.BLOBS.delete(foreignKey);
      fetchSpy.mockRestore();
    }
  });

  it("emits 200-op and 1-op delete commits before the deleted account frame", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const account = await enrollRookWithInvite("takedown-firehose");
      const stub = await getAccountStub(account.did);
      const writes = Array.from({ length: 201 }, (_, index) => ({
        $type: "com.atproto.repo.applyWrites#create",
        collection: "app.bsky.feed.post",
        rkey: `r${index.toString().padStart(3, "0")}`,
        record: { text: `post ${index}`, createdAt: new Date().toISOString() },
      }));
      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        await instance.rpcApplyWrites(writes);
      });
      const cursor = await getLatestSequencerCursor();

      const response = await takedownAccount(account, access);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        recordsDeleted: 201,
        collections: ["app.bsky.feed.post"],
      });

      const frames = (await backfillFirehose(cursor, 3)).map(decodeFirehoseFrame);
      expect(frames.map((frame) => frame.header.t)).toEqual([
        "#commit",
        "#commit",
        "#account",
      ]);

      const firstOps = frames[0].body.ops as Array<{
        action: string;
        path: string;
        cid: unknown;
      }>;
      const secondOps = frames[1].body.ops as Array<{
        action: string;
        path: string;
        cid: unknown;
      }>;
      expect(firstOps).toHaveLength(200);
      expect(secondOps).toHaveLength(1);
      const allOps = [...firstOps, ...secondOps];
      expect(allOps.map((op) => op.path)).toEqual(
        Array.from(
          { length: 201 },
          (_, index) => `app.bsky.feed.post/r${index.toString().padStart(3, "0")}`,
        ),
      );
      for (const op of allOps) {
        expect(op.action).toBe("delete");
        expect(op.cid).toBeNull();
      }
      expect(frames[2].body).toMatchObject({
        did: account.did,
        active: false,
        status: "deleted",
      });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("emits only a deleted account frame for an empty account", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const account = await enrollRookWithInvite("takedown-empty");
      const stub = await getAccountStub(account.did);
      const cursor = await getLatestSequencerCursor();

      const response = await takedownAccount(account, access);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        recordsDeleted: 0,
        blobsDeleted: 0,
        collections: [],
      });
      expect(await getLatestSequencerCursor()).toBe(cursor + 1);

      const [frame] = (await backfillFirehose(cursor, 1)).map(decodeFirehoseFrame);
      expect(frame.header.t).toBe("#account");
      expect(frame.body).toMatchObject({
        did: account.did,
        active: false,
        status: "deleted",
      });

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const cached = instance as unknown as {
          storage: unknown;
          repo: unknown;
          keypair: unknown;
          storageInitialized: boolean;
          repoInitialized: boolean;
        };
        expect(cached.storage).toBeNull();
        expect(cached.repo).toBeNull();
        expect(cached.keypair).toBeNull();
        expect(cached.storageInitialized).toBe(false);
        expect(cached.repoInitialized).toBe(false);
        expect(await instance.rpcGetState()).toBeNull();
      });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("validates the body, account, and exact handle before changing state", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const account = await enrollRookWithInvite("takedown-confirm");
      await publishRecord(account, "app.bsky.feed.post", "still-here");
      const cursor = await getLatestSequencerCursor();

      const missing = await adminFetch(`/admin/accounts/${account.did}`, access, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(missing.status).toBe(400);
      expect(await missing.json()).toMatchObject({ error: "ConfirmMismatch" });

      const wrong = await adminFetch(`/admin/accounts/${account.did}`, access, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ confirm: `${account.body.handle}-wrong` }),
      });
      expect(wrong.status).toBe(400);
      expect(await wrong.json()).toMatchObject({ error: "ConfirmMismatch" });

      const unknown = await adminFetch("/admin/accounts/did:plc:missing", access, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ confirm: "missing.rookery.test" }),
      });
      expect(unknown.status).toBe(404);
      expect(await unknown.json()).toMatchObject({ error: "AccountNotFound" });

      const malformed = await adminFetch(`/admin/accounts/${account.did}`, access, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: "not-json",
      });
      expect(malformed.status).toBe(400);
      expect(await malformed.json()).toMatchObject({ error: "InvalidRequest" });

      const row = await env.DIRECTORY.prepare(
        "SELECT active FROM accounts WHERE did = ?",
      ).bind(account.did).first<{ active: number }>();
      expect(row?.active).toBe(1);
      const record = await worker.fetch(
        `http://localhost/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(account.did)}&collection=app.bsky.feed.post&rkey=still-here`,
      );
      expect(record.status).toBe(200);
      expect(await env.DIRECTORY.prepare(
        "SELECT 1 FROM takedowns WHERE did = ?",
      ).bind(account.did).first()).toBeNull();
      expect(await getLatestSequencerCursor()).toBe(cursor);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("retries a wiped account using the caller DID and re-emits account deletion", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const account = await enrollRookWithInvite("takedown-retry");
      const stub = await getAccountStub(account.did);
      const cursor = await getLatestSequencerCursor();

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        expect(await instance.rpcTakedown(account.did)).toEqual({
          recordsDeleted: 0,
          blobsDeleted: 0,
          collections: [],
        });
      });
      const active = await env.DIRECTORY.prepare(
        "SELECT active FROM accounts WHERE did = ?",
      ).bind(account.did).first<{ active: number }>();
      expect(active?.active).toBe(1);

      // The Worker deactivates first; the retry must resolve this inactive row.
      await deactivateAccount(env.DIRECTORY, account.did);
      const deactivated = await env.DIRECTORY.prepare(
        "SELECT active FROM accounts WHERE did = ?",
      ).bind(account.did).first<{ active: number }>();
      expect(deactivated?.active).toBe(0);

      const lateKey = `${account.did}/late-after-wipe`;
      await env.BLOBS.put(lateKey, "late");

      const response = await takedownAccount(account, access);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        recordsDeleted: 0,
        blobsDeleted: 1,
        collections: [],
      });
      expect(await env.BLOBS.head(lateKey)).toBeNull();
      expect(await accountExists(account.did)).toBe(false);
      const auditCount = await env.DIRECTORY.prepare(
        "SELECT COUNT(*) AS count FROM takedowns WHERE did = ?",
      ).bind(account.did).first<{ count: number }>();
      expect(auditCount?.count).toBe(1);

      expect(await getLatestSequencerCursor()).toBe(cursor + 2);
      const frames = (await backfillFirehose(cursor, 2)).map(decodeFirehoseFrame);
      expect(frames.map((frame) => frame.header.t)).toEqual(["#account", "#account"]);
      for (const frame of frames) {
        expect(frame.body).toMatchObject({
          did: account.did,
          active: false,
          status: "deleted",
        });
      }
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("keeps invites while removing OAuth state and the account quota", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const account = await enrollRookWithInvite("takedown-related");
      const mintedToken = uniqueLabel("target-minted");
      await env.DIRECTORY.prepare(
        "INSERT INTO invites (token, minted_by) VALUES (?, ?)",
      ).bind(mintedToken, account.did).run();
      await setInviteQuota(env.DIRECTORY, account.did, 7);

      await initOAuth(env.DIRECTORY);
      const suffix = uniqueLabel("takedown-oauth");
      const now = Math.floor(Date.now() / 1000);
      await insertOAuthCode(env.DIRECTORY, {
        codeHash: `code-${suffix}`,
        clientId: "https://client.example",
        redirectUri: "https://client.example/callback",
        codeChallenge: `challenge-${suffix}`,
        scope: "atproto",
        did: account.did,
        dpopJkt: `jkt-${suffix}`,
        exp: now + 300,
      }, now);
      await insertOAuthSession(env.DIRECTORY, {
        sessionId: `session-${suffix}`,
        refreshTokenHash: `refresh-${suffix}`,
        clientId: "https://client.example",
        did: account.did,
        scope: "atproto",
        dpopJkt: `jkt-${suffix}`,
        exp: now + 300,
      }, now);
      await insertOAuthToken(env.DIRECTORY, {
        accessTokenHash: `access-${suffix}`,
        sessionId: `session-${suffix}`,
        clientId: "https://client.example",
        did: account.did,
        scope: "atproto",
        dpopJkt: `jkt-${suffix}`,
        exp: now + 300,
      }, now);

      const response = await takedownAccount(account, access);
      expect(response.status).toBe(200);

      expect(await getInvite(account.inviteToken)).toMatchObject({
        spent_by_did: account.did,
      });
      expect(await getInvite(mintedToken)).toMatchObject({
        minted_by: account.did,
        spent_by_did: null,
      });
      for (const table of ["oauth_codes", "oauth_sessions", "oauth_tokens", "invite_quotas"]) {
        const row = await env.DIRECTORY.prepare(
          `SELECT 1 FROM ${table} WHERE did = ? LIMIT 1`,
        ).bind(account.did).first();
        expect(row).toBeNull();
      }
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("falls back from email to common_name and then stringified sub for audit actors", async () => {
    const access = await generateAccessFixture();
    const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
    try {
      const serviceAccount = await enrollRookWithInvite("takedown-service-actor");
      const serviceResponse = await takedownAccount(serviceAccount, access, {
        email: "",
        common_name: "service-token.access",
        sub: "",
      });
      expect(serviceResponse.status).toBe(200);

      const subAccount = await enrollRookWithInvite("takedown-sub-actor");
      const subResponse = await takedownAccount(subAccount, access, {
        email: "",
        common_name: "",
        sub: 4242,
      });
      expect(subResponse.status).toBe(200);

      const actors = await env.DIRECTORY.prepare(
        "SELECT did, actor FROM takedowns WHERE did IN (?, ?)",
      ).bind(serviceAccount.did, subAccount.did).all<{ did: string; actor: string }>();
      expect(new Map(actors.results.map((row) => [row.did, row.actor]))).toEqual(
        new Map([
          [serviceAccount.did, "service-token.access"],
          [subAccount.did, "4242"],
        ]),
      );
    } finally {
      fetchSpy.mockRestore();
    }
  });

  describe("security alert webhook", () => {
    it("posts the completed takedown to the operator's alert endpoint", async () => {
      const access = await generateAccessFixture();
      const webhookRequests: Request[] = [];
      const fetchSpy = stubPlcDirectory({
        accessJwk: access.publicJwk,
        webhook: {
          url: "https://hub.test/alerts",
          handler: (request) => {
            webhookRequests.push(request);
            return new Response(null, { status: 200 });
          },
        },
      });
      try {
        const account = await enrollRookWithInvite("takedown-alert");
        await publishRecord(account, "app.bsky.feed.post", "alert-post");
        await uploadBlob(account, new TextEncoder().encode("alert blob"));
        const testEnv: Env = {
          ...env,
          HUB_WEBHOOK_URL: "https://hub.test/alerts",
          HUB_WEBHOOK_SECRET: "test-hub-secret",
        };
        const ctx = createExecutionContext();

        const response = await directTakedownAccount(account, access, testEnv, ctx);
        expect(response.status).toBe(200);
        const responseBody = await response.json() as TakedownBody;
        await waitOnExecutionContext(ctx);

        expect(webhookRequests).toHaveLength(1);
        const [request] = webhookRequests;
        expect(request.url).toBe("https://hub.test/alerts");
        expect(request.method).toBe("POST");
        expect(request.headers.get("X-Hub-Secret")).toBe("test-hub-secret");
        expect(request.headers.get("Content-Type")).toBe("application/json");
        const body = await request.json() as {
          office: string;
          ts: string;
          type: string;
          tier: string;
          actor: string;
          did: string;
          handle: string;
          records_deleted: number;
          blobs_deleted: number;
          collections: string[];
        };
        expect(body).toEqual({
          office: "cso",
          ts: body.ts,
          type: "account_takedown",
          tier: "T4",
          actor: "operator@example.com",
          did: account.did,
          handle: account.body.handle,
          records_deleted: responseBody.recordsDeleted,
          blobs_deleted: responseBody.blobsDeleted,
          collections: responseBody.collections,
        });
        expect(new Date(body.ts).toISOString()).toBe(body.ts);

        const audit = await env.DIRECTORY.prepare(
          "SELECT actor FROM takedowns WHERE did = ?",
        ).bind(account.did).first<{ actor: string }>();
        expect(audit?.actor).toBe(body.actor);
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it("fails open and logs when the alert fetch rejects", async () => {
      const access = await generateAccessFixture();
      const webhookRequests: Request[] = [];
      const fetchSpy = stubPlcDirectory({
        accessJwk: access.publicJwk,
        webhook: {
          url: "https://hub.test/alerts",
          handler: (request) => {
            webhookRequests.push(request);
            return Promise.reject(new Error("test webhook rejected"));
          },
        },
      });
      const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        const account = await enrollRookWithInvite("takedown-alert-reject");
        await publishRecord(account, "app.bsky.feed.post", "reject-post");
        const testEnv: Env = {
          ...env,
          HUB_WEBHOOK_URL: "https://hub.test/alerts",
          HUB_WEBHOOK_SECRET: "test-hub-secret",
        };
        const ctx = createExecutionContext();

        const response = await directTakedownAccount(account, access, testEnv, ctx);
        expect(response.status).toBe(200);
        const responseBody = await response.json() as TakedownBody;
        expect(responseBody).toMatchObject({ recordsDeleted: 1, blobsDeleted: 0 });
        await waitOnExecutionContext(ctx);

        expect(webhookRequests).toHaveLength(1);
        expect(consoleErrorSpy).toHaveBeenCalledWith(
          "takedown security alert delivery failed",
          { did: account.did, message: "test webhook rejected" },
        );
        expect(await accountExists(account.did)).toBe(false);
        expect(await env.DIRECTORY.prepare(
          "SELECT actor FROM takedowns WHERE did = ?",
        ).bind(account.did).first()).toMatchObject({ actor: "operator@example.com" });
      } finally {
        consoleErrorSpy.mockRestore();
        fetchSpy.mockRestore();
      }
    });

    it("fails open and logs the status when the alert endpoint returns non-2xx", async () => {
      const access = await generateAccessFixture();
      const webhookRequests: Request[] = [];
      const fetchSpy = stubPlcDirectory({
        accessJwk: access.publicJwk,
        webhook: {
          url: "https://hub.test/alerts",
          handler: (request) => {
            webhookRequests.push(request);
            return new Response("hub unavailable", { status: 500 });
          },
        },
      });
      const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        const account = await enrollRookWithInvite("takedown-alert-500");
        await publishRecord(account, "app.bsky.feed.post", "error-post");
        const testEnv: Env = {
          ...env,
          HUB_WEBHOOK_URL: "https://hub.test/alerts",
          HUB_WEBHOOK_SECRET: "test-hub-secret",
        };
        const ctx = createExecutionContext();

        const response = await directTakedownAccount(account, access, testEnv, ctx);
        expect(response.status).toBe(200);
        const responseBody = await response.json() as TakedownBody;
        expect(responseBody).toMatchObject({ recordsDeleted: 1, blobsDeleted: 0 });
        await waitOnExecutionContext(ctx);

        expect(webhookRequests).toHaveLength(1);
        expect(consoleErrorSpy).toHaveBeenCalledWith(
          "takedown security alert delivery failed",
          {
            did: account.did,
            message: "takedown security alert delivery failed: 500 hub unavailable",
          },
        );
        expect(await accountExists(account.did)).toBe(false);
        expect(await env.DIRECTORY.prepare(
          "SELECT actor FROM takedowns WHERE did = ?",
        ).bind(account.did).first()).toMatchObject({ actor: "operator@example.com" });
      } finally {
        consoleErrorSpy.mockRestore();
        fetchSpy.mockRestore();
      }
    });

    it("does not fetch the operator's alert endpoint when the URL is unconfigured", async () => {
      const access = await generateAccessFixture();
      const fetchSpy = stubPlcDirectory({ accessJwk: access.publicJwk });
      try {
        const account = await enrollRookWithInvite("takedown-alert-disabled");
        const testEnv: Env = {
          ...env,
          HUB_WEBHOOK_URL: undefined,
          HUB_WEBHOOK_SECRET: "test-hub-secret",
        };
        const ctx = createExecutionContext();

        const response = await directTakedownAccount(account, access, testEnv, ctx);
        expect(response.status).toBe(200);
        await response.json();
        await waitOnExecutionContext(ctx);

        const hubRequests = fetchSpy.mock.calls.filter(([input]) =>
          fetchInputUrl(input).startsWith("https://hub.test/")
        );
        expect(hubRequests).toHaveLength(0);
      } finally {
        fetchSpy.mockRestore();
      }
    });
  });
});
