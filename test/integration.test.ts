import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildAccessToken,
  createDpopJwt,
  createOauthDpopJwt,
  createPkcePair,
  env,
  generateAuthKeys,
  generateEcKeys,
  runInDurableObject,
  signJwt,
  signTos,
  worker,
} from "./helpers";
import { initDirectory, insertAccount } from "../src/directory";
import { base64urlEncode, parseJwt, sha256Base64url } from "../src/auth";
import { SequencerDurableObject } from "../src/sequencer-do";
import { __resetClientMetadataCache } from "../src/oauth/client-metadata";
import { getOAuthParRequest, initOAuth } from "../src/oauth/store";
import { getSequencerStub } from "./firehose-helpers";

const SERVICE_ORIGIN = `https://${env.ROOKERY_HOSTNAME}`;

async function resetSequencer(): Promise<void> {
  const stub = getSequencerStub();
  await runInDurableObject(stub, async (instance: SequencerDurableObject) => {
    await instance.sequenceIdentity("did:plc:reset", "reset.rookery.test");
    const ctx = (instance as unknown as { ctx: DurableObjectState }).ctx;
    ctx.storage.sql.exec("DELETE FROM firehose_events");
    ctx.storage.sql.exec(
      "DELETE FROM sqlite_sequence WHERE name = 'firehose_events'",
    );
  });
}

async function getFirehoseRows(): Promise<
  Array<{ seq: number; did: string; event_type: string; payload: ArrayBuffer }>
> {
  const stub = getSequencerStub();
  return runInDurableObject(stub, async (instance: SequencerDurableObject) => {
    const ctx = (instance as unknown as { ctx: DurableObjectState }).ctx;
    return ctx.storage.sql
      .exec("SELECT seq, did, event_type, payload FROM firehose_events ORDER BY seq ASC")
      .toArray() as Array<{
      seq: number;
      did: string;
      event_type: string;
      payload: ArrayBuffer;
    }>;
  });
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

function stubPlcDirectory() {
  const originalFetch = globalThis.fetch.bind(globalThis);
  return vi
    .spyOn(globalThis, "fetch")
    .mockImplementation(async (input, init) => {
      const url = fetchInputUrl(input);
      if (url.startsWith("https://plc.directory/")) {
        return new Response(null, { status: 200 });
      }
      return originalFetch(input as RequestInfo | URL, init);
    });
}

async function signupWithAuth(
  handle: string,
  authKeys: CryptoKeyPair,
  publicJwk: JsonWebKey,
  thumbprint: string,
  ref?: string,
): Promise<{
  status: number;
  body: {
    did?: string;
    handle?: string;
    access_token?: string;
    error?: string;
    message?: string;
  };
}> {
  const fetchSpy = stubPlcDirectory();
  try {
    const tosText = await fetchTosText();
    const accessToken = await buildAccessToken(authKeys, thumbprint, tosText, SERVICE_ORIGIN);
    const tosSig = await signTos(authKeys.privateKey, tosText);
    const dpop = await createDpopJwt(authKeys, publicJwk, "http://localhost/api/signup", null);
    const requestBody: Record<string, string> = {
      handle,
      tos_signature: tosSig,
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
          dpop,
        },
        body: JSON.stringify(requestBody),
      }),
    );
    return {
      status: response.status,
      body: await response.json(),
    };
  } finally {
    fetchSpy.mockRestore();
  }
}

async function signupWithFreshKeys(
  handle: string,
  ref?: string,
): ReturnType<typeof signupWithAuth> {
  const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
  return signupWithAuth(handle, authKeys, publicJwk, thumbprint, ref);
}

async function createAccountViaSignup(
  handle: string,
  authKeys: CryptoKeyPair,
  publicJwk: JsonWebKey,
  thumbprint: string,
): Promise<{ did: string; handle: string; access_token: string }> {
  const result = await signupWithAuth(handle, authKeys, publicJwk, thumbprint);
  expect(result.status).toBe(200);
  return result.body as { did: string; handle: string; access_token: string };
}

describe("Integration", () => {
  beforeAll(async () => {
    await initDirectory(env.DIRECTORY);
  });

  beforeEach(async () => {
    await resetSequencer();
  });

  it("runs the full lifecycle from signup through firehose", async () => {
    const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
    const { did } = await createAccountViaSignup(
      `lifecycle-${Date.now().toString(36)}`,
      authKeys,
      publicJwk,
      thumbprint,
    );
    expect(did.startsWith("did:plc:")).toBe(true);

    const tosText = await fetchTosText();
    const accessToken = await buildAccessToken(authKeys, thumbprint, tosText, SERVICE_ORIGIN);
    const createUrl = "http://localhost/xrpc/com.atproto.repo.createRecord";
    const createResponse = await worker.fetch(
      new Request(createUrl, {
        method: "POST",
        headers: {
          authorization: `DPoP ${accessToken}`,
          dpop: await createDpopJwt(authKeys, publicJwk, createUrl, accessToken),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          repo: did,
          collection: "com.example.test",
          rkey: "post1",
          record: { text: "hello", createdAt: new Date().toISOString() },
        }),
      }),
    );
    expect(createResponse.status).toBe(200);

    const getResponse = await worker.fetch(
      `http://localhost/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(did)}&collection=com.example.test&rkey=post1`,
    );
    expect(getResponse.status).toBe(200);
    expect(await getResponse.json()).toMatchObject({
      value: { text: "hello" },
    });

    const repoExport = await worker.fetch(
      `http://localhost/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(did)}`,
    );
    expect(repoExport.status).toBe(200);
    expect(repoExport.headers.get("content-type")).toBe("application/vnd.ipld.car");
    expect((await repoExport.arrayBuffer()).byteLength).toBeGreaterThan(0);

    const rows = await getFirehoseRows();
    expect(rows.map((row) => row.event_type)).toEqual(["identity", "account", "commit"]);
  });

  it("keeps multi-agent writes and reads isolated", async () => {
    const agentAKeys = await generateAuthKeys();
    const agentBKeys = await generateAuthKeys();
    const tosText = await fetchTosText();
    const agentA = await createAccountViaSignup(
      `agent-a-${Date.now().toString(36)}`,
      agentAKeys.authKeys,
      agentAKeys.publicJwk,
      agentAKeys.thumbprint,
    );
    const agentB = await createAccountViaSignup(
      `agent-b-${Date.now().toString(36)}`,
      agentBKeys.authKeys,
      agentBKeys.publicJwk,
      agentBKeys.thumbprint,
    );

    const createUrl = "http://localhost/xrpc/com.atproto.repo.createRecord";
    const agentAAccessToken = await buildAccessToken(
      agentAKeys.authKeys,
      agentAKeys.thumbprint,
      tosText,
      SERVICE_ORIGIN,
    );
    const agentBAccessToken = await buildAccessToken(
      agentBKeys.authKeys,
      agentBKeys.thumbprint,
      tosText,
      SERVICE_ORIGIN,
    );

    const agentAWrite = await worker.fetch(
      new Request(createUrl, {
        method: "POST",
        headers: {
          authorization: `DPoP ${agentAAccessToken}`,
          dpop: await createDpopJwt(
            agentAKeys.authKeys,
            agentAKeys.publicJwk,
            createUrl,
            agentAAccessToken,
          ),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          repo: agentA.did,
          collection: "com.example.test",
          rkey: "a-post",
          record: { text: "from agent a", createdAt: new Date().toISOString() },
        }),
      }),
    );
    expect(agentAWrite.status).toBe(200);

    const agentBWrite = await worker.fetch(
      new Request(createUrl, {
        method: "POST",
        headers: {
          authorization: `DPoP ${agentBAccessToken}`,
          dpop: await createDpopJwt(
            agentBKeys.authKeys,
            agentBKeys.publicJwk,
            createUrl,
            agentBAccessToken,
          ),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          repo: agentB.did,
          collection: "com.example.test",
          rkey: "b-post",
          record: { text: "from agent b", createdAt: new Date().toISOString() },
        }),
      }),
    );
    expect(agentBWrite.status).toBe(200);

    const agentARecord = await worker.fetch(
      `http://localhost/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(agentA.did)}&collection=com.example.test&rkey=a-post`,
    );
    expect(agentARecord.status).toBe(200);
    expect(await agentARecord.json()).toMatchObject({
      value: { text: "from agent a" },
    });

    const agentBRecord = await worker.fetch(
      `http://localhost/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(agentB.did)}&collection=com.example.test&rkey=b-post`,
    );
    expect(agentBRecord.status).toBe(200);
    expect(await agentBRecord.json()).toMatchObject({
      value: { text: "from agent b" },
    });

    const agentAList = await worker.fetch(
      `http://localhost/xrpc/com.atproto.repo.listRecords?repo=${encodeURIComponent(agentA.did)}&collection=com.example.test`,
    );
    expect(agentAList.status).toBe(200);
    const agentAListBody = await agentAList.json() as {
      records: Array<{ uri: string; value: { text: string } }>;
    };
    expect(agentAListBody.records).toHaveLength(1);
    expect(agentAListBody.records[0]).toMatchObject({
      uri: `at://${agentA.did}/com.example.test/a-post`,
      value: { text: "from agent a" },
    });

    const agentBList = await worker.fetch(
      `http://localhost/xrpc/com.atproto.repo.listRecords?repo=${encodeURIComponent(agentB.did)}&collection=com.example.test`,
    );
    expect(agentBList.status).toBe(200);
    const agentBListBody = await agentBList.json() as {
      records: Array<{ uri: string; value: { text: string } }>;
    };
    expect(agentBListBody.records).toHaveLength(1);
    expect(agentBListBody.records[0]).toMatchObject({
      uri: `at://${agentB.did}/com.example.test/b-post`,
      value: { text: "from agent b" },
    });
  });

  it("resolves the signed-up handle back to the same DID", async () => {
    const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
    const account = await createAccountViaSignup(
      `did-test-${Date.now().toString(36)}`,
      authKeys,
      publicJwk,
      thumbprint,
    );
    expect(account.did.startsWith("did:plc:")).toBe(true);

    const response = await worker.fetch(
      `http://localhost/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(account.handle)}`,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ did: account.did });
  });

  describe("handle acceptance policy", () => {
    it("lowercases labels before policy checks and storage", async () => {
      const reserved = await signupWithFreshKeys("Admin");
      expect(reserved.status).toBe(400);
      expect(reserved.body).toMatchObject({
        error: "HandleReserved",
        message: "Handle is reserved. Choose a different name.",
      });

      const accepted = await signupWithFreshKeys("MyAgent");
      expect(accepted.status).toBe(200);
      expect(accepted.body.handle).toBe("myagent.rookery.test");
    });

    it("reserves one and two character labels", async () => {
      for (const label of ["a", "ab"]) {
        const response = await signupWithFreshKeys(label);
        expect(response.status).toBe(400);
        expect(response.body).toMatchObject({
          error: "HandleReserved",
          message: "Handle is reserved. Choose a different name.",
        });
      }
    });

    it("blocks exact blocklist labels", async () => {
      for (const label of ["admin", "knot", "pds", "www", "solpbc", "rook", "swastika"]) {
        const response = await signupWithFreshKeys(label);
        expect(response.status).toBe(400);
        expect(response.body).toMatchObject({
          error: "HandleReserved",
          message: "Handle is reserved. Choose a different name.",
        });
      }
    });

    it("rejects dotted and syntactically invalid labels as invalid handles", async () => {
      const dotted = await signupWithFreshKeys("admin.x");
      expect(dotted.status).toBe(400);
      expect(dotted.body).toMatchObject({
        error: "InvalidHandle",
        message: "Invalid handle: submit a single name without dots.",
      });

      const invalidShort = await signupWithFreshKeys("a-");
      expect(invalidShort.status).toBe(400);
      expect(invalidShort.body).toMatchObject({ error: "InvalidHandle" });
    });

    it("applies blocklist before availability", async () => {
      await insertAccount(env.DIRECTORY, {
        did: "did:plc:blocktest",
        handle: "admin.rookery.test",
        doId: "blocktest-do",
      });

      const response = await signupWithFreshKeys("admin");
      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({
        error: "HandleReserved",
        message: "Handle is reserved. Choose a different name.",
      });
    });
  });

  it("covers enrollment edge cases", async () => {
    const duplicateHandle = `duphandle-${Date.now().toString(36)}`;
    const duplicateHandleKeys = await generateAuthKeys();
    await createAccountViaSignup(
      duplicateHandle,
      duplicateHandleKeys.authKeys,
      duplicateHandleKeys.publicJwk,
      duplicateHandleKeys.thumbprint,
    );

    const fetchSpy = stubPlcDirectory();
    const newUniqueIdSpy = vi.spyOn(env.ACCOUNT, "newUniqueId");
    try {
      const duplicateSignupKeys = await generateAuthKeys();
      const tosText = await fetchTosText();
      const duplicateToken = await buildAccessToken(
        duplicateSignupKeys.authKeys,
        duplicateSignupKeys.thumbprint,
        tosText,
        SERVICE_ORIGIN,
      );
      const duplicateResponse = await worker.fetch(
        new Request("http://localhost/api/signup", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            dpop: await createDpopJwt(
              duplicateSignupKeys.authKeys,
              duplicateSignupKeys.publicJwk,
              "http://localhost/api/signup",
              null,
            ),
          },
          body: JSON.stringify({
            handle: duplicateHandle,
            tos_signature: await signTos(duplicateSignupKeys.authKeys.privateKey, tosText),
            access_token: duplicateToken,
          }),
        }),
      );
      expect(duplicateResponse.status).toBe(409);
      const dupBody = await duplicateResponse.json() as { error: string; message: string };
      expect(dupBody.error).toBe("HandleTaken");
      expect(dupBody.message).toBe("Handle is already taken. Choose another name.");
      expect(
        fetchSpy.mock.calls.some(([input]) =>
          fetchInputUrl(input).startsWith("https://plc.directory/")
        ),
      ).toBe(false);
      expect(newUniqueIdSpy).not.toHaveBeenCalled();
    } finally {
      newUniqueIdSpy.mockRestore();
      fetchSpy.mockRestore();
    }

    const duplicateThumbprint = await generateAuthKeys();
    await createAccountViaSignup(
      `dup-thumb-a-${Date.now().toString(36)}`,
      duplicateThumbprint.authKeys,
      duplicateThumbprint.publicJwk,
      duplicateThumbprint.thumbprint,
    );
    const dupThumbAccount = await createAccountViaSignup(
      `dup-thumb-b-${Date.now().toString(36)}`,
      duplicateThumbprint.authKeys,
      duplicateThumbprint.publicJwk,
      duplicateThumbprint.thumbprint,
    );
    expect(dupThumbAccount.did.startsWith("did:plc:")).toBe(true);

    const missingAuthResponse = await worker.fetch(
      new Request("http://localhost/xrpc/com.atproto.repo.createRecord", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          repo: "did:plc:missing-auth",
          collection: "com.example.test",
          rkey: "missing-auth",
          record: { text: "missing auth", createdAt: new Date().toISOString() },
        }),
      }),
    );
    expect(missingAuthResponse.status).toBe(401);

    const invalidDpopResponse = await worker.fetch(
      new Request("http://localhost/xrpc/com.atproto.repo.createRecord", {
        method: "POST",
        headers: {
          authorization: "DPoP fake-token",
          dpop: "not-a-jwt",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          repo: "did:plc:invalid-dpop",
          collection: "com.example.test",
          rkey: "invalid-dpop",
          record: { text: "invalid", createdAt: new Date().toISOString() },
        }),
      }),
    );
    expect(invalidDpopResponse.status).toBe(401);
  });

  describe("enrollment validation", () => {
    it("ignores signup ref in the reference variant", async () => {
      const handle = `ref-ignored-${Date.now().toString(36)}`;
      const response = await signupWithFreshKeys(
        handle,
        "https://rookery.test/roost#unused-reference-token",
      );

      expect(response.status).toBe(200);
      expect(response.body.handle).toBe(`${handle}.rookery.test`);
    });

    it("rejects signup without DPoP header", async () => {
      const { authKeys, thumbprint } = await generateAuthKeys();
      const fetchSpy = stubPlcDirectory();

      try {
        const tosText = await fetchTosText();
        const accessToken = await buildAccessToken(authKeys, thumbprint, tosText, SERVICE_ORIGIN);
        const response = await worker.fetch(
          new Request("http://localhost/api/signup", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              handle: `no-dpop-${Date.now().toString(36)}`,
              tos_signature: await signTos(authKeys.privateKey, tosText),
              access_token: accessToken,
            }),
          }),
        );

        expect(response.status).toBe(401);
        await expect(response.json()).resolves.toMatchObject({ error: "AuthRequired" });
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it("rejects signup with bad tos_signature", async () => {
      const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
      const fetchSpy = stubPlcDirectory();

      try {
        const tosText = await fetchTosText();
        const accessToken = await buildAccessToken(authKeys, thumbprint, tosText, SERVICE_ORIGIN);
        const response = await worker.fetch(
          new Request("http://localhost/api/signup", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              dpop: await createDpopJwt(authKeys, publicJwk, "http://localhost/api/signup", null),
            },
            body: JSON.stringify({
              handle: `bad-tos-sig-${Date.now().toString(36)}`,
              tos_signature: await signTos(authKeys.privateKey, `${tosText}\n`),
              access_token: accessToken,
            }),
          }),
        );

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toMatchObject({ error: "InvalidSignature" });
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it("rejects signup with wrong tos_hash in access_token", async () => {
      const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
      const fetchSpy = stubPlcDirectory();

      try {
        const tosText = await fetchTosText();
        const accessToken = await signJwt(
          { typ: "wm+jwt", alg: "RS256" },
          {
            tos_hash: await sha256Base64url("wrong tos text"),
            aud: SERVICE_ORIGIN,
            cnf: { jkt: thumbprint },
            iat: Math.floor(Date.now() / 1000),
          },
          authKeys.privateKey,
        );
        const response = await worker.fetch(
          new Request("http://localhost/api/signup", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              dpop: await createDpopJwt(authKeys, publicJwk, "http://localhost/api/signup", null),
            },
            body: JSON.stringify({
              handle: `wrong-tos-hash-${Date.now().toString(36)}`,
              tos_signature: await signTos(authKeys.privateKey, tosText),
              access_token: accessToken,
            }),
          }),
        );

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toMatchObject({ error: "InvalidToken" });
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it("rejects write with stale tos_hash", async () => {
      const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
      const { did } = await createAccountViaSignup(
        `stale-write-${Date.now().toString(36)}`,
        authKeys,
        publicJwk,
        thumbprint,
      );
      const staleAccessToken = await signJwt(
        { typ: "wm+jwt", alg: "RS256" },
        {
          tos_hash: await sha256Base64url("wrong tos text"),
          aud: SERVICE_ORIGIN,
          cnf: { jkt: thumbprint },
          iat: Math.floor(Date.now() / 1000),
        },
        authKeys.privateKey,
      );
      const createUrl = "http://localhost/xrpc/com.atproto.repo.createRecord";
      const response = await worker.fetch(
        new Request(createUrl, {
          method: "POST",
          headers: {
            authorization: `DPoP ${staleAccessToken}`,
            dpop: await createDpopJwt(authKeys, publicJwk, createUrl, staleAccessToken),
            "content-type": "application/json",
          },
          body: JSON.stringify({
            repo: did,
            collection: "com.example.test",
            rkey: "stale-token",
            record: { text: "stale", createdAt: new Date().toISOString() },
          }),
        }),
      );

      expect(response.status).toBe(401);
      await expect(response.json()).resolves.toMatchObject({ error: "tos_changed" });
    });
  });

  it("round-trips blobs through uploadBlob and getBlob", async () => {
    const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
    const { did } = await createAccountViaSignup(
      `blob-${Date.now().toString(36)}`,
      authKeys,
      publicJwk,
      thumbprint,
    );
    const tosText = await fetchTosText();
    const accessToken = await buildAccessToken(authKeys, thumbprint, tosText, SERVICE_ORIGIN);
    const uploadUrl = "http://localhost/xrpc/com.atproto.repo.uploadBlob";
    const bytes = new TextEncoder().encode("test blob data");
    const uploadResponse = await worker.fetch(
      new Request(uploadUrl, {
        method: "POST",
        headers: {
          authorization: `DPoP ${accessToken}`,
          dpop: await createDpopJwt(authKeys, publicJwk, uploadUrl, accessToken),
          "content-type": "application/octet-stream",
          "content-length": String(bytes.byteLength),
        },
        body: bytes,
      }),
    );
    expect(uploadResponse.status).toBe(200);
    const uploadBody = await uploadResponse.json() as {
      blob: { ref: { $link: string } };
    };
    const cid = uploadBody.blob.ref.$link;

    const downloadResponse = await worker.fetch(
      `http://localhost/xrpc/com.atproto.sync.getBlob?did=${encodeURIComponent(did)}&cid=${encodeURIComponent(cid)}`,
    );
    expect(downloadResponse.status).toBe(200);
    expect(new Uint8Array(await downloadResponse.arrayBuffer())).toEqual(bytes);
  });

  it("accepts lexicon-agnostic collection NSIDs", async () => {
    const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
    const { did } = await createAccountViaSignup(
      `lexicon-${Date.now().toString(36)}`,
      authKeys,
      publicJwk,
      thumbprint,
    );
    const tosText = await fetchTosText();
    const accessToken = await buildAccessToken(authKeys, thumbprint, tosText, SERVICE_ORIGIN);
    const createUrl = "http://localhost/xrpc/com.atproto.repo.createRecord";

    for (const collection of [
      "com.example.foo.bar",
      "app.bsky.feed.post",
      "xyz.custom.thing",
      "io.github.myapp.status",
    ]) {
      const response = await worker.fetch(
        new Request(createUrl, {
          method: "POST",
          headers: {
            authorization: `DPoP ${accessToken}`,
            dpop: await createDpopJwt(authKeys, publicJwk, createUrl, accessToken),
            "content-type": "application/json",
          },
          body: JSON.stringify({
            repo: did,
            collection,
            rkey: `${collection.split(".").pop()}-${Date.now().toString(36)}`,
            record: { text: collection, createdAt: new Date().toISOString() },
          }),
        }),
      );
      expect(response.status).toBe(200);
    }
  });

  describe("OAuth authorize/PAR", () => {
    const PAR_URL = "http://localhost/oauth/par";
    const AUTHORIZE_URL = "http://localhost/oauth/authorize";
    const TOKEN_URL = "http://localhost/oauth/token";
    const REVOKE_URL = "http://localhost/oauth/revoke";
    const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    type ParSuccess = {
      requestUri: string;
      ecKeys: CryptoKeyPair;
      publicJwk: JsonWebKey;
      ecThumbprint: string;
      clientId: string;
      redirectUri: string;
      codeVerifier: string;
      state?: string;
    };

    type ConsentAccount = {
      authKeys: CryptoKeyPair;
      publicJwk: JsonWebKey;
      thumbprint: string;
      did: string;
    };

    type TokenSuccess = {
      access_token: string;
      token_type: "DPoP";
      expires_in: number;
      refresh_token: string;
      scope: string;
      sub: string;
    };

    beforeAll(async () => {
      await initOAuth(env.DIRECTORY);
    });

    beforeEach(() => {
      __resetClientMetadataCache();
    });

    function uniqueId(prefix: string): string {
      return `${prefix}-${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}`;
    }

    function stubOauthFetch(entries: Record<string, object>) {
      const originalFetch = globalThis.fetch.bind(globalThis);
      return vi
        .spyOn(globalThis, "fetch")
        .mockImplementation(async (input, init) => {
          const url = fetchInputUrl(input);
          if (url in entries) {
            return new Response(JSON.stringify(entries[url]), {
              status: 200,
              headers: { "content-type": "application/json" },
            });
          }
          if (url.startsWith("https://plc.directory/")) {
            return new Response(null, { status: 200 });
          }
          return originalFetch(input as RequestInfo | URL, init);
        });
    }

    function parClientMetadata(
      clientId: string,
      overrides: Record<string, unknown> = {},
    ): Record<string, unknown> {
      return {
        client_id: clientId,
        redirect_uris: ["http://127.0.0.1/callback"],
        response_types: ["code"],
        grant_types: ["authorization_code"],
        scope: "atproto",
        dpop_bound_access_tokens: true,
        token_endpoint_auth_method: "none",
        client_name: "Test Client",
        client_uri: "https://client.example",
        ...overrides,
      };
    }

    async function buildParForm(
      clientId: string,
      overrides: Record<string, string | undefined> = {},
    ): Promise<{ formValues: Record<string, string>; codeVerifier: string }> {
      const pkce = await createPkcePair();
      const values: Record<string, string> = {
        client_id: clientId,
        response_type: "code",
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
        redirect_uri: "http://127.0.0.1/callback",
        scope: "atproto",
        state: `state-${crypto.randomUUID()}`,
      };
      for (const [key, value] of Object.entries(overrides)) {
        if (value === undefined) {
          delete values[key];
        } else {
          values[key] = value;
        }
      }
      return { formValues: values, codeVerifier: pkce.verifier };
    }

    async function postPar(
      formValues: Record<string, string>,
    ): Promise<{
      response: Response;
      ecKeys: CryptoKeyPair;
      publicJwk: JsonWebKey;
      ecThumbprint: string;
    }> {
      const { ecKeys, publicJwk, thumbprint } = await generateEcKeys();
      const missingNonceDpop = await createOauthDpopJwt(
        ecKeys,
        publicJwk,
        "POST",
        PAR_URL,
        null,
      );
      const missingNonceResponse = await worker.fetch(
        new Request(PAR_URL, {
          method: "POST",
          headers: {
            dpop: missingNonceDpop,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams(formValues),
        }),
      );
      expect(missingNonceResponse.status).toBe(400);
      expect(missingNonceResponse.headers.get("DPoP-Nonce")).toBeTruthy();
      await expect(missingNonceResponse.json()).resolves.toMatchObject({
        error: "use_dpop_nonce",
      });

      const nonce = missingNonceResponse.headers.get("DPoP-Nonce")!;
      const dpop = await createOauthDpopJwt(ecKeys, publicJwk, "POST", PAR_URL, null, nonce);
      const response = await worker.fetch(
        new Request(PAR_URL, {
          method: "POST",
          headers: {
            dpop,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams(formValues),
        }),
      );
      expect(response.headers.get("DPoP-Nonce")).toBeTruthy();
      return { response, ecKeys, publicJwk, ecThumbprint: thumbprint };
    }

    async function doPar(opts: {
      clientId?: string;
      redirectUri?: string;
      formOverrides?: Record<string, string | undefined>;
    } = {}): Promise<ParSuccess> {
      const clientId = opts.clientId ?? `https://client.example/${uniqueId("client")}.json`;
      const redirectUri = opts.redirectUri ?? "http://127.0.0.1/callback";
      const { formValues, codeVerifier } = await buildParForm(clientId, {
        redirect_uri: redirectUri,
        ...opts.formOverrides,
      });
      const { response, ecKeys, publicJwk, ecThumbprint } = await postPar(formValues);
      expect(response.status).toBe(201);
      const body = await response.json() as { request_uri: string; expires_in: number };
      expect(body.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
      expect(body.expires_in).toBe(300);
      return {
        requestUri: body.request_uri,
        ecKeys,
        publicJwk,
        ecThumbprint,
        clientId,
        redirectUri,
        codeVerifier,
        state: formValues.state,
      };
    }

    function authorizeUrl(par: Pick<ParSuccess, "requestUri" | "clientId">, deny = false): string {
      const url = new URL(AUTHORIZE_URL);
      url.searchParams.set("request_uri", par.requestUri);
      url.searchParams.set("client_id", par.clientId);
      if (deny) url.searchParams.set("deny", "1");
      return url.toString();
    }

    async function createConsentAccount(prefix: string): Promise<ConsentAccount> {
      const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
      const account = await createAccountViaSignup(
        uniqueId(prefix),
        authKeys,
        publicJwk,
        thumbprint,
      );
      return { authKeys, publicJwk, thumbprint, did: account.did };
    }

    async function consentHeaders(
      account: ConsentAccount,
      htu = AUTHORIZE_URL,
      accessTokenOverride?: string,
    ): Promise<{ authorization: string; dpop: string }> {
      await new Promise((resolve) => setTimeout(resolve, 2));
      const accessToken = accessTokenOverride ??
        await buildAccessToken(account.authKeys, account.thumbprint, await fetchTosText(), SERVICE_ORIGIN);
      return {
        authorization: `DPoP ${accessToken}`,
        dpop: await createDpopJwt(account.authKeys, account.publicJwk, htu, accessToken, "GET"),
      };
    }

    async function signEs256Jwt(
      header: Record<string, unknown>,
      payload: Record<string, unknown>,
      privateKey: CryptoKey,
    ): Promise<string> {
      const encode = (obj: Record<string, unknown>) =>
        base64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
      const headerStr = encode(header);
      const payloadStr = encode(payload);
      const signingInput = `${headerStr}.${payloadStr}`;
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        new TextEncoder().encode(signingInput),
      );
      return `${signingInput}.${base64urlEncode(signature)}`;
    }

    async function codeRowForCode(code: string): Promise<{
      did: string;
      dpop_jkt: string;
      exp: number;
    } | null> {
      return env.DIRECTORY.prepare(
        "SELECT did, dpop_jkt, exp FROM oauth_codes WHERE code_hash = ?",
      ).bind(await sha256Base64url(code)).first<{ did: string; dpop_jkt: string; exp: number }>();
    }

    async function codeRowForRedirect(redirectUri: string): Promise<{ code_hash: string } | null> {
      return env.DIRECTORY.prepare(
        "SELECT code_hash FROM oauth_codes WHERE redirect_uri = ?",
      ).bind(redirectUri).first<{ code_hash: string }>();
    }

    async function authorizeCode(par: ParSuccess, account: ConsentAccount): Promise<string> {
      const response = await worker.fetch(
        new Request(authorizeUrl(par), {
          headers: await consentHeaders(account),
          redirect: "manual",
        }),
      );
      expect(response.status).toBe(302);
      const loc = new URL(response.headers.get("location")!);
      const code = loc.searchParams.get("code");
      expect(code).toBeTruthy();
      return code!;
    }

    async function postToken(
      formValues: Record<string, string>,
      ecKeys: CryptoKeyPair,
      publicJwk: JsonWebKey,
    ): Promise<Response> {
      const missingNonceDpop = await createOauthDpopJwt(
        ecKeys,
        publicJwk,
        "POST",
        TOKEN_URL,
        null,
      );
      const missingNonceResponse = await worker.fetch(
        new Request(TOKEN_URL, {
          method: "POST",
          headers: {
            dpop: missingNonceDpop,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams(formValues),
        }),
      );
      expect(missingNonceResponse.status).toBe(400);
      const nonce = missingNonceResponse.headers.get("DPoP-Nonce");
      expect(nonce).toBeTruthy();
      await expect(missingNonceResponse.json()).resolves.toMatchObject({
        error: "use_dpop_nonce",
      });

      const dpop = await createOauthDpopJwt(ecKeys, publicJwk, "POST", TOKEN_URL, null, nonce!);
      const response = await worker.fetch(
        new Request(TOKEN_URL, {
          method: "POST",
          headers: {
            dpop,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams(formValues),
        }),
      );
      expect(response.headers.get("DPoP-Nonce")).toBeTruthy();
      return response;
    }

    function codeTokenForm(
      par: ParSuccess,
      code: string,
      overrides: Record<string, string | undefined> = {},
    ): Record<string, string> {
      const values: Record<string, string> = {
        grant_type: "authorization_code",
        client_id: par.clientId,
        code,
        redirect_uri: par.redirectUri,
        code_verifier: par.codeVerifier,
      };
      for (const [key, value] of Object.entries(overrides)) {
        if (value === undefined) {
          delete values[key];
        } else {
          values[key] = value;
        }
      }
      return values;
    }

    async function exchangeCode(
      par: ParSuccess,
      code: string,
      overrides: Record<string, string | undefined> = {},
    ): Promise<Response> {
      return postToken(codeTokenForm(par, code, overrides), par.ecKeys, par.publicJwk);
    }

    async function refreshToken(
      par: ParSuccess,
      refresh: string,
      overrides: Record<string, string | undefined> = {},
    ): Promise<Response> {
      const values: Record<string, string> = {
        grant_type: "refresh_token",
        client_id: par.clientId,
        refresh_token: refresh,
      };
      for (const [key, value] of Object.entries(overrides)) {
        if (value === undefined) {
          delete values[key];
        } else {
          values[key] = value;
        }
      }
      return postToken(values, par.ecKeys, par.publicJwk);
    }

    async function expectTokenSuccess(response: Response): Promise<TokenSuccess> {
      expect(response.status).toBe(200);
      const body = await response.json() as TokenSuccess;
      expect(Object.keys(body).sort()).toEqual([
        "access_token",
        "expires_in",
        "refresh_token",
        "scope",
        "sub",
        "token_type",
      ]);
      expect(body.access_token.startsWith("rkat_")).toBe(true);
      expect(body.refresh_token.startsWith("rkrt_")).toBe(true);
      expect(body.token_type).toBe("DPoP");
      return body;
    }

    async function oauthHeaders(
      par: Pick<ParSuccess, "ecKeys" | "publicJwk">,
      url: string,
      accessToken: string,
      method = "POST",
    ): Promise<{ authorization: string; dpop: string }> {
      return {
        authorization: `DPoP ${accessToken}`,
        dpop: await createOauthDpopJwt(par.ecKeys, par.publicJwk, method, url, accessToken),
      };
    }

    async function issueOauthToken(
      scope = "atproto repo:com.example.test",
    ): Promise<{
      account: ConsentAccount;
      par: ParSuccess;
      token: TokenSuccess;
      fetchSpy: ReturnType<typeof stubOauthFetch>;
    }> {
      const account = await createConsentAccount("oauth-token");
      const clientId = `https://client.example/${uniqueId("token")}.json`;
      const redirectUri = `http://127.0.0.1/callback?case=${uniqueId("token")}`;
      const fetchSpy = stubOauthFetch({
        [clientId]: parClientMetadata(clientId, { redirect_uris: [redirectUri] }),
      });
      const par = await doPar({ clientId, redirectUri, formOverrides: { scope } });
      const code = await authorizeCode(par, account);
      const token = await expectTokenSuccess(await exchangeCode(par, code));
      return { account, par, token, fetchSpy };
    }

    async function createRecordWithOauth(
      par: Pick<ParSuccess, "ecKeys" | "publicJwk">,
      token: TokenSuccess,
      collection: string,
      rkey: string,
      dpopOverride?: string,
    ): Promise<Response> {
      const url = "http://localhost/xrpc/com.atproto.repo.createRecord";
      const headers = await oauthHeaders(par, url, token.access_token);
      if (dpopOverride !== undefined) {
        headers.dpop = dpopOverride;
      }
      return worker.fetch(
        new Request(url, {
          method: "POST",
          headers: {
            ...headers,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            repo: token.sub,
            collection,
            rkey,
            record: { text: rkey, createdAt: new Date().toISOString() },
          }),
        }),
      );
    }

    async function getServiceAuthWithOauth(
      par: Pick<ParSuccess, "ecKeys" | "publicJwk">,
      token: TokenSuccess,
      aud: string,
      lxm: string,
      exp?: number,
    ): Promise<Response> {
      const url = new URL("http://localhost/xrpc/com.atproto.server.getServiceAuth");
      url.searchParams.set("aud", aud);
      url.searchParams.set("lxm", lxm);
      if (exp !== undefined) {
        url.searchParams.set("exp", String(exp));
      }
      return worker.fetch(
        new Request(url, {
          method: "GET",
          headers: await oauthHeaders(
            par,
            `${url.origin}${url.pathname}`,
            token.access_token,
            "GET",
          ),
        }),
      );
    }

    async function uploadBlobWithOauth(
      par: Pick<ParSuccess, "ecKeys" | "publicJwk">,
      accessToken: string,
      body: Uint8Array,
    ): Promise<Response> {
      const url = "http://localhost/xrpc/com.atproto.repo.uploadBlob";
      return worker.fetch(
        new Request(url, {
          method: "POST",
          headers: {
            ...await oauthHeaders(par, url, accessToken),
            "content-type": "text/plain",
            "content-length": String(body.byteLength),
          },
          body,
        }),
      );
    }

    it("runs the happy path end-to-end", async () => {
      const account = await createConsentAccount("oauth-happy");
      const clientId = `https://client.example/${uniqueId("happy")}.json`;
      const redirectUri = `http://127.0.0.1/callback?case=${uniqueId("happy")}`;
      const fetchSpy = stubOauthFetch({
        [clientId]: parClientMetadata(clientId, { redirect_uris: [redirectUri] }),
      });
      try {
        const par = await doPar({ clientId, redirectUri });
        expect(fetchSpy.mock.calls.some(([input]) => fetchInputUrl(input) === clientId)).toBe(true);

        const before = Math.floor(Date.now() / 1000);
        const response = await worker.fetch(
          new Request(authorizeUrl(par), {
            headers: await consentHeaders(account),
            redirect: "manual",
          }),
        );
        const after = Math.floor(Date.now() / 1000);
        expect(response.status).toBe(302);
        const loc = new URL(response.headers.get("location")!);
        const code = loc.searchParams.get("code");
        expect(code).toBeTruthy();
        expect(loc.searchParams.get("state")).toBe(par.state);
        expect(loc.searchParams.get("iss")).toBe(SERVICE_ORIGIN);

        const row = await codeRowForCode(code!);
        expect(row).toMatchObject({ did: account.did, dpop_jkt: par.ecThumbprint });
        expect(row!.exp).toBeGreaterThanOrEqual(before + 50);
        expect(row!.exp).toBeLessThanOrEqual(after + 70);
        await expect(
          env.DIRECTORY.prepare(
            "SELECT 1 FROM oauth_par_requests WHERE request_uri = ?",
          ).bind(par.requestUri).first(),
        ).resolves.toBeNull();
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it("rejects a second authed GET for the same request_uri", async () => {
      const account = await createConsentAccount("oauth-single");
      const clientId = `https://client.example/${uniqueId("single")}.json`;
      const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
      try {
        const par = await doPar({ clientId });
        const first = await worker.fetch(
          new Request(authorizeUrl(par), {
            headers: await consentHeaders(account),
            redirect: "manual",
          }),
        );
        expect(first.status).toBe(302);

        const second = await worker.fetch(
          new Request(authorizeUrl(par), {
            headers: await consentHeaders(account),
            redirect: "manual",
          }),
        );
        expect(second.status).toBe(400);
        await expect(second.json()).resolves.toMatchObject({ error: "invalid_request" });
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it("rejects replaying exact consent proof bytes on another pending request_uri", async () => {
      const account = await createConsentAccount("oauth-replay");
      const clientId = `https://client.example/${uniqueId("replay")}.json`;
      const redirectOne = `http://127.0.0.1/callback?case=${uniqueId("one")}`;
      const redirectTwo = `http://127.0.0.1/callback?case=${uniqueId("two")}`;
      const fetchSpy = stubOauthFetch({
        [clientId]: parClientMetadata(clientId, { redirect_uris: [redirectOne, redirectTwo] }),
      });
      try {
        const parOne = await doPar({ clientId, redirectUri: redirectOne });
        const parTwo = await doPar({ clientId, redirectUri: redirectTwo });
        const headers = await consentHeaders(account);

        const first = await worker.fetch(
          new Request(authorizeUrl(parOne), { headers, redirect: "manual" }),
        );
        expect(first.status).toBe(302);

        const second = await worker.fetch(
          new Request(authorizeUrl(parTwo), { headers, redirect: "manual" }),
        );
        expect(second.status).toBe(401);
        await expect(second.json()).resolves.toMatchObject({ error: "AuthFailed" });
        await expect(codeRowForRedirect(redirectTwo)).resolves.toBeNull();
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it("previews without consuming and then consents", async () => {
      const account = await createConsentAccount("oauth-preview");
      const clientId = `https://client.example/${uniqueId("preview")}.json`;
      const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
      try {
        const par = await doPar({ clientId });
        const preview = await worker.fetch(authorizeUrl(par));
        expect(preview.status).toBe(200);
        await expect(preview.json()).resolves.toEqual({
          consent_request: {
            client_id: clientId,
            client_metadata: {
              client_name: "Test Client",
              client_uri: "https://client.example",
            },
            scope: "atproto",
            redirect_uri: "http://127.0.0.1/callback",
            login_hint: null,
          },
          how_to_consent:
            "GET this URL again with an `Authorization: DPoP <wm+jwt>` header and a matching DPoP proof built from the granting account's welcome-mat credential to grant; the DPoP htu is origin + path only, without query or fragment; append deny=1 to refuse.",
        });

        const consent = await worker.fetch(
          new Request(authorizeUrl(par), {
            headers: await consentHeaders(account),
            redirect: "manual",
          }),
        );
        expect(consent.status).toBe(302);
      } finally {
        fetchSpy.mockRestore();
      }
    });

    it("redirects denial and does not mint a code", async () => {
      const account = await createConsentAccount("oauth-deny");
      const clientId = `https://client.example/${uniqueId("deny")}.json`;
      const redirectUri = `http://127.0.0.1/callback?case=${uniqueId("deny")}`;
      const fetchSpy = stubOauthFetch({
        [clientId]: parClientMetadata(clientId, { redirect_uris: [redirectUri] }),
      });
      try {
        const par = await doPar({ clientId, redirectUri });
        const response = await worker.fetch(
          new Request(authorizeUrl(par, true), {
            headers: await consentHeaders(account),
            redirect: "manual",
          }),
        );
        expect(response.status).toBe(302);
        const loc = new URL(response.headers.get("location")!);
        expect(loc.searchParams.get("error")).toBe("access_denied");
        expect(loc.searchParams.get("state")).toBe(par.state);
        expect(loc.searchParams.get("iss")).toBe(SERVICE_ORIGIN);
        await expect(
          env.DIRECTORY.prepare(
            "SELECT 1 FROM oauth_par_requests WHERE request_uri = ?",
          ).bind(par.requestUri).first(),
        ).resolves.toBeNull();
        await expect(codeRowForRedirect(redirectUri)).resolves.toBeNull();
      } finally {
        fetchSpy.mockRestore();
      }
    });

    describe("token, revoke, and resource-server access", () => {
      it("exchanges a code, stores only hashes, and writes with the OAuth access token", async () => {
        const issued = await issueOauthToken("atproto repo:com.example.test");
        try {
          expect(issued.token.scope).toBe("atproto repo:com.example.test");
          expect(issued.token.sub).toBe(issued.account.did);
          expect(issued.token.expires_in).toBe(900);
          await expect(
            env.DIRECTORY.prepare(
              "SELECT 1 FROM oauth_tokens WHERE access_token_hash = ?",
            ).bind(issued.token.access_token).first(),
          ).resolves.toBeNull();
          await expect(
            env.DIRECTORY.prepare(
              "SELECT 1 FROM oauth_sessions WHERE refresh_token_hash = ?",
            ).bind(issued.token.refresh_token).first(),
          ).resolves.toBeNull();
          await expect(
            env.DIRECTORY.prepare(
              "SELECT 1 FROM oauth_tokens WHERE access_token_hash = ?",
            ).bind(await sha256Base64url(issued.token.access_token)).first(),
          ).resolves.toBeTruthy();
          await expect(
            env.DIRECTORY.prepare(
              "SELECT 1 FROM oauth_sessions WHERE refresh_token_hash = ?",
            ).bind(await sha256Base64url(issued.token.refresh_token)).first(),
          ).resolves.toBeTruthy();

          const write = await createRecordWithOauth(
            issued.par,
            issued.token,
            "com.example.test",
            uniqueId("oauth-write"),
          );
          expect(write.status).toBe(200);
        } finally {
          issued.fetchSpy.mockRestore();
        }
      });

      it("consumes codes on PKCE failure and enforces code bindings", async () => {
        const account = await createConsentAccount("oauth-bindings");
        const clientId = `https://client.example/${uniqueId("bindings")}.json`;
        const otherClientId = `https://client.example/${uniqueId("other-bindings")}.json`;
        const redirectUri = `http://127.0.0.1/callback?case=${uniqueId("bindings")}`;
        const fetchSpy = stubOauthFetch({
          [clientId]: parClientMetadata(clientId, { redirect_uris: [redirectUri] }),
          [otherClientId]: parClientMetadata(otherClientId, { redirect_uris: [redirectUri] }),
        });
        try {
          let par = await doPar({ clientId, redirectUri });
          let code = await authorizeCode(par, account);
          let response = await exchangeCode(par, code, { code_verifier: "wrong-verifier" });
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });
          response = await exchangeCode(par, code);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });

          par = await doPar({ clientId, redirectUri });
          code = await authorizeCode(par, account);
          await expectTokenSuccess(await exchangeCode(par, code));
          response = await exchangeCode(par, code);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });

          par = await doPar({ clientId, redirectUri });
          code = await authorizeCode(par, account);
          response = await exchangeCode(par, code, { client_id: otherClientId });
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });

          par = await doPar({ clientId, redirectUri });
          code = await authorizeCode(par, account);
          response = await exchangeCode(par, code, { redirect_uri: "http://127.0.0.1/callback?case=wrong" });
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });

          par = await doPar({ clientId, redirectUri });
          code = await authorizeCode(par, account);
          const otherKeys = await generateEcKeys();
          response = await postToken(codeTokenForm(par, code), otherKeys.ecKeys, otherKeys.publicJwk);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rotates refresh tokens, keeps fixed session expiry, and enforces refresh jkt binding", async () => {
        const issued = await issueOauthToken("atproto repo:com.example.test");
        try {
          const otherKeys = await generateEcKeys();
          let response = await postToken(
            {
              grant_type: "refresh_token",
              client_id: issued.par.clientId,
              refresh_token: issued.token.refresh_token,
            },
            otherKeys.ecKeys,
            otherKeys.publicJwk,
          );
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });

          const sessionExp = Math.floor(Date.now() / 1000) + 120;
          await env.DIRECTORY.prepare(
            "UPDATE oauth_sessions SET exp = ? WHERE refresh_token_hash = ?",
          ).bind(sessionExp, await sha256Base64url(issued.token.refresh_token)).run();
          const before = Math.floor(Date.now() / 1000);
          const refreshed = await expectTokenSuccess(await refreshToken(issued.par, issued.token.refresh_token));
          const after = Math.floor(Date.now() / 1000);
          expect(refreshed.expires_in).toBeLessThanOrEqual(sessionExp - before);
          expect(refreshed.expires_in).toBeGreaterThanOrEqual(sessionExp - after);

          response = await refreshToken(issued.par, issued.token.refresh_token);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });

          const refreshedAgain = await expectTokenSuccess(await refreshToken(issued.par, refreshed.refresh_token));
          expect(refreshedAgain.refresh_token).not.toBe(refreshed.refresh_token);
        } finally {
          issued.fetchSpy.mockRestore();
        }
      });

      it("rejects resource access when the owning session is expired", async () => {
        const issued = await issueOauthToken("atproto repo:com.example.test");
        try {
          await env.DIRECTORY.prepare(
            "UPDATE oauth_sessions SET exp = 0 WHERE refresh_token_hash = ?",
          ).bind(await sha256Base64url(issued.token.refresh_token)).run();
          const tokenRow = await env.DIRECTORY.prepare(
            "SELECT exp FROM oauth_tokens WHERE access_token_hash = ?",
          ).bind(await sha256Base64url(issued.token.access_token)).first<{ exp: number }>();
          expect(tokenRow!.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
          const response = await createRecordWithOauth(
            issued.par,
            issued.token,
            "com.example.test",
            uniqueId("expired-session"),
          );
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "InvalidToken" });
        } finally {
          issued.fetchSpy.mockRestore();
        }
      });

      it("revokes access tokens, refresh tokens, and ignores garbage", async () => {
        let issued = await issueOauthToken("atproto repo:com.example.test");
        try {
          const accessRevoke = await worker.fetch(
            new Request(REVOKE_URL, {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({ token: issued.token.access_token }),
            }),
          );
          expect(accessRevoke.status).toBe(200);
          let response = await createRecordWithOauth(
            issued.par,
            issued.token,
            "com.example.test",
            uniqueId("revoked-access"),
          );
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "InvalidToken" });
          response = await refreshToken(issued.par, issued.token.refresh_token);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_grant" });
        } finally {
          issued.fetchSpy.mockRestore();
        }

        issued = await issueOauthToken("atproto repo:com.example.test");
        try {
          const refreshRevoke = await worker.fetch(
            new Request(REVOKE_URL, {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({ token: issued.token.refresh_token }),
            }),
          );
          expect(refreshRevoke.status).toBe(200);
          const response = await createRecordWithOauth(
            issued.par,
            issued.token,
            "com.example.test",
            uniqueId("revoked-refresh"),
          );
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "InvalidToken" });
        } finally {
          issued.fetchSpy.mockRestore();
        }

        const garbage = await worker.fetch(
          new Request(REVOKE_URL, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ token: "garbage" }),
          }),
        );
        expect(garbage.status).toBe(200);
      });

      it("rejects forged resource proofs and replayed resource proof jtis", async () => {
        const issued = await issueOauthToken("atproto repo:com.example.test");
        try {
          const url = "http://localhost/xrpc/com.atproto.repo.createRecord";
          const dpop = await createOauthDpopJwt(
            issued.par.ecKeys,
            issued.par.publicJwk,
            "POST",
            url,
            issued.token.access_token,
          );
          const parts = dpop.split(".");
          parts[2] = `${parts[2][0] === "A" ? "B" : "A"}${parts[2].slice(1)}`;
          let response = await createRecordWithOauth(
            issued.par,
            issued.token,
            "com.example.test",
            uniqueId("forged"),
            parts.join("."),
          );
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "InvalidToken" });

          const replayDpop = await createOauthDpopJwt(
            issued.par.ecKeys,
            issued.par.publicJwk,
            "POST",
            url,
            issued.token.access_token,
          );
          response = await createRecordWithOauth(
            issued.par,
            issued.token,
            "com.example.test",
            uniqueId("replay-one"),
            replayDpop,
          );
          expect(response.status).toBe(200);
          response = await createRecordWithOauth(
            issued.par,
            issued.token,
            "com.example.test",
            uniqueId("replay-two"),
            replayDpop,
          );
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "InvalidToken" });
        } finally {
          issued.fetchSpy.mockRestore();
        }
      });

      it("enforces OAuth scopes for writes and blob uploads", async () => {
        let issued = await issueOauthToken("atproto repo:com.example.case");
        try {
          let response = await createRecordWithOauth(
            issued.par,
            issued.token,
            "com.example.Case",
            uniqueId("case-mismatch"),
          );
          expect(response.status).toBe(403);
          await expect(response.json()).resolves.toMatchObject({ error: "InsufficientScope" });
        } finally {
          issued.fetchSpy.mockRestore();
        }

        issued = await issueOauthToken("atproto repo:com.example.allowed");
        try {
          const url = "http://localhost/xrpc/com.atproto.repo.applyWrites";
          const response = await worker.fetch(
            new Request(url, {
              method: "POST",
              headers: {
                ...await oauthHeaders(issued.par, url, issued.token.access_token),
                "content-type": "application/json",
              },
              body: JSON.stringify({
                repo: issued.token.sub,
                writes: [
                  {
                    $type: "com.atproto.repo.applyWrites#create",
                    collection: "com.example.allowed",
                    rkey: "allowed-create",
                    record: { text: "allowed", createdAt: new Date().toISOString() },
                  },
                  {
                    $type: "com.atproto.repo.applyWrites#delete",
                    collection: "com.example.denied",
                    rkey: "denied-delete",
                  },
                ],
              }),
            }),
          );
          expect(response.status).toBe(403);
          await expect(response.json()).resolves.toMatchObject({ error: "InsufficientScope" });
          const get = await worker.fetch(
            `http://localhost/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(issued.token.sub)}&collection=com.example.allowed&rkey=allowed-create`,
          );
          expect(get.status).toBe(404);
        } finally {
          issued.fetchSpy.mockRestore();
        }

        issued = await issueOauthToken("atproto repo:com.example.test");
        try {
          const response = await uploadBlobWithOauth(
            issued.par,
            issued.token.access_token,
            new TextEncoder().encode("repo only blob"),
          );
          expect(response.status).toBe(403);
          await expect(response.json()).resolves.toMatchObject({ error: "InsufficientScope" });
        } finally {
          issued.fetchSpy.mockRestore();
        }

        issued = await issueOauthToken("atproto transition:generic");
        try {
          const response = await uploadBlobWithOauth(
            issued.par,
            issued.token.access_token,
            new TextEncoder().encode("transition blob"),
          );
          expect(response.status).toBe(200);
        } finally {
          issued.fetchSpy.mockRestore();
        }

        issued = await issueOauthToken("atproto");
        try {
          const response = await createRecordWithOauth(
            issued.par,
            issued.token,
            "com.example.test",
            uniqueId("atproto-only"),
          );
          expect(response.status).toBe(403);
          await expect(response.json()).resolves.toMatchObject({ error: "InsufficientScope" });
        } finally {
          issued.fetchSpy.mockRestore();
        }
      });

      it("mints service auth only for matching OAuth rpc scopes", async () => {
        const aud = "did:web:knot.rook.host";
        const lxm = "sh.tangled.repo.create";

        let issued = await issueOauthToken("atproto transition:generic");
        try {
          const response = await getServiceAuthWithOauth(issued.par, issued.token, aud, lxm);
          expect(response.status).toBe(403);
          await expect(response.json()).resolves.toMatchObject({ error: "InsufficientScope" });
        } finally {
          issued.fetchSpy.mockRestore();
        }

        issued = await issueOauthToken(`atproto rpc:${lxm}?aud=${aud}`);
        try {
          const exp = Math.floor(Date.now() / 1000) + 120;
          const response = await getServiceAuthWithOauth(issued.par, issued.token, aud, lxm, exp);
          expect(response.status).toBe(200);
          const body = await response.json() as { token: string };
          const jwt = parseJwt(body.token);

          expect(jwt.header).toMatchObject({
            typ: "JWT",
            alg: "ES256K",
            kid: "#atproto",
          });
          expect(jwt.payload).toMatchObject({
            iss: issued.token.sub,
            aud,
            lxm,
            exp,
          });
          expect(typeof jwt.payload.iat).toBe("number");
          expect(typeof jwt.payload.jti).toBe("string");
          expect(jwt.signature.length).toBeGreaterThan(0);
        } finally {
          issued.fetchSpy.mockRestore();
        }
      });

      it("rejects deactivated accounts for resource access and refresh", async () => {
        const issued = await issueOauthToken("atproto repo:com.example.test");
        try {
          await env.DIRECTORY.prepare(
            "UPDATE accounts SET active = 0 WHERE did = ?",
          ).bind(issued.token.sub).run();
          const response = await createRecordWithOauth(
            issued.par,
            issued.token,
            "com.example.test",
            uniqueId("deactivated-rs"),
          );
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "InvalidToken" });

          const refresh = await refreshToken(issued.par, issued.token.refresh_token);
          expect(refresh.status).toBe(400);
          await expect(refresh.json()).resolves.toMatchObject({ error: "invalid_grant" });
        } finally {
          issued.fetchSpy.mockRestore();
        }
      });
    });

    describe("PAR validation", () => {
      it("rejects unregistered redirect_uri", async () => {
        const clientId = `https://client.example/${uniqueId("bad-redirect")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const { formValues } = await buildParForm(clientId, {
            redirect_uri: "http://127.0.0.1/other",
          });
          const { response } = await postPar(formValues);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_request" });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects plain code challenge method", async () => {
        const clientId = `https://client.example/${uniqueId("plain")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const { formValues } = await buildParForm(clientId, {
            code_challenge_method: "plain",
          });
          const { response } = await postPar(formValues);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_request" });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects scope missing atproto", async () => {
        const clientId = `https://client.example/${uniqueId("scope-missing")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const { formValues } = await buildParForm(clientId, {
            scope: "transition:generic",
          });
          const { response } = await postPar(formValues);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_scope" });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects include scopes", async () => {
        const clientId = `https://client.example/${uniqueId("include")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const { formValues } = await buildParForm(clientId, {
            scope: "atproto include:app.bsky",
          });
          const { response } = await postPar(formValues);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_scope" });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects invalid repo NSIDs", async () => {
        const clientId = `https://client.example/${uniqueId("bad-nsid")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const { formValues } = await buildParForm(clientId, {
            scope: "atproto repo:not a nsid",
          });
          const { response } = await postPar(formValues);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_scope" });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("accepts valid repo NSID scopes", async () => {
        const clientId = `https://client.example/${uniqueId("good-nsid")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          await doPar({ clientId, formOverrides: { scope: "atproto repo:org.example.thing" } });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("accepts valid rpc and blob scopes", async () => {
        const clientId = `https://client.example/${uniqueId("good-rpc")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          await doPar({
            clientId,
            formOverrides: {
              scope: "atproto repo:sh.tangled.repo rpc:sh.tangled.repo.create?aud=* rpc:sh.tangled.repo.merge?aud=did:web:knot.rook.host blob:*/*",
            },
          });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("round-trips the rook CLI client metadata through PAR", async () => {
        const ROOK_CLIENT_ID = "https://rook.host/client-metadata.json";
        const ROOK_SCOPE =
          "atproto transition:generic repo:sh.tangled.repo repo:sh.tangled.repo.pull blob:*/* rpc:sh.tangled.repo.create?aud=did:web:knot.rook.host rpc:sh.tangled.git.receivePack?aud=did:web:knot.rook.host";
        const rookClientMetadata = {
          client_id: ROOK_CLIENT_ID,
          client_name: "rook cli",
          application_type: "native",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          redirect_uris: ["http://127.0.0.1/callback"],
          scope: ROOK_SCOPE,
          token_endpoint_auth_method: "none",
          dpop_bound_access_tokens: true,
          client_uri: "https://rook.host",
        };
        const fetchSpy = stubOauthFetch({
          [ROOK_CLIENT_ID]: rookClientMetadata,
        });
        try {
          const par = await doPar({
            clientId: ROOK_CLIENT_ID,
            redirectUri: "http://127.0.0.1:8976/callback",
            formOverrides: { scope: ROOK_SCOPE },
          });
          const stored = await getOAuthParRequest(env.DIRECTORY, par.requestUri);
          expect(stored?.scope).toBe(ROOK_SCOPE);
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects invalid rpc scopes", async () => {
        const clientId = `https://client.example/${uniqueId("bad-rpc")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const { formValues } = await buildParForm(clientId, {
            scope: "atproto rpc:sh.tangled.repo.create?aud=not-a-did",
          });
          const { response } = await postPar(formValues);
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_scope" });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("validates response_mode", async () => {
        const fragmentClient = `https://client.example/${uniqueId("fragment")}.json`;
        const queryClient = `https://client.example/${uniqueId("query")}.json`;
        const absentClient = `https://client.example/${uniqueId("absent")}.json`;
        const fetchSpy = stubOauthFetch({
          [fragmentClient]: parClientMetadata(fragmentClient),
          [queryClient]: parClientMetadata(queryClient),
          [absentClient]: parClientMetadata(absentClient),
        });
        try {
          const { formValues: fragmentForm } = await buildParForm(fragmentClient, { response_mode: "fragment" });
          const fragment = await postPar(fragmentForm);
          expect(fragment.response.status).toBe(400);
          await expect(fragment.response.json()).resolves.toMatchObject({ error: "invalid_request" });

          await doPar({ clientId: queryClient, formOverrides: { response_mode: "query" } });
          await doPar({ clientId: absentClient, formOverrides: { response_mode: undefined } });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("ignores display request parameter", async () => {
        const clientId = `https://client.example/${uniqueId("display")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          await doPar({ clientId, formOverrides: { display: "page" } });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("accepts loopback redirect URI port variance", async () => {
        const clientId = `https://client.example/${uniqueId("loopback")}.json`;
        const fetchSpy = stubOauthFetch({
          [clientId]: parClientMetadata(clientId, {
            redirect_uris: ["http://127.0.0.1/callback"],
          }),
        });
        try {
          await doPar({ clientId, redirectUri: "http://127.0.0.1:49152/callback" });
        } finally {
          fetchSpy.mockRestore();
        }
      });
    });

    describe("client authentication", () => {
      it("accepts a valid private_key_jwt client assertion", async () => {
        const clientId = `https://client.example/${uniqueId("private-key")}.json`;
        const { ecKeys, publicJwk } = await generateEcKeys();
        const fetchSpy = stubOauthFetch({
          [clientId]: parClientMetadata(clientId, {
            token_endpoint_auth_method: "private_key_jwt",
            token_endpoint_auth_signing_alg: "ES256",
            jwks: { keys: [{ ...publicJwk, kid: "client-key" }] },
          }),
        });
        try {
          const now = Math.floor(Date.now() / 1000);
          const assertion = await signEs256Jwt(
            { alg: "ES256", kid: "client-key" },
            {
              iss: clientId,
              sub: clientId,
              aud: SERVICE_ORIGIN,
              exp: now + 300,
              iat: now,
              jti: crypto.randomUUID(),
            },
            ecKeys.privateKey,
          );
          await doPar({
            clientId,
            formOverrides: {
              client_assertion_type: CLIENT_ASSERTION_TYPE,
              client_assertion: assertion,
            },
          });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects a private_key_jwt client assertion with bad audience", async () => {
        const clientId = `https://client.example/${uniqueId("bad-aud")}.json`;
        const { ecKeys, publicJwk } = await generateEcKeys();
        const fetchSpy = stubOauthFetch({
          [clientId]: parClientMetadata(clientId, {
            token_endpoint_auth_method: "private_key_jwt",
            token_endpoint_auth_signing_alg: "ES256",
            jwks: { keys: [{ ...publicJwk, kid: "client-key" }] },
          }),
        });
        try {
          const now = Math.floor(Date.now() / 1000);
          const assertion = await signEs256Jwt(
            { alg: "ES256", kid: "client-key" },
            {
              iss: clientId,
              sub: clientId,
              aud: "https://wrong.example",
              exp: now + 300,
              iat: now,
              jti: crypto.randomUUID(),
            },
            ecKeys.privateKey,
          );
          const { formValues } = await buildParForm(clientId, {
            client_assertion_type: CLIENT_ASSERTION_TYPE,
            client_assertion: assertion,
          });
          const { response } = await postPar(formValues);
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_client" });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects metadata client_id mismatch for none clients", async () => {
        const clientId = `https://client.example/${uniqueId("mismatch")}.json`;
        const fetchSpy = stubOauthFetch({
          [clientId]: parClientMetadata("https://other.example/client.json"),
        });
        try {
          const { formValues } = await buildParForm(clientId);
          const { response } = await postPar(formValues);
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_client" });
        } finally {
          fetchSpy.mockRestore();
        }
      });
    });

    it("treats any Authorization header as consent path", async () => {
      const clientId = `https://client.example/${uniqueId("predicate")}.json`;
      const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
      try {
        const par = await doPar({ clientId });
        const response = await worker.fetch(
          new Request(authorizeUrl(par), {
            headers: { authorization: "Bearer junk" },
            redirect: "manual",
          }),
        );
        expect(response.status).toBe(401);
        await expect(response.json()).resolves.toMatchObject({ error: "AuthRequired" });
      } finally {
        fetchSpy.mockRestore();
      }
    });

    describe("authorize rejections", () => {
      it("rejects unknown request_uri without redirect", async () => {
        const response = await worker.fetch(
          `${AUTHORIZE_URL}?request_uri=${encodeURIComponent("urn:missing")}&client_id=${encodeURIComponent("https://client.example/missing.json")}`,
        );
        expect(response.status).toBe(400);
        expect(response.headers.get("location")).toBeNull();
      });

      it("rejects expired request_uri without redirect", async () => {
        const clientId = `https://client.example/${uniqueId("expired")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const par = await doPar({ clientId });
          await env.DIRECTORY.prepare(
            "UPDATE oauth_par_requests SET exp = 0 WHERE request_uri = ?",
          ).bind(par.requestUri).run();
          const response = await worker.fetch(authorizeUrl(par));
          expect(response.status).toBe(400);
          expect(response.headers.get("location")).toBeNull();
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects client_id mismatch without redirect", async () => {
        const clientId = `https://client.example/${uniqueId("client-mismatch")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const par = await doPar({ clientId });
          const url = new URL(AUTHORIZE_URL);
          url.searchParams.set("request_uri", par.requestUri);
          url.searchParams.set("client_id", "https://other.example/client.json");
          const response = await worker.fetch(url.toString());
          expect(response.status).toBe(400);
          await expect(response.json()).resolves.toMatchObject({ error: "invalid_request" });
          expect(response.headers.get("location")).toBeNull();
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects stale ToS consent tokens", async () => {
        const account = await createConsentAccount("oauth-stale");
        const clientId = `https://client.example/${uniqueId("stale")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const par = await doPar({ clientId });
          const staleToken = await signJwt(
            { typ: "wm+jwt", alg: "RS256" },
            {
              tos_hash: await sha256Base64url("wrong tos text"),
              aud: SERVICE_ORIGIN,
              cnf: { jkt: account.thumbprint },
              iat: Math.floor(Date.now() / 1000),
            },
            account.authKeys.privateKey,
          );
          const response = await worker.fetch(
            new Request(authorizeUrl(par), {
              headers: await consentHeaders(account, AUTHORIZE_URL, staleToken),
              redirect: "manual",
            }),
          );
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "tos_changed" });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects valid-looking consent proof for a key with no account", async () => {
        const keys = await generateAuthKeys();
        const clientId = `https://client.example/${uniqueId("no-account")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const par = await doPar({ clientId });
          await new Promise((resolve) => setTimeout(resolve, 2));
          const accessToken = await buildAccessToken(
            keys.authKeys,
            keys.thumbprint,
            await fetchTosText(),
            SERVICE_ORIGIN,
          );
          const response = await worker.fetch(
            new Request(authorizeUrl(par), {
              headers: {
                authorization: `DPoP ${accessToken}`,
                dpop: await createDpopJwt(keys.authKeys, keys.publicJwk, AUTHORIZE_URL, accessToken, "GET"),
              },
              redirect: "manual",
            }),
          );
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "AccountNotFound" });
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects deactivated accounts without minting a code", async () => {
        const account = await createConsentAccount("oauth-deactivated");
        await env.DIRECTORY.prepare(
          "UPDATE accounts SET active = 0 WHERE did = ?",
        ).bind(account.did).run();
        const clientId = `https://client.example/${uniqueId("deactivated")}.json`;
        const redirectUri = `http://127.0.0.1/callback?case=${uniqueId("deactivated")}`;
        const fetchSpy = stubOauthFetch({
          [clientId]: parClientMetadata(clientId, { redirect_uris: [redirectUri] }),
        });
        try {
          const par = await doPar({ clientId, redirectUri });
          const response = await worker.fetch(
            new Request(authorizeUrl(par), {
              headers: await consentHeaders(account),
              redirect: "manual",
            }),
          );
          expect(response.status).toBe(401);
          await expect(response.json()).resolves.toMatchObject({ error: "AccountNotFound" });
          await expect(codeRowForRedirect(redirectUri)).resolves.toBeNull();
        } finally {
          fetchSpy.mockRestore();
        }
      });
    });

    describe("consent proof binding", () => {
      it("rejects welcome-mat DPoP htu that includes the query", async () => {
        const account = await createConsentAccount("oauth-query-htu");
        const clientId = `https://client.example/${uniqueId("query-htu")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const par = await doPar({ clientId });
          const fullUrl = authorizeUrl(par);
          const response = await worker.fetch(
            new Request(fullUrl, {
              headers: await consentHeaders(account, fullUrl),
              redirect: "manual",
            }),
          );
          expect(response.status).toBe(401);
        } finally {
          fetchSpy.mockRestore();
        }
      });

      it("rejects welcome-mat DPoP with wrong ath", async () => {
        const account = await createConsentAccount("oauth-wrong-ath");
        const clientId = `https://client.example/${uniqueId("wrong-ath")}.json`;
        const fetchSpy = stubOauthFetch({ [clientId]: parClientMetadata(clientId) });
        try {
          const par = await doPar({ clientId });
          const accessToken = await buildAccessToken(
            account.authKeys,
            account.thumbprint,
            await fetchTosText(),
            SERVICE_ORIGIN,
          );
          await new Promise((resolve) => setTimeout(resolve, 2));
          const response = await worker.fetch(
            new Request(authorizeUrl(par), {
              headers: {
                authorization: `DPoP ${accessToken}`,
                dpop: await createDpopJwt(
                  account.authKeys,
                  account.publicJwk,
                  AUTHORIZE_URL,
                  `${accessToken}-tampered`,
                  "GET",
                ),
              },
              redirect: "manual",
            }),
          );
          expect(response.status).toBe(401);
        } finally {
          fetchSpy.mockRestore();
        }
      });
    });
  });
});
