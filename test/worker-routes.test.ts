// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { describe, it, expect, beforeAll } from "vitest";
import {
  buildAccessToken,
  createDpopJwt,
  env,
  generateAuthKeys,
  runInDurableObject,
  worker,
} from "./helpers";
import { AccountDurableObject, type BlobRef } from "../src/account-do";
import { initDirectory, insertAccount } from "../src/directory";
import { Secp256k1Keypair } from "@atproto/crypto";
import { toString } from "uint8arrays/to-string";

async function setupRouteTestAccount() {
  const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();

  const signing = await Secp256k1Keypair.create({ exportable: true });
  const rotation = await Secp256k1Keypair.create({ exportable: true });

  const did = `did:plc:routes${Date.now().toString(36)}`;
  const handle = `routes-${Date.now().toString(36)}.rookery.test`;
  const doId = env.ACCOUNT.newUniqueId();
  const stub = env.ACCOUNT.get(doId);

  await runInDurableObject(stub, async (instance: AccountDurableObject) => {
    await instance.rpcInitAccount({
      did,
      handle,
      signingKeyHex: toString(await signing.export(), "hex"),
      signingKeyPub: signing.did().split(":").pop()!,
      rotationKeyHex: toString(await rotation.export(), "hex"),
      rotationKeyPub: rotation.did().split(":").pop()!,
      jwkThumbprint: thumbprint,
    });
  });

  await insertAccount(env.DIRECTORY, {
    did,
    handle,
    doId: doId.toString(),
    jwkThumbprint: thumbprint,
  });

  return { did, handle, stub, authKeys, publicJwk, thumbprint };
}

describe("Worker routes", () => {
  beforeAll(async () => {
    await initDirectory(env.DIRECTORY);
  });

  describe("CORS middleware", () => {
    it("includes CORS headers on GET responses", async () => {
      const response = await worker.fetch("http://localhost/");
      expect(response.status).toBe(200);
      expect(response.headers.get("access-control-allow-origin")).toBe("*");
    });

    it("handles OPTIONS preflight before route middleware", async () => {
      const response = await worker.fetch(
        new Request("http://localhost/xrpc/com.atproto.repo.getRecord", {
          method: "OPTIONS",
          headers: {
            origin: "https://example.com",
            "access-control-request-method": "GET",
            "access-control-request-headers": "Authorization, DPoP",
          },
        }),
      );

      expect(response.status).toBe(204);
      expect(response.headers.get("access-control-allow-origin")).toBe("*");
      expect(response.headers.get("access-control-allow-methods")).toContain("GET");
      expect(response.headers.get("access-control-allow-methods")).toContain("POST");
      expect(response.headers.get("access-control-allow-headers")).toContain("Authorization");
      expect(response.headers.get("access-control-allow-headers")).toContain("DPoP");
      expect(response.headers.get("access-control-max-age")).toBe("86400");
    });

    it("includes CORS headers on POST error responses", async () => {
      const response = await worker.fetch(
        new Request("http://localhost/xrpc/com.atproto.repo.createRecord", {
          method: "POST",
          headers: {
            "content-type": "application/json",
          },
          body: JSON.stringify({}),
        }),
      );

      expect(response.status).toBe(401);
      expect(response.headers.get("access-control-allow-origin")).toBe("*");
    });
  });

  it("serves welcome and terms documents", async () => {
    const welcome = await worker.fetch("http://localhost/.well-known/welcome.md");
    expect(welcome.status).toBe(200);
    expect(await welcome.text()).toContain("WelcomeMat");

    const tos = await worker.fetch("http://localhost/tos");
    expect(tos.status).toBe(200);
    expect(await tos.text()).toContain("Terms of Service");
  });

  it("keeps commons-only invite routes hidden on the reference variant", async () => {
    expect((await worker.fetch("http://localhost/roost")).status).toBe(404);
    expect((await worker.fetch("http://localhost/client-metadata.json")).status).toBe(404);

    const apiInvite = await worker.fetch(new Request("http://localhost/api/invites", {
      method: "POST",
    }));
    expect(apiInvite.status).toBe(404);

    const adminInvite = await worker.fetch(new Request("http://localhost/admin/invites", {
      method: "POST",
    }));
    expect(adminInvite.status).toBe(404);

    const adminList = await worker.fetch("http://localhost/admin/invites");
    expect(adminList.status).toBe(404);

    const quota = await worker.fetch(new Request("http://localhost/admin/quotas/did:plc:reference", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ quota: 1 }),
    }));
    expect(quota.status).toBe(404);

    const config = await worker.fetch(new Request("http://localhost/admin/config/invite_quota_default", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value: 1 }),
    }));
    expect(config.status).toBe(404);

    const takedown = await worker.fetch(new Request(
      "http://localhost/admin/accounts/did:plc:reference",
      {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ confirm: "reference.rookery.test" }),
      },
    ));
    expect(takedown.status).toBe(404);
  });

  it("serves repo read and sync routes", async () => {
    const { did, handle, stub } = await setupRouteTestAccount();

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await instance.rpcCreateRecord("app.bsky.feed.post", "route-rkey", {
        text: "route post",
        createdAt: new Date().toISOString(),
      });
    });

    const getRecord = await worker.fetch(
      `http://localhost/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(handle)}&collection=app.bsky.feed.post&rkey=route-rkey`,
    );
    expect(getRecord.status).toBe(200);
    expect(await getRecord.json()).toMatchObject({
      uri: `at://${did}/app.bsky.feed.post/route-rkey`,
      value: { text: "route post" },
    });

    const listRecords = await worker.fetch(
      `http://localhost/xrpc/com.atproto.repo.listRecords?repo=${encodeURIComponent(handle)}&collection=app.bsky.feed.post`,
    );
    expect(listRecords.status).toBe(200);
    const listBody = await listRecords.json() as {
      records: Array<{ uri: string }>;
    };
    expect(listBody.records.some((record) => record.uri.endsWith("/route-rkey"))).toBe(true);

    const describeRepo = await worker.fetch(
      `http://localhost/xrpc/com.atproto.repo.describeRepo?repo=${encodeURIComponent(handle)}`,
    );
    expect(describeRepo.status).toBe(200);
    expect(await describeRepo.json()).toMatchObject({
      did,
      collections: ["app.bsky.feed.post"],
      handle: expect.any(String),
      handleIsCorrect: true,
    });

    const latestCommit = await worker.fetch(
      `http://localhost/xrpc/com.atproto.sync.getLatestCommit?did=${encodeURIComponent(did)}`,
    );
    expect(latestCommit.status).toBe(200);
    expect(await latestCommit.json()).toMatchObject({
      cid: expect.any(String),
      rev: expect.any(String),
    });

    const repoStatus = await worker.fetch(
      `http://localhost/xrpc/com.atproto.sync.getRepoStatus?did=${encodeURIComponent(did)}`,
    );
    expect(repoStatus.status).toBe(200);
    expect(await repoStatus.json()).toMatchObject({
      did,
      active: true,
      status: "active",
    });

    const repoExport = await worker.fetch(
      `http://localhost/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(did)}`,
    );
    expect(repoExport.status).toBe(200);
    expect(repoExport.headers.get("content-type")).toBe("application/vnd.ipld.car");
    expect((await repoExport.arrayBuffer()).byteLength).toBeGreaterThan(0);
  });

  it("serves custom records with blob links through repo read routes", async () => {
    const { did, handle, stub } = await setupRouteTestAccount();
    let patchBlob!: BlobRef;

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      patchBlob = await instance.rpcUploadBlob(
        new TextEncoder().encode("diff --git a/file b/file\n"),
        "application/gzip",
      );
      await instance.rpcCreateRecord("sh.tangled.repo.pull", "pull-rkey", {
        $type: "sh.tangled.repo.pull",
        title: "Route pull",
        description: "Custom collection regression",
        source: {
          repo: `at://${did}/sh.tangled.repo/source`,
          branch: "feature",
        },
        target: {
          repo: `at://${did}/sh.tangled.repo/target`,
          branch: "main",
        },
        rounds: [
          {
            createdAt: new Date().toISOString(),
            patchBlob,
          },
        ],
        createdAt: new Date().toISOString(),
      });
    });

    const getParams = new URLSearchParams({
      repo: handle,
      collection: "sh.tangled.repo.pull",
      rkey: "pull-rkey",
    });
    const getRecord = await worker.fetch(
      `http://localhost/xrpc/com.atproto.repo.getRecord?${getParams}`,
    );
    expect(getRecord.status).toBe(200);
    const getBody = await getRecord.json() as {
      value: { rounds: Array<{ patchBlob: BlobRef }> };
    };
    expect(getBody.value.rounds[0]!.patchBlob.ref).toEqual({
      $link: patchBlob.ref.$link,
    });

    const listParams = new URLSearchParams({
      repo: handle,
      collection: "sh.tangled.repo.pull",
    });
    const listRecords = await worker.fetch(
      `http://localhost/xrpc/com.atproto.repo.listRecords?${listParams}`,
    );
    expect(listRecords.status).toBe(200);
    const listBody = await listRecords.json() as {
      records: Array<{
        uri: string;
        value: { rounds: Array<{ patchBlob: BlobRef }> };
      }>;
    };
    const listedPull = listBody.records.find((record) =>
      record.uri.endsWith("/pull-rkey"),
    );
    expect(listedPull).toBeDefined();
    expect(listedPull!.value.rounds[0]!.patchBlob.ref).toEqual({
      $link: patchBlob.ref.$link,
    });
  });

  it("handles authenticated repo write routes", async () => {
    const { did, stub, authKeys, publicJwk, thumbprint } = await setupRouteTestAccount();
    const tosText = await worker.fetch("http://localhost/tos").then((response) => response.text());
    const accessToken = await buildAccessToken(
      authKeys,
      thumbprint,
      tosText,
      `https://${env.ROOKERY_HOSTNAME}`,
    );

    const createUrl = "http://localhost/xrpc/com.atproto.repo.createRecord";
    const createDpop = await createDpopJwt(authKeys, publicJwk, createUrl, accessToken);
    const createResponse = await worker.fetch(
      new Request(createUrl, {
        method: "POST",
        headers: {
          authorization: `DPoP ${accessToken}`,
          dpop: createDpop,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          repo: did,
          collection: "app.bsky.feed.post",
          rkey: "write-rkey",
          record: { text: "created", createdAt: new Date().toISOString() },
        }),
      }),
    );
    expect(createResponse.status).toBe(200);

    const putUrl = "http://localhost/xrpc/com.atproto.repo.putRecord";
    const putDpop = await createDpopJwt(authKeys, publicJwk, putUrl, accessToken);
    const putResponse = await worker.fetch(
      new Request(putUrl, {
        method: "POST",
        headers: {
          authorization: `DPoP ${accessToken}`,
          dpop: putDpop,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          repo: did,
          collection: "app.bsky.feed.post",
          rkey: "write-rkey",
          record: { text: "updated", createdAt: new Date().toISOString() },
        }),
      }),
    );
    expect(putResponse.status).toBe(200);

    const applyWritesUrl = "http://localhost/xrpc/com.atproto.repo.applyWrites";
    const applyWritesDpop = await createDpopJwt(authKeys, publicJwk, applyWritesUrl, accessToken);
    const applyWritesResponse = await worker.fetch(
      new Request(applyWritesUrl, {
        method: "POST",
        headers: {
          authorization: `DPoP ${accessToken}`,
          dpop: applyWritesDpop,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          repo: did,
          writes: [
            {
              $type: "com.atproto.repo.applyWrites#update",
              collection: "app.bsky.feed.post",
              rkey: "write-rkey",
              record: { text: "batch-updated", createdAt: new Date().toISOString() },
            },
          ],
        }),
      }),
    );
    expect(applyWritesResponse.status).toBe(200);
    expect(await applyWritesResponse.json()).toMatchObject({
      results: [
        {
          $type: "com.atproto.repo.applyWrites#updateResult",
          uri: `at://${did}/app.bsky.feed.post/write-rkey`,
        },
      ],
    });

    const deleteUrl = "http://localhost/xrpc/com.atproto.repo.deleteRecord";
    const deleteDpop = await createDpopJwt(authKeys, publicJwk, deleteUrl, accessToken);
    const deleteResponse = await worker.fetch(
      new Request(deleteUrl, {
        method: "POST",
        headers: {
          authorization: `DPoP ${accessToken}`,
          dpop: deleteDpop,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          repo: did,
          collection: "app.bsky.feed.post",
          rkey: "write-rkey",
        }),
      }),
    );
    expect(deleteResponse.status).toBe(200);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      const record = await instance.rpcGetRecord("app.bsky.feed.post", "write-rkey");
      expect(record).toBeNull();
    });
  });
});
