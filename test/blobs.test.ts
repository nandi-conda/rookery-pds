import { describe, it, expect, beforeAll } from "vitest";
import {
  buildAccessToken,
  env,
  generateAuthKeys,
  runInDurableObject,
  signJwt,
  worker,
} from "./helpers";
import { AccountDurableObject, type BlobRef } from "../src/account-do";
import { initDirectory, insertAccount } from "../src/directory";
import { Secp256k1Keypair } from "@atproto/crypto";
import { toString } from "uint8arrays/to-string";
import { sha256Base64url } from "../src/auth";

async function setupBlobTestAccount(
  testEnv: typeof env,
  opts?: { jwkThumbprint?: string },
) {
  const signing = await Secp256k1Keypair.create({ exportable: true });
  const rotation = await Secp256k1Keypair.create({ exportable: true });

  const did = `did:plc:blobtest${Date.now().toString(36)}`;
  const handle = `blobtest-${Date.now().toString(36)}.rookery.test`;

  const doId = testEnv.ACCOUNT.newUniqueId();
  const stub = testEnv.ACCOUNT.get(doId);

  await runInDurableObject(stub, async (instance: AccountDurableObject) => {
    await instance.rpcInitAccount({
      did,
      handle,
      signingKeyHex: toString(await signing.export(), "hex"),
      signingKeyPub: signing.did().split(":").pop()!,
      rotationKeyHex: toString(await rotation.export(), "hex"),
      rotationKeyPub: rotation.did().split(":").pop()!,
      jwkThumbprint: opts?.jwkThumbprint,
    });
  });

  await initDirectory(testEnv.DIRECTORY);
  await insertAccount(testEnv.DIRECTORY, {
    did,
    handle,
    doId: doId.toString(),
    jwkThumbprint: opts?.jwkThumbprint,
  });

  return { did, handle, doId, stub };
}

describe("Blob storage", () => {
  beforeAll(async () => {
    await initDirectory(env.DIRECTORY);
  });

  it("uploads and retrieves a blob via DO RPC", async () => {
    const { did, stub } = await setupBlobTestAccount(env);

    const content = new TextEncoder().encode("hello blob world");
    let blobRef!: BlobRef;

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      blobRef = await instance.rpcUploadBlob(content, "text/plain");
    });

    expect(blobRef.$type).toBe("blob");
    expect(blobRef.ref.$link).toBeTruthy();
    expect(blobRef.mimeType).toBe("text/plain");
    expect(blobRef.size).toBe(content.length);

    const key = `${did}/${blobRef.ref.$link}`;
    const object = await env.BLOBS.get(key);
    expect(object).not.toBeNull();
    expect(object!.httpMetadata?.contentType).toBe("text/plain");

    const retrieved = new Uint8Array(await object!.arrayBuffer());
    expect(retrieved).toEqual(content);
  });

  it("lists blobs for an account", async () => {
    const { stub } = await setupBlobTestAccount(env);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await instance.rpcUploadBlob(new TextEncoder().encode("blob1"), "text/plain");
      await instance.rpcUploadBlob(new TextEncoder().encode("blob2"), "image/png");

      const result = await instance.rpcListBlobs();
      expect(result.cids).toHaveLength(2);
      expect(result.cids.every((c: string) => typeof c === "string" && c.length > 0)).toBe(true);
    });
  });

  it("retrieves blob with correct content-type via getBlob route", async () => {
    const { did, stub } = await setupBlobTestAccount(env);

    let blobRef!: BlobRef;
    const content = new TextEncoder().encode("image data here");

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      blobRef = await instance.rpcUploadBlob(content, "image/jpeg");
    });

    const response = await worker.fetch(
      `http://localhost/xrpc/com.atproto.sync.getBlob?did=${encodeURIComponent(did)}&cid=${encodeURIComponent(blobRef.ref.$link)}`,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("image/jpeg");
    const retrieved = new Uint8Array(await response.arrayBuffer());
    expect(retrieved).toEqual(content);
  });

  it("returns content-addressed CIDs (same content = same CID)", async () => {
    const { stub } = await setupBlobTestAccount(env);

    const content = new TextEncoder().encode("duplicate content");

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      const ref1 = await instance.rpcUploadBlob(content, "text/plain");
      const ref2 = await instance.rpcUploadBlob(content, "text/plain");
      expect(ref1.ref.$link).toBe(ref2.ref.$link);
    });
  });

  it("uploads a blob via the DPoP-authenticated route", async () => {
    const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
    const { did } = await setupBlobTestAccount(env, { jwkThumbprint: thumbprint });
    const tosText = await worker.fetch("http://localhost/tos").then((response) => response.text());
    const accessToken = await buildAccessToken(
      authKeys,
      thumbprint,
      tosText,
      `https://${env.ROOKERY_HOSTNAME}`,
    );
    const body = new TextEncoder().encode("blob via route");
    const dpopJwt = await signJwt(
      {
        typ: "dpop+jwt",
        alg: "RS256",
        jwk: publicJwk,
      },
      {
        jti: `jti-${Date.now().toString(36)}`,
        htm: "POST",
        htu: "http://localhost/xrpc/com.atproto.repo.uploadBlob",
        iat: Math.floor(Date.now() / 1000),
        ath: await sha256Base64url(accessToken),
      },
      authKeys.privateKey,
    );

    const response = await worker.fetch(
      new Request("http://localhost/xrpc/com.atproto.repo.uploadBlob", {
        method: "POST",
        headers: {
          authorization: `DPoP ${accessToken}`,
          dpop: dpopJwt,
          "content-type": "text/plain",
          "content-length": String(body.byteLength),
        },
        body,
      }),
    );

    expect(response.status).toBe(200);
    const json = await response.json() as { blob: BlobRef };
    expect(json.blob.mimeType).toBe("text/plain");

    const stored = await env.BLOBS.get(`${did}/${json.blob.ref.$link}`);
    expect(stored).not.toBeNull();
    const storedBytes = new Uint8Array(await stored!.arrayBuffer());
    expect(storedBytes).toEqual(body);
  });
});
