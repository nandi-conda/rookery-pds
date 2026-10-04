import { describe, it, expect } from "vitest";
import { env, runInDurableObject, worker } from "./helpers";
import { Secp256k1Keypair } from "@atproto/crypto";
import { toString } from "uint8arrays/to-string";
import { AccountDurableObject } from "../src/account-do";
import { SqliteRepoStorage } from "../src/storage";

const TEST_DID = "did:plc:test123456789";
const TEST_HANDLE = "test.rookery.test";

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

async function provisionAccount(instance: AccountDurableObject) {
  const keys = await generateTestKeys();
  await instance.rpcInitAccount({
    did: TEST_DID,
    handle: TEST_HANDLE,
    ...keys,
  });
  return keys;
}

describe("AccountDurableObject", () => {
  it("initializes storage on first access", async () => {
    const id = env.ACCOUNT.newUniqueId();
    const stub = env.ACCOUNT.get(id);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      const storage = await instance.getStorage();
      expect(storage).toBeInstanceOf(SqliteRepoStorage);
    });
  });

  it("provisions an account and creates a repo", async () => {
    const id = env.ACCOUNT.newUniqueId();
    const stub = env.ACCOUNT.get(id);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await provisionAccount(instance);

      const repo = await instance.getRepo();
      expect(repo).toBeDefined();
      expect(repo.did).toBe(TEST_DID);
      expect(repo.cid).toBeDefined();
    });
  });

  it("rpcGetState returns account state after provisioning", async () => {
    const id = env.ACCOUNT.newUniqueId();
    const stub = env.ACCOUNT.get(id);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      const before = await instance.rpcGetState();
      expect(before?.did).toBeFalsy();

      await provisionAccount(instance);

      const state = await instance.rpcGetState();
      expect(state).not.toBeNull();
      expect(state!.did).toBe(TEST_DID);
      expect(state!.handle).toBe(TEST_HANDLE);
      expect(state!.active).toBe(true);
      expect(state!.root_cid).toBeTruthy();
    });
  });

  it("rpcGetLatestCommit returns commit after provisioning", async () => {
    const id = env.ACCOUNT.newUniqueId();
    const stub = env.ACCOUNT.get(id);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await provisionAccount(instance);

      const commit = await instance.rpcGetLatestCommit();
      expect(commit).not.toBeNull();
      expect(commit!.cid).toBeTruthy();
      expect(commit!.rev).toBeTruthy();
    });
  });

  it("rpcCreateRecord creates and retrieves a record", async () => {
    const id = env.ACCOUNT.newUniqueId();
    const stub = env.ACCOUNT.get(id);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await provisionAccount(instance);

      const result = await instance.rpcCreateRecord(
        "app.bsky.feed.post",
        undefined,
        { text: "Hello from rookery!", createdAt: new Date().toISOString() },
      );

      expect(result.uri).toContain(`at://${TEST_DID}/app.bsky.feed.post/`);
      expect(result.cid).toBeTruthy();
      expect(result.commit.cid).toBeTruthy();
      expect(result.commit.rev).toBeTruthy();

      const rkey = result.uri.split("/").pop()!;
      const record = await instance.rpcGetRecord("app.bsky.feed.post", rkey);
      expect(record).not.toBeNull();
      expect(record!.cid).toBe(result.cid);
    });
  });

  it("rpcDescribeRepo lists collections", async () => {
    const id = env.ACCOUNT.newUniqueId();
    const stub = env.ACCOUNT.get(id);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await provisionAccount(instance);

      await instance.rpcCreateRecord("app.bsky.feed.post", undefined, {
        text: "test",
        createdAt: new Date().toISOString(),
      });

      const desc = await instance.rpcDescribeRepo();
      expect(desc.did).toBe(TEST_DID);
      expect(desc.collections).toContain("app.bsky.feed.post");
      expect(desc.cid).toBeTruthy();
      expect(desc.handle).toBe(TEST_HANDLE);
      expect(desc.handleIsCorrect).toBe(true);
    });
  });

  it("rpcDeleteRecord removes a record", async () => {
    const id = env.ACCOUNT.newUniqueId();
    const stub = env.ACCOUNT.get(id);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await provisionAccount(instance);

      await instance.rpcCreateRecord("app.bsky.feed.post", "test-rkey", {
        text: "to delete",
        createdAt: new Date().toISOString(),
      });

      const deleteResult = await instance.rpcDeleteRecord(
        "app.bsky.feed.post",
        "test-rkey",
      );
      expect(deleteResult.commit.cid).toBeTruthy();

      const record = await instance.rpcGetRecord("app.bsky.feed.post", "test-rkey");
      expect(record).toBeNull();
    });
  });

  it("rpcPutRecord creates and updates a record", async () => {
    const id = env.ACCOUNT.newUniqueId();
    const stub = env.ACCOUNT.get(id);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await provisionAccount(instance);

      const created = await instance.rpcPutRecord("app.bsky.feed.post", "put-rkey", {
        text: "first",
        createdAt: new Date().toISOString(),
      });
      expect(created.uri).toBe(`at://${TEST_DID}/app.bsky.feed.post/put-rkey`);

      const updated = await instance.rpcPutRecord("app.bsky.feed.post", "put-rkey", {
        text: "second",
        createdAt: new Date().toISOString(),
      });

      expect(updated.uri).toBe(created.uri);
      expect(updated.cid).not.toBe(created.cid);

      const record = await instance.rpcGetRecord("app.bsky.feed.post", "put-rkey");
      expect(record).not.toBeNull();
      expect(record!.record).toMatchObject({ text: "second" });
    });
  });

  it("rpcApplyWrites applies multiple writes", async () => {
    const id = env.ACCOUNT.newUniqueId();
    const stub = env.ACCOUNT.get(id);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await provisionAccount(instance);

      const result = await instance.rpcApplyWrites([
        {
          $type: "com.atproto.repo.applyWrites#create",
          collection: "app.bsky.feed.post",
          record: { text: "post 1", createdAt: new Date().toISOString() },
        },
        {
          $type: "com.atproto.repo.applyWrites#create",
          collection: "app.bsky.feed.post",
          record: { text: "post 2", createdAt: new Date().toISOString() },
        },
      ]);

      expect(result.commit.cid).toBeTruthy();
      expect(result.results).toHaveLength(2);
    });
  });

  it("rpcApplyWrites supports update operations", async () => {
    const id = env.ACCOUNT.newUniqueId();
    const stub = env.ACCOUNT.get(id);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await provisionAccount(instance);

      await instance.rpcCreateRecord("app.bsky.feed.post", "update-rkey", {
        text: "before",
        createdAt: new Date().toISOString(),
      });

      const result = await instance.rpcApplyWrites([
        {
          $type: "com.atproto.repo.applyWrites#update",
          collection: "app.bsky.feed.post",
          rkey: "update-rkey",
          record: { text: "after", createdAt: new Date().toISOString() },
        },
      ]);

      expect(result.commit.cid).toBeTruthy();
      expect(result.results).toHaveLength(1);
      expect(result.results[0]).toMatchObject({
        $type: "com.atproto.repo.applyWrites#updateResult",
        uri: `at://${TEST_DID}/app.bsky.feed.post/update-rkey`,
      });

      const record = await instance.rpcGetRecord("app.bsky.feed.post", "update-rkey");
      expect(record).not.toBeNull();
      expect(record!.record).toMatchObject({ text: "after" });
    });
  });
});

describe("Worker health check", () => {
  it("GET / returns status ok", async () => {
    const response = await worker.fetch(
      new Request("http://rookery.test/"),
      env,
    );
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data).toEqual({ status: "ok" });
  });
});
