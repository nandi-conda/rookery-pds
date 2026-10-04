import { describe, it, expect } from "vitest";
import { env, runInDurableObject } from "./helpers";
import { BlockMap, CidSet } from "@atproto/repo";
import { CID, type LexValue } from "@atproto/lex-data";
import { AccountDurableObject } from "../src/account-do";

async function createCid(
  data: LexValue,
): Promise<{ cid: CID; bytes: Uint8Array }> {
  const blocks = new BlockMap();
  const cid = await blocks.add(data);
  const bytes = blocks.get(cid)!;
  return { cid, bytes };
}

describe("SqliteRepoStorage", () => {
  describe("basic operations", () => {
    it("stores and retrieves blocks", async () => {
      const id = env.ACCOUNT.newUniqueId();
      const stub = env.ACCOUNT.get(id);

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const storage = await instance.getStorage();
        const { cid, bytes } = await createCid({ hello: "world" });

        await storage.putBlock(cid, bytes, "rev1");
        const retrieved = await storage.getBytes(cid);

        expect(retrieved).not.toBeNull();
        expect(new Uint8Array(retrieved!)).toEqual(bytes);
      });
    });

    it("returns null for non-existent blocks", async () => {
      const id = env.ACCOUNT.newUniqueId();
      const stub = env.ACCOUNT.get(id);

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const storage = await instance.getStorage();
        const { cid } = await createCid({ nonexistent: true });
        expect(await storage.getBytes(cid)).toBeNull();
      });
    });

    it("checks block existence with has()", async () => {
      const id = env.ACCOUNT.newUniqueId();
      const stub = env.ACCOUNT.get(id);

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const storage = await instance.getStorage();
        const { cid, bytes } = await createCid({ test: "data" });

        expect(await storage.has(cid)).toBe(false);
        await storage.putBlock(cid, bytes, "rev1");
        expect(await storage.has(cid)).toBe(true);
      });
    });

    it("stores multiple blocks with putMany()", async () => {
      const id = env.ACCOUNT.newUniqueId();
      const stub = env.ACCOUNT.get(id);

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const storage = await instance.getStorage();
        const blocks = new BlockMap();
        const b1 = await createCid({ block: 1 });
        const b2 = await createCid({ block: 2 });
        const b3 = await createCid({ block: 3 });

        blocks.set(b1.cid, b1.bytes);
        blocks.set(b2.cid, b2.bytes);
        blocks.set(b3.cid, b3.bytes);

        await storage.putMany(blocks, "rev1");

        expect(await storage.has(b1.cid)).toBe(true);
        expect(await storage.has(b2.cid)).toBe(true);
        expect(await storage.has(b3.cid)).toBe(true);
        expect(await storage.countBlocks()).toBe(3);
      });
    });

    it("retrieves multiple blocks with getBlocks()", async () => {
      const id = env.ACCOUNT.newUniqueId();
      const stub = env.ACCOUNT.get(id);

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const storage = await instance.getStorage();
        const b1 = await createCid({ block: 1 });
        const b2 = await createCid({ block: 2 });
        const missing = await createCid({ nonexistent: true });

        await storage.putBlock(b1.cid, b1.bytes, "rev1");
        await storage.putBlock(b2.cid, b2.bytes, "rev1");

        const result = await storage.getBlocks([b1.cid, b2.cid, missing.cid]);

        expect(result.blocks.has(b1.cid)).toBe(true);
        expect(result.blocks.has(b2.cid)).toBe(true);
        expect(result.missing).toHaveLength(1);
      });
    });
  });

  describe("root and revision", () => {
    it("starts with null root", async () => {
      const id = env.ACCOUNT.newUniqueId();
      const stub = env.ACCOUNT.get(id);

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const storage = await instance.getStorage();
        expect(await storage.getRoot()).toBeNull();
        expect(await storage.getRev()).toBeNull();
      });
    });

    it("updates root and revision", async () => {
      const id = env.ACCOUNT.newUniqueId();
      const stub = env.ACCOUNT.get(id);

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const storage = await instance.getStorage();
        const { cid, bytes } = await createCid({ root: "commit1" });

        await storage.putBlock(cid, bytes, "rev1");
        await storage.updateRoot(cid, "rev1");

        const root = await storage.getRoot();
        expect(root).not.toBeNull();
        expect(root!.toString()).toBe(cid.toString());
        expect(await storage.getRev()).toBe("rev1");
      });
    });
  });

  describe("applyCommit", () => {
    it("applies a commit with new blocks", async () => {
      const id = env.ACCOUNT.newUniqueId();
      const stub = env.ACCOUNT.get(id);

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const storage = await instance.getStorage();
        const commitBlock = await createCid({ type: "commit", data: "test" });
        const dataBlock = await createCid({ record: "data" });

        const newBlocks = new BlockMap();
        newBlocks.set(commitBlock.cid, commitBlock.bytes);
        newBlocks.set(dataBlock.cid, dataBlock.bytes);

        await storage.applyCommit({
          cid: commitBlock.cid,
          rev: "rev1",
          since: null,
          prev: null,
          newBlocks,
          relevantBlocks: new BlockMap(),
          removedCids: new CidSet(),
        });

        expect(await storage.has(commitBlock.cid)).toBe(true);
        expect(await storage.has(dataBlock.cid)).toBe(true);
        expect((await storage.getRoot())?.toString()).toBe(commitBlock.cid.toString());
        expect(await storage.getRev()).toBe("rev1");
      });
    });

    it("removes old blocks when applying commit", async () => {
      const id = env.ACCOUNT.newUniqueId();
      const stub = env.ACCOUNT.get(id);

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const storage = await instance.getStorage();

        const oldBlock = await createCid({ old: "data" });
        const initialCommit = await createCid({ type: "commit", rev: 1 });
        const initialBlocks = new BlockMap();
        initialBlocks.set(oldBlock.cid, oldBlock.bytes);
        initialBlocks.set(initialCommit.cid, initialCommit.bytes);

        await storage.applyCommit({
          cid: initialCommit.cid,
          rev: "rev1",
          since: null,
          prev: null,
          newBlocks: initialBlocks,
          relevantBlocks: new BlockMap(),
          removedCids: new CidSet(),
        });

        expect(await storage.has(oldBlock.cid)).toBe(true);

        const newBlock = await createCid({ new: "data" });
        const newCommit = await createCid({ type: "commit", rev: 2 });
        const newBlocks = new BlockMap();
        newBlocks.set(newBlock.cid, newBlock.bytes);
        newBlocks.set(newCommit.cid, newCommit.bytes);

        const removedCids = new CidSet();
        removedCids.add(oldBlock.cid);

        await storage.applyCommit({
          cid: newCommit.cid,
          rev: "rev2",
          since: "rev1",
          prev: initialCommit.cid,
          newBlocks,
          relevantBlocks: new BlockMap(),
          removedCids,
        });

        expect(await storage.has(oldBlock.cid)).toBe(false);
        expect(await storage.has(newBlock.cid)).toBe(true);
        expect((await storage.getRoot())?.toString()).toBe(newCommit.cid.toString());
        expect(await storage.getRev()).toBe("rev2");
      });
    });
  });

  describe("collections", () => {
    it("manages collections", async () => {
      const id = env.ACCOUNT.newUniqueId();
      const stub = env.ACCOUNT.get(id);

      await runInDurableObject(stub, async (instance: AccountDurableObject) => {
        const storage = await instance.getStorage();

        expect(storage.getCollections()).toEqual([]);

        storage.addCollection("app.bsky.feed.post");
        storage.addCollection("app.bsky.feed.like");
        storage.addCollection("app.bsky.feed.post");

        const collections = storage.getCollections();
        expect(collections).toHaveLength(2);
        expect(collections).toContain("app.bsky.feed.post");
        expect(collections).toContain("app.bsky.feed.like");
      });
    });
  });
});
