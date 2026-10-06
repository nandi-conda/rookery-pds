// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { DurableObject } from "cloudflare:workers";
import { create as createCid, format as formatCid } from "@atcute/cid";
import {
  Repo,
  WriteOpAction,
  BlockMap,
  blocksToCarFile,
  type RecordCreateOp,
  type RecordDeleteOp,
  type RecordUpdateOp,
  type RecordWriteOp,
} from "@atproto/repo";
import { Secp256k1Keypair } from "@atproto/crypto";
import { CID } from "@atproto/lex-data";
import { jsonToLex, lexToJson } from "@atproto/lex-json";
import { base64urlEncode } from "./auth";
import { SqliteRepoStorage } from "./storage";
import type { Env } from "./types";

const CODEC_RAW = 0x55;
type RepoCollection = `${string}.${string}.${string}`;
type RepoJsonValue = Parameters<typeof jsonToLex>[0];
type RepoLexRecord = RecordCreateOp["record"];

let generatedRkeyCounter = 0;

function nextRkey(): string {
  return `${Date.now().toString(36)}${(generatedRkeyCounter++).toString(36)}`;
}

function asRepoCollection(collection: string): RepoCollection {
  return collection as RepoCollection;
}

function asRepoRecord(record: unknown): RepoLexRecord {
  return jsonToLex(record as RepoJsonValue) as RepoLexRecord;
}

function asRepoJson(record: unknown): unknown {
  return lexToJson(record as Parameters<typeof lexToJson>[0]);
}

export interface BlobRef {
  $type: "blob";
  ref: { $link: string };
  mimeType: string;
  size: number;
}

export interface TakedownResult {
  recordsDeleted: number;
  blobsDeleted: number;
  collections: string[];
}

export class AccountDurableObject extends DurableObject<Env> {
  private storage: SqliteRepoStorage | null = null;
  private repo: Repo | null = null;
  private keypair: Secp256k1Keypair | null = null;
  private storageInitialized = false;
  private repoInitialized = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  private async ensureStorageInitialized(): Promise<void> {
    if (!this.storageInitialized) {
      await this.ctx.blockConcurrencyWhile(async () => {
        if (this.storageInitialized) return;
        this.storage = new SqliteRepoStorage(this.ctx.storage.sql);
        this.storage.initSchema();
        this.storageInitialized = true;
      });
    }
  }

  private async ensureRepoInitialized(): Promise<void> {
    await this.ensureStorageInitialized();
    if (!this.repoInitialized) {
      await this.ctx.blockConcurrencyWhile(async () => {
        if (this.repoInitialized) return;

        const state = this.storage!.getState();
        if (!state || !state.signing_key_hex) {
          return;
        }

        this.keypair = await Secp256k1Keypair.import(state.signing_key_hex);

        const root = await this.storage!.getRoot();
        if (root) {
          this.repo = await Repo.load(this.storage!, root);
        } else {
          this.repo = await Repo.create(this.storage!, state.did, this.keypair);
        }

        this.repoInitialized = true;
      });
    }
  }

  /** Expose storage for tests */
  async getStorage(): Promise<SqliteRepoStorage> {
    await this.ensureStorageInitialized();
    return this.storage!;
  }

  /** Expose repo for tests */
  async getRepo(): Promise<Repo> {
    await this.ensureRepoInitialized();
    if (!this.repo) {
      throw new Error("Repo not initialized - account may not be provisioned");
    }
    return this.repo;
  }

  async rpcSignServiceAuth(opts: {
    aud: string;
    lxm: string;
    exp: number;
  }): Promise<{ token: string }> {
    await this.ensureRepoInitialized();
    if (!this.repo || !this.keypair) {
      throw new Error("Repo not initialized - account may not be provisioned");
    }

    const now = Math.floor(Date.now() / 1000);
    const header = { typ: "JWT", alg: "ES256K", kid: "#atproto" };
    const payload = {
      iss: this.repo.did,
      aud: opts.aud,
      exp: opts.exp,
      iat: now,
      jti: crypto.randomUUID(),
      lxm: opts.lxm,
    };
    const signingInput = [
      base64urlEncode(new TextEncoder().encode(JSON.stringify(header))),
      base64urlEncode(new TextEncoder().encode(JSON.stringify(payload))),
    ].join(".");
    const signature = await this.keypair.sign(new TextEncoder().encode(signingInput));
    return { token: `${signingInput}.${base64urlEncode(signature)}` };
  }

  private async emitCommitEvent(
    prevDataCid: string | null,
    ops: Array<{
      action: "create" | "update" | "delete";
      path: string;
      cid: string | null;
    }>,
  ): Promise<void> {
    const commit = this.storage!.lastCommit!;
    const carBytes = await blocksToCarFile(commit.cid, commit.newBlocks);
    const seqId = this.env.SEQUENCER.idFromName("sequencer");
    const seqStub = this.env.SEQUENCER.get(seqId);
    await seqStub.sequenceCommit({
      did: this.repo!.did,
      commit: commit.cid.toString(),
      rev: commit.rev,
      since: commit.since,
      prevData: prevDataCid,
      blocks: carBytes,
      ops,
    });
  }

  /**
   * RPC: Provision a new account in this DO.
   * Must be called before any repo operations.
   * Rookery is multi-tenant: keys live in DO SQL, not env.
   */
  async rpcInitAccount(opts: {
    did: string;
    handle: string;
    signingKeyHex: string;
    signingKeyPub: string;
    rotationKeyHex: string;
    rotationKeyPub: string;
    jwkThumbprint?: string;
  }): Promise<{ did: string; handle: string }> {
    await this.ensureStorageInitialized();

    this.storage!.initAccountState({
      did: opts.did,
      handle: opts.handle,
      signing_key_hex: opts.signingKeyHex,
      signing_key_pub: opts.signingKeyPub,
      rotation_key_hex: opts.rotationKeyHex,
      rotation_key_pub: opts.rotationKeyPub,
      jwk_thumbprint: opts.jwkThumbprint ?? null,
    });

    this.repoInitialized = false;
    this.repo = null;
    this.keypair = null;

    await this.ensureRepoInitialized();

    // Emit identity and account events for firehose
    const seqId = this.env.SEQUENCER.idFromName("sequencer");
    const seqStub = this.env.SEQUENCER.get(seqId);
    await seqStub.sequenceIdentity(opts.did, opts.handle);
    await seqStub.sequenceAccount(opts.did, true, null);

    return { did: opts.did, handle: opts.handle };
  }

  /** RPC: Rotation key DID and a signature over `bytes`, for PLC operations. */
  async rpcSignWithRotationKey(bytes: Uint8Array): Promise<{ keyDid: string; sig: Uint8Array }> {
    await this.ensureStorageInitialized();
    const state = this.storage!.getState();
    if (!state?.rotation_key_hex) {
      throw new Error("Account not provisioned");
    }
    const rotationKey = await Secp256k1Keypair.import(state.rotation_key_hex);
    return { keyDid: rotationKey.did(), sig: await rotationKey.sign(bytes) };
  }

  /** RPC: Record a handle change already published to PLC, and announce it on the firehose. */
  async rpcSetHandle(handle: string): Promise<void> {
    await this.ensureStorageInitialized();
    const state = this.storage!.getState();
    if (!state?.did) {
      throw new Error("Account not provisioned");
    }
    this.storage!.setHandle(handle);
    const seqStub = this.env.SEQUENCER.get(this.env.SEQUENCER.idFromName("sequencer"));
    await seqStub.sequenceIdentity(state.did, handle);
  }

  /** RPC: Get account state */
  async rpcGetState(): Promise<{
    did: string;
    handle: string;
    root_cid: string | null;
    rev: string | null;
    active: boolean;
  } | null> {
    await this.ensureStorageInitialized();
    const state = this.storage!.getState();
    if (!state || !state.did) return null;
    return {
      did: state.did,
      handle: state.handle,
      root_cid: state.root_cid,
      rev: state.rev,
      active: state.active === 1,
    };
  }

  /** RPC: Get latest commit info */
  async rpcGetLatestCommit(): Promise<{ cid: string; rev: string } | null> {
    await this.ensureRepoInitialized();
    if (!this.repo) return null;
    const root = await this.storage!.getRoot();
    const rev = await this.storage!.getRev();
    if (!root || !rev) return null;
    return { cid: root.toString(), rev };
  }

  /** RPC: Describe repo metadata */
  async rpcDescribeRepo(): Promise<{
    did: string;
    collections: string[];
    cid: string;
    handle: string;
    handleIsCorrect: boolean;
  }> {
    const repo = await this.getRepo();
    const storage = await this.getStorage();
    const state = this.storage!.getState();
    return {
      did: repo.did,
      collections: storage.getCollections(),
      cid: repo.cid.toString(),
      handle: state!.handle,
      handleIsCorrect: true,
    };
  }

  /** RPC: Has this account ever published a collection? */
  async rpcHasPublished(): Promise<boolean> {
    await this.ensureStorageInitialized();
    return this.storage!.getCollections().length > 0;
  }

  /** RPC: Get a single record */
  async rpcGetRecord(
    collection: string,
    rkey: string,
  ): Promise<{ cid: string; record: unknown } | null> {
    const repo = await this.getRepo();
    const dataKey = `${collection}/${rkey}`;
    const recordCid = await repo.data.get(dataKey);
    if (!recordCid) return null;

    const record = await repo.getRecord(collection, rkey);
    if (!record) return null;

    return {
      cid: recordCid.toString(),
      record: asRepoJson(record),
    };
  }

  /** RPC: List records in a collection */
  async rpcListRecords(
    collection: string,
    opts: { limit: number; cursor?: string; reverse?: boolean },
  ): Promise<{
    records: Array<{ uri: string; cid: string; value: unknown }>;
    cursor?: string;
  }> {
    const repo = await this.getRepo();
    const records: Array<{ uri: string; cid: string; value: unknown }> = [];
    const startFrom = opts.cursor || `${collection}/`;

    for await (const record of repo.walkRecords(startFrom)) {
      if (record.collection !== collection) {
        if (records.length > 0) break;
        continue;
      }

      records.push({
        uri: `at://${repo.did}/${record.collection}/${record.rkey}`,
        cid: record.cid.toString(),
        value: asRepoJson(record.record),
      });

      if (records.length >= opts.limit + 1) break;
    }

    if (opts.reverse) records.reverse();

    const hasMore = records.length > opts.limit;
    const results = hasMore ? records.slice(0, opts.limit) : records;
    const cursor = hasMore
      ? `${collection}/${results[results.length - 1]?.uri.split("/").pop() ?? ""}`
      : undefined;

    return { records: results, cursor };
  }

  /** RPC: Create a record */
  async rpcCreateRecord(
    collection: string,
    rkey: string | undefined,
    record: unknown,
  ): Promise<{
    uri: string;
    cid: string;
    commit: { cid: string; rev: string };
  }> {
    const repo = await this.getRepo();
    await this.ensureRepoInitialized();
    const keypair = this.keypair!;
    const prevDataCid = this.storage!.getState()?.prev_data_cid ?? null;

    const actualRkey = rkey || nextRkey();
    const createOp: RecordCreateOp = {
      action: WriteOpAction.Create,
      collection: asRepoCollection(collection),
      rkey: actualRkey,
      record: asRepoRecord(record),
    };

    const updatedRepo = await repo.applyWrites([createOp], keypair);
    this.repo = updatedRepo;

    const dataKey = `${collection}/${actualRkey}`;
    const recordCid = await this.repo.data.get(dataKey);
    if (!recordCid) {
      throw new Error(`Failed to create record: ${collection}/${actualRkey}`);
    }

    this.storage!.addCollection(collection);

    await this.emitCommitEvent(prevDataCid, [
      {
        action: "create",
        path: `${collection}/${actualRkey}`,
        cid: recordCid.toString(),
      },
    ]);

    return {
      uri: `at://${this.repo.did}/${collection}/${actualRkey}`,
      cid: recordCid.toString(),
      commit: {
        cid: this.repo.cid.toString(),
        rev: this.repo.commit.rev,
      },
    };
  }

  /** RPC: Create or update a record (putRecord semantics) */
  async rpcPutRecord(
    collection: string,
    rkey: string,
    record: unknown,
  ): Promise<{
    uri: string;
    cid: string;
    commit: { cid: string; rev: string };
  }> {
    const repo = await this.getRepo();
    await this.ensureRepoInitialized();
    const keypair = this.keypair!;
    const prevDataCid = this.storage!.getState()?.prev_data_cid ?? null;

    // Check if record already exists to decide create vs update
    const dataKey = `${collection}/${rkey}`;
    const existingCid = await repo.data.get(dataKey);

    const op: RecordWriteOp = existingCid
      ? {
          action: WriteOpAction.Update,
          collection: asRepoCollection(collection),
          rkey,
          record: asRepoRecord(record),
        }
      : {
          action: WriteOpAction.Create,
          collection: asRepoCollection(collection),
          rkey,
          record: asRepoRecord(record),
        };

    const updatedRepo = await repo.applyWrites([op], keypair);
    this.repo = updatedRepo;

    const recordCid = await this.repo.data.get(dataKey);
    if (!recordCid) {
      throw new Error(`Failed to put record: ${collection}/${rkey}`);
    }

    this.storage!.addCollection(collection);

    await this.emitCommitEvent(prevDataCid, [
      {
        action: existingCid ? "update" : "create",
        path: `${collection}/${rkey}`,
        cid: recordCid.toString(),
      },
    ]);

    return {
      uri: `at://${this.repo.did}/${collection}/${rkey}`,
      cid: recordCid.toString(),
      commit: {
        cid: this.repo.cid.toString(),
        rev: this.repo.commit.rev,
      },
    };
  }

  /** RPC: Delete a record */
  async rpcDeleteRecord(
    collection: string,
    rkey: string,
  ): Promise<{ commit: { cid: string; rev: string } }> {
    const repo = await this.getRepo();
    await this.ensureRepoInitialized();
    const keypair = this.keypair!;
    const prevDataCid = this.storage!.getState()?.prev_data_cid ?? null;

    const deleteOp: RecordDeleteOp = {
      action: WriteOpAction.Delete,
      collection: asRepoCollection(collection),
      rkey,
    };

    const updatedRepo = await repo.applyWrites([deleteOp], keypair);
    this.repo = updatedRepo;

    await this.emitCommitEvent(prevDataCid, [
      {
        action: "delete",
        path: `${collection}/${rkey}`,
        cid: null,
      },
    ]);

    return {
      commit: {
        cid: this.repo.cid.toString(),
        rev: this.repo.commit.rev,
      },
    };
  }

  /** RPC: Apply multiple writes atomically */
  async rpcApplyWrites(
    writes: Array<{
      $type: string;
      collection: string;
      rkey?: string;
      record?: unknown;
    }>,
  ): Promise<{
    commit: { cid: string; rev: string };
    results: unknown[];
  }> {
    const repo = await this.getRepo();
    await this.ensureRepoInitialized();
    const keypair = this.keypair!;
    const prevDataCid = this.storage!.getState()?.prev_data_cid ?? null;

    const ops: RecordWriteOp[] = [];
    const results: unknown[] = [];

    for (const write of writes) {
      if (write.$type === "com.atproto.repo.applyWrites#create") {
        const rkey = write.rkey || nextRkey();
        const createOp: RecordCreateOp = {
          action: WriteOpAction.Create,
          collection: asRepoCollection(write.collection),
          rkey,
          record: asRepoRecord(write.record),
        };
        ops.push(createOp);
        this.storage!.addCollection(write.collection);
        results.push({
          $type: "com.atproto.repo.applyWrites#createResult",
          uri: `at://${repo.did}/${write.collection}/${rkey}`,
          cid: "",
        });
      } else if (write.$type === "com.atproto.repo.applyWrites#delete") {
        if (!write.rkey) throw new Error("Delete requires rkey");
        const deleteOp: RecordDeleteOp = {
          action: WriteOpAction.Delete,
          collection: asRepoCollection(write.collection),
          rkey: write.rkey,
        };
        ops.push(deleteOp);
        results.push({
          $type: "com.atproto.repo.applyWrites#deleteResult",
        });
      } else if (write.$type === "com.atproto.repo.applyWrites#update") {
        if (!write.rkey) throw new Error("Update requires rkey");
        const updateOp: RecordUpdateOp = {
          action: WriteOpAction.Update,
          collection: asRepoCollection(write.collection),
          rkey: write.rkey,
          record: asRepoRecord(write.record),
        };
        ops.push(updateOp);
        this.storage!.addCollection(write.collection);
        results.push({
          $type: "com.atproto.repo.applyWrites#updateResult",
          uri: `at://${repo.did}/${write.collection}/${write.rkey}`,
          cid: "",
        });
      }
    }

    const updatedRepo = await repo.applyWrites(ops, keypair);
    this.repo = updatedRepo;

    // Build firehose ops from the already-constructed ops array
    const firehoseOps: Array<{
      action: "create" | "update" | "delete";
      path: string;
      cid: string | null;
    }> = [];
    for (const op of ops) {
      if (op.action === WriteOpAction.Create) {
        const createOp = op as RecordCreateOp;
        const recordCid = await this.repo.data.get(
          `${createOp.collection}/${createOp.rkey}`,
        );
        firehoseOps.push({
          action: "create",
          path: `${createOp.collection}/${createOp.rkey}`,
          cid: recordCid?.toString() ?? null,
        });
      } else if (op.action === WriteOpAction.Delete) {
        const deleteOp = op as RecordDeleteOp;
        firehoseOps.push({
          action: "delete",
          path: `${deleteOp.collection}/${deleteOp.rkey}`,
          cid: null,
        });
      } else if (op.action === WriteOpAction.Update) {
        const updateOp = op as RecordUpdateOp;
        const recordCid = await this.repo.data.get(
          `${updateOp.collection}/${updateOp.rkey}`,
        );
        firehoseOps.push({
          action: "update",
          path: `${updateOp.collection}/${updateOp.rkey}`,
          cid: recordCid?.toString() ?? null,
        });
      }
    }
    await this.emitCommitEvent(prevDataCid, firehoseOps);

    return {
      commit: {
        cid: this.repo.cid.toString(),
        rev: this.repo.commit.rev,
      },
      results,
    };
  }

  /** RPC: Permanently remove an account's repo, blobs, and DO storage. */
  async rpcTakedown(did: string): Promise<TakedownResult> {
    await this.ensureRepoInitialized();

    const records: Array<{ collection: string; rkey: string }> = [];
    const collectionSet = new Set<string>();
    if (this.repo) {
      for await (const record of this.repo.walkRecords()) {
        records.push({ collection: record.collection, rkey: record.rkey });
        collectionSet.add(record.collection);
      }
    }

    for (let offset = 0; offset < records.length; offset += 200) {
      const chunk = records.slice(offset, offset + 200);
      const prevDataCid = this.storage!.getState()?.prev_data_cid ?? null;
      const deleteOps: RecordDeleteOp[] = chunk.map((record) => ({
        action: WriteOpAction.Delete,
        collection: asRepoCollection(record.collection),
        rkey: record.rkey,
      }));

      this.repo = await this.repo!.applyWrites(deleteOps, this.keypair!);
      await this.emitCommitEvent(
        prevDataCid,
        chunk.map((record) => ({
          action: "delete" as const,
          path: `${record.collection}/${record.rkey}`,
          cid: null,
        })),
      );
    }

    const seqId = this.env.SEQUENCER.idFromName("sequencer");
    const seqStub = this.env.SEQUENCER.get(seqId);
    await seqStub.sequenceAccount(did, false, "deleted");

    const prefix = `${did}/`;
    let blobsDeleted = 0;
    let cursor: string | undefined;
    do {
      const listed = await this.env.BLOBS.list({ prefix, cursor });
      const keys = listed.objects.map((object) => object.key);
      if (keys.length > 0) {
        await this.env.BLOBS.delete(keys);
        blobsDeleted += keys.length;
      }
      if (listed.truncated && !listed.cursor) {
        throw new Error("R2 blob listing was truncated without a cursor");
      }
      cursor = listed.truncated ? listed.cursor : undefined;
    } while (cursor);

    await this.ctx.storage.deleteAll();
    this.storage = null;
    this.repo = null;
    this.keypair = null;
    this.storageInitialized = false;
    this.repoInitialized = false;

    return {
      recordsDeleted: records.length,
      blobsDeleted,
      collections: Array.from(collectionSet).sort(),
    };
  }

  /** RPC: Get repo status */
  async rpcGetRepoStatus(): Promise<{
    did: string;
    active: boolean;
    status: string;
    rev: string | null;
  } | null> {
    await this.ensureStorageInitialized();
    const state = this.storage!.getState();
    if (!state || !state.did) return null;
    return {
      did: state.did,
      active: state.active === 1,
      status: state.active === 1 ? "active" : "deactivated",
      rev: state.rev,
    };
  }

  /** RPC: Export repo as CAR bytes */
  async rpcExportRepo(): Promise<Uint8Array> {
    await this.ensureRepoInitialized();
    const root = await this.storage!.getRoot();
    if (!root) throw new Error("Repo has no root");

    const allBlocks = new BlockMap();
    const rows = this.storage!.getAllBlocks();
    for (const row of rows) {
      allBlocks.set(CID.parse(row.cid), new Uint8Array(row.bytes as ArrayBuffer));
    }

    return blocksToCarFile(root, allBlocks);
  }

  /** RPC: Upload a blob to R2 and track in metadata */
  async rpcUploadBlob(bytes: Uint8Array, mimeType: string): Promise<BlobRef> {
    await this.ensureStorageInitialized();
    const state = this.storage!.getState();
    if (!state?.did) throw new Error("Account not provisioned");

    const cidObj = await createCid(CODEC_RAW, bytes);
    const cidStr = formatCid(cidObj);

    const key = `${state.did}/${cidStr}`;
    await this.env.BLOBS.put(key, bytes, {
      httpMetadata: { contentType: mimeType },
    });

    this.storage!.insertBlob(cidStr, mimeType, bytes.length);

    return {
      $type: "blob",
      ref: { $link: cidStr },
      mimeType,
      size: bytes.length,
    };
  }

  /** RPC: List blob CIDs for this account */
  async rpcListBlobs(
    opts?: { limit?: number; cursor?: string },
  ): Promise<{ cids: string[]; cursor?: string }> {
    await this.ensureStorageInitialized();
    return this.storage!.listBlobs(opts);
  }
}
