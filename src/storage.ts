import { CID } from "@atproto/lex-data";
import {
  BlockMap,
  ReadableBlockstore,
  cborToLex,
  type CommitData,
  type RepoStorage,
} from "@atproto/repo";

export interface AccountState {
  did: string;
  handle: string;
  signing_key_hex: string;
  signing_key_pub: string;
  rotation_key_hex: string;
  rotation_key_pub: string;
  jwk_thumbprint: string | null;
  root_cid: string | null;
  rev: string | null;
  prev_data_cid: string | null;
  active: number;
  created_at: string;
}

export class SqliteRepoStorage
  extends ReadableBlockstore
  implements RepoStorage
{
  lastCommit: CommitData | null = null;

  constructor(private sql: SqlStorage) {
    super();
  }

  /**
   * Initialize the database schema. Called once on DO startup.
   */
  initSchema(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS blocks (
        cid TEXT PRIMARY KEY,
        bytes BLOB NOT NULL,
        rev TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_blocks_rev ON blocks(rev);

      CREATE TABLE IF NOT EXISTS repo_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        did TEXT,
        handle TEXT,
        signing_key_hex TEXT,
        signing_key_pub TEXT,
        rotation_key_hex TEXT,
        rotation_key_pub TEXT,
        jwk_thumbprint TEXT,
        root_cid TEXT,
        rev TEXT,
        prev_data_cid TEXT,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      INSERT OR IGNORE INTO repo_state (id) VALUES (1);

      CREATE TABLE IF NOT EXISTS collections (
        collection TEXT PRIMARY KEY
      );

      CREATE TABLE IF NOT EXISTS blobs (
        cid TEXT PRIMARY KEY,
        mime_type TEXT NOT NULL,
        size INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
  }

  /**
   * Set account-specific state in repo_state. Called during account provisioning.
   */
  initAccountState(opts: {
    did: string;
    handle: string;
    signing_key_hex: string;
    signing_key_pub: string;
    rotation_key_hex: string;
    rotation_key_pub: string;
    jwk_thumbprint: string | null;
  }): void {
    this.sql.exec(
      `UPDATE repo_state SET
        did = ?, handle = ?,
        signing_key_hex = ?, signing_key_pub = ?,
        rotation_key_hex = ?, rotation_key_pub = ?,
        jwk_thumbprint = ?
      WHERE id = 1`,
      opts.did,
      opts.handle,
      opts.signing_key_hex,
      opts.signing_key_pub,
      opts.rotation_key_hex,
      opts.rotation_key_pub,
      opts.jwk_thumbprint,
    );
  }

  /**
   * Get the full account state from repo_state.
   */
  getState(): AccountState | null {
    const rows = this.sql.exec("SELECT * FROM repo_state WHERE id = 1").toArray();
    if (rows.length === 0) return null;
    return rows[0] as unknown as AccountState;
  }

  async getRoot(): Promise<CID | null> {
    const rows = this.sql
      .exec("SELECT root_cid FROM repo_state WHERE id = 1")
      .toArray();
    if (rows.length === 0 || !rows[0]?.root_cid) return null;
    return CID.parse(rows[0]!.root_cid as string);
  }

  async getRev(): Promise<string | null> {
    const rows = this.sql.exec("SELECT rev FROM repo_state WHERE id = 1").toArray();
    return rows.length > 0 ? ((rows[0]!.rev as string) ?? null) : null;
  }

  async getBytes(cid: CID): Promise<Uint8Array | null> {
    const rows = this.sql
      .exec("SELECT bytes FROM blocks WHERE cid = ?", cid.toString())
      .toArray();
    if (rows.length === 0 || !rows[0]?.bytes) return null;
    // DO SQLite returns ArrayBuffer for BLOB columns
    return new Uint8Array(rows[0]!.bytes as ArrayBuffer);
  }

  async has(cid: CID): Promise<boolean> {
    const rows = this.sql
      .exec("SELECT 1 FROM blocks WHERE cid = ? LIMIT 1", cid.toString())
      .toArray();
    return rows.length > 0;
  }

  async getBlocks(cids: CID[]): Promise<{ blocks: BlockMap; missing: CID[] }> {
    const blocks = new BlockMap();
    const missing: CID[] = [];
    for (const cid of cids) {
      const bytes = await this.getBytes(cid);
      if (bytes) {
        blocks.set(cid, bytes);
      } else {
        missing.push(cid);
      }
    }
    return { blocks, missing };
  }

  async putBlock(cid: CID, block: Uint8Array, rev: string): Promise<void> {
    this.sql.exec(
      "INSERT OR REPLACE INTO blocks (cid, bytes, rev) VALUES (?, ?, ?)",
      cid.toString(),
      block,
      rev,
    );
  }

  async putMany(blocks: BlockMap, rev: string): Promise<void> {
    // Access BlockMap's internal map to avoid iterator issues in Workers
    const internalMap = (blocks as unknown as { map: Map<string, Uint8Array> }).map;
    if (internalMap) {
      for (const [cidStr, bytes] of internalMap) {
        this.sql.exec(
          "INSERT OR REPLACE INTO blocks (cid, bytes, rev) VALUES (?, ?, ?)",
          cidStr,
          bytes,
          rev,
        );
      }
    }
  }

  async updateRoot(cid: CID, rev: string): Promise<void> {
    this.sql.exec(
      "UPDATE repo_state SET root_cid = ?, rev = ? WHERE id = 1",
      cid.toString(),
      rev,
    );
  }

  async applyCommit(commit: CommitData): Promise<void> {
    this.lastCommit = commit;

    // Insert new blocks - access BlockMap's internal map for Workers compat
    const internalMap = (
      commit.newBlocks as unknown as { map: Map<string, Uint8Array> }
    ).map;
    if (internalMap) {
      for (const [cidStr, bytes] of internalMap) {
        this.sql.exec(
          "INSERT OR REPLACE INTO blocks (cid, bytes, rev) VALUES (?, ?, ?)",
          cidStr,
          bytes,
          commit.rev,
        );
      }
    }

    // Remove old blocks - access CidSet's internal set for Workers compat
    const removedSet = (commit.removedCids as unknown as { set: Set<string> }).set;
    if (removedSet) {
      for (const cidStr of removedSet) {
        this.sql.exec("DELETE FROM blocks WHERE cid = ?", cidStr);
      }
    }

    // Update root
    // NOTE: no await between block inserts and root update - DO write coalescing
    this.sql.exec(
      "UPDATE repo_state SET root_cid = ?, rev = ? WHERE id = 1",
      commit.cid.toString(),
      commit.rev,
    );

    // Extract and store prev_data_cid from the commit block
    const commitBytes = internalMap?.get(commit.cid.toString());
    if (commitBytes) {
      const commitObj = cborToLex(commitBytes) as { data: CID };
      if (commitObj.data) {
        this.sql.exec(
          "UPDATE repo_state SET prev_data_cid = ? WHERE id = 1",
          commitObj.data.toString(),
        );
      }
    }
  }

  addCollection(collection: string): void {
    this.sql.exec(
      "INSERT OR IGNORE INTO collections (collection) VALUES (?)",
      collection,
    );
  }

  getCollections(): string[] {
    const rows = this.sql
      .exec("SELECT collection FROM collections ORDER BY collection")
      .toArray();
    return rows.map((row) => row.collection as string);
  }

  insertBlob(cid: string, mimeType: string, size: number): void {
    this.sql.exec(
      "INSERT OR IGNORE INTO blobs (cid, mime_type, size) VALUES (?, ?, ?)",
      cid,
      mimeType,
      size,
    );
  }

  listBlobs(opts?: { limit?: number; cursor?: string }): { cids: string[]; cursor?: string } {
    const limit = opts?.limit ?? 500;
    let rows: Array<{ cid: string }>;
    if (opts?.cursor) {
      rows = this.sql
        .exec("SELECT cid FROM blobs WHERE cid > ? ORDER BY cid ASC LIMIT ?", opts.cursor, limit + 1)
        .toArray() as Array<{ cid: string }>;
    } else {
      rows = this.sql
        .exec("SELECT cid FROM blobs ORDER BY cid ASC LIMIT ?", limit + 1)
        .toArray() as Array<{ cid: string }>;
    }
    const hasMore = rows.length > limit;
    const results = hasMore ? rows.slice(0, limit) : rows;
    return {
      cids: results.map((r) => r.cid),
      cursor: hasMore ? results[results.length - 1].cid : undefined,
    };
  }

  /**
   * Get all blocks (used for CAR export).
   */
  getAllBlocks(): Array<{ cid: string; bytes: ArrayBuffer }> {
    return this.sql
      .exec("SELECT cid, bytes FROM blocks")
      .toArray() as Array<{ cid: string; bytes: ArrayBuffer }>;
  }

  /**
   * Count blocks (for testing).
   */
  async countBlocks(): Promise<number> {
    const rows = this.sql.exec("SELECT COUNT(*) as count FROM blocks").toArray();
    return rows.length > 0 ? ((rows[0]!.count as number) ?? 0) : 0;
  }

  /**
   * Clear all data (for testing).
   */
  async destroy(): Promise<void> {
    this.sql.exec("DELETE FROM blocks");
    this.sql.exec(
      "UPDATE repo_state SET root_cid = NULL, rev = NULL WHERE id = 1",
    );
  }
}
