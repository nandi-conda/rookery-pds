import { DurableObject } from "cloudflare:workers";
import { CID } from "@atproto/lex-data";
import { encode as cborEncode } from "./cbor-compat";
import type { Env } from "./types";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS firehose_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload BLOB NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

export class SequencerDurableObject extends DurableObject<Env> {
  private initialized = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.ctx.blockConcurrencyWhile(async () => {
        if (this.initialized) return;
        this.ctx.storage.sql.exec(SCHEMA);
        this.initialized = true;
      });
    }
  }

  async sequenceCommit(data: {
    did: string;
    commit: string;
    rev: string;
    since: string | null;
    prevData: string | null;
    blocks: Uint8Array;
    ops: Array<{
      action: "create" | "update" | "delete";
      path: string;
      cid: string | null;
    }>;
  }): Promise<{ seq: number }> {
    await this.ensureInitialized();

    const result = this.ctx.storage.sql
      .exec(
        "INSERT INTO firehose_events (did, event_type, payload) VALUES (?, 'commit', x'00') RETURNING seq",
        data.did,
      )
      .one();
    const seq = result.seq as number;

    const header = cborEncode({ op: 1, t: "#commit" });
    const body = cborEncode({
      seq,
      repo: data.did,
      commit: CID.parse(data.commit),
      rev: data.rev,
      since: data.since,
      blocks: data.blocks,
      ops: data.ops.map((op) => ({
        action: op.action,
        path: op.path,
        cid: op.cid ? CID.parse(op.cid) : null,
      })),
      prevData: data.prevData ? CID.parse(data.prevData) : null,
      rebase: false,
      tooBig: data.blocks.length > 1_000_000,
      blobs: [],
      time: new Date().toISOString(),
    });
    const frame = concatBytes(header, body);

    this.ctx.storage.sql.exec(
      "UPDATE firehose_events SET payload = ? WHERE seq = ?",
      frame,
      seq,
    );

    this.broadcast(frame, seq);
    return { seq };
  }

  async sequenceIdentity(
    did: string,
    handle: string,
  ): Promise<{ seq: number }> {
    await this.ensureInitialized();

    const result = this.ctx.storage.sql
      .exec(
        "INSERT INTO firehose_events (did, event_type, payload) VALUES (?, 'identity', x'00') RETURNING seq",
        did,
      )
      .one();
    const seq = result.seq as number;
    const time = new Date().toISOString();

    const header = cborEncode({ op: 1, t: "#identity" });
    const body = cborEncode({ seq, did, handle, time });
    const frame = concatBytes(header, body);

    this.ctx.storage.sql.exec(
      "UPDATE firehose_events SET payload = ? WHERE seq = ?",
      frame,
      seq,
    );

    this.broadcast(frame, seq);
    return { seq };
  }

  async sequenceAccount(
    did: string,
    active: boolean,
    status: string | null,
  ): Promise<{ seq: number }> {
    await this.ensureInitialized();

    const result = this.ctx.storage.sql
      .exec(
        "INSERT INTO firehose_events (did, event_type, payload) VALUES (?, 'account', x'00') RETURNING seq",
        did,
      )
      .one();
    const seq = result.seq as number;
    const time = new Date().toISOString();

    const header = cborEncode({ op: 1, t: "#account" });
    const body = cborEncode({ seq, did, active, status, time });
    const frame = concatBytes(header, body);

    this.ctx.storage.sql.exec(
      "UPDATE firehose_events SET payload = ? WHERE seq = ?",
      frame,
      seq,
    );

    this.broadcast(frame, seq);
    return { seq };
  }

  override async fetch(request: Request): Promise<Response> {
    await this.ensureInitialized();

    const upgradeHeader = request.headers.get("Upgrade");
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
      return new Response("Expected WebSocket upgrade", { status: 426 });
    }

    const url = new URL(request.url);
    const cursorParam = url.searchParams.get("cursor");
    const cursor = cursorParam !== null ? parseInt(cursorParam, 10) : null;
    if (cursorParam !== null && (cursor === null || Number.isNaN(cursor) || cursor < 0)) {
      return new Response("Invalid cursor", { status: 400 });
    }

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];

    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ cursor: cursor ?? 0 });

    if (cursor !== null) {
      await this.backfill(server, cursor);
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  override webSocketMessage(
    _ws: WebSocket,
    _message: string | ArrayBuffer,
  ): void {}

  override webSocketClose(
    _ws: WebSocket,
    _code: number,
    _reason: string,
    _wasClean: boolean,
  ): void {}

  private async backfill(ws: WebSocket, cursor: number): Promise<void> {
    const latestSeq = this.getLatestSeq();

    if (cursor > latestSeq && latestSeq > 0) {
      const frame = concatBytes(
        cborEncode({ op: -1 }),
        cborEncode({
          error: "FutureCursor",
          message: "Cursor is in the future",
        }),
      );
      ws.send(frame);
      ws.close(1008, "FutureCursor");
      return;
    }

    const rows = this.ctx.storage.sql
      .exec(
        "SELECT seq, payload FROM firehose_events WHERE seq > ? ORDER BY seq ASC LIMIT 1000",
        cursor,
      )
      .toArray();

    let lastSeq = cursor;
    for (const row of rows) {
      lastSeq = row.seq as number;
      ws.send(new Uint8Array(row.payload as ArrayBuffer));
    }

    if (lastSeq > cursor) {
      const attachment = (ws.deserializeAttachment() ?? {
        cursor,
      }) as { cursor: number };
      attachment.cursor = lastSeq;
      ws.serializeAttachment(attachment);
    }
  }

  private broadcast(frame: Uint8Array, seq: number): void {
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.send(frame);
        const attachment = (ws.deserializeAttachment() ?? {
          cursor: 0,
        }) as { cursor: number };
        attachment.cursor = seq;
        ws.serializeAttachment(attachment);
      } catch {}
    }
  }

  private getLatestSeq(): number {
    const result = this.ctx.storage.sql
      .exec("SELECT MAX(seq) as seq FROM firehose_events")
      .one();
    return (result?.seq as number) ?? 0;
  }
}
