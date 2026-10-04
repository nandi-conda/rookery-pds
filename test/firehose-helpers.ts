// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { runInDurableObject } from "cloudflare:test";
import { SequencerDurableObject } from "../src/sequencer-do";
import { env } from "./helpers";

export function getSequencerStub() {
  const id = env.SEQUENCER.idFromName("sequencer");
  return env.SEQUENCER.get(id);
}

export async function getLatestSequencerCursor(): Promise<number> {
  const stub = getSequencerStub();
  return runInDurableObject(stub, async (instance: SequencerDurableObject) => {
    const ctx = (instance as unknown as { ctx: DurableObjectState }).ctx;
    const row = ctx.storage.sql
      .exec("SELECT COALESCE(MAX(seq), 0) AS seq FROM firehose_events")
      .one();
    return row.seq as number;
  });
}

export async function waitForMessages(
  ws: WebSocket,
  count: number,
): Promise<Array<string | ArrayBuffer>> {
  const messages: Array<string | ArrayBuffer> = [];
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for ${count} messages`));
    }, 3000);

    const onMessage = (event: MessageEvent<string | ArrayBuffer>) => {
      messages.push(event.data);
      if (messages.length >= count) {
        cleanup();
        resolve(messages);
      }
    };

    const cleanup = () => {
      clearTimeout(timeout);
      ws.removeEventListener("message", onMessage);
    };

    ws.addEventListener("message", onMessage);
  });
}

export async function backfillFirehose(
  cursor: number,
  count: number,
): Promise<Array<ArrayBuffer>> {
  const response = await getSequencerStub().fetch(
    new Request(`http://fake-host/xrpc/com.atproto.sync.subscribeRepos?cursor=${cursor}`, {
      headers: { Upgrade: "websocket" },
    }),
  );
  if (response.status !== 101 || !response.webSocket) {
    throw new Error(`Firehose upgrade failed with status ${response.status}`);
  }

  const ws = response.webSocket;
  ws.accept();
  try {
    const messages = await waitForMessages(ws, count);
    return messages.map((message) => {
      if (!(message instanceof ArrayBuffer)) {
        throw new Error("Expected binary firehose frame");
      }
      return message;
    });
  } finally {
    ws.close();
  }
}
