// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { beforeEach, describe, expect, it, vi } from "vitest";
import { BlockMap } from "@atproto/repo";
import { resolveRepo } from "../src/directory";
import { AccountDurableObject } from "../src/account-do";
import { SequencerDurableObject } from "../src/sequencer-do";
import {
  buildAccessToken,
  createDpopJwt,
  env,
  generateAuthKeys,
  runInDurableObject,
  signTos,
  worker,
} from "./helpers";
import { getSequencerStub, waitForMessages } from "./firehose-helpers";

async function createCid(data: unknown): Promise<string> {
  const blocks = new BlockMap();
  const cid = await blocks.add(data as Record<string, unknown>);
  return cid.toString();
}

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

async function createAccountViaSignup(handle: string): Promise<{ did: string }> {
  const originalFetch = globalThis.fetch.bind(globalThis);
  const fetchSpy = vi
    .spyOn(globalThis, "fetch")
    .mockImplementation(async (input, init) => {
      const url =
        typeof input === "string" ? input : input instanceof Request ? input.url : input.url;
      if (url.startsWith("https://plc.directory/")) {
        return new Response(null, { status: 200 });
      }
      return originalFetch(input as RequestInfo | URL, init);
    });

  try {
    const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
    const tosText = await worker.fetch("http://localhost/tos").then((response) => response.text());
    const accessToken = await buildAccessToken(
      authKeys,
      thumbprint,
      tosText,
      `https://${env.ROOKERY_HOSTNAME}`,
    );
    const response = await worker.fetch(
      new Request("http://localhost/api/signup", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          dpop: await createDpopJwt(authKeys, publicJwk, "http://localhost/api/signup", null),
        },
        body: JSON.stringify({
          handle,
          tos_signature: await signTos(authKeys.privateKey, tosText),
          access_token: accessToken,
        }),
      }),
    );
    expect(response.status).toBe(200);
    return response.json<{ did: string }>();
  } finally {
    fetchSpy.mockRestore();
  }
}

beforeEach(async () => {
  await resetSequencer();
});

describe("SequencerDurableObject", () => {
  it("initializes and assigns monotonic seq numbers", async () => {
    const stub = getSequencerStub();

    await runInDurableObject(stub, async (instance: SequencerDurableObject) => {
      const first = await instance.sequenceIdentity(
        "did:plc:test-seq-1",
        "first.rookery.test",
      );
      const second = await instance.sequenceIdentity(
        "did:plc:test-seq-2",
        "second.rookery.test",
      );

      expect(first.seq).toBe(1);
      expect(second.seq).toBe(2);
    });
  });

  it("sequenceCommit stores an event and increments seq", async () => {
    const stub = getSequencerStub();
    const commitCid = await createCid({ type: "commit" });
    const prevDataCid = await createCid({ data: "prev" });
    const recordCid = await createCid({ record: "create" });

    await runInDurableObject(stub, async (instance: SequencerDurableObject) => {
      const identity = await instance.sequenceIdentity(
        "did:plc:test-identity",
        "identity.rookery.test",
      );
      const commit = await instance.sequenceCommit({
        did: "did:plc:test-identity",
        commit: commitCid,
        rev: "rev-1",
        since: null,
        prevData: prevDataCid,
        blocks: new Uint8Array([]),
        ops: [
          {
            action: "create",
            path: "app.bsky.feed.post/test",
            cid: recordCid,
          },
        ],
      });

      expect(identity.seq).toBe(1);
      expect(commit.seq).toBe(2);
    });

    const rows = await getFirehoseRows();
    expect(rows.map((row) => row.event_type)).toEqual(["identity", "commit"]);
  });

  it("sequenceAccount stores an account event", async () => {
    const stub = getSequencerStub();

    await runInDurableObject(stub, async (instance: SequencerDurableObject) => {
      const result = await instance.sequenceAccount("did:plc:test", true, null);
      expect(result).toEqual({ seq: 1 });
    });

    const rows = await getFirehoseRows();
    expect(rows).toHaveLength(1);
    expect(rows[0].event_type).toBe("account");
  });

  it("emits identity and account events on signup", async () => {
    const handle = `signup-${Date.now().toString(36)}`;
    await createAccountViaSignup(handle);

    const rows = await getFirehoseRows();
    expect(rows).toHaveLength(2);
    expect(rows.map((row) => row.event_type)).toEqual(["identity", "account"]);
  });

  it("emits a commit event when creating a record", async () => {
    const handle = `record-${Date.now().toString(36)}`;
    await createAccountViaSignup(handle);

    const resolved = await resolveRepo(`${handle}.rookery.test`, env);
    const doId = env.ACCOUNT.idFromString(resolved.doId);
    const stub = env.ACCOUNT.get(doId);

    await runInDurableObject(stub, async (instance: AccountDurableObject) => {
      await instance.rpcCreateRecord("app.bsky.feed.post", "test-rkey", {
        text: "hello",
        createdAt: new Date().toISOString(),
      });
    });

    const rows = await getFirehoseRows();
    expect(rows.map((row) => row.event_type)).toEqual([
      "identity",
      "account",
      "commit",
    ]);
  });

  it("returns 101 for websocket upgrades", async () => {
    const stub = getSequencerStub();
    const response = await stub.fetch(
      new Request("http://fake-host/xrpc/com.atproto.sync.subscribeRepos", {
        headers: { Upgrade: "websocket" },
      }),
    );

    expect(response.status).toBe(101);
    expect(response.webSocket).toBeDefined();
    response.webSocket?.accept();
    response.webSocket?.close();
  });

  it("rejects invalid cursor values", async () => {
    const stub = getSequencerStub();
    const response = await stub.fetch(
      new Request(
        "http://fake-host/xrpc/com.atproto.sync.subscribeRepos?cursor=not-a-number",
        {
          headers: { Upgrade: "websocket" },
        },
      ),
    );

    expect(response.status).toBe(400);
    expect(await response.text()).toBe("Invalid cursor");
  });

  it("backfills only events after the requested cursor", async () => {
    const stub = getSequencerStub();

    await runInDurableObject(stub, async (instance: SequencerDurableObject) => {
      await instance.sequenceIdentity("did:plc:test-1", "one.rookery.test");
      await instance.sequenceIdentity("did:plc:test-2", "two.rookery.test");
      await instance.sequenceIdentity("did:plc:test-3", "three.rookery.test");
    });

    const response = await stub.fetch(
      new Request(
        "http://fake-host/xrpc/com.atproto.sync.subscribeRepos?cursor=2",
        {
          headers: { Upgrade: "websocket" },
        },
      ),
    );

    expect(response.status).toBe(101);
    const ws = response.webSocket;
    expect(ws).toBeDefined();

    ws!.accept();
    const messagesPromise = waitForMessages(ws!, 1);
    const messages = await messagesPromise;

    expect(messages).toHaveLength(1);
    expect(messages[0]).toBeInstanceOf(ArrayBuffer);
    ws!.close();
  });
});
