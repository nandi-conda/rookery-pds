import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  buildAccessToken,
  createDpopJwt,
  env,
  generateAuthKeys,
  signTos,
  worker,
} from "./helpers";
import { initDirectory } from "../src/directory";
import { InvalidAgentRecordError, validateAgentRecord, validateProcRecord } from "../src/agentbus";

const SERVICE_ORIGIN = `https://${env.ROOKERY_HOSTNAME}`;

type Agent = {
  did: string;
  call: (method: string, body: unknown) => Promise<Response>;
};

let counter = 0;

async function enroll(prefix: string): Promise<Agent> {
  const { authKeys, publicJwk, thumbprint } = await generateAuthKeys();
  const originalFetch = globalThis.fetch.bind(globalThis);
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof Request ? input.url : input.href;
    if (url.startsWith("https://plc.directory/")) return new Response(null, { status: 200 });
    return originalFetch(input as RequestInfo | URL, init);
  });
  let did: string;
  let accessToken: string;
  try {
    const tosText = await (await worker.fetch(`${SERVICE_ORIGIN}/tos`)).text();
    accessToken = await buildAccessToken(authKeys, thumbprint, tosText, SERVICE_ORIGIN);
    const signupUrl = `${SERVICE_ORIGIN}/api/signup`;
    const res = await worker.fetch(new Request(signupUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        dpop: await createDpopJwt(authKeys, publicJwk, signupUrl, null),
      },
      body: JSON.stringify({
        handle: `${prefix}${Date.now().toString(36)}${counter++}`,
        tos_signature: await signTos(authKeys.privateKey, tosText),
        access_token: accessToken,
      }),
    }));
    expect(res.status).toBe(200);
    ({ did } = await res.json<{ did: string }>());
  } finally {
    spy.mockRestore();
  }

  return {
    did,
    call: async (method, body) => {
      const url = `${SERVICE_ORIGIN}/xrpc/com.atproto.repo.${method}`;
      return worker.fetch(new Request(url, {
        method: "POST",
        headers: {
          authorization: `DPoP ${accessToken}`,
          dpop: await createDpopJwt(authKeys, publicJwk, url, accessToken),
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      }));
    },
  };
}

function agentRecord(name: string, extra: Record<string, unknown> = {}) {
  return {
    $type: "dev.agentbus.agent",
    name,
    description: `${name} agent`,
    capabilities: ["plan"],
    taskClasses: ["dev.agentbus.task.plan"],
    interfaces: ["org.agentbus.Agent1"],
    freeq: { server: "irc.freeq.at", channel: "#agentbus-test" },
    createdAt: new Date().toISOString(),
    ...extra,
  };
}

async function listAgents(query: string) {
  const res = await worker.fetch(`${SERVICE_ORIGIN}/xrpc/dev.agentbus.listAgents?${query}`);
  return { status: res.status, body: await res.json<{ agents: Array<{ did: string; name: string; uri: string; handle: string; value: Record<string, unknown> }>; cursor?: string; error?: string }>() };
}

describe("validateAgentRecord", () => {
  it("accepts a well-formed record", () => {
    expect(validateAgentRecord("planner", agentRecord("planner")).name).toBe("planner");
  });

  it.each([
    ["rkey mismatch", "other", agentRecord("planner")],
    ["digit-leading name", "1planner", agentRecord("1planner")],
    ["hyphenated name", "my-agent", agentRecord("my-agent")],
    ["missing createdAt", "planner", { ...agentRecord("planner"), createdAt: undefined }],
    ["wrong $type", "planner", agentRecord("planner", { $type: "dev.agentbus.other" })],
    ["non-string capability", "planner", agentRecord("planner", { capabilities: [1] })],
    ["transportKey not did:key", "planner", agentRecord("planner", { transportKey: "abc" })],
    ["freeq without server", "planner", agentRecord("planner", { freeq: { channel: "#x" } })],
    ["array record", "planner", []],
  ])("rejects %s", (_label, rkey, record) => {
    expect(() => validateAgentRecord(rkey, record)).toThrow(InvalidAgentRecordError);
  });
});

describe("dev.agentbus.agent registry", () => {
  beforeAll(async () => {
    await initDirectory(env.DIRECTORY);
  });

  it("indexes, filters, updates and removes agent records", async () => {
    const host = await enroll("desk");

    expect((await host.call("putRecord", {
      repo: host.did, collection: "dev.agentbus.agent", rkey: "planner", record: agentRecord("planner"),
    })).status).toBe(200);
    expect((await host.call("createRecord", {
      repo: host.did, collection: "dev.agentbus.agent", rkey: "coder",
      record: agentRecord("coder", { capabilities: ["code.review"], taskClasses: ["dev.agentbus.task.code"] }),
    })).status).toBe(200);

    let listed = await listAgents(`did=${encodeURIComponent(host.did)}`);
    expect(listed.status).toBe(200);
    expect(listed.body.agents.map((a) => a.name)).toEqual(["coder", "planner"]);
    expect(listed.body.agents[1]).toMatchObject({
      uri: `at://${host.did}/dev.agentbus.agent/planner`,
      did: host.did,
      value: { name: "planner", freeq: { server: "irc.freeq.at" } },
    });
    expect(listed.body.agents[1]!.handle.endsWith(env.ROOKERY_HANDLE_DOMAIN)).toBe(true);

    listed = await listAgents(`did=${encodeURIComponent(host.did)}&capability=code.review`);
    expect(listed.body.agents.map((a) => a.name)).toEqual(["coder"]);
    listed = await listAgents(`did=${encodeURIComponent(host.did)}&taskClass=dev.agentbus.task.plan`);
    expect(listed.body.agents.map((a) => a.name)).toEqual(["planner"]);

    expect((await host.call("putRecord", {
      repo: host.did, collection: "dev.agentbus.agent", rkey: "planner",
      record: agentRecord("planner", { capabilities: ["plan", "code.review"] }),
    })).status).toBe(200);
    listed = await listAgents(`did=${encodeURIComponent(host.did)}&capability=code.review`);
    expect(listed.body.agents.map((a) => a.name)).toEqual(["coder", "planner"]);

    expect((await host.call("deleteRecord", {
      repo: host.did, collection: "dev.agentbus.agent", rkey: "coder",
    })).status).toBe(200);
    listed = await listAgents(`did=${encodeURIComponent(host.did)}`);
    expect(listed.body.agents.map((a) => a.name)).toEqual(["planner"]);
  });

  it("applies agent writes from applyWrites atomically with validation", async () => {
    const host = await enroll("batch");
    const bad = await host.call("applyWrites", {
      repo: host.did,
      writes: [
        { $type: "com.atproto.repo.applyWrites#create", collection: "dev.agentbus.agent", rkey: "a", record: agentRecord("a") },
        { $type: "com.atproto.repo.applyWrites#create", collection: "dev.agentbus.agent", rkey: "b", record: agentRecord("c") },
      ],
    });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: "InvalidRecord" });
    expect((await listAgents(`did=${encodeURIComponent(host.did)}`)).body.agents).toEqual([]);

    const good = await host.call("applyWrites", {
      repo: host.did,
      writes: [
        { $type: "com.atproto.repo.applyWrites#create", collection: "dev.agentbus.agent", rkey: "a", record: agentRecord("a") },
        { $type: "com.atproto.repo.applyWrites#create", collection: "dev.agentbus.agent", rkey: "b", record: agentRecord("b") },
        { $type: "com.atproto.repo.applyWrites#create", collection: "com.example.other", record: { text: "untouched" } },
      ],
    });
    expect(good.status).toBe(200);
    expect((await listAgents(`did=${encodeURIComponent(host.did)}`)).body.agents.map((a) => a.name)).toEqual(["a", "b"]);

    await host.call("applyWrites", {
      repo: host.did,
      writes: [{ $type: "com.atproto.repo.applyWrites#delete", collection: "dev.agentbus.agent", rkey: "a" }],
    });
    expect((await listAgents(`did=${encodeURIComponent(host.did)}`)).body.agents.map((a) => a.name)).toEqual(["b"]);
  });

  it("rejects invalid agent records without writing them", async () => {
    const host = await enroll("bad");
    const noRkey = await host.call("createRecord", {
      repo: host.did, collection: "dev.agentbus.agent", record: agentRecord("planner"),
    });
    expect(noRkey.status).toBe(400);
    expect(await noRkey.json()).toMatchObject({ error: "InvalidRecord" });

    const mismatch = await host.call("putRecord", {
      repo: host.did, collection: "dev.agentbus.agent", rkey: "planner", record: agentRecord("coder"),
    });
    expect(mismatch.status).toBe(400);

    const repoRead = await worker.fetch(
      `${SERVICE_ORIGIN}/xrpc/com.atproto.repo.listRecords?repo=${encodeURIComponent(host.did)}&collection=dev.agentbus.agent`,
    );
    expect((await repoRead.json<{ records: unknown[] }>()).records).toEqual([]);
  });

  it("paginates across accounts with a bounded limit", async () => {
    const one = await enroll("pagea");
    const two = await enroll("pageb");
    for (const host of [one, two]) {
      expect((await host.call("putRecord", {
        repo: host.did, collection: "dev.agentbus.agent", rkey: "pager", record: agentRecord("pager", { capabilities: ["pager.test"] }),
      })).status).toBe(200);
    }

    const first = await listAgents("capability=pager.test&limit=1");
    expect(first.body.agents).toHaveLength(1);
    expect(first.body.cursor).toBeDefined();
    const second = await listAgents(`capability=pager.test&limit=1&cursor=${encodeURIComponent(first.body.cursor!)}`);
    expect(second.body.agents).toHaveLength(1);
    expect(new Set([first.body.agents[0]!.did, second.body.agents[0]!.did])).toEqual(new Set([one.did, two.did]));

    expect((await listAgents("limit=0")).status).toBe(400);
    expect((await listAgents("cursor=nope")).status).toBe(400);
  });
});

function procRecord(name: string, extra: Record<string, unknown> = {}) {
  return {
    $type: "dev.agentbus.proc",
    name,
    description: `${name} proc`,
    provides: [{ function: "weather.current" }, { function: "weather.forecast", regions: ["EU"] }],
    publishes: [{ topic: "weather.current", subjects: "place" }, { topic: "weather.alert", subjects: "place" }],
    freeq: { server: "irc.freeq.at" },
    createdAt: new Date().toISOString(),
    ...extra,
  };
}

async function listProcs(query: string) {
  const res = await worker.fetch(`${SERVICE_ORIGIN}/xrpc/dev.agentbus.listProcs?${query}`);
  return { status: res.status, body: await res.json<{ procs: Array<{ did: string; name: string; uri: string; value: Record<string, unknown> }>; cursor?: string }>() };
}

describe("validateProcRecord", () => {
  it("accepts a well-formed record", () => {
    expect(validateProcRecord("weather", procRecord("weather")).name).toBe("weather");
  });

  it.each([
    ["rkey mismatch", "other", procRecord("weather")],
    ["missing createdAt", "weather", { ...procRecord("weather"), createdAt: undefined }],
    ["wrong $type", "weather", procRecord("weather", { $type: "dev.agentbus.agent" })],
    ["provides not array", "weather", procRecord("weather", { provides: "weather.current" })],
    ["function with spaces", "weather", procRecord("weather", { provides: [{ function: "weather current" }] })],
    ["topic pattern", "weather", procRecord("weather", { publishes: [{ topic: "weather.*" }] })],
    ["bad regions", "weather", procRecord("weather", { provides: [{ function: "weather.current", regions: [1] }] })],
    ["freeq without server", "weather", procRecord("weather", { freeq: {} })],
  ])("rejects %s", (_label, rkey, record) => {
    expect(() => validateProcRecord(rkey, record)).toThrow(InvalidAgentRecordError);
  });
});

describe("dev.agentbus.proc registry", () => {
  beforeAll(async () => {
    await initDirectory(env.DIRECTORY);
  });

  it("indexes, filters and removes proc records", async () => {
    const proc = await enroll("wx");
    expect((await proc.call("putRecord", {
      repo: proc.did, collection: "dev.agentbus.proc", rkey: "weather", record: procRecord("weather"),
    })).status).toBe(200);

    let listed = await listProcs(`did=${encodeURIComponent(proc.did)}`);
    expect(listed.status).toBe(200);
    expect(listed.body.procs).toHaveLength(1);
    expect(listed.body.procs[0]).toMatchObject({
      uri: `at://${proc.did}/dev.agentbus.proc/weather`,
      name: "weather",
      value: { publishes: [{ topic: "weather.current" }, { topic: "weather.alert" }] },
    });
    listed = await listProcs(`did=${encodeURIComponent(proc.did)}&topic=weather.alert`);
    expect(listed.body.procs.map((p) => p.name)).toEqual(["weather"]);
    listed = await listProcs(`did=${encodeURIComponent(proc.did)}&function=calendar.events`);
    expect(listed.body.procs).toEqual([]);

    const bad = await proc.call("putRecord", {
      repo: proc.did, collection: "dev.agentbus.proc", rkey: "weather",
      record: procRecord("weather", { publishes: [{ topic: "" }] }),
    });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: "InvalidRecord" });

    expect((await proc.call("deleteRecord", {
      repo: proc.did, collection: "dev.agentbus.proc", rkey: "weather",
    })).status).toBe(200);
    expect((await listProcs(`did=${encodeURIComponent(proc.did)}`)).body.procs).toEqual([]);
    expect((await listProcs("limit=0")).status).toBe(400);
  });
});

describe("#agentbus DID service", () => {
  it("adds the agentbus service to the genesis op only when configured", async () => {
    const { buildUnsignedGenesisOp } = await import("../src/identity");
    const key = { did: () => "did:key:zTest" } as Parameters<typeof buildUnsignedGenesisOp>[2];
    expect(buildUnsignedGenesisOp("a.rookery.test", "rookery.test", key, key).services.agentbus).toBeUndefined();
    expect(
      buildUnsignedGenesisOp("a.rookery.test", "rookery.test", key, key, "ircs://irc.freeq.at:6697").services,
    ).toEqual({
      atproto_pds: { type: "AtprotoPersonalDataServer", endpoint: "https://rookery.test" },
      agentbus: { type: "AgentBusEndpoint", endpoint: "ircs://irc.freeq.at:6697" },
    });
  });
});
