import { afterEach, describe, expect, it, vi } from "vitest";
import { HandleDnsError, publishHandleDns } from "../src/handle-dns";
import { env } from "./helpers";

const dnsEnv = { ...env, CLOUDFLARE_DNS_TOKEN: "token", CLOUDFLARE_ZONE_ID: "zone" };

describe("publishHandleDns", () => {
  afterEach(() => vi.restoreAllMocks());

  it("creates the _atproto TXT record when none exists", async () => {
    const calls: Array<[string, string]> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      calls.push([init?.method ?? "GET", String(input)]);
      return Response.json({ success: true, result: [] });
    });
    await publishHandleDns(dnsEnv, "weather.agent.latha.org", "did:plc:x");
    expect(calls.map(([m]) => m)).toEqual(["GET", "POST"]);
  });

  it("reports Cloudflare's status and error text", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }, { status: 403 }),
    );
    await expect(publishHandleDns(dnsEnv, "weather.agent.latha.org", "did:plc:x")).rejects.toThrow(
      new HandleDnsError("Cloudflare DNS lookup for _atproto.weather.agent.latha.org failed (403): 10000 Authentication error"),
    );
  });
});
