// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import type { Env } from "./types";

/** Cloudflare refused a handle's TXT record; the message carries its status and error text. */
export class HandleDnsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HandleDnsError";
  }
}

type CloudflareResult = { success?: boolean; errors?: Array<{ code: number; message: string }>; result?: Array<{ id: string }> };

async function cloudflareCall(what: string, res: Response): Promise<CloudflareResult> {
  const body = await res.json<CloudflareResult>().catch(() => ({}) as CloudflareResult);
  if (!res.ok || body.success === false) {
    const detail = (body.errors ?? []).map((e) => `${e.code} ${e.message}`).join("; ");
    throw new HandleDnsError(`Cloudflare DNS ${what} failed (${res.status})${detail ? `: ${detail}` : ""}`);
  }
  return body;
}

/**
 * Publish `_atproto.<handle>` TXT = `did=<did>` in Cloudflare DNS, so the
 * handle resolves over DNS without the handle host needing its own TLS cert.
 * No-op when CLOUDFLARE_DNS_TOKEN is unset (handles then resolve over HTTPS
 * via /.well-known/atproto-did).
 */
export async function publishHandleDns(env: Env, handle: string, did: string): Promise<void> {
  if (!env.CLOUDFLARE_DNS_TOKEN) {
    return;
  }
  if (!env.CLOUDFLARE_ZONE_ID) {
    throw new HandleDnsError("CLOUDFLARE_ZONE_ID is required when CLOUDFLARE_DNS_TOKEN is set");
  }
  const base = `https://api.cloudflare.com/client/v4/zones/${env.CLOUDFLARE_ZONE_ID}/dns_records`;
  const headers = {
    Authorization: `Bearer ${env.CLOUDFLARE_DNS_TOKEN}`,
    "Content-Type": "application/json",
  };
  const name = `_atproto.${handle}`;
  const record = JSON.stringify({ type: "TXT", name, content: `"did=${did}"`, ttl: 300 });

  const list = await cloudflareCall(
    `lookup for ${name}`,
    await fetch(`${base}?type=TXT&name=${encodeURIComponent(name)}`, { headers }),
  );
  const existing = list.result?.[0];
  await cloudflareCall(
    `write for ${name}`,
    existing
      ? await fetch(`${base}/${existing.id}`, { method: "PUT", headers, body: record })
      : await fetch(base, { method: "POST", headers, body: record }),
  );
}
