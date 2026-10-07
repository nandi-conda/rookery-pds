// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import type { Env } from "./types";

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
    throw new Error("CLOUDFLARE_ZONE_ID is required when CLOUDFLARE_DNS_TOKEN is set");
  }
  const base = `https://api.cloudflare.com/client/v4/zones/${env.CLOUDFLARE_ZONE_ID}/dns_records`;
  const headers = {
    Authorization: `Bearer ${env.CLOUDFLARE_DNS_TOKEN}`,
    "Content-Type": "application/json",
  };
  const name = `_atproto.${handle}`;
  const record = JSON.stringify({ type: "TXT", name, content: `"did=${did}"`, ttl: 300 });

  const listRes = await fetch(`${base}?type=TXT&name=${encodeURIComponent(name)}`, { headers });
  const list = await listRes.json<{ success: boolean; result: Array<{ id: string }> }>();
  if (!listRes.ok || !list.success) {
    throw new Error(`Cloudflare DNS lookup for ${name} failed (${listRes.status})`);
  }
  const existing = list.result[0];
  const res = existing
    ? await fetch(`${base}/${existing.id}`, { method: "PUT", headers, body: record })
    : await fetch(base, { method: "POST", headers, body: record });
  if (!res.ok) {
    throw new Error(`Cloudflare DNS write for ${name} failed (${res.status})`);
  }
}
