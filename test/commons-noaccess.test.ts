// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { describe, expect, it } from "vitest";
import { worker } from "./helpers";

describe("commons admin Access fail-closed config", () => {
  it("404s admin routes when Access env bindings are unset", async () => {
    expect((await worker.fetch("https://rookery.test/admin/invites")).status).toBe(404);
    expect((await worker.fetch(new Request("https://rookery.test/admin/invites", {
      method: "POST",
    }))).status).toBe(404);
    expect((await worker.fetch(new Request("https://rookery.test/admin/quotas/did:plc:unset", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ quota: 1 }),
    }))).status).toBe(404);
    expect((await worker.fetch(new Request("https://rookery.test/admin/config/invite_quota_default", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value: 1 }),
    }))).status).toBe(404);
    expect((await worker.fetch(new Request("https://rookery.test/admin/invites/some-token", {
      method: "DELETE",
    }))).status).toBe(404);
    expect((await worker.fetch(new Request(
      "https://rookery.test/admin/accounts/did:plc:unset",
      {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ confirm: "unset.rookery.test" }),
      },
    ))).status).toBe(404);
  });
});
