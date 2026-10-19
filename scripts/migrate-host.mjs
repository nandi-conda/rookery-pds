// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

// Moves accounts from one rookery host to another with their DIDs unchanged:
// export each from FROM, import it into TO, then have TO re-point the DID's
// PLC document (PDS endpoint and handle) at itself and ask the relays to crawl it.
//
//   FROM=https://old.example TO=https://new.example ROOKERY_OPERATOR_TOKEN=... \
//     node scripts/migrate-host.mjs [did ...]
//
// With no DIDs it moves every repo FROM lists. Both hosts must accept the same
// operator token. Re-running is safe: an account TO already has is only re-synced.

const { FROM, TO, ROOKERY_OPERATOR_TOKEN: token } = process.env;
if (!FROM || !TO || !token) {
  console.error("FROM, TO and ROOKERY_OPERATOR_TOKEN are required");
  process.exit(2);
}
const from = FROM.replace(/\/$/, "");
const to = TO.replace(/\/$/, "");
const auth = { authorization: `Bearer ${token}` };

async function ok(res, what) {
  if (!res.ok) {
    throw new Error(`${what}: ${res.status} ${await res.text()}`);
  }
  return res;
}

async function listDids() {
  const dids = [];
  let cursor;
  do {
    const query = new URLSearchParams({ limit: "500", ...(cursor ? { cursor } : {}) });
    const page = await (await ok(await fetch(`${from}/xrpc/com.atproto.sync.listRepos?${query}`), "listRepos")).json();
    dids.push(...page.repos.map((r) => r.did));
    cursor = page.cursor;
  } while (cursor);
  return dids;
}

const dids = process.argv.length > 2 ? process.argv.slice(2) : await listDids();
console.log(`moving ${dids.length} account(s) from ${from} to ${to}`);

for (const did of dids) {
  const exported = await ok(
    await fetch(`${from}/operator/account/export?did=${encodeURIComponent(did)}`, { headers: auth }),
    `export ${did}`,
  );
  const imported = await fetch(`${to}/operator/account/import`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/cbor" },
    body: await exported.arrayBuffer(),
  });
  let handle;
  if (imported.status === 409) {
    handle = (await (await ok(
      await fetch(`${to}/xrpc/com.atproto.repo.describeRepo?repo=${encodeURIComponent(did)}`),
      `describeRepo ${did}`,
    )).json()).handle;
    console.log(`${did}: already on ${to}`);
  } else {
    const result = await (await ok(imported, `import ${did}`)).json();
    handle = result.handle;
    console.log(`${did}: imported ${handle} (rev ${result.rev}, ${result.blocks} blocks, ${result.blobs} blobs, ${result.agents} agents, ${result.procs} procs)`);
  }
  const synced = await (await ok(await fetch(`${to}/operator/identity/sync`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ did, handle }),
  }), `identity sync ${did}`)).json();
  console.log(`${did}: PLC now names ${synced.pds} as the PDS of ${synced.handle}`);
}

const hostname = new URL(to).hostname;
for (const relay of ["https://bsky.network"]) {
  await ok(await fetch(`${relay}/xrpc/com.atproto.sync.requestCrawl`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ hostname }),
  }), `requestCrawl ${relay}`);
  console.log(`asked ${relay} to crawl ${hostname}`);
}
