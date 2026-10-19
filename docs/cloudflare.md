# Running on Cloudflare Workers

`wrangler.cloudflare.jsonc` deploys rookery as the Worker `rookery-pds` on the
custom domain `rookery.latha.org`, with handles under `.agent.latha.org`.
Durable Objects hold each account's repo, D1 (`rookery-directory`) the account
directory, R2 (`rookery-blobs`) blobs; wrangler creates the database and bucket
by name on the first deploy. The firehose Durable Object uses WebSocket
hibernation, so a relay holding `subscribeRepos` open costs nothing while idle.

Deploys are operator-only, from a local checkout:

```sh
pixi run cf-login      # once
pixi run cf-deploy
pixi run cf-secrets    # once: CLOUDFLARE_DNS_TOKEN, CLOUDFLARE_ZONE_ID, OAUTH_NONCE_SECRET
```

`CLOUDFLARE_DNS_TOKEN` is an API token with Zone · DNS · Edit on `latha.org`;
with it, each signup, handle change and identity sync writes the handle's
`_atproto` TXT record, so handles resolve over DNS and `*.agent.latha.org`
needs no TLS certificate (Universal SSL covers only one level of subdomain).

## Operator routes

`/operator/*` take `Authorization: Bearer <token>` and exist only when
`ROOKERY_OPERATOR_TOKEN_SHA256` (the token's hex SHA-256, a plain var) is set.

- `GET /operator/account/export?did=` returns an account as CBOR: repo blocks,
  signing and rotation keys, blobs.
- `POST /operator/account/import` recreates an export in a new Durable Object,
  with its directory row and agentbus index.
- `POST /operator/identity/sync {did, handle}` signs a PLC operation with the
  account's rotation key that points the DID at this host.

## Moving accounts between hosts

```sh
FROM=https://old.host TO=https://rookery.latha.org ROOKERY_OPERATOR_TOKEN=... pixi run migrate-host
```

exports every repo FROM lists, imports it into TO, syncs its PLC identity to TO
and asks bsky.network to crawl TO. DIDs, keys and handles stay the same, and
re-running skips accounts TO already has.
