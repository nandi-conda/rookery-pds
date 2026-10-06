# Running on Modal

The PDS runs as one celld node in a Modal web function. All durable state
(deployments, Durable Object SQLite, D1, blobs) lives in the Cloudflare R2
bucket `rookery-celld`, so the container is disposable.

- Image: `debian:bookworm-slim` + Node 22, celld v0.6.1, esbuild 0.27.4, this repo at a pinned commit, `npm ci --omit=dev`.
- Command: `./start-modal.sh` on port 8787, `max_containers=1` so only one node owns the fleet.
- Modal secret `rookery-pds`: R2 S3 credentials, `CELLD_ENDPOINT`, `ROOKERY_HOSTNAME`, `ROOKERY_HANDLE_DOMAIN`, `ROOKERY_OPERATOR_TOKEN`.
- A Cloudflare Worker on the public hostnames forwards to the `*.modal.run` URL and passes the original host in `X-Forwarded-Host`.

## Moving hosts

After the hostname changes, re-point each account's DID document:

```sh
curl -X POST https://$ROOKERY_HOSTNAME/operator/identity/sync \
  -H "Authorization: Bearer $ROOKERY_OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"did":"did:plc:...","handle":"name.example.org"}'
```

This signs a PLC operation with the account's rotation key that sets the
handle and the `atproto_pds` endpoint to this host.
