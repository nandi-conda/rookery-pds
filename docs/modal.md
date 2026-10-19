# Running on Modal

The PDS runs as one celld node in a Modal web function. All durable state
(deployments, Durable Object SQLite, D1, blobs) lives in the Cloudflare R2
bucket `rookery-celld`, so the container is disposable.

- Image: `debian:bookworm-slim` + Node 22, celld v0.6.1, esbuild 0.27.4, this repo at a pinned commit, `npm ci --omit=dev`.
- Command: `./start-modal.sh` on port 8787, `max_containers=1` so only one node owns the fleet. Deploy with `modal deploy deploy/modal_app.py`: the function must be `@modal.concurrent`, or the relay's long-lived subscribeRepos connection blocks every other request.
- Modal secret `rookery-pds`: R2 S3 credentials, `CELLD_ENDPOINT`, `ROOKERY_HOSTNAME`, `ROOKERY_HANDLE_DOMAIN`, `ROOKERY_OPERATOR_TOKEN`, and `CLOUDFLARE_DNS_TOKEN` + `CLOUDFLARE_ZONE_ID` so each handle gets an `_atproto` TXT record (handles then need no TLS cert of their own).
- Without R2: `./start-modal-minio.sh` instead, with secrets `minio-root` (`MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD`) and `rookery-pds` (`CELLD_ENDPOINT` = the Modal MinIO, e.g. `https://codegod100--minio-web.modal.run`, plus the `ROOKERY_*` vars). The bucket `rookery-celld` must already exist there.
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

## Idle bucket traffic

`start-modal.sh` stretches celld's idle timers (presence, lease, rebalance,
waker, deploy poll) and sets `CELLD_DURABILITY=bucket` so an idle node touches the bucket once every 30 seconds
instead of about once a second. 30s is celld's floor, so a bucket host with a
longer scale-down window (Modal's default is 60s) still only reaches zero when
rookery itself does. Override any of them through the environment.
