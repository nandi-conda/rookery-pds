#!/bin/bash
# Modal entrypoint: one celld node whose fleet bucket lives in Cloudflare R2.
# Unlike start.sh (Fly), there is no local MinIO: Modal containers are
# ephemeral, and celld keeps all durable state in the bucket.
#
# Required env (Modal secret rookery-pds):
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY  R2 S3 credentials
#   CELLD_ENDPOINT                            https://<account>.r2.cloudflarestorage.com
#   ROOKERY_HOSTNAME, ROOKERY_HANDLE_DOMAIN   public PDS host and handle suffix
#   ROOKERY_OPERATOR_TOKEN                    bearer token for /operator/* routes
#   CLOUDFLARE_DNS_TOKEN, CLOUDFLARE_ZONE_ID  optional: publish _atproto handle TXT records

set -euo pipefail

: "${AWS_ACCESS_KEY_ID:?}" "${AWS_SECRET_ACCESS_KEY:?}" "${CELLD_ENDPOINT:?}"
: "${ROOKERY_HOSTNAME:?}" "${ROOKERY_HANDLE_DOMAIN:?}" "${ROOKERY_OPERATOR_TOKEN:?}"
export AWS_EC2_METADATA_DISABLED=true
export AWS_REGION=auto
BUCKET="${CELLD_BUCKET:-s3://rookery-celld}"

# Idle-friendly celld timers for this single node (max_containers=1). Defaults
# hit the bucket about once a second (lease renewals, presence scans, capacity
# samples), which keeps a scale-to-zero bucket host such as the Modal MinIO
# awake forever. These stretch every idle loop to one burst per 30s, the floor
# celld allows (CELLD_PRESENCE_HEARTBEAT_MS max is 30000). The 90s lease still
# lets a replacement node take over a hard-killed one well inside celld's
# 240s recovery retry budget.
export CELLD_PRESENCE_HEARTBEAT_MS="${CELLD_PRESENCE_HEARTBEAT_MS:-30000}"
export CELLD_TTL_MS="${CELLD_TTL_MS:-90000}"
# One node: nothing to rebalance (0 still samples capacity every 5s).
export CELLD_REBALANCE_INTERVAL_MS="${CELLD_REBALANCE_INTERVAL_MS:-300000}"
# rookery sets no Durable Object alarms.
export CELLD_WAKER_TICK_MS="${CELLD_WAKER_TICK_MS:-300000}"
# Each start runs `celld deploy` below, so the pointer poll can be slow.
export CELLD_DEPLOY_POLL_S="${CELLD_DEPLOY_POLL_S:-300}"

cd /app

# Host-specific vars come from the environment so the image stays host-agnostic.
node -e '
const fs = require("fs");
const cfg = JSON.parse(fs.readFileSync("wrangler.jsonc", "utf8"));
for (const k of ["ROOKERY_HOSTNAME", "ROOKERY_HANDLE_DOMAIN", "ROOKERY_OPERATOR_TOKEN", "CLOUDFLARE_DNS_TOKEN", "CLOUDFLARE_ZONE_ID"]) {
  if (process.env[k]) cfg.vars[k] = process.env[k];
}
fs.writeFileSync("wrangler.jsonc", JSON.stringify(cfg));
'

celld --version

# Deploy is idempotent, so a failure here is real: stop instead of serving a stale fleet.
celld deploy --bucket "$BUCKET" --endpoint "$CELLD_ENDPOINT" --region auto

exec celld --bucket "$BUCKET" \
  --endpoint "$CELLD_ENDPOINT" \
  --region auto \
  --listen 0.0.0.0:8787 \
  --internal-listen 127.0.0.1:9002
