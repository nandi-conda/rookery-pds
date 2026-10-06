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

set -euo pipefail
set -x

: "${AWS_ACCESS_KEY_ID:?}" "${AWS_SECRET_ACCESS_KEY:?}" "${CELLD_ENDPOINT:?}"
: "${ROOKERY_HOSTNAME:?}" "${ROOKERY_HANDLE_DOMAIN:?}" "${ROOKERY_OPERATOR_TOKEN:?}"
export AWS_EC2_METADATA_DISABLED=true
export AWS_REGION=auto
BUCKET="${CELLD_BUCKET:-s3://rookery-celld}"

cd /app

# Host-specific vars come from the environment so the image stays host-agnostic.
node -e '
const fs = require("fs");
const cfg = JSON.parse(fs.readFileSync("wrangler.jsonc", "utf8"));
for (const k of ["ROOKERY_HOSTNAME", "ROOKERY_HANDLE_DOMAIN", "ROOKERY_OPERATOR_TOKEN"]) cfg.vars[k] = process.env[k];
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
