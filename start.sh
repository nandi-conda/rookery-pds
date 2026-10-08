#!/bin/bash
# Latha mantra: verbose and explicit. Every step logged. No silent failures.
#
# celld replicates cell state to an external S3-compatible bucket (the Modal-hosted
# MinIO). Nothing is stored in-container, so this node is replaceable. All bucket
# settings come from Fly secrets; we refuse to start if any are missing.

set -euo pipefail

echo "=== Rookery PDS Startup ==="
echo "Date: $(date -u)"
echo "Host: $(hostname)"
echo "User: $(whoami)"
echo "Working dir: $(pwd)"
echo ""

echo "=== Step 1: Checking bucket configuration ==="
MISSING=0
for VAR in CELLD_BUCKET CELLD_ENDPOINT CELLD_REGION AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY; do
  if [ -z "${!VAR:-}" ]; then
    echo "ERROR: $VAR is not set (set it with: fly secrets set $VAR=... --app rookery-pds)"
    MISSING=1
  else
    echo "$VAR is set"
  fi
done
if [ "$MISSING" = 1 ]; then
  echo "ERROR: refusing to start without a bucket. celld would otherwise come up empty."
  exit 1
fi
export AWS_EC2_METADATA_DISABLED=true
export AWS_REGION="$CELLD_REGION"
echo "Bucket:   $CELLD_BUCKET"
echo "Endpoint: $CELLD_ENDPOINT"
echo "Region:   $CELLD_REGION"

echo ""
echo "=== Step 2: Checking the bucket is reachable ==="
# HEAD the bucket with SigV4. 200 = exists and creds work. Anything else is fatal:
# we never create the bucket here, because an empty bucket would orphan existing accounts.
BUCKET_NAME="${CELLD_BUCKET#s3://}"
BUCKET_NAME="${BUCKET_NAME%%/*}"
BUCKET_STATUS=$(curl -sS -o /tmp/bucket-head.out -w "%{http_code}" --max-time 60 -I \
  --aws-sigv4 "aws:amz:${CELLD_REGION}:s3" \
  --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
  "${CELLD_ENDPOINT%/}/${BUCKET_NAME}") || BUCKET_STATUS="curl-failed"
echo "Bucket HEAD status: $BUCKET_STATUS"
if [ "$BUCKET_STATUS" != "200" ]; then
  echo "ERROR: bucket $BUCKET_NAME at $CELLD_ENDPOINT is not usable (status $BUCKET_STATUS)"
  cat /tmp/bucket-head.out || true
  exit 1
fi

echo ""
echo "=== Step 3: Verifying celld binary ==="
which celld
which esbuild
celld --version

echo ""
echo "=== Step 4: Verifying project files ==="
ls -lh wrangler.jsonc src/worker.ts package.json
ls -d node_modules

echo ""
echo "=== Step 5: Deploying worker to celld ==="
echo "Running: celld deploy --bucket $CELLD_BUCKET --endpoint $CELLD_ENDPOINT --region $CELLD_REGION"
# Deploy is idempotent, so a failure here is real: stop instead of serving a stale or empty fleet.
celld deploy --bucket "$CELLD_BUCKET" \
  --endpoint "$CELLD_ENDPOINT" \
  --region "$CELLD_REGION"
echo "Deploy succeeded!"

echo ""
echo "=== Step 6: Starting celld node ==="
echo "Listen: 0.0.0.0:8787  Internal: 127.0.0.1:9002"
echo "Note: single node, so writes wait on the bucket round-trip. Expected."
set -x
exec celld --bucket "$CELLD_BUCKET" \
  --endpoint "$CELLD_ENDPOINT" \
  --region "$CELLD_REGION" \
  --listen 0.0.0.0:8787 \
  --internal-listen 127.0.0.1:9002
