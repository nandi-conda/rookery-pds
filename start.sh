#!/bin/bash
# Latha mantra: verbose and explicit. Every step logged. No silent failures.

set -e
set -x  # Print every command before executing

echo "=== Rookery PDS Startup ==="
echo "Date: $(date -u)"
echo "Host: $(hostname)"
echo "User: $(whoami)"
echo "Working dir: $(pwd)"
echo ""

# MinIO credentials (local only, not exposed externally)
export MINIO_ROOT_USER="celld"
export MINIO_ROOT_PASSWORD="celld-minio-secret-key-change-me"
export AWS_ACCESS_KEY_ID="celld"
export AWS_SECRET_ACCESS_KEY="celld-minio-secret-key-change-me"
export AWS_EC2_METADATA_DISABLED=true
export AWS_REGION="us-east-1"

echo "=== Step 1: Starting MinIO ==="
mkdir -p /data/minio
echo "MinIO data dir: /data/minio"
ls -la /data/ || echo "WARNING: /data not accessible"

# Start MinIO in background
minio server /data/minio --address 127.0.0.1:9000 --console-address 127.0.0.1:9001 &
MINIO_PID=$!
echo "MinIO PID: $MINIO_PID"

echo ""
echo "=== Step 2: Waiting for MinIO to be ready ==="
MINIO_READY=false
for i in $(seq 1 30); do
  echo "Attempt $i/30: checking MinIO health..."
  if curl -s --max-time 2 http://127.0.0.1:9000/minio/health/live > /dev/null 2>&1; then
    echo "MinIO is ready!"
    MINIO_READY=true
    break
  fi
  echo "MinIO not ready yet, waiting..."
  sleep 1
done

if [ "$MINIO_READY" = false ]; then
  echo "ERROR: MinIO failed to start after 30 seconds"
  echo "MinIO process status:"
  ps aux | grep minio || echo "MinIO process not found"
  exit 1
fi

echo ""
echo "=== Step 2b: Ensuring bucket rookery-celld exists ==="
# MinIO starts empty; celld needs the fleet bucket to exist. 200 = created, 409 = already there.
BUCKET_STATUS=$(curl -sS -o /tmp/bucket-create.out -w "%{http_code}" -X PUT \
  --aws-sigv4 "aws:amz:${AWS_REGION}:s3" \
  --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
  http://127.0.0.1:9000/rookery-celld)
echo "Bucket create HTTP status: $BUCKET_STATUS"
if [ "$BUCKET_STATUS" != "200" ] && [ "$BUCKET_STATUS" != "409" ]; then
  echo "ERROR: could not create bucket rookery-celld"
  cat /tmp/bucket-create.out
  exit 1
fi

echo ""
echo "=== Step 3: Verifying celld binary ==="
which celld || echo "ERROR: celld not in PATH"
which esbuild || echo "ERROR: esbuild not in PATH (celld deploy needs it)"
celld --version || echo "ERROR: celld --version failed"
ls -lh /usr/local/bin/celld || echo "ERROR: celld binary not found"

echo ""
echo "=== Step 4: Verifying project files ==="
echo "Current directory: $(pwd)"
ls -lh wrangler.jsonc || echo "ERROR: wrangler.jsonc missing"
ls -lh src/worker.ts || echo "ERROR: src/worker.ts missing"
ls -lh package.json || echo "ERROR: package.json missing"
echo "Node modules:"
ls -d node_modules 2>/dev/null && echo "node_modules exists" || echo "WARNING: node_modules missing"

echo ""
echo "=== Step 5: Deploying worker to celld ==="
echo "Bucket: s3://rookery-celld"
echo "Endpoint: http://127.0.0.1:9000"
echo "Running: celld deploy --bucket s3://rookery-celld --endpoint http://127.0.0.1:9000 --region us-east-1"

# Deploy is idempotent, so a failure here is real: stop instead of serving a stale or empty fleet.
celld deploy --bucket s3://rookery-celld \
  --endpoint http://127.0.0.1:9000 \
  --region us-east-1
echo "Deploy succeeded!"

echo ""
echo "=== Step 6: Starting celld node ==="
echo "Listen: 0.0.0.0:8787"
echo "Internal: 127.0.0.1:9002"
echo "Bucket: s3://rookery-celld"
echo ""
echo "Executing: celld --bucket s3://rookery-celld --endpoint http://127.0.0.1:9000 --region us-east-1 --listen 0.0.0.0:8787 --internal-listen 127.0.0.1:9002"
echo ""

exec celld --bucket s3://rookery-celld \
  --endpoint http://127.0.0.1:9000 \
  --region us-east-1 \
  --listen 0.0.0.0:8787 \
  --internal-listen 127.0.0.1:9002
