#!/bin/bash
set -e

# MinIO credentials (local only, not exposed)
export MINIO_ROOT_USER="celld"
export MINIO_ROOT_PASSWORD="celld-minio-secret-key-change-me"

# Start MinIO in background (data on Fly volume)
mkdir -p /data/minio
minio server /data/minio --address 127.0.0.1:9000 --console-address 127.0.0.1:9001 &
MINIO_PID=$!

# Wait for MinIO to be ready
echo "Waiting for MinIO..."
for i in $(seq 1 30); do
  if curl -s http://127.0.0.1:9000/minio/health/live > /dev/null 2>&1; then
    echo "MinIO ready"
    break
  fi
  sleep 1
done

# Create the bucket if it doesn't exist
export AWS_ACCESS_KEY_ID="celld"
export AWS_SECRET_ACCESS_KEY="celld-minio-secret-key-change-me"
export AWS_EC2_METADATA_DISABLED=true

# Use minio client or curl to create bucket
# MinIO auto-creates buckets on first use via S3 API, so we can skip explicit creation

# Deploy the worker to the bucket (first time only, or on update)
# celld deploy uploads the worker bundle to the bucket
echo "Deploying worker to celld..."
celld deploy --bucket s3://rookery-celld \
  --endpoint http://127.0.0.1:9000 \
  --region us-east-1 || echo "Deploy may have failed, continuing..."

# Start celld node
echo "Starting celld..."
exec celld --bucket s3://rookery-celld \
  --endpoint http://127.0.0.1:9000 \
  --region us-east-1 \
  --listen 0.0.0.0:8787 \
  --internal-listen 127.0.0.1:9002
