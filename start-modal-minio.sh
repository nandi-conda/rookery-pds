#!/bin/bash
# Modal entrypoint for a MinIO bucket instead of R2: maps the MinIO root
# credentials (Modal secret minio-root) onto the S3 credentials celld reads,
# then hands over to start-modal.sh. CELLD_ENDPOINT (Modal secret rookery-pds)
# names the MinIO, e.g. https://codegod100--minio-web.modal.run.

set -euo pipefail

: "${MINIO_ROOT_USER:?}" "${MINIO_ROOT_PASSWORD:?}" "${CELLD_ENDPOINT:?}"
export AWS_ACCESS_KEY_ID="$MINIO_ROOT_USER" AWS_SECRET_ACCESS_KEY="$MINIO_ROOT_PASSWORD"
exec /app/start-modal.sh
