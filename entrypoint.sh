#!/bin/bash
set -e
# Ensure the celld state directory exists on the Fly volume
mkdir -p /data/celld
# Symlink it into the project (celld dev uses PROJECT/.celld/dev)
ln -sfn /data/celld /app/.celld
# Start celld
exec celld dev --no-watch --host 0.0.0.0 --port 8787
