"""rookery on Modal: one celld node as a Modal web server.

    modal deploy deploy/modal_app.py

The node must take many requests at once (the relay holds a subscribeRepos
websocket open for good), so the function is @modal.concurrent; with Modal's
default of one input per container, that websocket would block every other
request. max_containers=1 because one node owns the celld fleet. It scales to zero
when idle (never min_containers); the relay reconnects on the next crawl. Secrets: see docs/modal.md (minio-root + rookery-pds
for start-modal-minio.sh). ROOKERY_REF picks the commit to run (default main).
"""

import os
import subprocess

import modal

REF = os.environ.get("ROOKERY_REF", "main")

image = (
    modal.Image.debian_slim()
    .apt_install("ca-certificates", "curl", "gnupg", "git")
    .run_commands(
        "mkdir -p /etc/apt/keyrings"
        " && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg"
        " && echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main'"
        " > /etc/apt/sources.list.d/nodesource.list && apt-get update && apt-get install -y nodejs",
        "curl -fsSL https://github.com/denoland/celld/releases/download/v0.6.1/celld-x86_64-unknown-linux-gnu.gz"
        " | gunzip > /usr/local/bin/celld && chmod +x /usr/local/bin/celld",
        "npm install -g esbuild@0.27.4",
        f"git clone https://github.com/nandi-conda/rookery-pds /app && cd /app && git checkout {REF} && npm ci --omit=dev",
    )
)

app = modal.App("rookery-pds")


@app.function(
    image=image,
    secrets=[modal.Secret.from_name("minio-root"), modal.Secret.from_name("rookery-pds")],
    max_containers=1,
    memory=1024,
    timeout=24 * 3600,
)
@modal.concurrent(max_inputs=500)
@modal.web_server(8787, startup_timeout=300)
def web():
    subprocess.Popen(["/app/start-modal-minio.sh"])
