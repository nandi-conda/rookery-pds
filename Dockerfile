FROM debian:bookworm-slim

# Install dependencies
RUN apt-get update && apt-get install -y ca-certificates curl gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Install celld binary
RUN curl -L -o /tmp/celld.gz https://github.com/denoland/celld/releases/download/v0.6.1/celld-x86_64-unknown-linux-gnu.gz \
    && gunzip -c /tmp/celld.gz > /usr/local/bin/celld \
    && rm /tmp/celld.gz \
    && chmod +x /usr/local/bin/celld

# Install MinIO (S3-compatible storage for celld)
RUN curl -L -o /usr/local/bin/minio https://dl.min.io/server/minio/release/linux-amd64/minio \
    && chmod +x /usr/local/bin/minio

WORKDIR /app

# Copy project
COPY wrangler.jsonc ./
COPY src/ ./src/
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy startup script
COPY start.sh ./
RUN chmod +x start.sh

EXPOSE 8787 9000 9001

CMD ["./start.sh"]
