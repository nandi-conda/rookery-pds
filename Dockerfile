FROM debian:bookworm-slim

# Install CA certificates, curl, and Node.js (for npm dependencies)
RUN apt-get update && apt-get install -y ca-certificates curl gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Install celld binary (v0.6.1, Rust + V8 Workers runtime)
RUN curl -L -o /tmp/celld.gz https://github.com/denoland/celld/releases/download/v0.6.1/celld-x86_64-unknown-linux-gnu.gz \
    && gunzip -c /tmp/celld.gz > /usr/local/bin/celld \
    && rm /tmp/celld.gz \
    && chmod +x /usr/local/bin/celld

WORKDIR /app

# Copy project config and source
COPY wrangler.jsonc ./
COPY src/ ./src/
COPY package.json package-lock.json ./

# Install npm dependencies (celld resolves these for the worker)
RUN npm ci --omit=dev

# celld dev stores state in PROJECT/.celld/dev — symlink to Fly volume for persistence
RUN mkdir -p /data/celld && ln -sfn /data/celld /app/.celld

EXPOSE 8787

# Single-node: no S3 needed, persistent local storage on the volume
CMD ["celld", "dev", "--no-watch", "--host", "0.0.0.0", "--port", "8787"]
