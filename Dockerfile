FROM node:22-slim

# Install CA certificates for TLS verification (workerd needs these)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Cache buster - update to force rebuild
ARG CACHE_BUST=20261004-0226

WORKDIR /app

# Install dependencies (including dev for wrangler build)
COPY package.json package-lock.json ./
RUN npm ci

# Copy source and config
COPY src/ ./src/
COPY wrangler.toml ./
COPY tsconfig.json ./

# Build the worker with wrangler (compiles TS, bundles)
RUN npx wrangler deploy --dry-run --outdir dist

# Install miniflare for running the worker
RUN npm install -g miniflare@3

# Create data directories for SQLite (D1) and filesystem (R2)
RUN mkdir -p /data/d1 /data/r2 /data/do /data/kv

# Copy the runner script
COPY run-miniflare.mjs ./

EXPOSE 8787

CMD ["node", "run-miniflare.mjs"]
