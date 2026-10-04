FROM node:22-slim

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy source
COPY src/ ./src/
COPY wrangler.toml ./

# Install miniflare for running the worker
RUN npm install -g miniflare@3

# Create data directories for SQLite (D1) and filesystem (R2)
RUN mkdir -p /data/d1 /data/r2 /data/do

# Copy the runner script
COPY run-miniflare.mjs ./

EXPOSE 8787

CMD ["node", "run-miniflare.mjs"]
