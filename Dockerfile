FROM debian:bookworm-slim

# Install CA certificates for TLS (celld needs these for outbound HTTPS)
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

# Install celld binary (v0.6.1, Rust + V8 Workers runtime)
RUN curl -L -o /tmp/celld.gz https://github.com/denoland/celld/releases/download/v0.6.1/celld-x86_64-unknown-linux-gnu.gz \
    && gunzip -c /tmp/celld.gz > /usr/local/bin/celld \
    && rm /tmp/celld.gz \
    && chmod +x /usr/local/bin/celld

WORKDIR /app

# Copy project config and source
COPY wrangler.jsonc ./
COPY src/ ./src/
COPY package.json ./

# celld dev stores state in PROJECT/.celld/dev — symlink to Fly volume for persistence
RUN mkdir -p /data/celld && ln -sfn /data/celld /app/.celld

EXPOSE 8787

# Single-node: no S3 needed, persistent local storage on the volume
CMD ["celld", "dev", "--no-watch", "--host", "0.0.0.0", "--port", "8787"]
