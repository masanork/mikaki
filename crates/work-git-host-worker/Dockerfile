# Build context is generated explicitly; it contains only this file, host.mjs
# only host.mjs. Source packs are supplied through the private port at runtime.
# Never use the repository root as context.
FROM node:26-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY host.mjs /app/host.mjs
EXPOSE 8080
ENTRYPOINT ["node", "--max-old-space-size=1024", "/app/host.mjs"]
