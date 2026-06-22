# PhishLens web — Next.js (App Router) standalone production image.
# Multi-stage: deps → build (with prisma generate) → minimal non-root runtime.
FROM node:20-slim AS deps

WORKDIR /app

# Install deps from the lockfile only (reproducible). openssl is needed by
# Prisma's generator.
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci


FROM node:20-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Generate the Prisma client (output: src/generated/prisma) before the build,
# then produce the standalone server bundle. A build-time DATABASE_URL is only
# needed so prisma.config.ts loads cleanly; no DB connection is made.
ENV NEXT_TELEMETRY_DISABLED=1
RUN npx prisma generate \
    && npm run build


FROM node:20-slim AS runtime

WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1001 nodejs \
    && useradd --system --uid 1001 --gid nodejs nextjs

# The standalone output bundles only the files the server actually needs
# (traced node_modules incl. the generated Prisma client). Static assets and
# public/ are copied alongside it as Next expects.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
    CMD node -e "require('http').get('http://127.0.0.1:3000/',r=>process.exit(r.statusCode<500?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "server.js"]
