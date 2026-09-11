# ===========================================================================
# Stage 1: Builder
# Installs all deps (including devDeps for build) and compiles the frontend
# ===========================================================================
FROM node:22-alpine AS builder

WORKDIR /app

# Enable corepack for deterministic pnpm version
RUN corepack enable && corepack prepare pnpm@latest --activate

# Copy lockfile and manifest first for layer caching
COPY package.json pnpm-lock.yaml ./

# Install ALL deps (including devDeps needed for Vite build)
RUN pnpm install --frozen-lockfile

# Copy the full source and build
COPY . .
RUN pnpm build

# ===========================================================================
# Stage 2: Runtime
# Minimal image — only production deps and compiled output
# No source code, no dev tools, no credentials
# ===========================================================================
FROM node:22-alpine

# Create non-root user
RUN addgroup -S veyronix && adduser -S -G veyronix -h /app -s /sbin/nologin veyronix

WORKDIR /app

# Enable corepack for pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# Copy manifests and install ONLY production dependencies
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod

# Copy compiled output from builder stage
COPY --from=builder /app/dist ./dist

# Set ownership
RUN chown -R veyronix:veyronix /app

# Switch to non-root user
USER veyronix

EXPOSE 3000

ENV HOST=0.0.0.0 \
    PORT=3000 \
    NODE_ENV=production

# Health check — the compiled Express server serves the SPA and same-origin API proxy.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/ || exit 1

CMD ["node", "dist/index.js"]
