FROM node:22-alpine AS builder

WORKDIR /app

# Enable corepack for pnpm
RUN corepack enable pnpm

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

COPY . .
# We must build with environment variables that point to the backend in production if needed
# However, Vite will proxy /api in dev and preview.
RUN pnpm build

# Stage 2: Serve using Node Alpine
FROM node:22-alpine

# Non-root user
RUN addgroup -S veyronix && adduser -S veyronix -G veyronix

WORKDIR /app

RUN corepack enable pnpm

COPY package.json pnpm-lock.yaml* ./
# Install only prod dependencies
RUN pnpm install --frozen-lockfile --prod

# Copy built assets
COPY --from=builder /app/dist ./dist
COPY vite.config.ts ./

RUN chown -R veyronix:veyronix /app
USER veyronix

EXPOSE 3000

ENV HOST=0.0.0.0
ENV PORT=3000

# We use preview for simplicity to serve the static bundle with proxy support for /api
CMD ["pnpm", "preview", "--host", "0.0.0.0", "--port", "3000"]
