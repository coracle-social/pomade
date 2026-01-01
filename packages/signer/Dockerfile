FROM node:20-alpine

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

# Copy workspace configuration
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.json ./

# Copy all packages
COPY packages ./packages

# Install dependencies (skip husky in Docker)
ENV HUSKY=0
RUN pnpm install --frozen-lockfile

# Build packages
RUN pnpm --filter @pomade/core build
RUN pnpm --filter @pomade/signer build

# Set working directory to signer package
WORKDIR /app/packages/signer

# Create data directory
RUN mkdir -p /data

# Set environment variable for database path
ENV POMADE_DB_PATH=/data/pomade-signer.db

CMD ["node", "dist/index.js"]
