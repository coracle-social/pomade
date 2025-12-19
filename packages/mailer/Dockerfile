FROM node:20-alpine

# Install pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

# Copy workspace configuration
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./

# Copy all packages
COPY packages ./packages

# Install dependencies
RUN pnpm install --frozen-lockfile

# Build packages
RUN pnpm --filter @pomade/core build
RUN pnpm --filter @pomade/sqlite build
RUN pnpm --filter @pomade/mailer build

# Set working directory to mailer package
WORKDIR /app/packages/mailer

# Create data directory
RUN mkdir -p /data

# Set environment variable for database path
ENV POMADE_DB_PATH=/data/pomade-mailer.db

CMD ["node", "dist/index.js"]
