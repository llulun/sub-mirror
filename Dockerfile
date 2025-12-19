# Use Node.js LTS Alpine
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files first for caching
COPY package*.json ./

# Install dependencies (production only)
# --ignore-scripts to prevent husky install from failing (husky is devDependency)
RUN npm ci --only=production --ignore-scripts

# Copy source code
COPY src ./src
COPY public ./public
COPY bin ./bin

# Create data and logs directories
RUN mkdir -p data logs

# Environment variables
ENV PORT=8080
ENV NODE_ENV=production
ENV DATA_DIR=/app/data
ENV STORAGE_TYPE=file

# Admin Configuration
ENV ADMIN_USER=admin
ENV ADMIN_PASS=
ENV ADMIN_TOKEN=

# Cloudflare Configuration
ENV CF_SITE_KEY=
ENV CF_SECRET_KEY=

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

# Start server
CMD ["node", "src/server.js"]
