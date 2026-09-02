# Patchpoint backend API.
#
# The frontend is a separate image (Dockerfile.client) served by nginx, so
# nothing here builds or serves client assets.

FROM node:20-alpine

ENV NODE_ENV=production

WORKDIR /app

# Install dependencies first so the layer caches independently of source.
# `npm ci` installs exactly what the lockfile pins; `npm install` can resolve
# to different versions between builds.
COPY server/package.json server/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server/src ./src

# Drop privileges. The node image ships an unprivileged `node` user.
USER node

EXPOSE 3001

# Report unhealthy until the API answers, so compose can gate the frontend.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD node -e "require('http').get('http://127.0.0.1:3001/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "src/index.js"]
