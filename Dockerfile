# Build stage for backend
FROM node:20-alpine AS backend-build

WORKDIR /app

COPY server/package.json server/package-lock.json* ./
RUN npm install --production

# Build stage for frontend
FROM node:20-alpine AS frontend-build

WORKDIR /app

COPY client/package.json client/package-lock.json* ./
RUN npm install

COPY client/ ./
RUN npm run build

# Final stage
FROM node:20-alpine

# Install PostgreSQL client
RUN apk add --no-cache postgresql-client

WORKDIR /app

# Copy backend
COPY server/package.json server/package-lock.json* ./
RUN npm install --production

# Copy frontend build
COPY --from=frontend-build /app/dist ./dist

# Copy server source
COPY server/src ./src

# Create data directory
RUN mkdir -p /app/data

EXPOSE 3001

CMD ["node", "src/index.js"]
