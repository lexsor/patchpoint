#!/bin/bash
# Docker build test script
# Validates that docker compose build succeeds

set -e

echo "=== Vulnerability Dashboard - Docker Build Test ==="
echo ""

# Check prerequisites
echo "Checking prerequisites..."
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose is not installed"
    exit 1
fi

echo "Docker: $(docker --version)"
echo "Docker Compose: $(docker compose version)"
echo ""

# Build
echo "Building Docker images..."
docker compose build

echo ""
echo "Build successful!"
echo ""
echo "=== Test Summary ==="
echo "✓ Prerequisites met"
echo "✓ Docker images built successfully"
echo ""
echo "To run the stack: docker compose up"
echo "To access dashboard: http://localhost:3000"
echo "To access API: http://localhost:3001"
